"""Thin shim so `pip install .` creates a `403x` command."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from forbiddenx.output import print_banner, print_summary, export_results, live_progress
from forbiddenx.core   import Scanner, COMMON_PATHS, payload_stats
import argparse


def normalise_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip()


def load_url_list(path: str) -> list[str]:
    urls = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(normalise_url(line))
    return urls


def _make_scanner(args) -> Scanner:
    return Scanner(
        threads=args.threads, timeout=args.timeout,
        proxy=args.proxy, delay=args.delay,
        user_agent=args.user_agent, verify_ssl=args.verify_ssl,
        max_per_target=getattr(args, "max_bypass", 0) or 0,
    )


BUG_BOUNTY_TIPS = """
╔══════════════════════════════════════════════════════════════════╗
║              403x  ·  Bug Bounty Integration Guide               ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  1. RECON PIPELINE                                               ║
║     subfinder -d target.com -silent \\                           ║
║       | httpx -mc 403,401 -silent \\                             ║
║       | tee urls.txt                                             ║
║     403x -l urls.txt -t 50 -o results.txt                        ║
║                                                                  ║
║  2. BURP SUITE INTEGRATION                                       ║
║     403x -l urls.txt -p http://127.0.0.1:8080                    ║
║     → All bypass attempts flow through Burp for replay/analysis  ║
║                                                                  ║
║  3. RATE LIMITING / IDS EVASION                                  ║
║     403x -l urls.txt --delay 0.5 -t 5                            ║
║     → Slow scan to avoid detection on WAF-protected targets      ║
║                                                                  ║
║  4. FFUF COMBO (validate then fuzz deeper)                       ║
║     ffuf -u https://target.com/FUZZ -w wordlist.txt \\           ║
║          -mc 403 -o fuzz.txt                                     ║
║     → feed fuzz.txt results as -l input to 403x                  ║
║                                                                  ║
║  5. CHAIN WITH NUCLEI                                            ║
║     cat bypass_results.txt | grep "BYPASS SUCCESS" \\            ║
║       | nuclei -t exposures/ -t cves/                            ║
║                                                                  ║
║  6. WRITING A GOOD BYPASS REPORT                                 ║
║     • State original 403 URL & headers                           ║
║     • Show exact bypass URL/headers used                         ║
║     • Prove access: include response body snippet (sanitised)    ║
║     • Provide curl PoC:                                          ║
║       curl -sk -H "X-Original-URL: /admin" https://target.com/  ║
║     • Map to CWE-284 (Improper Access Control) / OWASP A01       ║
║                                                                  ║
║  7. SEVERITY GUIDANCE                                            ║
║     High/Critical  → admin panels, user data, RCE primitives     ║
║     Medium         → internal APIs, config disclosure            ║
║     Low/Info       → dev endpoints, metrics, status pages        ║
║                                                                  ║
║  8. FALSE POSITIVE FILTERING                                     ║
║     • Compare content-length — same 403 body ≠ bypass            ║
║     • Check response title / h1 tags                             ║
║     • 301/302 → follow redirect and verify destination           ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="403x",
        description="Advanced 403 Bypass Recon Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  403x -u https://target.com/admin
  403x -u https://target.com --discover
  403x -l urls.txt -o results.txt -t 50
  403x -u https://target.com/admin -p http://127.0.0.1:8080
  403x -l targets.txt --force --delay 0.2
  403x --stats
  403x --tips
        """,
    )

    tg = p.add_argument_group("Targets")
    tg.add_argument("-u", "--url",   metavar="URL",  help="Single target URL")
    tg.add_argument("-l", "--list",  metavar="FILE", help="File with one URL per line")
    tg.add_argument("--discover",    action="store_true",
                    help="Auto-discover 403/401 endpoints on base domain(s)")

    sc = p.add_argument_group("Scanner")
    sc.add_argument("-t", "--threads",   type=int,   default=30,  metavar="N")
    sc.add_argument("--timeout",         type=int,   default=10,  metavar="SEC")
    sc.add_argument("--delay",           type=float, default=0,   metavar="SEC")
    sc.add_argument("--force",           action="store_true",
                    help="Bypass even non-403 responses")
    sc.add_argument("--max-bypass",      type=int,   default=0,   metavar="N",
                    help="Stop after N successful bypasses per URL (0=unlimited)")
    sc.add_argument("--verify-ssl",      action="store_true")
    sc.add_argument("--user-agent",      metavar="UA",
                    default="403x/1.0 (Security Research)")

    net = p.add_argument_group("Network")
    net.add_argument("-p", "--proxy", metavar="URL",
                     help="Proxy URL (e.g. http://127.0.0.1:8080)")

    out = p.add_argument_group("Output")
    out.add_argument("-o", "--output",  metavar="FILE")
    out.add_argument("--no-banner",     action="store_true")
    out.add_argument("--quiet",         action="store_true",
                     help="Only print bypass successes")
    out.add_argument("--stats",         action="store_true",
                     help="Show payload statistics and exit")
    out.add_argument("--tips",          action="store_true",
                     help="Show bug bounty integration tips and exit")

    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if not args.no_banner:
        print_banner()

    # Info-only flags
    if args.stats:
        s = payload_stats()
        print(f"\n  Payload statistics")
        print(f"  {'─'*40}")
        print(f"  Path variants per URL  : {s['path_variants']}")
        print(f"  Header injection sets  : {s['header_sets']}")
        print(f"  HTTP methods           : {s['methods']}")
        print(f"  Protocol variants      : {s['protocol']}")
        print(f"  Port variants          : {s['port_variants']}")
        print(f"  {'─'*40}")
        print(f"  TOTAL requests per URL : {s['total_per_url']}\n")
        return

    if args.tips:
        print(BUG_BOUNTY_TIPS)
        return

    # Build target list
    urls = []
    if args.url:
        urls.append(normalise_url(args.url))
    if args.list:
        try:
            urls.extend(load_url_list(args.list))
        except FileNotFoundError:
            print(f"[!] URL list file not found: {args.list}")
            sys.exit(1)
    if not urls:
        print("[!] No targets. Use -u <url> or -l <file>")
        sys.exit(1)

    scanner = _make_scanner(args)

    if args.discover:
        print(f"\n[~] Auto-discovering on {len(urls)} domain(s)...\n")
        discovered = []
        for base in urls:
            found = scanner.discover_endpoints(base)
            if found:
                print(f"  Found {len(found)} endpoint(s) on {base}")
                for ep in found:
                    print(f"    [403] {ep}")
                discovered.extend(found)
            else:
                print(f"  Nothing found on {base}")
        if not discovered:
            print("\n[!] No protected endpoints discovered.")
            sys.exit(0)
        urls = list(dict.fromkeys(discovered))
        print()

    urls = list(dict.fromkeys(urls))

    if not args.quiet:
        s = payload_stats()
        print(f"[+] {len(urls)} target(s)  ·  {s['total_per_url']} requests/URL  ·  {args.threads} threads\n")

    cb = None if args.quiet else lambda url, code, bps: live_progress(url, code, bps)
    all_results = scanner.scan_many(urls, force=args.force, progress_cb=cb)

    if not args.quiet:
        print_summary(all_results)
    else:
        for url, (code, bypasses) in all_results.items():
            for b in bypasses:
                if b.bypass:
                    print(f"[BYPASS {b.status_code}] {b.technique} → {b.url}")

    output_file = args.output or "bypass_results.txt"
    export_results(all_results, output_file)
