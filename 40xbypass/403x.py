#!/usr/bin/env python3
"""
403x - Advanced 403 Bypass Recon Framework
CLI Entry Point
"""

import argparse
import sys
from urllib.parse import urlparse

from forbiddenx import (
    Scanner,
    print_banner,
    print_summary,
    export_results,
    live_progress,
)


# ── Helpers ──────────────────────────────────────────────────

def normalise_url(url: str) -> str:
    """Ensure URL has a scheme."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip()


def load_url_list(path: str) -> list[str]:
    """Read URLs from a file (one per line, # comments allowed)."""
    urls = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(normalise_url(line))
    return urls


def build_target_list(args) -> list[str]:
    """Resolve -u / -l / --discover into a final list of URLs."""
    urls = []

    if args.url:
        urls.append(normalise_url(args.url))

    if args.list:
        try:
            urls.extend(load_url_list(args.list))
        except FileNotFoundError:
            print(f"[!] URL list file not found: {args.list}")
            sys.exit(1)

    # Auto-discover: scan each domain's common paths
    if args.discover:
        scanner = _make_scanner(args)
        base_urls = list(urls)
        if not base_urls:
            print("[!] --discover requires at least one base URL via -u or -l")
            sys.exit(1)
        print(f"\n[~] Auto-discovering sensitive endpoints on {len(base_urls)} domain(s)...\n")
        discovered = []
        for base in base_urls:
            found = scanner.discover_endpoints(base)
            if found:
                print(f"  Found {len(found)} endpoints on {base}")
                for ep in found:
                    print(f"    [403] {ep}")
                discovered.extend(found)
            else:
                print(f"  No 403/401 endpoints found on {base}")
        if not discovered:
            print("\n[!] No protected endpoints discovered. Try manual paths.")
            sys.exit(0)
        urls = discovered  # replace base URLs with discovered targets
        print()

    if not urls:
        print("[!] No targets specified. Use -u <url> or -l <file>")
        sys.exit(1)

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            unique.append(u)

    return unique


def _make_scanner(args) -> Scanner:
    return Scanner(
        threads=args.threads,
        timeout=args.timeout,
        proxy=args.proxy,
        delay=args.delay,
        user_agent=args.user_agent,
        verify_ssl=args.verify_ssl,
    )


# ── Argument parser ──────────────────────────────────────────

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
        """,
    )

    # ── Targets ──────────────────────────────
    tg = p.add_argument_group("Targets")
    tg.add_argument(
        "-u", "--url",
        metavar="URL",
        help="Single target URL (e.g. https://target.com/admin)",
    )
    tg.add_argument(
        "-l", "--list",
        metavar="FILE",
        help="File containing one URL per line",
    )
    tg.add_argument(
        "--discover",
        action="store_true",
        help="Auto-discover 403/401 endpoints on base domain(s) before scanning",
    )

    # ── Scanner options ───────────────────────
    sc = p.add_argument_group("Scanner")
    sc.add_argument(
        "-t", "--threads",
        type=int, default=30, metavar="N",
        help="Number of threads (default: 30)",
    )
    sc.add_argument(
        "--timeout",
        type=int, default=10, metavar="SEC",
        help="Request timeout in seconds (default: 10)",
    )
    sc.add_argument(
        "--delay",
        type=float, default=0, metavar="SEC",
        help="Delay between requests in seconds (default: 0)",
    )
    sc.add_argument(
        "--force",
        action="store_true",
        help="Attempt bypasses even if endpoint is NOT 401/403",
    )
    sc.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Verify SSL certificates (disabled by default)",
    )
    sc.add_argument(
        "--user-agent",
        metavar="UA",
        default="403x/1.0 (Security Research)",
        help="Custom User-Agent string",
    )

    # ── Network ───────────────────────────────
    net = p.add_argument_group("Network")
    net.add_argument(
        "-p", "--proxy",
        metavar="URL",
        help="Proxy URL (e.g. http://127.0.0.1:8080 for Burp Suite)",
    )

    # ── Output ────────────────────────────────
    out = p.add_argument_group("Output")
    out.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Save results to file (default: bypass_results.txt)",
    )
    out.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the ASCII banner",
    )
    out.add_argument(
        "--quiet",
        action="store_true",
        help="Only print bypass successes (suppress all other output)",
    )

    return p


# ── Main ─────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args   = parser.parse_args()

    if not args.no_banner:
        print_banner()

    urls    = build_target_list(args)
    scanner = _make_scanner(args)

    # Choose progress callback
    cb = None
    if not args.quiet:
        def cb(url, code, bypasses):
            live_progress(url, code, bypasses)

    if not args.quiet:
        print(f"[+] Scanning {len(urls)} target(s) with {args.threads} threads...\n")

    all_results = scanner.scan_many(urls, force=args.force, progress_cb=cb)

    # Summary
    if not args.quiet:
        print_summary(all_results)
    else:
        # Quiet mode: only print bypass lines
        for url, (code, bypasses) in all_results.items():
            for b in bypasses:
                if b.bypass:
                    print(f"[BYPASS {b.status_code}] {b.technique} → {b.url}")

    # Export
    output_file = args.output or "bypass_results.txt"
    export_results(all_results, output_file)


if __name__ == "__main__":
    main()
