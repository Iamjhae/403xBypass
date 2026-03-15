"""
403x - Output & Reporting
"""

import sys
from datetime import datetime
from .core import BypassResult

# ── ANSI colours (auto-disabled on non-TTY) ──────────────────
_COLOUR = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOUR else text

RED    = lambda t: _c("91", t)
GREEN  = lambda t: _c("92", t)
YELLOW = lambda t: _c("93", t)
CYAN   = lambda t: _c("96", t)
BOLD   = lambda t: _c("1",  t)
DIM    = lambda t: _c("2",  t)
WHITE  = lambda t: _c("97", t)

# ── Banner ───────────────────────────────────────────────────

BANNER = r"""
███████╗ ██████╗ ██████╗ ██╗  ██╗██╗  ██╗
██╔════╝██╔═══██╗██╔══██╗╚██╗██╔╝╚██╗██╔╝
█████╗  ██║   ██║██████╔╝ ╚███╔╝  ╚███╔╝ 
██╔══╝  ██║   ██║██╔══██╗ ██╔██╗  ██╔██╗ 
██║     ╚██████╔╝██║  ██║██╔╝ ██╗██╔╝ ██╗
╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝

  Advanced 403 Bypass Recon Framework
  by Arookiech | Bug Bounty | Security Research
"""


def print_banner():
    print(CYAN(BANNER))


# ── Status helpers ───────────────────────────────────────────

def status_label(code: int) -> str:
    if code == 0:
        return RED("TIMEOUT")
    if code in (200, 201, 202, 204):
        return GREEN(str(code))
    if code in (301, 302, 307, 308):
        return YELLOW(str(code))
    if code in (401, 403):
        return RED(str(code))
    return DIM(str(code))


# ── Live progress callbacks ──────────────────────────────────

def live_progress(url: str, code: int, bypasses: list[BypassResult]):
    found = [b for b in bypasses if b.bypass]
    icon  = "✅" if found else ("🔒" if code in (401, 403) else "⏭ ")
    print(f"  {icon}  {status_label(code)}  {url}  "
          + (GREEN(f"({len(found)} bypass{'es' if len(found) != 1 else ''} found)") if found else ""))

    for b in found:
        print(f"       {GREEN('⮕')} [{b.technique}]  {BOLD(b.url)}  "
              f"{GREEN(str(b.status_code))} len={b.content_length}")
        if b.headers_used:
            for k, v in b.headers_used.items():
                print(f"         {DIM(k+': '+v)}")


# ── Summary table ────────────────────────────────────────────

def print_summary(all_results: dict):
    """all_results = { url: (code, [BypassResult]) }"""
    bypassed = {
        url: [b for b in bypasses if b.bypass]
        for url, (_, bypasses) in all_results.items()
        if any(b.bypass for b in bypasses)
    }

    print("\n" + BOLD("─" * 60))
    print(BOLD(f"  SCAN COMPLETE — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print(BOLD("─" * 60))
    print(f"  Targets scanned : {len(all_results)}")
    print(f"  Bypasses found  : {GREEN(str(sum(len(v) for v in bypassed.values())))}")
    print()

    if bypassed:
        print(BOLD("  ╔══════════════════════════════════════════════════════╗"))
        print(BOLD("  ║              BYPASS RESULTS SUMMARY                 ║"))
        print(BOLD("  ╚══════════════════════════════════════════════════════╝\n"))

        for url, blist in bypassed.items():
            print(f"  {RED('TARGET')}  {BOLD(url)}")
            for b in blist:
                print(f"    {GREEN('✓')} [{b.status_code}] {b.technique}")
                print(f"      URL: {b.url}")
                if b.headers_used:
                    for k, v in b.headers_used.items():
                        print(f"      {DIM(k+': '+v)}")
            print()
    else:
        print(f"  {YELLOW('No bypasses found across all targets.')}\n")


# ── File export ──────────────────────────────────────────────

def export_results(all_results: dict, output_file: str):
    lines = [
        "403x - Bypass Results",
        f"Generated: {datetime.now().isoformat()}",
        "=" * 60,
        "",
    ]

    for url, (code, bypasses) in all_results.items():
        found = [b for b in bypasses if b.bypass]
        lines.append(f"TARGET: {url}  [original status: {code}]")

        if found:
            lines.append(f"  BYPASSES FOUND: {len(found)}")
            for b in found:
                lines.append(f"    [{b.status_code}] {b.technique}")
                lines.append(f"    URL: {b.url}")
                if b.headers_used:
                    for k, v in b.headers_used.items():
                        lines.append(f"    Header: {k}: {v}")
                lines.append("")
        else:
            lines.append("  No bypasses found.")
            lines.append("")

    with open(output_file, "w") as f:
        f.write("\n".join(lines))

    print(f"\n  {GREEN('Results saved →')} {output_file}")
