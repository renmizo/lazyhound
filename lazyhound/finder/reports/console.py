"""ANSI console report renderer."""

from __future__ import annotations

import sys
from typing import IO

from lazyhound.finder.finder_models import CheckCategory, Severity, ScanResult


# ANSI color codes
_COLORS = {
    Severity.CRITICAL: "\033[1;91m",      # bold bright red
    Severity.HIGH: "\033[38;5;208m",      # orange (256-color)
    Severity.MEDIUM: "\033[93m",          # yellow
    Severity.LOW: "\033[92m",             # green
    Severity.INFO: "\033[94m",            # blue
}
_GRADE_COLORS = {
    "A": "\033[92m",
    "B": "\033[92m",
    "C": "\033[93m",
    "D": "\033[91m",
    "F": "\033[1;91m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


def _sev_label(sev: Severity) -> str:
    return f"{_COLORS[sev]}{sev.value.upper():>8}{_RESET}"


def _bar(value: int, max_val: int, width: int = 30) -> str:
    if max_val == 0:
        return ""
    filled = int(value / max_val * width)
    return f"{'█' * filled}{'░' * (width - filled)}"


class ConsoleReport:
    """Writes a human-readable ANSI report to a text stream."""

    def __init__(self, stream: IO[str] | None = None, style: int = 2) -> None:
        self.stream = stream or sys.stdout
        from .finding_styles import get_style
        self._style = get_style(style)

    def _write(self, text: str = "") -> None:
        self.stream.write(text + "\n")

    def render(self, result: ScanResult) -> None:
        self._header(result)
        self._severity_summary(result)
        self._category_summary(result)
        self._findings(result)
        self._footer(result)

    # -- sections --

    def _header(self, r: ScanResult) -> None:
        self._write()
        self._write(f"{_BOLD}╔══════════════════════════════════════════════════════════════╗{_RESET}")
        self._write(f"{_BOLD}║  LazyHound — Active Directory Security Assessment        ║{_RESET}")
        self._write(f"{_BOLD}╚══════════════════════════════════════════════════════════════╝{_RESET}")
        self._write()
        self._write(f"  Domain:     {_BOLD}{r.target_domain}{_RESET}")
        self._write(f"  Scan ID:    {r.scan_id}")
        self._write(f"  Started:    {r.started_at:%Y-%m-%d %H:%M:%S UTC}")
        if r.completed_at:
            self._write(f"  Completed:  {r.completed_at:%Y-%m-%d %H:%M:%S UTC}")
        self._write(f"  Duration:   {r.duration_ms:.0f} ms")
        self._write()

        grade_color = _GRADE_COLORS.get(r.grade, "")
        health = r.health_pct
        affected = r.affected_object_count
        total = r.total_objects
        self._write(f"  Risk Score: {_BOLD}{r.risk_score}/100{_RESET}  "
                     f"Rating: {grade_color}{_BOLD}{r.rating}{_RESET}")
        self._write(f"  Health:     {health:.0f}% "
                     f"({total - affected}/{total} objects clean)")
        if r.raw_risk_score != r.risk_score:
            self._write(f"  Raw Risk:   {r.raw_risk_score}/100 (before health adjustment)")
        self._write(f"  Checks:     {r.checks_passed} passed, {r.checks_failed} with findings")
        self._write(f"  Findings:   {r.total_findings} total "
                     f"({r.total_risk_points} raw pts, {r.weighted_risk_points:.0f} weighted)")
        self._write()

    def _severity_summary(self, r: ScanResult) -> None:
        by_sev = r.findings_by_severity()
        max_count = max((len(v) for v in by_sev.values()), default=1)
        self._write(f"  {_BOLD}Severity Breakdown{_RESET}")
        self._write(f"  {'─' * 56}")
        for sev in Severity:
            count = len(by_sev[sev])
            bar = _bar(count, max_count, 25)
            self._write(f"  {_sev_label(sev)}  {bar}  {count}")
        self._write()

    def _category_summary(self, r: ScanResult) -> None:
        by_cat = r.findings_by_category()
        if not by_cat:
            return
        self._write(f"  {_BOLD}Category Breakdown{_RESET}")
        self._write(f"  {'─' * 56}")
        for cat in CheckCategory:
            findings = by_cat.get(cat, [])
            if not findings:
                continue
            pts = sum(f.risk_points or 0 for f in findings)
            wpts = pts * cat.weight
            self._write(f"  {cat.label:<22}  {len(findings):>3} finding(s)  "
                         f"{pts:>4} pts  (×{cat.weight:.1f} = {wpts:.0f})")
        self._write()

    def _findings(self, r: ScanResult) -> None:
        all_findings = []
        for cr in r.check_results:
            for f in cr.findings:
                all_findings.append(f)
        all_findings.sort(key=lambda f: f.severity.sort_order)

        if not all_findings:
            self._write(f"  {_BOLD}No findings — great job!{_RESET}")
            self._write()
            return

        self._style.render_header(len(all_findings), self._write)
        for i, f in enumerate(all_findings, 1):
            self._style.render_finding(f, i, self._write)

    def _footer(self, r: ScanResult) -> None:
        errors = [cr for cr in r.check_results if cr.error]
        if errors:
            self._write()
            self._write(f"  {_BOLD}Errors ({len(errors)}){_RESET}")
            self._write(f"  {'─' * 56}")
            for cr in errors:
                self._write(f"  {cr.check_id} ({cr.check_name}): {cr.error}")
        self._write()
        self._write(f"  {_DIM}Report generated by LazyHound{_RESET}")
        self._write()
