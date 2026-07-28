"""Finding display style strategies for console output.

Four styles control how individual findings are rendered:
  1 — Compact:  dense, minimal spacing
  2 — Clean:    left-aligned severity, separator per finding (default)
  3 — Boxed:    box-drawing characters around each finding
  4 — Detailed: full labelled breakdown with finding numbers
"""

from __future__ import annotations

import textwrap
from abc import ABC, abstractmethod
from typing import Callable

from lazyhound.finder.finder_models import Finding, Severity

# ANSI escape codes — kept in sync with console.py
_COLORS = {
    Severity.CRITICAL: "\033[1;91m",      # bold bright red
    Severity.HIGH: "\033[38;5;208m",      # orange (256-color)
    Severity.MEDIUM: "\033[93m",          # yellow
    Severity.LOW: "\033[92m",             # green
    Severity.INFO: "\033[94m",            # blue
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

WriteFn = Callable[[str], None]


def _colored_sev(sev: Severity) -> str:
    """Return the severity name in its ANSI color."""
    return f"{_COLORS[sev]}{sev.value.upper()}{_RESET}"


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------

class FindingStyle(ABC):
    """Base class for finding display strategies."""

    @abstractmethod
    def render_finding(self, f: Finding, index: int, write: WriteFn) -> None:
        """Render a single finding."""

    def render_header(self, count: int, write: WriteFn) -> None:
        write(f"{_BOLD}Findings ({count}){_RESET}")
        write("═" * 58)


# ---------------------------------------------------------------------------
# Style 1 — Compact
# ---------------------------------------------------------------------------

class CompactStyle(FindingStyle):
    """Dense, minimal spacing.  Good for scanning large result sets."""

    def render_finding(self, f: Finding, index: int, write: WriteFn) -> None:
        sev = _colored_sev(f.severity)
        write(f"{sev} [{f.check_id}] {_BOLD}{f.title}{_RESET}")
        write(f"  {f.description}")
        if f.affected_objects:
            shown = f.affected_objects[:10]
            extra = " ..." if f.affected_count > 10 else ""
            write(f"  Affected ({f.affected_count}): {', '.join(shown)}{extra}")
        parts: list[str] = []
        if f.mitre:
            parts.append(f"MITRE: {f.mitre.technique_id}")
        if f.remediation:
            parts.append(f"Fix: {f.remediation.description}")
        if parts:
            write(f"  {_DIM}{'  '.join(parts)}{_RESET}")


# ---------------------------------------------------------------------------
# Style 2 — Clean (default)
# ---------------------------------------------------------------------------

class CleanStyle(FindingStyle):
    """Left-aligned severity tag, thin separator per finding."""

    def render_finding(self, f: Finding, index: int, write: WriteFn) -> None:
        write("")
        sev = _colored_sev(f.severity)
        write(f"{sev}  [{f.check_id}] {_BOLD}{f.title}{_RESET}")
        write("─" * 58)
        write(f"  {f.description}")

        if f.affected_objects:
            shown = f.affected_objects[:10]
            extra = " ..." if f.affected_count > 10 else ""
            write("")
            write(f"  Affected ({f.affected_count}): {', '.join(shown)}{extra}")

        if f.mitre:
            write("")
            write(f"  {_DIM}MITRE: {f.mitre.technique_id} "
                  f"— {f.mitre.technique_name} ({f.mitre.tactic}){_RESET}")
        if f.remediation:
            write(f"  Fix:   {f.remediation.description}")
            if f.remediation.powershell:
                write(f"  {_DIM}PS>    {f.remediation.powershell}{_RESET}")
            if f.remediation.gpo_path:
                write(f"  {_DIM}GPO:   {f.remediation.gpo_path}{_RESET}")


# ---------------------------------------------------------------------------
# Style 3 — Boxed
# ---------------------------------------------------------------------------

_BOX_WIDTH = 58  # inner width


class BoxedStyle(FindingStyle):
    """Box-drawing characters frame each finding."""

    def _box_line(self, text: str) -> str:
        """Pad *text* to fit inside the box (accounting for ANSI codes)."""
        # Strip ANSI to measure visible length
        import re
        visible = re.sub(r"\033\[[0-9;]*m", "", text)
        pad = max(0, _BOX_WIDTH - len(visible))
        return f"│ {text}{' ' * pad} │"

    def render_finding(self, f: Finding, index: int, write: WriteFn) -> None:
        sev = _colored_sev(f.severity)
        label = f"─ {sev} "
        # top border
        import re
        visible_label = re.sub(r"\033\[[0-9;]*m", "", f"─ {f.severity.value.upper()} ")
        remaining = _BOX_WIDTH + 2 - len(visible_label)
        write("")
        write(f"┌{label}{'─' * remaining}┐")

        write(self._box_line(f"{_BOLD}[{f.check_id}] {f.title}{_RESET}"))
        write(self._box_line(""))

        # Description — wrap long lines
        for line in textwrap.wrap(f.description, width=_BOX_WIDTH):
            write(self._box_line(line))

        if f.affected_objects:
            write(self._box_line(""))
            shown = f.affected_objects[:10]
            extra = " ..." if f.affected_count > 10 else ""
            aff = f"Affected ({f.affected_count}): {', '.join(shown)}{extra}"
            for line in textwrap.wrap(aff, width=_BOX_WIDTH):
                write(self._box_line(line))

        if f.mitre:
            mitre_text = (f"{_DIM}MITRE: {f.mitre.technique_id} "
                          f"— {f.mitre.technique_name} ({f.mitre.tactic}){_RESET}")
            write(self._box_line(mitre_text))
        if f.remediation:
            write(self._box_line(f"Fix: {f.remediation.description}"))
            if f.remediation.powershell:
                write(self._box_line(f"{_DIM}PS> {f.remediation.powershell}{_RESET}"))
            if f.remediation.gpo_path:
                write(self._box_line(f"{_DIM}GPO: {f.remediation.gpo_path}{_RESET}"))

        # bottom border
        write(f"└{'─' * (_BOX_WIDTH + 2)}┘")


# ---------------------------------------------------------------------------
# Style 4 — Detailed
# ---------------------------------------------------------------------------

class DetailedStyle(FindingStyle):
    """Full labelled breakdown with finding numbers."""

    def render_finding(self, f: Finding, index: int, write: WriteFn) -> None:
        write("")
        write("━" * 58)
        write(f"Finding #{index}")
        write("━" * 58)
        sev = _colored_sev(f.severity)
        write(f"  Severity:    {sev}")
        write(f"  Check:       {f.check_id}")
        write(f"  Title:       {_BOLD}{f.title}{_RESET}")

        # Wrap long descriptions with continuation indent
        desc_lines = textwrap.wrap(f.description, width=44)
        if desc_lines:
            write(f"  Description: {desc_lines[0]}")
            for line in desc_lines[1:]:
                write(f"               {line}")

        if f.affected_objects:
            write(f"  Affected:    {f.affected_count} object(s)")
            shown = f.affected_objects[:10]
            extra = " ..." if f.affected_count > 10 else ""
            write(f"               {', '.join(shown)}{extra}")

        if f.mitre:
            write(f"  {_DIM}MITRE:       {f.mitre.technique_id} — {f.mitre.technique_name}")
            write(f"               Tactic: {f.mitre.tactic}{_RESET}")

        if f.remediation:
            write(f"  Remediation: {f.remediation.description}")
            if f.remediation.powershell:
                write(f"  {_DIM}PowerShell:  {f.remediation.powershell}{_RESET}")
            if f.remediation.gpo_path:
                write(f"  {_DIM}GPO Path:    {f.remediation.gpo_path}{_RESET}")


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

STYLES: dict[int, type[FindingStyle]] = {
    1: CompactStyle,
    2: CleanStyle,
    3: BoxedStyle,
    4: DetailedStyle,
}


def get_style(style_id: int) -> FindingStyle:
    """Return a FindingStyle instance for the given style ID (1-4)."""
    cls = STYLES.get(style_id, CleanStyle)
    return cls()
