"""CSV report writer for offline analysis results — one row per finding."""

from __future__ import annotations

import csv
import io
from pathlib import Path


COLUMNS = [
    "category",
    "severity",
    "principal",
    "principal_sid",
    "target",
    "target_sid",
    "description",
    "right",
    "details",
]


class AnalysisCSVReport:
    """Export offline analysis findings to CSV."""

    @staticmethod
    def to_string(result, *, show_builtin: bool = False) -> str:
        findings = result.findings if show_builtin else result.actionable
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(COLUMNS)
        for f in findings:
            details_parts = []
            for k, v in sorted(f.details.items()):
                if k not in ("right", "principal_name", "target_name"):
                    details_parts.append(f"{k}={v}")
            writer.writerow([
                f.category.value,
                f.severity.value,
                f.principal_name or "",
                f.principal_sid or "",
                f.target_name or "",
                f.details.get("target_sid", ""),
                f.description,
                f.details.get("right", ""),
                "; ".join(details_parts),
            ])
        return buf.getvalue()

    @staticmethod
    def write(result, path: str | Path, *, show_builtin: bool = False) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            AnalysisCSVReport.to_string(result, show_builtin=show_builtin),
            encoding="utf-8",
        )
        return p
