"""CSV report writer — one row per finding."""

from __future__ import annotations

import csv
import io
from pathlib import Path

from lazyhound.finder.finder_models import ScanResult

COLUMNS = [
    "check_id",
    "severity",
    "category",
    "title",
    "description",
    "affected_count",
    "risk_points",
    "mitre_technique",
    "remediation",
    "affected_objects",
]


class CSVReport:
    """Export findings to CSV."""

    @staticmethod
    def to_string(result: ScanResult) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(COLUMNS)
        for cr in result.check_results:
            for f in cr.findings:
                writer.writerow([
                    f.check_id,
                    f.severity.value,
                    f.category.value,
                    f.title,
                    f.description,
                    f.affected_count,
                    f.risk_points,
                    f.mitre.technique_id if f.mitre else "",
                    f.remediation.description if f.remediation else "",
                    "; ".join(f.affected_objects[:50]),
                ])
        return buf.getvalue()

    @staticmethod
    def write(result: ScanResult, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(CSVReport.to_string(result), encoding="utf-8")
        return p
