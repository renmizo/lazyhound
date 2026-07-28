"""JSON report writer."""

from __future__ import annotations

import json
from pathlib import Path

from lazyhound.finder.finder_models import ScanResult


class JSONReport:
    """Serialize a ScanResult to JSON."""

    @staticmethod
    def to_string(result: ScanResult, indent: int = 2) -> str:
        return json.dumps(result.to_dict(), indent=indent, default=str)

    @staticmethod
    def write(result: ScanResult, path: str | Path, indent: int = 2) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(JSONReport.to_string(result, indent), encoding="utf-8")
        return p
