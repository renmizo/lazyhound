"""PDF report writer — converts HTML reports to PDF.

Requires weasyprint (optional dependency).  Install with:
    pip install weasyprint
"""

from __future__ import annotations

from pathlib import Path

from lazyhound.finder.finder_models import ScanResult


class PDFReport:
    """Export scan results to PDF via HTML rendering."""

    @staticmethod
    def write(result: ScanResult, path: str | Path) -> Path:
        try:
            from weasyprint import HTML  # type: ignore[import-untyped]
        except ImportError:
            raise RuntimeError(
                "PDF export requires weasyprint. Install with: pip install weasyprint"
            )

        from .html_report import HTMLReport

        html_str = HTMLReport.to_string(result)
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        HTML(string=html_str).write_pdf(str(p))
        return p


class PDFAnalysisReport:
    """Export offline analysis results to PDF via HTML rendering."""

    @staticmethod
    def write(result, path: str | Path, *, show_builtin: bool = False) -> Path:
        try:
            from weasyprint import HTML  # type: ignore[import-untyped]
        except ImportError:
            raise RuntimeError(
                "PDF export requires weasyprint. Install with: pip install weasyprint"
            )

        from .html_analysis_report import HTMLAnalysisReport

        html_str = HTMLAnalysisReport.to_string(result, show_builtin=show_builtin)
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        HTML(string=html_str).write_pdf(str(p))
        return p
