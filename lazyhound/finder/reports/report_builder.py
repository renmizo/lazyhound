"""Composable report builder.

Allows operators to select any combination of sections and export a single
unified report in DOCX, PDF, or Markdown format.

Available sections:
  - summary        : Environment summary (domain metadata, object counts, etc.)
  - findings       : Executive findings from offline analysis
  - attack_paths   : Mermaid attack path diagrams
  - domain_trust   : Mermaid domain trust map
  - delegation     : Mermaid delegation map
  - collection_stats : Raw collection statistics
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


# All section names recognised by the builder, in default display order.
AVAILABLE_SECTIONS: list[tuple[str, str]] = [
    ("summary", "Environment summary (domain info, object counts, privilege groups)"),
    ("findings", "Executive findings (severity breakdown, attack paths, remediation)"),
    ("attack_paths", "Attack path diagrams (Mermaid)"),
    ("domain_trust", "Domain trust map (Mermaid)"),
    ("delegation", "Delegation map (Mermaid)"),
    ("collection_stats", "Collection statistics (object class breakdown, sessions)"),
]

SECTION_NAMES: list[str] = [s[0] for s in AVAILABLE_SECTIONS]


@dataclass
class ReportSpec:
    """Describes what sections to include and how to export the report."""
    sections: list[str] = field(default_factory=lambda: list(SECTION_NAMES))
    output_path: str = ""
    output_format: str = "markdown"  # markdown, docx, pdf
    template_path: str | None = None
    # Analysis options
    owned: list[str] | None = None
    checks: set[str] | None = None
    exclude: set[str] | None = None
    show_builtin: bool = False
    max_paths: int = 25


@dataclass
class ReportSection:
    """A rendered section ready for assembly."""
    key: str
    title: str
    markdown: str
    data: dict | None = None


def build_sections(
    collection_data: dict,
    idx: Any,
    spec: ReportSpec,
    analysis_result: Any = None,
) -> list[ReportSection]:
    """Generate all requested sections and return them in order.

    If *analysis_result* is provided it is reused for findings and
    attack_paths sections, avoiding a redundant re-analysis.
    """
    sections: list[ReportSection] = []

    for key in spec.sections:
        if key == "summary":
            sections.append(_build_summary(idx))
        elif key == "findings":
            sections.append(_build_findings(
                collection_data, spec.owned, spec.checks,
                spec.exclude, spec.show_builtin,
                analysis_result=analysis_result,
            ))
        elif key == "attack_paths":
            sections.append(_build_attack_paths(
                collection_data, spec.owned, spec.max_paths,
                analysis_result=analysis_result,
            ))
        elif key == "domain_trust":
            sections.append(_build_domain_trust(idx))
        elif key == "delegation":
            sections.append(_build_delegation(idx))
        elif key == "collection_stats":
            sections.append(_build_collection_stats(idx))

    return sections


# -- Section builders ------------------------------------------------------

def _build_summary(idx: Any) -> ReportSection:
    from .summary_report import generate_summary, render_markdown
    data = generate_summary(idx)
    md = render_markdown(data)
    return ReportSection(
        key="summary",
        title="Executive Summary",
        markdown=md,
        data=data,
    )


def _build_findings(
    collection_data: dict,
    owned: list[str] | None,
    checks: set[str] | None,
    exclude: set[str] | None,
    show_builtin: bool,
    analysis_result: Any = None,
) -> ReportSection:
    from .findings_report import generate_findings_report, render_markdown
    if analysis_result is None:
        from ..collect.analyzer import analyze
        analysis_result = analyze(collection_data, checks=checks, exclude=exclude, owned=owned)
    data = generate_findings_report(analysis_result, show_builtin=show_builtin)
    md = render_markdown(data)
    return ReportSection(
        key="findings",
        title="Findings",
        markdown=md,
        data=data,
    )


def _build_attack_paths(
    collection_data: dict,
    owned: list[str] | None,
    max_paths: int,
    analysis_result: Any = None,
) -> ReportSection:
    from .mermaid_maps import attack_paths_full_mermaid
    md = attack_paths_full_mermaid(
        collection_data, owned=owned, max_paths=max_paths, result=analysis_result,
    )
    return ReportSection(
        key="attack_paths",
        title="Attack Paths",
        markdown=md,
    )


def _build_domain_trust(idx: Any) -> ReportSection:
    from .mermaid_maps import domain_trust_mermaid
    md = domain_trust_mermaid(idx)
    return ReportSection(
        key="domain_trust",
        title="Domain Trust Map",
        markdown=md,
    )


def _build_delegation(idx: Any) -> ReportSection:
    from .mermaid_maps import delegation_mermaid
    md = delegation_mermaid(idx)
    return ReportSection(
        key="delegation",
        title="Delegation Map",
        markdown=md,
    )


def _build_collection_stats(idx: Any) -> ReportSection:
    stats = idx.stats()
    lines = [
        "# Collection Statistics\n",
        "| Object Class | Count |",
        "|--------------|------:|",
    ]
    for cls, count in sorted(stats.get("by_class", {}).items(), key=lambda x: -x[1]):
        lines.append(f"| {cls} | {count} |")
    lines.append(f"| **Total** | **{stats.get('total_objects', 0)}** |")
    lines.append("")
    if stats.get("sessions"):
        lines.append(f"Sessions collected: {stats['sessions']}")
    if stats.get("local_group_members"):
        lines.append(f"Local group memberships: {stats['local_group_members']}")
    lines.append("")
    lines.append("---\n*Report generated by LazyHound*\n")
    md = "\n".join(lines)

    return ReportSection(
        key="collection_stats",
        title="Collection Statistics",
        markdown=md,
        data=stats,
    )


# -- Exporters -------------------------------------------------------------

def export_report(
    sections: list[ReportSection],
    spec: ReportSpec,
    domain: str = "",
) -> Path:
    """Write the assembled report to disk in the requested format."""
    fmt = spec.output_format.lower().strip()
    p = Path(spec.output_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    if fmt in ("md", "markdown"):
        return _write_markdown(sections, p, domain)
    elif fmt == "docx":
        return _write_docx(sections, p, domain, spec.template_path)
    elif fmt == "pdf":
        return _write_pdf(sections, p, domain)
    elif fmt == "json":
        return _write_json(sections, p, domain)
    else:
        raise RuntimeError(
            f"Unknown report format: {fmt}. Use: markdown, docx, pdf, json"
        )


def _write_markdown(
    sections: list[ReportSection], dest: Path, domain: str,
) -> Path:
    """Concatenate all sections into a single Markdown file."""
    parts = [
        f"# LazyHound Report — {domain}\n",
        f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n",
        "---\n",
    ]
    for sec in sections:
        parts.append(sec.markdown)
        parts.append("\n---\n")
    dest.write_text("\n".join(parts), encoding="utf-8")
    return dest


def _write_json(
    sections: list[ReportSection], dest: Path, domain: str,
) -> Path:
    """Export all section data as a single JSON document."""
    report = {
        "domain": domain,
        "generated_at": datetime.now().isoformat(),
        "sections": {},
    }
    for sec in sections:
        report["sections"][sec.key] = {
            "title": sec.title,
            "data": sec.data,
            "markdown": sec.markdown,
        }
    dest.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return dest


def _write_docx(
    sections: list[ReportSection],
    dest: Path,
    domain: str,
    template_path: str | None,
) -> Path:
    """Build a DOCX report, optionally from a template."""
    from .docx_report import build_docx
    return build_docx(sections, dest, domain, template_path)


def _write_pdf(
    sections: list[ReportSection], dest: Path, domain: str,
) -> Path:
    """Build PDF by converting the Markdown content through HTML."""
    try:
        import weasyprint  # noqa: F401
    except ImportError:
        raise RuntimeError(
            "PDF export requires weasyprint. Install with: pip install weasyprint"
        )

    # Build HTML from Markdown sections
    html_parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        "<style>",
        "body{font-family:Calibri,Arial,sans-serif;margin:40px;color:#1a1a2e;}",
        "h1{color:#0f3460;border-bottom:2px solid #0f3460;padding-bottom:4px;}",
        "h2{color:#0f3460;}",
        "table{border-collapse:collapse;width:100%;margin:12px 0;}",
        "th,td{border:1px solid #ccc;padding:6px 10px;text-align:left;}",
        "th{background:#0f3460;color:#fff;}",
        "tr:nth-child(even){background:#f4f4f4;}",
        "pre{background:#f4f4f4;padding:10px;border-radius:4px;overflow-x:auto;}",
        "code{font-family:Consolas,monospace;font-size:0.95em;}",
        "</style></head><body>",
        f"<h1>LazyHound Report &mdash; {domain}</h1>",
        f"<p><em>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</em></p>",
        "<hr>",
    ]
    try:
        import markdown as md_lib
        for sec in sections:
            html_parts.append(md_lib.markdown(
                sec.markdown, extensions=["tables", "fenced_code"],
            ))
            html_parts.append("<hr>")
    except ImportError:
        # Fallback: wrap markdown in <pre>
        for sec in sections:
            html_parts.append(f"<h2>{sec.title}</h2>")
            html_parts.append(f"<pre>{sec.markdown}</pre><hr>")

    html_parts.append("</body></html>")
    html_content = "\n".join(html_parts)

    doc = weasyprint.HTML(string=html_content)
    doc.write_pdf(str(dest))
    return dest
