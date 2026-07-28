"""Unified markdown report — fuses attack paths (Map) with posture findings
(Assess), with findings prioritized by reachability to Tier Zero.

Composable via ``sections`` (same vocabulary as the HTML report):
title, summary, matrix, paths, findings. None/'all' -> every section, in order.
"""
from __future__ import annotations

from lazyhound.finder.collect.analyzer import Category
from lazyhound.finder.reports.html_unified_report import normalize_sections

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _all_findings(scan_result) -> list:
    if not scan_result:
        return []
    return [f for cr in scan_result.check_results for f in cr.findings]


def _paths(analysis_result) -> list:
    if not analysis_result:
        return []
    return [f for f in analysis_result.findings if f.category == Category.SHORTEST_PATH]


def _sev(f) -> str:
    return getattr(f.severity, "value", str(f.severity))


def build_unified_markdown(scan_result, analysis_result, domain: str = "",
                           sections=None) -> str:
    secs = normalize_sections(sections)
    findings = _all_findings(scan_result)
    paths = _paths(analysis_result)
    reachable = [f for f in findings if f.details.get("reaches_tier_zero")]

    def _title() -> list[str]:
        return [f"# LazyHound Report — {domain or 'unknown'}", ""]

    def _summary() -> list[str]:
        return [
            "## Summary", "",
            f"- Posture findings: **{len(findings)}** "
            f"({len(reachable)} touch principals that can reach Tier Zero)",
            f"- Attack paths to Tier Zero: **{len(paths)}**", "",
        ]

    def _matrix() -> list[str]:
        by_cat: dict[str, dict] = {}
        for f in findings:
            label = getattr(f.category, "label", getattr(f.category, "value", str(f.category)))
            row = by_cat.setdefault(label, {"total": 0, **{s: 0 for s in _SEV_ORDER}})
            row["total"] += 1
            row[_sev(f)] += 1
        out = ["## Findings Matrix", "",
               "| Type | Total | Critical | High | Medium | Low | Info |",
               "|---|---|---|---|---|---|---|"]
        if not by_cat and not paths:
            out.append("| _No findings_ | 0 | | | | | |")
        for label, r in sorted(by_cat.items(), key=lambda kv: -kv[1]["total"]):
            out.append(f"| {label} | {r['total']} | "
                       + " | ".join(str(r[s] or "") for s in _SEV_ORDER) + " |")
        if paths:
            out.append(f"| Attack Paths → Tier Zero | {len(paths)} | | | | | |")
        tot = {s: sum(r[s] for r in by_cat.values()) for s in _SEV_ORDER}
        out.append(f"| **Total** | **{len(findings)}** | "
                   + " | ".join(str(tot[s] or "") for s in _SEV_ORDER) + " |")
        out.append("")
        return out

    def _paths_sec() -> list[str]:
        out = ["## Attack Paths to Tier Zero", ""]
        if paths:
            out += ["| Source | Hops | Target | Path |", "|---|---|---|---|"]
            for p in sorted(paths, key=lambda x: x.details.get("depth", 99))[:50]:
                path_str = " → ".join(p.details.get("path_names", []) or [p.principal_name])
                out.append(f"| {p.principal_name} | {p.details.get('depth', '')} | "
                           f"{p.target_name} | {path_str} |")
            if len(paths) > 50:
                out.append(f"\n_…and {len(paths) - 50} more paths._")
        else:
            out.append("_None found._")
        out.append("")
        return out

    def _findings_sec() -> list[str]:
        out = ["## Findings (prioritized by reachability)", ""]

        def _sort_key(f):
            return (0 if f.details.get("reaches_tier_zero") else 1,
                    f.details.get("tier_zero_hops", 99), f.severity.sort_order)

        if not findings:
            out.append("_No findings._")
        for f in sorted(findings, key=_sort_key):
            tag = ""
            if f.details.get("reaches_tier_zero"):
                tag = f" — ⚠ reaches Tier Zero in {f.details.get('tier_zero_hops')} hop(s)"
            out.append(f"### [{_sev(f).upper()}] {f.title}{tag}")
            if f.description:
                out.append(f.description)
            aff = ", ".join(str(a) for a in (f.affected_objects or [])[:8])
            if aff:
                extra = f" (+{len(f.affected_objects) - 8} more)" if len(f.affected_objects) > 8 else ""
                out.append(f"- Affected: {aff}{extra}")
            out.append("")
        return out

    renderers = {"title": _title, "summary": _summary, "matrix": _matrix,
                 "paths": _paths_sec, "findings": _findings_sec}
    lines: list[str] = []
    for name in secs:
        lines += renderers[name]()
    return "\n".join(lines)
