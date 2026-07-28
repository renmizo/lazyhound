"""Executive findings report from offline analysis.

Generates a prioritized, executive-friendly report from AnalysisResult data,
including risk summary, top attack paths, remediation priorities, and
category breakdowns.  Works from collection JSON via the analyzer.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from ..collect.analyzer import (
    AnalysisResult,
    Category,
    Finding,
    Severity,
    analyze,
)


_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.INFO: 3,
}

_SEVERITY_ICONS = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.INFO: "INFO",
}


def generate_findings_report(
    result: AnalysisResult,
    *,
    show_builtin: bool = False,
    max_paths: int = 10,
    max_affected: int = 10,
) -> dict:
    """Build a findings report data dict from an AnalysisResult."""

    findings = result.actionable if not show_builtin else result.findings

    # Severity breakdown
    by_severity: dict[str, int] = {}
    for sev in Severity:
        count = sum(1 for f in findings if f.severity == sev)
        if count:
            by_severity[sev.value] = count

    # Category breakdown with severity distribution
    by_category: dict[str, dict] = {}
    cat_groups = result.by_category()
    for cat in Category:
        cat_findings = cat_groups.get(cat, [])
        if not show_builtin:
            cat_findings = [f for f in cat_findings if not f.is_builtin]
        if not cat_findings:
            continue
        sev_dist = Counter(f.severity.value for f in cat_findings)
        max_sev = min(cat_findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99)).severity
        by_category[cat.value] = {
            "count": len(cat_findings),
            "max_severity": max_sev.value,
            "severity_distribution": dict(sev_dist),
        }

    # Top attack paths (from shortest-path findings)
    attack_paths = []
    sp = [f for f in findings if f.category == Category.SHORTEST_PATH]
    sp.sort(key=lambda f: f.details.get("depth", 99))
    for f in sp[:max_paths]:
        attack_paths.append({
            "from": f.principal_name,
            "to": f.target_name,
            "depth": f.details.get("depth"),
            "path": f.details.get("path_names", []),
            "edges": f.details.get("path_edges", []),
            "severity": f.severity.value,
        })

    # Most-targeted objects (appear as targets across multiple findings)
    target_counts: Counter[str] = Counter()
    for f in findings:
        if f.target_name:
            target_counts[f.target_name] += 1
    most_targeted = [
        {"name": name, "finding_count": count}
        for name, count in target_counts.most_common(max_affected)
    ]

    # Most-privileged attackers (principals that appear in most findings)
    principal_counts: Counter[str] = Counter()
    for f in findings:
        if f.principal_name and not f.is_builtin:
            principal_counts[f.principal_name] += 1
    top_principals = [
        {"name": name, "finding_count": count}
        for name, count in principal_counts.most_common(max_affected)
    ]

    # Blast radius summary
    blast_radius = []
    br = [f for f in findings if f.category == Category.BLAST_RADIUS]
    for f in br:
        blast_radius.append({
            "principal": f.principal_name,
            "total_reachable": f.details.get("total_reachable", 0),
            "high_value_reachable": f.details.get("hv_count", 0),
            "severity": f.severity.value,
        })

    # Correlation findings
    correlations = []
    corr = [f for f in findings if f.category == Category.CROSS_CORRELATION]
    for f in corr[:max_affected]:
        correlations.append({
            "description": f.description,
            "principal": f.principal_name,
            "severity": f.severity.value,
        })

    # Health: count unique affected objects (principals + targets)
    affected_names: set[str] = set()
    for f in findings:
        if f.principal_name and not f.is_builtin:
            affected_names.add(f.principal_name)
        if f.target_name:
            affected_names.add(f.target_name)
    total_objects = result.total_objects or 1
    affected_count = min(len(affected_names), total_objects)
    health_pct = (total_objects - affected_count) / total_objects * 100

    from ..finder_models import ScoringProfile

    # Risk grade — blended with health percentage
    total = len(findings)
    crit_count = by_severity.get("critical", 0)
    high_count = by_severity.get("high", 0)
    if crit_count >= 5 or total >= 50:
        raw_grade = "F"
    elif crit_count >= 2 or high_count >= 10:
        raw_grade = "D"
    elif crit_count >= 1 or high_count >= 5:
        raw_grade = "C"
    elif high_count >= 1:
        raw_grade = "B"
    else:
        raw_grade = "A"

    # Apply health uplift: if health is very high, bump grade up by one step
    _GRADE_ORDER = ["F", "D", "C", "B", "A"]
    grade = raw_grade
    if health_pct >= 95 and raw_grade != "A":
        idx = _GRADE_ORDER.index(raw_grade)
        grade = _GRADE_ORDER[min(idx + 1, len(_GRADE_ORDER) - 1)]

    # Remediation priorities
    remediation_priorities = _build_remediation_priorities(findings)

    return {
        "domain": result.domain,
        "source_file": result.source_file,
        "grade": grade,
        "rating": ScoringProfile.grade_to_rating(grade),
        "total_findings": total,
        "total_actionable": len(result.actionable),
        "total_builtin": len(result.builtin),
        "total_objects": total_objects,
        "affected_objects": affected_count,
        "health_pct": round(health_pct, 1),
        "severity_breakdown": by_severity,
        "category_breakdown": by_category,
        "attack_paths": attack_paths,
        "blast_radius": blast_radius,
        "most_targeted_objects": most_targeted,
        "top_attacking_principals": top_principals,
        "cross_correlations": correlations,
        "remediation_priorities": remediation_priorities,
    }


def _build_remediation_priorities(findings: list[Finding]) -> list[dict]:
    """Group findings into actionable remediation items, ordered by impact."""
    priorities: list[dict] = []

    # Category-level grouping with recommendations
    _CATEGORY_REMEDIATION: dict[Category, str] = {
        Category.KERBEROAST: "Set long, random passwords (25+ chars) on service accounts or migrate to gMSA. Disable RC4 encryption where possible.",
        Category.ASREP_ROAST: "Enable Kerberos pre-authentication on all user accounts.",
        Category.UNCONSTRAINED_DELEG: "Remove unconstrained delegation. Use constrained delegation or RBCD instead.",
        Category.CONSTRAINED_DELEG: "Review constrained delegation targets. Remove delegation from accounts that don't require it.",
        Category.RBCD: "Audit msDS-AllowedToActOnBehalfOfOtherIdentity values. Restrict who can write this attribute.",
        Category.DCSYNC: "Remove DCSync rights from non-DC accounts. Audit Replicating Directory Changes permissions.",
        Category.ACL_ABUSE: "Review and tighten DACLs. Remove unnecessary GenericAll, WriteDACL, WriteOwner permissions.",
        Category.DANGEROUS_CONFIG: "Remove PASSWD_NOTREQD flag. Enable password expiration. Set MachineAccountQuota to 0.",
        Category.OWNERSHIP: "Review object ownership. Ensure high-value objects are owned by Domain Admins.",
        Category.GPO_ABUSE: "Restrict GPO edit and link permissions to trusted administrators only.",
        Category.ADCS_ABUSE: "Review certificate template permissions. Disable vulnerable templates (ESC1-ESC13).",
        Category.LAPS_READ: "Restrict LAPS password read access to authorized administrators only.",
        Category.GMSA_READ: "Review msDS-GroupMSAMembership ACLs. Restrict gMSA password readers.",
        Category.TRUST_ABUSE: "Enable SID filtering on all trusts. Review trust direction and necessity.",
    }

    cat_findings: dict[Category, list[Finding]] = defaultdict(list)
    for f in findings:
        cat_findings[f.category].append(f)

    for cat, cat_f in sorted(cat_findings.items(),
                              key=lambda x: min(_SEVERITY_ORDER.get(f.severity, 99) for f in x[1])):
        if cat in (Category.SHORTEST_PATH, Category.BLAST_RADIUS,
                   Category.CROSS_CORRELATION, Category.GROUP_MEMBERSHIP,
                   Category.SESSION_ABUSE, Category.LOCAL_ACCESS,
                   Category.OU_CONTROL):
            continue

        remediation = _CATEGORY_REMEDIATION.get(cat, "Review and remediate findings in this category.")
        max_sev = min(cat_f, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99)).severity
        affected = set()
        for f in cat_f:
            if f.principal_name and not f.is_builtin:
                affected.add(f.principal_name)
            if f.target_name:
                affected.add(f.target_name)

        priorities.append({
            "category": cat.value,
            "severity": max_sev.value,
            "finding_count": len(cat_f),
            "affected_objects": len(affected),
            "remediation": remediation,
        })

    return priorities


def render_markdown(report: dict) -> str:
    """Render findings report dict as Markdown."""
    lines: list[str] = []

    lines.append(f"# LazyHound Executive Findings Report — {report['domain']}\n")

    # Executive summary
    lines.append("## Executive Summary\n")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| **Rating** | **{report.get('rating', report['grade'])}** |")
    health_pct = report.get("health_pct", 0)
    total_obj = report.get("total_objects", 0)
    affected = report.get("affected_objects", 0)
    lines.append(f"| **Health** | {health_pct}% ({total_obj - affected}/{total_obj} objects clean) |")
    lines.append(f"| **Total Findings** | {report['total_findings']} |")
    lines.append(f"| **Actionable Findings** | {report['total_actionable']} |")
    lines.append(f"| **Source** | `{report['source_file']}` |")
    lines.append("")

    # Severity breakdown
    if report["severity_breakdown"]:
        lines.append("## Severity Breakdown\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|------:|")
        for sev in ("critical", "high", "medium", "info"):
            count = report["severity_breakdown"].get(sev, 0)
            if count:
                lines.append(f"| {sev.upper()} | {count} |")
        lines.append("")

    # Category breakdown
    if report["category_breakdown"]:
        lines.append("## Findings by Category\n")
        lines.append("| Category | Count | Max Severity |")
        lines.append("|----------|------:|-------------|")
        for cat, info in sorted(report["category_breakdown"].items(),
                                key=lambda x: _SEVERITY_ORDER.get(
                                    Severity(x[1]["max_severity"]), 99)):
            lines.append(f"| {cat} | {info['count']} | {info['max_severity'].upper()} |")
        lines.append("")

    # Top attack paths
    if report["attack_paths"]:
        lines.append("## Top Attack Paths\n")
        for i, path in enumerate(report["attack_paths"], 1):
            names = path["path"]
            edges = path.get("edges", [])
            if edges:
                parts = [names[0]] if names else []
                for j, name in enumerate(names[1:]):
                    edge = edges[j] if j < len(edges) else ""
                    if edge:
                        parts.append(f"-[{edge}]-> {name}")
                    else:
                        parts.append(f"-> {name}")
                chain = " ".join(parts)
            else:
                chain = " → ".join(names)
            lines.append(f"**{i}. [{path['severity'].upper()}]** "
                         f"`{path['from']}` → `{path['to']}` ({path['depth']} hops)")
            lines.append(f"   {chain}\n")
        lines.append("")

    # Blast radius
    if report["blast_radius"]:
        lines.append("## Blast Radius (Owned Principals)\n")
        lines.append("| Principal | Reachable | High-Value | Severity |")
        lines.append("|-----------|----------:|-----------:|----------|")
        for br in report["blast_radius"]:
            lines.append(f"| {br['principal']} | {br['total_reachable']} | "
                         f"{br['high_value_reachable']} | {br['severity'].upper()} |")
        lines.append("")

    # Most targeted objects
    if report["most_targeted_objects"]:
        lines.append("## Most Targeted Objects\n")
        lines.append("| Object | Findings |")
        lines.append("|--------|--------:|")
        for obj in report["most_targeted_objects"]:
            lines.append(f"| `{obj['name']}` | {obj['finding_count']} |")
        lines.append("")

    # Top attacking principals
    if report["top_attacking_principals"]:
        lines.append("## Top Attacking Principals\n")
        lines.append("| Principal | Findings |")
        lines.append("|-----------|--------:|")
        for p in report["top_attacking_principals"]:
            lines.append(f"| `{p['name']}` | {p['finding_count']} |")
        lines.append("")

    # Cross-correlations
    if report["cross_correlations"]:
        lines.append("## Cross-Correlated Risks\n")
        for c in report["cross_correlations"]:
            lines.append(f"- **[{c['severity'].upper()}]** {c['description']}")
        lines.append("")

    # Remediation priorities
    if report["remediation_priorities"]:
        lines.append("## Remediation Priorities\n")
        for i, p in enumerate(report["remediation_priorities"], 1):
            lines.append(f"### {i}. {p['category']} ({p['severity'].upper()}, "
                         f"{p['finding_count']} findings, {p['affected_objects']} objects)\n")
            lines.append(f"{p['remediation']}\n")

    lines.append("---\n*Report generated by LazyHound*\n")
    return "\n".join(lines)


def render_json(report: dict) -> str:
    """Render findings report as JSON string."""
    return json.dumps(report, indent=2, default=str)


def write_findings_report(
    data: dict,
    output: str | Path,
    fmt: str = "markdown",
    *,
    owned: list[str] | None = None,
    checks: set[str] | None = None,
    exclude: set[str] | None = None,
    show_builtin: bool = False,
) -> Path:
    """Run analysis and write findings report to a file."""
    result = analyze(data, checks=checks, exclude=exclude, owned=owned)
    report = generate_findings_report(result, show_builtin=show_builtin)
    p = Path(output)
    p.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        p.write_text(render_json(report), encoding="utf-8")
    else:
        p.write_text(render_markdown(report), encoding="utf-8")
    return p
