"""Console output formatting using Rich."""

from __future__ import annotations

import json
import sys
from collections import Counter

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from .collect.analyzer import AnalysisResult, Category, Finding, Severity

console = Console()

_SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold orange3",
    Severity.MEDIUM: "yellow",
    Severity.INFO: "blue",
}

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.INFO]

# Default page size for analysis findings per category
DEFAULT_ANALYSIS_TOP = 50


def _interactive_pager_findings(
    findings: list[Finding],
    category: Category,
    show_inherited: bool,
    style: int,
    top: int,
    skip: int = 0,
    idx=None,
) -> None:
    """Interactively page through analysis findings for a category.

    ``top <= 0`` disables paging and renders everything at once.
    """
    total = len(findings)
    if top <= 0:
        # --top 0 means "show all"
        _print_category_table(category, findings, show_inherited, style=style, idx=idx)
        return

    if total <= top and skip == 0:
        _print_category_table(category, findings, show_inherited, style=style, idx=idx)
        return

    offset = skip
    while True:
        page = findings[offset : offset + top]
        if not page:
            break

        _print_category_table(category, page, show_inherited, style=style, idx=idx)

        start = offset + 1
        end = min(offset + top, total)
        on_first = offset == 0
        on_last = end >= total

        if on_first and on_last:
            break

        opts: list[str] = []
        if not on_first:
            opts.append("[bold][p][/bold] previous")
        if not on_last:
            opts.append("[bold][n/Enter][/bold] next")
        opts.append("[bold][q][/bold] quit")
        prompt = f"  [dim]Showing {start}\u2013{end} of {total:,} findings.[/dim]  {' | '.join(opts)}: "
        console.print(prompt, end="")

        try:
            choice = input().strip().lower()
        except (KeyboardInterrupt, EOFError):
            console.print()
            break

        if choice in ("q", "quit"):
            break
        elif choice in ("p", "prev", "previous"):
            offset = max(0, offset - top)
        else:
            if on_last:
                break
            offset = end

_CATEGORY_ORDER = [
    Category.BLAST_RADIUS,
    Category.CROSS_CORRELATION,
    Category.SHORTEST_PATH,
    Category.DCSYNC,
    Category.LAPS_READ,
    Category.GMSA_READ,
    Category.ACL_ABUSE,
    Category.GPO_ABUSE,
    Category.OU_CONTROL,
    Category.KERBEROAST,
    Category.ASREP_ROAST,
    Category.UNCONSTRAINED_DELEG,
    Category.CONSTRAINED_DELEG,
    Category.RBCD,
    Category.ADCS_ABUSE,
    Category.TRUST_ABUSE,
    Category.GROUP_MEMBERSHIP,
    Category.OWNERSHIP,
    Category.DANGEROUS_CONFIG,
    Category.SESSION_ABUSE,
    Category.LOCAL_ACCESS,
    Category.HYBRID_SYNC,
    Category.AZURE_PRIVILEGE,
]


def _severity_style(finding: Finding) -> str:
    return _SEVERITY_STYLES.get(finding.severity, "")


def print_version() -> None:
    """Display ASCII art logo with version number."""
    from . import __version__

    art = r"""
    __                      __  __                      __
   / /   ____ _____  __  __/ / / /___  __  ______  ____/ /
  / /   / __ `/_  / / / / / /_/ / __ \/ / / / __ \/ __  / 
 / /___/ /_/ / / /_/ /_/ / __  / /_/ / /_/ / / / / /_/ /  
/_____/\__,_/ /___/\__, /_/ /_/\____/\__,_/_/ /_/\__,_/   
                  /____/
"""
    console.print(f"[bold cyan]{art}[/]", highlight=False)
    console.print(f"  [bold white]v{__version__}[/]  [dim]— Active Directory attack path analysis[/]")
    console.print()


def print_banner() -> None:
    banner = Text.from_markup(
        "[bold cyan]LazyHound[/] — BloodHound-style attack path analysis"
    )
    console.print(Panel(banner, border_style="cyan"))


def print_analysis_results(
    result: AnalysisResult,
    show_inherited: bool = False,
    show_builtin: bool = False,
    json_output: bool = False,
    style: int = 2,
    top: int | None = None,
    skip: int = 0,
    idx=None,
) -> None:
    """Print comprehensive analysis results to the console.

    When *top* is not None (or defaults to 50 via DEFAULT_ANALYSIS_TOP),
    each category's findings are paginated.  Use ``--top 0`` to show all.
    """
    if json_output:
        _print_json(result, show_inherited, show_builtin)
        return

    actionable = result.actionable
    builtin = result.builtin

    # Severity breakdown
    sev_counts: Counter[Severity] = Counter()
    for f in actionable:
        sev_counts[f.severity] += 1

    cat_counts: Counter[Category] = Counter()
    for f in actionable:
        cat_counts[f.category] += 1

    # Summary panel
    summary_lines = [
        f"Domain:       {result.domain}",
        f"Source:       {result.source_file}",
        f"Total:        {len(result.findings)} findings",
        f"[bold yellow]Actionable:   {len(actionable)}[/]",
        f"[dim]Built-in:     {len(builtin)}[/]",
    ]
    if result.owned_sids:
        summary_lines.append(f"[bold red]Owned:        {len(result.owned_sids)} principal(s)[/]")
    summary_lines.append("")

    for sev in _SEVERITY_ORDER:
        cnt = sev_counts.get(sev, 0)
        sev_style = _SEVERITY_STYLES.get(sev, "")
        if cnt:
            summary_lines.append(f"  [{sev_style}]{sev.value.upper():>10}: {cnt}[/]")

    console.print(Panel("\n".join(summary_lines), title="Analysis Summary", border_style="green"))

    if not actionable and not show_builtin:
        console.print("[green]No actionable findings.[/]")
        return

    # Resolve effective page size
    effective_top = top if top is not None else DEFAULT_ANALYSIS_TOP

    # Print findings grouped by category
    findings_by_cat = result.by_category()
    for cat in _CATEGORY_ORDER:
        cat_findings = findings_by_cat.get(cat, [])
        if not cat_findings:
            continue

        # Split actionable vs builtin
        cat_actionable = [f for f in cat_findings if not f.is_builtin]
        cat_builtin = [f for f in cat_findings if f.is_builtin]

        if not cat_actionable and not show_builtin:
            continue

        # Color-code category header by worst severity (Feature 10)
        worst_sev = min(cat_actionable, key=lambda f: _SEVERITY_ORDER.index(f.severity)
                        if f.severity in _SEVERITY_ORDER else 99).severity if cat_actionable else Severity.INFO
        sev_badge = f"[{_SEVERITY_STYLES.get(worst_sev, '')}]{worst_sev.value.upper()}[/]" if cat_actionable else ""

        console.print()
        console.rule(f"[bold]{cat.value}[/]  ({len(cat_actionable)} findings, worst: {sev_badge})")
        console.print()

        if cat_actionable:
            _interactive_pager_findings(
                cat_actionable, cat, show_inherited, style,
                top=effective_top, skip=skip, idx=idx,
            )

        if show_builtin and cat_builtin:
            console.print(f"  [dim]Built-in / expected ({len(cat_builtin)}):[/]")
            _print_category_table(cat, cat_builtin, show_inherited, style=style, idx=idx)


def _get_table_kwargs(style: int) -> dict:
    """Return Rich Table constructor kwargs for the given display style."""
    if style == 1:  # Compact
        return {"show_lines": False, "pad_edge": False, "box": None, "padding": (0, 1)}
    elif style == 3:  # Boxed
        import rich.box
        return {"show_lines": True, "box": rich.box.ROUNDED, "pad_edge": True}
    elif style == 4:  # Detailed
        import rich.box
        return {"show_lines": True, "box": rich.box.HEAVY_EDGE, "pad_edge": True}
    else:  # style 2 (Clean) — default
        import rich.box
        return {"show_lines": False, "pad_edge": False, "box": rich.box.SIMPLE}


def _print_category_table(
    category: Category,
    findings: list[Finding],
    show_inherited: bool,
    style: int = 2,
    idx=None,
) -> None:
    """Render a table of findings for a specific category."""
    filtered = findings
    if not show_inherited:
        filtered = [f for f in findings if not f.inherited]
        skipped = len(findings) - len(filtered)
        if skipped:
            console.print(f"  [dim](hiding {skipped} inherited ACEs — use --show-inherited to include)[/]")

    if not filtered:
        console.print("  [dim]No non-inherited entries.[/]")
        return

    tkw = _get_table_kwargs(style)

    if category == Category.BLAST_RADIUS:
        _print_blast_radius_table(filtered, tkw)
    elif category == Category.ACL_ABUSE:
        _print_acl_table(filtered, tkw)
    elif category in (Category.KERBEROAST, Category.ASREP_ROAST):
        _print_kerberos_table(filtered, tkw)
    elif category in (Category.UNCONSTRAINED_DELEG, Category.CONSTRAINED_DELEG, Category.RBCD):
        _print_delegation_table(filtered, tkw)
    elif category == Category.GROUP_MEMBERSHIP:
        _print_membership_table(filtered, tkw)
    elif category == Category.CROSS_CORRELATION:
        _print_correlation_table(filtered, tkw)
    elif category == Category.SHORTEST_PATH:
        _print_path_table(filtered, tkw, idx=idx)
    elif category in (Category.GPO_ABUSE, Category.OU_CONTROL):
        _print_acl_table(filtered, tkw)
    elif category == Category.DCSYNC:
        _print_dcsync_table(filtered, tkw)
    elif category == Category.ADCS_ABUSE:
        _print_adcs_table(filtered, tkw)
    elif category == Category.TRUST_ABUSE:
        _print_trust_table(filtered, tkw)
    elif category in (Category.LAPS_READ, Category.GMSA_READ):
        _print_laps_gmsa_table(filtered, tkw)
    elif category in (Category.SESSION_ABUSE, Category.LOCAL_ACCESS):
        _print_session_local_table(filtered, tkw)
    else:
        _print_generic_table(filtered, tkw)


def _print_acl_table(findings: list[Finding], tkw: dict | None = None) -> None:
    table = Table(**(tkw or {"show_lines": False, "pad_edge": False, "box": None}))
    table.add_column("Sev", min_width=4)
    table.add_column("Trustee", style="bold", min_width=20)
    table.add_column("SID", min_width=15)
    table.add_column("Rights", min_width=15)
    table.add_column("Target", min_width=25)
    table.add_column("Class", min_width=8)
    table.add_column("Inh", justify="center", min_width=3)

    for f in findings:
        style = _severity_style(f)
        table.add_row(
            f.severity.value[0].upper(),
            f.principal_name,
            f.principal_sid,
            ", ".join(f.rights),
            f.target_name,
            f.target_class,
            "Y" if f.inherited else "",
            style=style,
        )
    console.print(table)
    console.print()


def _print_kerberos_table(findings: list[Finding], tkw: dict | None = None) -> None:
    table = Table(**(tkw or {"show_lines": False, "pad_edge": False, "box": None}))
    table.add_column("Sev", min_width=4)
    table.add_column("Account", style="bold", min_width=20)
    table.add_column("SID", min_width=15)
    table.add_column("Details", min_width=30)
    table.add_column("SPNs", min_width=30)

    for f in findings:
        style = _severity_style(f)
        spns = f.details.get("spns", [])
        spn_str = ", ".join(spns[:5])
        if len(spns) > 5:
            spn_str += f" (+{len(spns) - 5} more)"
        table.add_row(
            f.severity.value[0].upper(),
            f.principal_name,
            f.principal_sid,
            f.description,
            spn_str,
            style=style,
        )
    console.print(table)
    console.print()


def _print_delegation_table(findings: list[Finding], tkw: dict | None = None) -> None:
    table = Table(**(tkw or {"show_lines": False, "pad_edge": False, "box": None}))
    table.add_column("Sev", min_width=4)
    table.add_column("Principal", style="bold", min_width=20)
    table.add_column("Class", min_width=8)
    table.add_column("Details", min_width=30)
    table.add_column("Delegate To", min_width=30)

    for f in findings:
        style = _severity_style(f)
        targets = f.details.get("delegate_to", [])
        target_str = ", ".join(targets[:5])
        if len(targets) > 5:
            target_str += f" (+{len(targets) - 5} more)"
        table.add_row(
            f.severity.value[0].upper(),
            f.principal_name,
            f.target_class,
            f.description,
            target_str,
            style=style,
        )
    console.print(table)
    console.print()


def _print_membership_table(findings: list[Finding], tkw: dict | None = None) -> None:
    table = Table(**(tkw or {"show_lines": False, "pad_edge": False, "box": None}))
    table.add_column("Sev", min_width=4)
    table.add_column("User", style="bold", min_width=20)
    table.add_column("Target Group", min_width=20)
    table.add_column("Path", min_width=40)

    for f in findings:
        style = _severity_style(f)
        chain = " → ".join(f.details.get("path_names", []))
        table.add_row(
            f.severity.value[0].upper(),
            f.principal_name,
            f.target_name,
            chain,
            style=style,
        )
    console.print(table)
    console.print()


def _print_correlation_table(findings: list[Finding], tkw: dict | None = None) -> None:
    table = Table(**(tkw or {"show_lines": False, "pad_edge": False, "box": None}))
    table.add_column("Sev", min_width=4)
    table.add_column("Principal", style="bold", min_width=20)
    table.add_column("Compound Risk", min_width=60)

    for f in findings:
        style = _severity_style(f)
        table.add_row(
            f.severity.value[0].upper(),
            f.principal_name,
            f.description,
            style=style,
        )
    console.print(table)
    console.print()


def _format_path_with_edges(path_names: list[str], path_edges: list[str]) -> str:
    """Build a human-readable attack path string with edge labels.

    Example: ``DC01$ -[GenericAll]-> Administrator``
    """
    if not path_names:
        return ""
    parts: list[str] = [path_names[0]]
    for i, name in enumerate(path_names[1:]):
        edge = path_edges[i] if i < len(path_edges) else ""
        if edge:
            parts.append(f"-[{edge}]-> {name}")
        else:
            parts.append(f"-> {name}")
    return " ".join(parts)


def _print_path_table(findings: list[Finding], tkw: dict | None = None,
                      idx=None) -> None:
    """Render shortest-path findings with edge labels. When `idx` is a
    CollectionIndex and the collection is multi-realm, show a Realm column."""
    show_realm = idx is not None and len(idx.domains()) > 1
    table = Table(**(tkw or {"show_lines": False, "pad_edge": False, "box": None}))
    table.add_column("Sev", min_width=4)
    table.add_column("Principal", style="bold", min_width=20)
    if show_realm:
        table.add_column("Realm", min_width=10)
    table.add_column("Hops", justify="center", min_width=4)
    table.add_column("Target", min_width=20)
    table.add_column("Path", min_width=50)

    for f in findings:
        style = _severity_style(f)
        path_names = f.details.get("path_names", [])
        path_edges = f.details.get("path_edges", [])
        depth = f.details.get("depth", 0)
        cells = [f.severity.value[0].upper(), f.principal_name]
        if show_realm:
            cells.append(idx.realm_label_of_sid(getattr(f, "principal_sid", "") or ""))
        cells += [str(depth), f.target_name,
                  _format_path_with_edges(path_names, path_edges)]
        table.add_row(*cells, style=style)
    console.print(table)
    console.print()


def _print_blast_radius_table(findings: list[Finding], tkw: dict | None = None) -> None:
    """Render blast radius findings with summary + detailed paths."""
    # Separate summary findings from path findings
    summaries = [f for f in findings if f.target_class == "summary"]
    hv_paths = [f for f in findings if f.target_class == "high-value"]
    reachable = [f for f in findings if f.target_class == "reachable"]

    for summary in summaries:
        owned_name = summary.principal_name
        details = summary.details
        total = details.get("total_reachable", 0)
        hv_count = details.get("hv_count", 0)
        by_depth = details.get("by_depth", {})

        # Owned principal header
        style = "bold red" if hv_count else "bold yellow"
        console.print(f"  [{style}]OWNED: {owned_name}[/]")
        console.print(f"    Reachable objects: {total}")
        if hv_count:
            console.print(f"    [bold red]High-value targets: {hv_count}[/]")
        if by_depth:
            depth_parts = [f"{count} at {depth} hop(s)" for depth, count in sorted(by_depth.items())]
            console.print(f"    Depth breakdown: {', '.join(depth_parts)}")
        console.print()

    # HV target paths
    _tkw = tkw or {"show_lines": False, "pad_edge": False, "box": None}
    if hv_paths:
        table = Table(
            title="Paths to High-Value Targets",
            **_tkw,
        )
        table.add_column("Sev", min_width=4)
        table.add_column("Owned", style="bold", min_width=15)
        table.add_column("Hops", justify="center", min_width=4)
        table.add_column("Target", style="bold red", min_width=20)
        table.add_column("Path", min_width=50)

        for f in sorted(hv_paths, key=lambda x: x.details.get("depth", 0)):
            path_names = f.details.get("path_names", [])
            path_edges = f.details.get("path_edges", [])
            depth = f.details.get("depth", 0)

            # Format path with edge labels
            path_parts: list[str] = []
            for i, name in enumerate(path_names):
                if i == 0:
                    path_parts.append(name)
                else:
                    edge = path_edges[i - 1] if (i - 1) < len(path_edges) else ""
                    if edge:
                        path_parts.append(f"-[{edge}]-> {name}")
                    else:
                        path_parts.append(f"-> {name}")

            table.add_row(
                "C",
                f.principal_name,
                str(depth),
                f.target_name,
                " ".join(path_parts),
                style="bold red",
            )
        console.print(table)
        console.print()

    # Nearby reachable objects (within 3 hops)
    if reachable:
        table = Table(
            title="Directly Reachable Objects (1-3 hops)",
            **_tkw,
        )
        table.add_column("Sev", min_width=4)
        table.add_column("Owned", style="bold", min_width=15)
        table.add_column("Hops", justify="center", min_width=4)
        table.add_column("Target", min_width=20)
        table.add_column("Via", min_width=40)

        for f in sorted(reachable, key=lambda x: x.details.get("depth", 0)):
            style = _severity_style(f)
            depth = f.details.get("depth", 0)
            path_names = f.details.get("path_names", [])
            path_edges = f.details.get("path_edges", [])

            path_parts: list[str] = []
            for i, name in enumerate(path_names):
                if i == 0:
                    path_parts.append(name)
                else:
                    edge = path_edges[i - 1] if (i - 1) < len(path_edges) else ""
                    if edge:
                        path_parts.append(f"-[{edge}]-> {name}")
                    else:
                        path_parts.append(f"-> {name}")

            table.add_row(
                f.severity.value[0].upper(),
                f.principal_name,
                str(depth),
                f.target_name,
                " ".join(path_parts),
                style=style,
            )
        console.print(table)
        console.print()


def _print_dcsync_table(findings: list[Finding], tkw: dict | None = None) -> None:
    """Render DCSync findings."""
    table = Table(**(tkw or {"show_lines": False, "pad_edge": False, "box": None}))
    table.add_column("Sev", min_width=4)
    table.add_column("Principal", style="bold", min_width=20)
    table.add_column("SID", min_width=15)
    table.add_column("Rights", min_width=20)
    table.add_column("Details", min_width=40)

    for f in findings:
        style = _severity_style(f)
        table.add_row(
            f.severity.value[0].upper(),
            f.principal_name,
            f.principal_sid,
            ", ".join(f.rights),
            f.description,
            style=style,
        )
    console.print(table)
    console.print()


def _print_adcs_table(findings: list[Finding], tkw: dict | None = None) -> None:
    """Render ADCS abuse findings."""
    table = Table(**(tkw or {"show_lines": False, "pad_edge": False, "box": None}))
    table.add_column("Sev", min_width=4)
    table.add_column("ESC", min_width=5)
    table.add_column("Principal", style="bold", min_width=20)
    table.add_column("Template/CA", min_width=20)
    table.add_column("Details", min_width=40)

    for f in findings:
        style = _severity_style(f)
        esc_type = f.details.get("esc_type", "")
        table.add_row(
            f.severity.value[0].upper(),
            esc_type,
            f.principal_name,
            f.target_name,
            f.description,
            style=style,
        )
    console.print(table)
    console.print()


def _print_trust_table(findings: list[Finding], tkw: dict | None = None) -> None:
    """Render trust abuse findings."""
    table = Table(**(tkw or {"show_lines": False, "pad_edge": False, "box": None}))
    table.add_column("Sev", min_width=4)
    table.add_column("Principal", style="bold", min_width=20)
    table.add_column("Target", min_width=20)
    table.add_column("Details", min_width=50)

    for f in findings:
        style = _severity_style(f)
        table.add_row(
            f.severity.value[0].upper(),
            f.principal_name,
            f.target_name,
            f.description,
            style=style,
        )
    console.print(table)
    console.print()


def _print_generic_table(findings: list[Finding], tkw: dict | None = None) -> None:
    table = Table(**(tkw or {"show_lines": False, "pad_edge": False, "box": None}))
    table.add_column("Sev", min_width=4)
    table.add_column("Principal", style="bold", min_width=20)
    table.add_column("Target", min_width=20)
    table.add_column("Details", min_width=40)

    for f in findings:
        style = _severity_style(f)
        table.add_row(
            f.severity.value[0].upper(),
            f.principal_name,
            f.target_name,
            f.description,
            style=style,
        )
    console.print(table)

    # Expand details for findings that contain instance lists
    for f in findings:
        details = f.details
        if not details:
            continue
        instance_lines: list[str] = []
        for key, val in details.items():
            if isinstance(val, list) and val:
                items = [str(v) for v in val[:20]]
                label = key.replace("_", " ").title()
                instance_lines.append(f"  [bold]{label}[/] ({len(val)}): "
                                      + ", ".join(items))
                if len(val) > 20:
                    instance_lines[-1] += f" ... (+{len(val) - 20} more)"
        if instance_lines:
            console.print(f"  [dim]▸ {f.principal_name} — {f.target_name}:[/]")
            for line in instance_lines:
                console.print(line)

    console.print()


def _print_laps_gmsa_table(findings: list[Finding], tkw: dict | None = None) -> None:
    """Render LAPS/gMSA password read findings with principal → target detail."""
    table = Table(**(tkw or {"show_lines": False, "pad_edge": False, "box": None}))
    table.add_column("Sev", min_width=4)
    table.add_column("Trustee", style="bold", min_width=20)
    table.add_column("SID", min_width=15)
    table.add_column("Target", min_width=20)
    table.add_column("Rights", min_width=15)
    table.add_column("Inh", justify="center", min_width=3)

    for f in findings:
        style = _severity_style(f)
        table.add_row(
            f.severity.value[0].upper(),
            f.principal_name,
            f.principal_sid,
            f.target_name,
            ", ".join(f.rights) if f.rights else f.details.get("laps_type", f.details.get("via", "")),
            "Y" if f.inherited else "",
            style=style,
        )
    console.print(table)
    console.print()


def _print_session_local_table(findings: list[Finding], tkw: dict | None = None) -> None:
    """Render session abuse / local group access findings."""
    table = Table(**(tkw or {"show_lines": False, "pad_edge": False, "box": None}))
    table.add_column("Sev", min_width=4)
    table.add_column("Principal", style="bold", min_width=20)
    table.add_column("Target", min_width=20)
    table.add_column("Access Type", min_width=15)
    table.add_column("Details", min_width=40)

    for f in findings:
        style = _severity_style(f)
        access_type = ", ".join(f.rights) if f.rights else f.target_class
        table.add_row(
            f.severity.value[0].upper(),
            f.principal_name,
            f.target_name,
            access_type,
            f.description,
            style=style,
        )
    console.print(table)
    console.print()


def _print_json(result: AnalysisResult, show_inherited: bool, show_builtin: bool) -> None:
    """Output findings as JSON to stdout."""
    findings = result.findings
    if not show_builtin:
        findings = [f for f in findings if not f.is_builtin]
    if not show_inherited:
        findings = [f for f in findings if not f.inherited]

    output = {
        "domain": result.domain,
        "source": result.source_file,
        "total_findings": len(findings),
        "owned_sids": sorted(result.owned_sids) if result.owned_sids else [],
        "findings": [
            {
                "category": f.category.value,
                "severity": f.severity.value,
                "principal_sid": f.principal_sid,
                "principal_name": f.principal_name,
                "target_dn": f.target_dn,
                "target_name": f.target_name,
                "target_class": f.target_class,
                "description": f.description,
                "rights": f.rights,
                "inherited": f.inherited,
                "is_builtin": f.is_builtin,
                "details": f.details,
            }
            for f in findings
        ],
    }
    json.dump(output, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


# Legacy compat
def print_write_dacl_results(result: AnalysisResult, show_inherited: bool, show_builtin: bool) -> None:
    """Backward-compatible wrapper."""
    print_analysis_results(result, show_inherited=show_inherited, show_builtin=show_builtin)


def print_error(msg: str) -> None:
    console.print(f"[bold red]Error:[/] {msg}")


def print_info(msg: str) -> None:
    console.print(f"[cyan][*][/] {msg}")


def print_success(msg: str) -> None:
    console.print(f"[green][+][/] {msg}")


def print_warning(msg: str) -> None:
    console.print(f"[yellow][!][/] {msg}")
