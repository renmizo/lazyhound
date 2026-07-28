"""Mermaid diagram generators for attack paths, domain trusts, and delegation.

Produces Mermaid markdown that renders in GitHub, VS Code, and most Markdown
viewers.  Each generator returns a plain string containing the Mermaid code
block (fenced with ```mermaid ... ```).
"""

from __future__ import annotations

from pathlib import Path

from ..collect.analyzer import (
    Category,
    _build_attack_graph,
    _get_uac,
    _is_high_value,
    analyze,
)
from ..collect.query import CollectionIndex


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _mermaid_safe(text: str) -> str:
    """Escape text for use inside Mermaid node labels."""
    return (
        text.replace("&", "&amp;")
        .replace('"', "'")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", " ")
        .replace("(", "[")
        .replace(")", "]")
    )


def _short_name(name: str, max_len: int = 30) -> str:
    """Truncate long names for readability."""
    if len(name) <= max_len:
        return name
    return name[: max_len - 3] + "..."


# ---------------------------------------------------------------------------
# 1. Attack Path Map
# ---------------------------------------------------------------------------
def attack_paths_mermaid(
    data: dict,
    *,
    owned: list[str] | None = None,
    max_paths: int = 25,
    max_depth: int = 8,
    result=None,
) -> str:
    """Generate a Mermaid flowchart of attack paths to high-value targets.

    Uses the analyzer's shortest-path findings to build the diagram.
    If *owned* is provided, paths from those principals are highlighted.
    If *result* is provided, it is reused instead of re-running analysis.
    """
    if result is None:
        result = analyze(data, checks={"shortest-path"}, owned=owned)
    sp_findings = [
        f for f in result.findings if f.category == Category.SHORTEST_PATH
    ]

    if not sp_findings:
        return "```mermaid\ngraph LR\n    NO_PATHS[No attack paths found]\n```\n"

    # Sort by depth (shortest first), then limit
    sp_findings.sort(key=lambda f: f.details.get("depth", 99))
    sp_findings = sp_findings[:max_paths]

    # Collect unique nodes and edges
    nodes: dict[str, dict] = {}  # id -> {name, class, style}
    edges: list[tuple[str, str, str]] = []  # (from_id, to_id, label)

    for finding in sp_findings:
        path_names = finding.details.get("path_names", [])
        path_sids = finding.details.get("path_sids", [])
        if len(path_names) < 2:
            continue

        for i, (sid, name) in enumerate(zip(path_sids, path_names)):
            node_id = _node_id(sid)
            if node_id not in nodes:
                is_hv = _is_high_value(sid)
                is_source = i == 0
                style = ""
                if is_hv:
                    style = "hv"
                elif is_source:
                    style = "source"
                nodes[node_id] = {
                    "name": _short_name(_mermaid_safe(name)),
                    "style": style,
                }

            if i < len(path_names) - 1:
                from_id = _node_id(path_sids[i])
                to_id = _node_id(path_sids[i + 1])
                # Try to get edge label from description
                edge_label = ""
                edges.append((from_id, to_id, edge_label))

    # Deduplicate edges
    unique_edges: set[tuple[str, str, str]] = set()
    for e in edges:
        unique_edges.add(e)

    lines = [
        "```mermaid",
        "graph LR",
        "    %% Attack Paths to High-Value Targets",
        "    classDef hvTarget fill:#dc3545,stroke:#fff,color:#fff,font-weight:bold",
        "    classDef source fill:#17a2b8,stroke:#fff,color:#fff",
        "    classDef default fill:#2b2b3d,stroke:#555,color:#e0e0e0",
        "",
    ]

    # Emit nodes
    for nid, info in sorted(nodes.items()):
        label = info["name"]
        lines.append(f'    {nid}["{label}"]')

    lines.append("")

    # Emit edges
    for from_id, to_id, label in sorted(unique_edges):
        if label:
            lines.append(f"    {from_id} -->|{_mermaid_safe(label)}| {to_id}")
        else:
            lines.append(f"    {from_id} --> {to_id}")

    lines.append("")

    # Apply styles
    hv_nodes = [nid for nid, info in nodes.items() if info["style"] == "hv"]
    src_nodes = [nid for nid, info in nodes.items() if info["style"] == "source"]
    if hv_nodes:
        lines.append(f"    class {','.join(hv_nodes)} hvTarget")
    if src_nodes:
        lines.append(f"    class {','.join(src_nodes)} source")

    lines.append("```")
    return "\n".join(lines) + "\n"


def attack_paths_full_mermaid(
    data: dict,
    *,
    owned: list[str] | None = None,
    max_paths: int = 25,
    result=None,
) -> str:
    """Generate a Mermaid flowchart with edge labels from the attack graph.

    Builds the attack graph directly and traces paths from the shortest-path
    findings, labeling each edge with its type (MemberOf, ACL, Owns, etc.).
    If *result* is provided, it is reused instead of re-running analysis.
    """
    objects = data.get("objects", [])
    sid_map = dict(data.get("sid_map", {}))
    sessions = data.get("sessions")
    local_group_members = data.get("local_group_members")

    # Build the full attack graph
    graph, sid_names, _ = _build_attack_graph(
        objects, sid_map, sessions=sessions, local_group_members=local_group_members,
    )

    # Get shortest-path findings to know which paths to render
    if result is None:
        result = analyze(data, checks={"shortest-path"}, owned=owned)
    sp_findings = [
        f for f in result.findings if f.category == Category.SHORTEST_PATH
    ]
    if not sp_findings:
        return "```mermaid\ngraph LR\n    NO_PATHS[No attack paths found]\n```\n"

    sp_findings.sort(key=lambda f: f.details.get("depth", 99))
    sp_findings = sp_findings[:max_paths]

    nodes: dict[str, dict] = {}
    edges: set[tuple[str, str, str]] = set()

    for finding in sp_findings:
        path_sids = finding.details.get("path_sids", [])
        path_names = finding.details.get("path_names", [])

        for i, (sid, name) in enumerate(zip(path_sids, path_names)):
            nid = _node_id(sid)
            if nid not in nodes:
                is_hv = _is_high_value(sid)
                nodes[nid] = {
                    "name": _short_name(_mermaid_safe(name)),
                    "style": "hv" if is_hv else ("source" if i == 0 else ""),
                }

            if i < len(path_sids) - 1:
                from_sid = path_sids[i]
                to_sid = path_sids[i + 1]
                from_id = _node_id(from_sid)
                to_id = _node_id(to_sid)

                # Find edge label from attack graph
                edge_labels = []
                for dst, label in graph.get(from_sid, set()):
                    if dst == to_sid:
                        edge_labels.append(label)

                edge_label = ", ".join(sorted(set(edge_labels))) if edge_labels else ""
                edges.add((from_id, to_id, edge_label))

    lines = [
        "```mermaid",
        "graph LR",
        "    %% Attack Paths with Edge Labels",
        "    classDef hvTarget fill:#dc3545,stroke:#fff,color:#fff,font-weight:bold",
        "    classDef source fill:#17a2b8,stroke:#fff,color:#fff",
        "    classDef default fill:#2b2b3d,stroke:#555,color:#e0e0e0",
        "",
    ]

    for nid, info in sorted(nodes.items()):
        lines.append(f'    {nid}["{info["name"]}"]')
    lines.append("")

    for from_id, to_id, label in sorted(edges):
        if label:
            lines.append(f"    {from_id} -->|{_mermaid_safe(label)}| {to_id}")
        else:
            lines.append(f"    {from_id} --> {to_id}")
    lines.append("")

    hv_nodes = [nid for nid, info in nodes.items() if info["style"] == "hv"]
    src_nodes = [nid for nid, info in nodes.items() if info["style"] == "source"]
    if hv_nodes:
        lines.append(f"    class {','.join(hv_nodes)} hvTarget")
    if src_nodes:
        lines.append(f"    class {','.join(src_nodes)} source")

    lines.append("```")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# 2. Domain / Trust Map
# ---------------------------------------------------------------------------
def domain_trust_mermaid(idx: CollectionIndex) -> str:
    """Generate a Mermaid diagram of domain trust relationships."""
    domain = idx.domain
    trusts = idx.trusts()

    # Domain controllers
    dcs = []
    for obj in idx.objects_by_class("computer"):
        uac = _get_uac(obj)
        if uac & 0x2000:  # SERVER_TRUST_ACCOUNT
            dcs.append(obj.get("name", ""))

    _TRUST_DIRS = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}

    lines = [
        "```mermaid",
        "graph TB",
        f"    %% Domain Trust Map — {_mermaid_safe(domain)}",
        "    classDef thisDomain fill:#0f3460,stroke:#53c0f0,color:#fff,font-weight:bold",
        "    classDef trustedDomain fill:#2b2b3d,stroke:#ffc107,color:#e0e0e0",
        "    classDef dcNode fill:#16213e,stroke:#53c0f0,color:#e0e0e0",
        "",
    ]

    # Current domain subgraph
    domain_id = _node_id(domain)
    lines.append(f"    subgraph {domain_id}_sub [{_mermaid_safe(domain)}]")
    if dcs:
        for dc in dcs:
            dc_id = _node_id(dc)
            lines.append(f'        {dc_id}["{_mermaid_safe(dc)}<br/>Domain Controller"]')
    else:
        lines.append(f'        {domain_id}_placeholder["{_mermaid_safe(domain)}"]')
    lines.append("    end")
    lines.append("")

    # OU summary
    ous = idx.objects_by_class("ou")
    groups = idx.objects_by_class("group")
    users = idx.objects_by_class("user")
    computers = idx.objects_by_class("computer")

    stats_id = _node_id(domain + "_stats")
    lines.append(f'    {stats_id}["{_mermaid_safe(domain)}<br/>'
                 f'{len(users)} users | {len(computers)} computers<br/>'
                 f'{len(groups)} groups | {len(ous)} OUs"]')
    lines.append(f"    {domain_id}_sub --- {stats_id}")
    lines.append("")

    # Trust edges
    if trusts:
        for t in trusts:
            props = t.get("properties", {})
            trust_name = t.get("name", "Unknown")
            trust_id = _node_id(trust_name)
            try:
                direction = int(props.get("trustDirection") or 0)
            except (ValueError, TypeError):
                direction = 0
            tattrs = props.get("trustAttributes", 0)
            try:
                tattrs = int(tattrs)
            except (ValueError, TypeError):
                tattrs = 0
            is_forest = bool(tattrs & 0x08)
            sid_filtering = "SID filtering on" if (tattrs & 0x04) else "SID filtering OFF"

            trust_label = _TRUST_DIRS.get(direction, "Unknown")
            if is_forest:
                trust_label += ", Forest"

            lines.append(f'    {trust_id}["{_mermaid_safe(trust_name)}"]')

            if direction == 3:  # Bidirectional
                lines.append(f"    {domain_id}_sub <-->|{trust_label}<br/>{sid_filtering}| {trust_id}")
            elif direction == 2:  # Outbound
                lines.append(f"    {domain_id}_sub -->|{trust_label}<br/>{sid_filtering}| {trust_id}")
            elif direction == 1:  # Inbound
                lines.append(f"    {trust_id} -->|{trust_label}<br/>{sid_filtering}| {domain_id}_sub")
            else:
                lines.append(f"    {domain_id}_sub -.-|Disabled| {trust_id}")
        lines.append("")

    # Styles
    lines.append(f"    class {domain_id}_sub thisDomain")
    if dcs:
        dc_ids = ",".join(_node_id(dc) for dc in dcs)
        lines.append(f"    class {dc_ids} dcNode")
    trust_ids = [_node_id(t.get("name", "")) for t in trusts]
    if trust_ids:
        lines.append(f"    class {','.join(trust_ids)} trustedDomain")

    lines.append("```")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# 3. Delegation Map
# ---------------------------------------------------------------------------
def delegation_mermaid(idx: CollectionIndex) -> str:
    """Generate a Mermaid diagram of all delegation relationships."""
    deleg_map = idx.delegation_map()

    if not deleg_map:
        return "```mermaid\ngraph LR\n    NONE[No delegation relationships found]\n```\n"

    lines = [
        "```mermaid",
        "graph LR",
        f"    %% Delegation Map — {_mermaid_safe(idx.domain)}",
        "    classDef unconstrained fill:#dc3545,stroke:#fff,color:#fff,font-weight:bold",
        "    classDef constrained fill:#fd7e14,stroke:#fff,color:#fff",
        "    classDef rbcd fill:#ffc107,stroke:#333,color:#333",
        "    classDef target fill:#2b2b3d,stroke:#555,color:#e0e0e0",
        "    classDef disabled fill:#6c757d,stroke:#555,color:#fff,stroke-dasharray:5",
        "",
    ]

    nodes: dict[str, dict] = {}
    edge_lines: list[str] = []
    unconstrained_ids: list[str] = []
    constrained_ids: list[str] = []
    rbcd_ids: list[str] = []
    disabled_ids: list[str] = []
    target_ids: list[str] = []

    for entry in deleg_map:
        principal = entry["principal"]
        principal_id = _node_id(entry.get("principal_sid", principal))
        dtype = entry["delegation_type"]
        enabled = entry.get("enabled", True)
        targets = entry.get("targets", [])

        if principal_id not in nodes:
            cls_label = entry.get("principal_class", "")
            label = f"{_mermaid_safe(_short_name(principal))}<br/>({cls_label})"
            nodes[principal_id] = {"label": label}
            lines.append(f'    {principal_id}["{label}"]')

        if not enabled:
            disabled_ids.append(principal_id)

        if dtype == "Unconstrained":
            unconstrained_ids.append(principal_id)
            any_id = _node_id("ANY_SERVICE")
            if any_id not in nodes:
                nodes[any_id] = {"label": "ANY SERVICE"}
                lines.append(f'    {any_id}{{"ANY SERVICE"}}')
                target_ids.append(any_id)
            arrow = "-.->" if not enabled else "-->"
            edge_lines.append(f"    {principal_id} {arrow}|Unconstrained| {any_id}")

        elif dtype == "Constrained":
            constrained_ids.append(principal_id)
            proto = "+S4U" if entry.get("protocol_transition") else ""
            for target_spn in targets:
                t_id = _node_id(target_spn)
                if t_id not in nodes:
                    nodes[t_id] = {"label": _mermaid_safe(_short_name(target_spn, 40))}
                    lines.append(f'    {t_id}["{nodes[t_id]["label"]}"]')
                    target_ids.append(t_id)
                arrow = "-.->" if not enabled else "-->"
                label = f"Constrained{proto}"
                edge_lines.append(f"    {principal_id} {arrow}|{label}| {t_id}")

        elif dtype == "RBCD":
            rbcd_ids.append(principal_id)

    lines.append("")
    lines.extend(edge_lines)
    lines.append("")

    # Apply class styles
    if unconstrained_ids:
        lines.append(f"    class {','.join(set(unconstrained_ids))} unconstrained")
    if constrained_ids:
        # Don't override unconstrained style
        pure_constrained = set(constrained_ids) - set(unconstrained_ids)
        if pure_constrained:
            lines.append(f"    class {','.join(pure_constrained)} constrained")
    if rbcd_ids:
        pure_rbcd = set(rbcd_ids) - set(unconstrained_ids) - set(constrained_ids)
        if pure_rbcd:
            lines.append(f"    class {','.join(pure_rbcd)} rbcd")
    if disabled_ids:
        pure_disabled = set(disabled_ids) - set(unconstrained_ids) - set(constrained_ids) - set(rbcd_ids)
        if pure_disabled:
            lines.append(f"    class {','.join(pure_disabled)} disabled")
    if target_ids:
        lines.append(f"    class {','.join(set(target_ids))} target")

    lines.append("```")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Node ID helper
# ---------------------------------------------------------------------------
def _node_id(identifier: str) -> str:
    """Convert an identifier to a valid Mermaid node ID."""
    # Replace all non-alphanumeric chars with underscore
    clean = ""
    for ch in identifier:
        if ch.isalnum():
            clean += ch
        else:
            clean += "_"
    # Ensure it starts with a letter
    if clean and not clean[0].isalpha():
        clean = "n" + clean
    return clean or "unknown"


# ---------------------------------------------------------------------------
# File writers
# ---------------------------------------------------------------------------
def write_attack_paths(
    data: dict,
    output: str | Path,
    *,
    owned: list[str] | None = None,
    max_paths: int = 25,
    detailed: bool = True,
    result=None,
) -> Path:
    """Generate and write attack path Mermaid diagram."""
    if detailed:
        content = attack_paths_full_mermaid(data, owned=owned, max_paths=max_paths, result=result)
    else:
        content = attack_paths_mermaid(data, owned=owned, max_paths=max_paths, result=result)
    p = Path(output)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def write_domain_trust(idx: CollectionIndex, output: str | Path) -> Path:
    """Generate and write domain trust Mermaid diagram."""
    content = domain_trust_mermaid(idx)
    p = Path(output)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def write_delegation(idx: CollectionIndex, output: str | Path) -> Path:
    """Generate and write delegation Mermaid diagram."""
    content = delegation_mermaid(idx)
    p = Path(output)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p
