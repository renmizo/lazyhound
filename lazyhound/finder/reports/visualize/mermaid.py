"""Mermaid renderer for a VisualGraph — BloodHound-style themed markdown block.

Renders in GitHub/Obsidian/VS Code mermaid previews: per-type colour classes
(shared palette with the Graphviz renderer), Tier-Zero / owned emphasis,
node shapes per type, and weight-coloured edges.
"""
from __future__ import annotations

from .model import (
    NodeType, VisualGraph, VisualNode, PALETTE, TIER_ZERO_FILL, OWNED_RING,
    humanize_edge,
)

# (open, close) bracket syntax per node type — gives each type a distinct shape.
_BRACKETS = {
    NodeType.USER: ("([", "])"),
    NodeType.GROUP: ("{{", "}}"),
    NodeType.COMPUTER: ("[", "]"),
    NodeType.OU: ("[/", "/]"),
    NodeType.DOMAIN: ("[[", "]]"),
    NodeType.GPO: (">", "]"),
    NodeType.CERT: ("[(", ")]"),
    NodeType.TRUST: ("{{", "}}"),
    NodeType.AAD_USER: ("([", "])"),
    NodeType.AAD_GROUP: ("{{", "}}"),
    NodeType.AAD_APP: ("[(", ")]"),
    NodeType.AAD_SP: ("[(", ")]"),
    NodeType.AAD_DEVICE: ("[", "]"),
    NodeType.AZ_TENANT: ("[[", "]]"),
    NodeType.AZ_RESOURCE: ("[", "]"),
    NodeType.UNKNOWN: ("[", "]"),
}


def _safe(text: str) -> str:
    return (text or "").replace('"', "'").replace("[", "(").replace("]", ")")


def _edge_weight_color(weight: float) -> str:
    if weight <= 1.0:
        return "#e05c5c"
    if weight <= 2.0:
        return "#e6a14d"
    if weight <= 3.0:
        return "#c9c24b"
    return "#7f8896"


def _node_line(n: VisualNode) -> str:
    op, cl = _BRACKETS.get(n.ntype, ("[", "]"))
    name = _safe(n.label if len(n.label) <= 40 else n.label[:38] + "…")
    return f'    {n.id}{op}"{name}<br/><small>{n.ntype.value}</small>"{cl}'


def render_mermaid(graph: VisualGraph, theme: str = "dark") -> str:
    rankdir = graph.direction if graph.direction in ("LR", "TB", "RL", "BT") else "LR"
    init = "%%{init: {'theme':'dark', 'flowchart':{'curve':'basis'}}}%%"
    lines = ["```mermaid", init, f"graph {rankdir}", f"    %% {_safe(graph.title)}"]
    if not graph.nodes:
        lines += ["    NONE[No data to display]", "```", ""]
        return "\n".join(lines)

    for nid in sorted(graph.nodes):
        lines.append(_node_line(graph.nodes[nid]))

    # Edges + per-edge weight colouring via linkStyle (by edge index)
    link_styles: list[str] = []
    for i, e in enumerate(graph.edges):
        lbl = _safe(humanize_edge(e.label))
        arrow = f"-->|{lbl}|" if lbl else "-->"
        lines.append(f"    {e.src} {arrow} {e.dst}")
        link_styles.append(f"    linkStyle {i} stroke:{_edge_weight_color(e.weight)},"
                           f"stroke-width:1.5px;")

    # Per-type colour classes (shared palette), then Tier-Zero / owned overrides.
    present: dict[NodeType, list[str]] = {}
    for n in graph.nodes.values():
        present.setdefault(n.ntype, []).append(n.id)
    for nt, ids in present.items():
        colour = PALETTE.get(nt, "#8a8a8a")
        lines.append(f"    classDef {nt.value} fill:{colour},stroke:#0d0f12,color:#fff;")
        lines.append(f"    class {','.join(sorted(ids))} {nt.value};")

    lines.append(f"    classDef tierzero fill:{TIER_ZERO_FILL},stroke:#fff,"
                 f"stroke-width:2px,color:#fff;")
    lines.append(f"    classDef owned stroke:{OWNED_RING},stroke-width:4px,color:#fff;")
    tz = sorted(n.id for n in graph.nodes.values() if n.tier_zero)
    ow = sorted(n.id for n in graph.nodes.values() if n.owned)
    if tz:
        lines.append(f"    class {','.join(tz)} tierzero;")
    if ow:
        lines.append(f"    class {','.join(ow)} owned;")
    lines.extend(link_styles)
    lines += ["```", ""]
    return "\n".join(lines)
