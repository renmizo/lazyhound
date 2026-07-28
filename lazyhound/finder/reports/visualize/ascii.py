"""Pure-python ASCII rendering of a VisualGraph (terminal + .txt)."""
from __future__ import annotations

import shutil

from .model import VisualGraph, VisualNode


def _term_width(default: int = 100) -> int:
    try:
        return max(40, shutil.get_terminal_size((default, 24)).columns)
    except Exception:
        return default


def _marker(n: VisualNode) -> str:
    tags = []
    if n.tier_zero:
        tags.append("★T0")
    if n.owned:
        tags.append("⊙owned")
    return ("  " + " ".join(tags)) if tags else ""


def _decorate(n: VisualNode) -> str:
    return f"{n.label} ({n.ntype.value}){_marker(n)}"


def render_ascii(graph: VisualGraph) -> str:
    _term_width()  # reserved for future width-aware truncation
    lines = [graph.title, "=" * len(graph.title), ""]

    if not graph.nodes:
        lines.append("(no data to display)")
        return "\n".join(lines) + "\n"

    # adjacency + indegree
    adj: dict[str, list[tuple[str, str]]] = {nid: [] for nid in graph.nodes}
    indeg: dict[str, int] = {nid: 0 for nid in graph.nodes}
    for e in graph.edges:
        adj.setdefault(e.src, []).append((e.dst, e.label))
        indeg[e.dst] = indeg.get(e.dst, 0) + 1
    for nid in adj:
        adj[nid].sort(key=lambda t: (graph.nodes[t[0]].label, t[1]))

    roots = sorted((nid for nid in graph.nodes if indeg.get(nid, 0) == 0),
                   key=lambda nid: graph.nodes[nid].label)
    if not roots:  # cyclic fallback: start at a stable node
        roots = sorted(graph.nodes, key=lambda nid: graph.nodes[nid].label)[:1]

    def walk(nid: str, prefix: str, is_root: bool, is_last: bool,
             edge_label: str, visited: set[str]) -> None:
        node = graph.nodes[nid]
        if is_root:
            lines.append(f"{prefix}▶ {_decorate(node)}")
            child_prefix = prefix + "  "
        else:
            branch = "└─" if is_last else "├─"
            arrow = f"[{edge_label}]→ " if edge_label else ""
            lines.append(f"{prefix}{branch}{arrow}{_decorate(node)}")
            child_prefix = prefix + ("    " if is_last else "│   ")
        if nid in visited:
            if adj.get(nid):
                lines.append(f"{child_prefix}(… already shown)")
            return
        visited = visited | {nid}
        children = adj.get(nid, [])
        for i, (child, label) in enumerate(children):
            walk(child, child_prefix, False, i == len(children) - 1, label, visited)

    for r in roots:
        walk(r, "", True, True, "", set())
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"
