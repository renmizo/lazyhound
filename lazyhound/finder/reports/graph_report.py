"""Attack Path Graph report (report run --type graph).

A self-contained SVG node-link diagram of the shortest paths to Tier Zero,
layered left→right by hop-distance. Pure SVG — offline & PDF-safe.
"""
from __future__ import annotations

from datetime import datetime, timezone

from lazyhound.finder.collect.analyzer import Category
from lazyhound.finder.reports.html_unified_report import (
    STYLES, _THEME_VARS, _BASE_CSS, _SEV_COLOR, _e)
from lazyhound.finder.reports import svg

_CSS = """
.graph-wrap{overflow-x:auto;background:var(--panel);border:1px solid var(--border);
border-radius:var(--radius);padding:14px;margin:14px 0}
.svg-node rect{fill:var(--panel);stroke:var(--accent);stroke-width:1.5}
.svg-node text{font-size:11px;fill:var(--text)}
.svg-node.src rect{stroke:#4da3ff}
.svg-node.tz rect{fill:var(--sev-critical,#e5484d);stroke:var(--sev-critical,#e5484d)}
.svg-node.tz text{fill:#fff;font-weight:700}
.svg-edge{stroke:var(--muted);stroke-width:1.4}
.svg-edge-lab{font-size:9px;fill:var(--muted)}
.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:.8rem;color:var(--muted);margin:8px 0}
.legend .k{display:inline-block;width:11px;height:11px;border-radius:3px;margin-right:5px;vertical-align:middle}
"""

_NODE_W, _NODE_H, _COL_GAP, _ROW_GAP = 130, 30, 190, 46


def _shortest_paths(result):
    fs = [f for f in (result.actionable if result else [])
          if f.category == Category.SHORTEST_PATH]
    return sorted(fs, key=lambda f: f.details.get("depth", 99))


def _layout(paths, max_paths: int = 15, max_nodes: int = 48):
    """Return (nodes, edges, truncated). nodes:{name,depth,col,row,role};
    edges:{a,b,label}. Depth = min hops to a Tier-Zero target (target=0)."""
    sel = paths[:max_paths]
    depth: dict[str, int] = {}
    role: dict[str, str] = {}
    edges = []
    seen_edge = set()
    _rrank = {"tz": 0, "src": 1, "mid": 2}
    for f in sel:
        names = f.details.get("path_names") or [f.principal_name, f.target_name]
        labels = f.details.get("path_edges") or []
        n = len(names)
        for i, nm in enumerate(names):
            d = n - 1 - i                       # distance to the path end (TZ)
            depth[nm] = min(depth.get(nm, d), d)
            r = "tz" if i == n - 1 else ("src" if i == 0 else "mid")
            if _rrank[r] < _rrank.get(role.get(nm, "mid"), 2):   # keep strongest role
                role[nm] = r
            role.setdefault(nm, r)
        for i in range(n - 1):
            key = (names[i], names[i + 1])
            if key in seen_edge:
                continue
            seen_edge.add(key)
            edges.append({"a": names[i], "b": names[i + 1],
                          "label": labels[i] if i < len(labels) else ""})
    truncated = 0
    if len(depth) > max_nodes:
        keep = set(sorted(depth, key=lambda k: depth[k])[:max_nodes])
        truncated = len(depth) - len(keep)
        depth = {k: v for k, v in depth.items() if k in keep}
        edges = [e for e in edges if e["a"] in depth and e["b"] in depth]
    by_col: dict[int, list[str]] = {}
    for nm in depth:
        by_col.setdefault(depth[nm], []).append(nm)
    nodes = []
    for d, names in by_col.items():
        for row, nm in enumerate(names):
            nodes.append({"name": nm, "depth": d, "col": d, "row": row,
                          "role": role.get(nm, "mid")})
    return nodes, edges, truncated


def build_graph_html(result, domain: str = "", style: int = 1, generated: str | None = None) -> str:
    if style not in _THEME_VARS:
        style = 1
    ts = generated or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    title = domain or getattr(result, "domain", "") or "unknown realm"
    paths = _shortest_paths(result)
    css = (f":root{{{_THEME_VARS[style]}}}\n:root{{--sev-critical:{_SEV_COLOR['critical']};}}\n"
           + _BASE_CSS + _CSS)
    o = ["<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>",
         "<meta name='viewport' content='width=device-width,initial-scale=1'>",
         f"<title>LazyHound Attack Path Graph — {_e(title)}</title>",
         f"<style>{css}</style></head><body class='style-{style}'><div class='wrap'>",
         f"<header class='rpt'><h1>Attack Path Graph</h1><div class='sub'>{_e(title)} · "
         f"generated {_e(ts)}</div></header>"]
    if not paths:
        o.append("<p class='muted'>No attack paths to Tier Zero were found.</p>"
                 "</div></body></html>")
        return "\n".join(o)

    nodes, edges, trunc = _layout(paths)
    maxcol = max((n["col"] for n in nodes), default=0)
    maxrow = max((n["row"] for n in nodes), default=0)
    W = (maxcol + 1) * _COL_GAP + 40
    H = (maxrow + 1) * _ROW_GAP + 40
    pos = {}
    for n in nodes:
        x = 20 + (maxcol - n["col"]) * _COL_GAP     # TZ (col 0) on the right
        y = 20 + n["row"] * _ROW_GAP
        pos[n["name"]] = (x, y)
    body = [svg.svg_open(W, H, "svg-graph")]
    for e in edges:
        (x1, y1), (x2, y2) = pos[e["a"]], pos[e["b"]]
        body.append(svg.edge_line(x1 + _NODE_W, y1 + _NODE_H / 2, x2, y2 + _NODE_H / 2, e["label"]))
    for n in nodes:
        x, y = pos[n["name"]]
        body.append(svg.node_box(x, y, _NODE_W, _NODE_H, n["name"], cls=n["role"]))
    body.append(svg.svg_close())
    o.append(f"<div class='graph-wrap'>{''.join(body)}</div>")
    o.append("<div class='legend'>"
             "<span><span class='k' style='background:#4da3ff'></span>attacker source</span>"
             "<span><span class='k' style='background:var(--accent)'></span>hop</span>"
             f"<span><span class='k' style='background:{_SEV_COLOR['critical']}'></span>Tier Zero</span></div>")
    if trunc:
        o.append(f"<p class='muted'>…{trunc} node(s) hidden (showing the top "
                 f"{min(len(paths), 15)} shortest paths).</p>")
    o.append("</div></body></html>")
    return "\n".join(o)


def build_graph_markdown(result, domain: str = "") -> str:
    title = domain or getattr(result, "domain", "") or "unknown"
    paths = _shortest_paths(result)
    lines = [f"# Attack Path Graph — {title}", ""]
    if not paths:
        lines.append("_No attack paths to Tier Zero were found._")
        return "\n".join(lines)
    for f in paths[:100]:
        names = f.details.get("path_names") or [f.principal_name, f.target_name]
        labels = f.details.get("path_edges") or []
        chain = names[0]
        for i, nm in enumerate(names[1:]):
            lab = labels[i] if i < len(labels) else ""
            chain += (f" -[{lab}]-> " if lab else " -> ") + nm
        lines.append(f"- {chain}")
    return "\n".join(lines)
