"""Graphviz (dot) renderer + offline image export via the local `dot` binary.

Styled to read like a BloodHound graph (static export): each node is a
colour-coded, rounded "card" carrying a white type icon (user / computer /
folder / …), the object name, and a descriptive tag line (type · TIER 0 ·
TARGET · OWNED). Tier-Zero nodes get a red ring, owned/start nodes a gold
ring, the target a white ring. Edges are labelled with the abuse primitive
and coloured by difficulty. A compact icon legend sits in the corner.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .model import (
    NodeType, VisualGraph, VisualNode, PALETTE as _PALETTE,
    TIER_ZERO_FILL as _TIER_ZERO_FILL, OWNED_RING as _OWNED_RING,
    humanize_edge,
)

ICON_DIR = Path(__file__).resolve().parent / "icons"

# NodeType -> icon file (several types share an icon).
_ICON_FILES: dict[NodeType, str] = {
    NodeType.USER: "user.png",
    NodeType.GROUP: "group.png",
    NodeType.COMPUTER: "computer.png",
    NodeType.OU: "folder.png",
    NodeType.DOMAIN: "domain.png",
    NodeType.GPO: "gpo.png",
    NodeType.CERT: "cert.png",
    NodeType.TRUST: "trust.png",
    NodeType.AAD_USER: "user.png",
    NodeType.AAD_GROUP: "group.png",
    NodeType.AAD_APP: "app.png",
    NodeType.AAD_SP: "app.png",
    NodeType.AAD_DEVICE: "device.png",
    NodeType.AZ_TENANT: "cloud.png",
    NodeType.AZ_RESOURCE: "cloud.png",
    NodeType.UNKNOWN: "unknown.png",
}

# Human-friendly type names for the tag line / legend.
_TYPE_LABEL: dict[NodeType, str] = {
    NodeType.USER: "User",
    NodeType.GROUP: "Group",
    NodeType.COMPUTER: "Computer",
    NodeType.OU: "OU",
    NodeType.DOMAIN: "Domain",
    NodeType.GPO: "GPO",
    NodeType.CERT: "Cert Template",
    NodeType.TRUST: "Trust",
    NodeType.AAD_USER: "Entra User",
    NodeType.AAD_GROUP: "Entra Group",
    NodeType.AAD_APP: "App Registration",
    NodeType.AAD_SP: "Service Principal",
    NodeType.AAD_DEVICE: "Device",
    NodeType.AZ_TENANT: "Azure Tenant",
    NodeType.AZ_RESOURCE: "Azure Resource",
    NodeType.UNKNOWN: "Object",
}

_THEMES = {
    "dark": {"bg": "#16181d", "fg": "#e8e8e8", "edge": "#8a8f98",
             "card_border": "#0d0f12", "legend_bg": "#1f232b"},
    "light": {"bg": "white", "fg": "#1a1a1a", "edge": "#666666",
              "card_border": "#cccccc", "legend_bg": "#f0f0f0"},
}


def _icon_path(nt: NodeType) -> str:
    return str(ICON_DIR / _ICON_FILES.get(nt, "unknown.png"))


def _edge_color(weight: float) -> str:
    if weight <= 1.0:
        return "#e05c5c"   # trivial
    if weight <= 2.0:
        return "#e6a14d"
    if weight <= 3.0:
        return "#c9c24b"
    return "#7f8896"       # harder


def _esc(text: str) -> str:
    """Escape for a double-quoted DOT string."""
    return (text or "").replace("\\", "\\\\").replace('"', '\\"')


def _h(text: str) -> str:
    """Escape for an HTML-like label."""
    return ((text or "")
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _card(n: VisualNode, theme: dict) -> str:
    """An HTML-like 'card' label: icon + name + descriptive tag line."""
    fill = _PALETTE.get(n.ntype, "#8a8a8a")
    border = theme["card_border"]
    bwidth = 2
    # ring priority: owned (start) > tier zero > target
    if n.owned:
        border, bwidth = _OWNED_RING, 3
    elif n.tier_zero:
        border, bwidth = _TIER_ZERO_FILL, 3
    elif n.is_target:
        border, bwidth = "#ffffff", 3

    tags = [_TYPE_LABEL.get(n.ntype, "Object")]
    if n.tier_zero:
        tags.append("TIER 0")
    if n.is_target:
        tags.append("TARGET")
    if n.owned:
        tags.append("OWNED")
    tagline = "  ·  ".join(tags)

    display = n.label if len(n.label) <= 34 else n.label[:32] + "…"
    icon = _icon_path(n.ntype)
    return (
        f'<<TABLE BORDER="{bwidth}" COLOR="{border}" CELLBORDER="0" '
        f'CELLSPACING="0" CELLPADDING="7" BGCOLOR="{fill}" STYLE="ROUNDED">'
        f'<TR><TD FIXEDSIZE="TRUE" WIDTH="38" HEIGHT="38">'
        f'<IMG SRC="{icon}" SCALE="TRUE"/></TD></TR>'
        f'<TR><TD><FONT COLOR="#ffffff" POINT-SIZE="13"><B>{_h(display)}</B>'
        f'</FONT></TD></TR>'
        f'<TR><TD><FONT COLOR="#f0f0f0" POINT-SIZE="8">{_h(tagline)}</FONT>'
        f'</TD></TR></TABLE>>'
    )


def _legend_table_html(present: set[NodeType], theme: dict) -> str:
    """A wide, single-row HTML legend table (compact height): node-type icons,
    ring markers, and the edge-difficulty key — all laid out horizontally."""
    fg = theme["fg"]
    cells = [f'<TD><FONT COLOR="{fg}" POINT-SIZE="10"><B>Legend</B></FONT></TD>']
    for nt in sorted(present, key=lambda x: _TYPE_LABEL.get(x, x.value)):
        cells.append(
            f'<TD FIXEDSIZE="TRUE" WIDTH="16" HEIGHT="16">'
            f'<IMG SRC="{_icon_path(nt)}" SCALE="TRUE"/></TD>'
            f'<TD ALIGN="LEFT"><FONT COLOR="{fg}" POINT-SIZE="9">'
            f'{_h(_TYPE_LABEL.get(nt, nt.value))}</FONT></TD>')
    for color, name in ((_TIER_ZERO_FILL, "Tier Zero"),
                        (_OWNED_RING, "Owned/start"), ("#ffffff", "Target")):
        cells.append(
            f'<TD FIXEDSIZE="TRUE" WIDTH="15" HEIGHT="15" BORDER="3" '
            f'COLOR="{color}"></TD>'
            f'<TD ALIGN="LEFT"><FONT COLOR="{fg}" POINT-SIZE="9">{name}</FONT></TD>')
    cells.append(f'<TD><FONT COLOR="{fg}" POINT-SIZE="9"><B>Arrow:</B></FONT></TD>')
    for color, name in (("#e05c5c", "trivial"), ("#e6a14d", "easy"),
                        ("#c9c24b", "moderate"), ("#7f8896", "harder")):
        cells.append(
            f'<TD FIXEDSIZE="TRUE" WIDTH="18" HEIGHT="7" BGCOLOR="{color}"></TD>'
            f'<TD ALIGN="LEFT"><FONT COLOR="{fg}" POINT-SIZE="9">{name}</FONT></TD>')
    return (
        f'<<TABLE BORDER="1" COLOR="{theme["edge"]}" CELLBORDER="0" '
        f'CELLSPACING="5" CELLPADDING="2" BGCOLOR="{theme["legend_bg"]}">'
        f'<TR>{"".join(cells)}</TR></TABLE>>'
    )


def _legend(present: set[NodeType], theme: dict) -> list[str]:
    """Inline legend node (used in dot/svg text output)."""
    return [f'  "lg_box" [shape=none, margin=0, '
            f'label={_legend_table_html(present, theme)}];']


def _legend_graph_source(present: set[NodeType], theme: dict) -> str:
    """Standalone digraph containing only the legend (transparent bg), so it can
    be rendered separately and composited at the bottom of the PNG."""
    return (
        'digraph legend {\n'
        '  bgcolor="transparent"; margin=0; pad="0.1";\n'
        '  node [shape=none, margin=0, fontname="DejaVu Sans"];\n'
        f'  "lg" [label={_legend_table_html(present, theme)}];\n'
        '}\n'
    )


def render_dot(graph: VisualGraph, theme: str = "dark", legend: bool = True) -> str:
    t = _THEMES.get(theme, _THEMES["dark"])
    rankdir = graph.direction if graph.direction in ("LR", "TB", "RL", "BT") else "LR"
    subtitle = getattr(graph, "subtitle", "") or ""
    title_html = (
        f'<<FONT POINT-SIZE="20"><B>{_h(graph.title)}</B></FONT>'
        + (f'<BR/><FONT POINT-SIZE="12" COLOR="{t["edge"]}">{_h(subtitle)}</FONT>'
           if subtitle else "")
        + '>'
    )
    out = [
        f'digraph "{graph.kind}" {{',
        f'  rankdir={rankdir}; splines=spline; overlap=false;',
        f'  nodesep=0.55; ranksep=1.0; pad=0.5;',
        f'  bgcolor="{t["bg"]}";',
        f'  labelloc="t"; fontcolor="{t["fg"]}"; fontname="DejaVu Sans"; '
        f'label={title_html};',
        f'  node [shape=none, margin=0, fontname="DejaVu Sans"];',
        f'  edge [fontname="DejaVu Sans", fontsize=10, color="{t["edge"]}", '
        f'fontcolor="{t["fg"]}", penwidth=1.5, arrowsize=0.9];',
    ]
    present: set[NodeType] = set()
    for nid in sorted(graph.nodes):
        node = graph.nodes[nid]
        present.add(node.ntype)
        out.append(f'  {nid} [label={_card(node, t)}];')
    for e in graph.edges:
        out.append(f'  {e.src} -> {e.dst} [label="{_esc(humanize_edge(e.label))}",'
                   f'color="{_edge_color(e.weight)}",'
                   f'fontcolor="{_edge_color(e.weight)}"];')
    if legend and present:
        out.extend(_legend(present, t))
    out.append("}")
    return "\n".join(out) + "\n"


def _hex_rgb(hexcolor: str) -> tuple[int, int, int]:
    h = (hexcolor or "#000000").lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))


def _dot_png_bytes(src: str, dot_bin: str) -> bytes | None:
    proc = subprocess.run([dot_bin, "-Tpng", "-Gdpi=160"],
                          input=src.encode("utf-8"), capture_output=True)
    return proc.stdout if proc.returncode == 0 and proc.stdout else None


def _composite_png(graph: VisualGraph, path: str, theme: str, dot_bin: str) -> str | None:
    """Render title+path (no inline legend) and a separate wide legend strip, then
    stack them vertically — title (top), path (middle), legend (bottom)."""
    try:
        from io import BytesIO
        from PIL import Image
    except Exception:
        return None
    t = _THEMES.get(theme, _THEMES["dark"])
    main_png = _dot_png_bytes(render_dot(graph, theme, legend=False), dot_bin)
    if main_png is None:
        return None
    imgs = [Image.open(BytesIO(main_png)).convert("RGBA")]
    present = {n.ntype for n in graph.nodes.values()}
    if present:
        leg_png = _dot_png_bytes(_legend_graph_source(present, t), dot_bin)
        if leg_png:
            imgs.append(Image.open(BytesIO(leg_png)).convert("RGBA"))
    pad = 26
    width = max(i.width for i in imgs)
    height = sum(i.height for i in imgs) + pad * (len(imgs) - 1)
    canvas = Image.new("RGBA", (width, height), _hex_rgb(t["bg"]) + (255,))
    y = 0
    for img in imgs:
        canvas.alpha_composite(img, ((width - img.width) // 2, y))
        y += img.height + pad
    canvas.convert("RGB").save(path)
    return path


def render_image(graph: VisualGraph, fmt: str, path: str, theme: str = "dark") -> str:
    """Render to .svg/.png via `dot`. If `dot` is absent or fails, write .dot source.

    PNG is composited so the legend sits, small and wide, at the BOTTOM (title →
    path → legend, top-down). PNG is rendered at 160 dpi for crispness.
    """
    dot_bin = shutil.which("dot")
    if not dot_bin:
        src = render_dot(graph, theme)
        dot_path = str(Path(path).with_suffix(".dot"))
        Path(dot_path).write_text(src, encoding="utf-8")
        print(f"Graphviz 'dot' not found; wrote DOT source to {dot_path}. "
              f"Install graphviz or run: dot -T{fmt} {dot_path} -o {path}")
        return dot_path

    if fmt == "png":
        out = _composite_png(graph, path, theme, dot_bin)
        if out:
            return out  # fall through to a plain render only if compositing failed

    src = render_dot(graph, theme)
    args = [dot_bin, f"-T{fmt}"]
    if fmt == "png":
        args.append("-Gdpi=160")
    args += ["-o", path]
    proc = subprocess.run(args, input=src, text=True, capture_output=True)
    if proc.returncode != 0:
        dot_path = str(Path(path).with_suffix(".dot"))
        Path(dot_path).write_text(src, encoding="utf-8")
        print(f"dot failed ({proc.stderr.strip()}); wrote DOT source to {dot_path}")
        return dot_path
    return path
