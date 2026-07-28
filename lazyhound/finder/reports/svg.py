"""Dependency-free inline-SVG primitives for the visual reports.

Pure Python (math only) → SVG-fragment strings. No JavaScript, no external
assets: the reports render identically in a browser and in WeasyPrint PDF.
"""
from __future__ import annotations

import html as _html
import math


def _e(v) -> str:
    return _html.escape(str(v))


def _polar(cx: float, cy: float, r: float, deg: float) -> tuple[float, float]:
    a = math.radians(deg - 90)          # 0° = 12 o'clock, clockwise
    return cx + r * math.cos(a), cy + r * math.sin(a)


def _arc_path(cx: float, cy: float, r: float, a0: float, a1: float) -> str:
    x0, y0 = _polar(cx, cy, r, a0)
    x1, y1 = _polar(cx, cy, r, a1)
    large = 1 if (a1 - a0) % 360 > 180 else 0
    return f"M{x0:.2f},{y0:.2f} A{r:.2f},{r:.2f} 0 {large} 1 {x1:.2f},{y1:.2f}"


def svg_open(w: float, h: float, cls: str = "") -> str:
    c = f" class='{cls}'" if cls else ""
    return (f"<svg viewBox='0 0 {w:.0f} {h:.0f}' width='100%' height='auto'{c} "
            f"xmlns='http://www.w3.org/2000/svg'>")


def svg_close() -> str:
    return "</svg>"


def donut(segments, size: float = 180, thickness: float = 34, center_label: str = "") -> str:
    """segments: [(value, color, label)]. Ring of arcs sized by value."""
    vals = [(v, c) for v, c, *_ in segments if v > 0]
    total = sum(v for v, _ in vals) or 1
    cx = cy = size / 2
    r = (size - thickness) / 2
    out = [svg_open(size, size, "svg-donut")]
    if len(vals) == 1:                  # a lone full slice = a plain ring
        out.append(f"<circle cx='{cx}' cy='{cy}' r='{r:.2f}' fill='none' "
                   f"stroke='{vals[0][1]}' stroke-width='{thickness}'/>")
    else:
        a = 0.0
        for v, color in vals:
            a1 = a + v / total * 360
            out.append(f"<path d='{_arc_path(cx, cy, r, a, min(a1, a + 359.9))}' "
                       f"fill='none' stroke='{color}' stroke-width='{thickness}'/>")
            a = a1
    if center_label:
        out.append(f"<text x='{cx}' y='{cy}' text-anchor='middle' "
                   f"dominant-baseline='central' class='svg-donut-c'>{_e(center_label)}</text>")
    out.append(svg_close())
    return "".join(out)


def gauge(fraction: float, label: str, size: float = 220, color: str = "#e5484d") -> str:
    """A top semicircular gauge (0..1, left→right) with a big centre label."""
    frac = max(0.0, min(1.0, fraction))
    w, h = size, size * 0.62
    cx, cy, r, th = size / 2, size * 0.56, size * 0.42, size * 0.11
    # top semicircle: 270° (9 o'clock) → 360°/0° (12) → 90° (3 o'clock)
    a0 = 270
    out = [svg_open(w, h, "svg-gauge")]
    out.append(f"<path d='{_arc_path(cx, cy, r, a0, a0 + 180)}' fill='none' "
               f"stroke='rgba(127,127,127,.18)' stroke-width='{th}' stroke-linecap='round'/>")
    out.append(f"<path d='{_arc_path(cx, cy, r, a0, a0 + 180 * frac)}' fill='none' "
               f"stroke='{color}' stroke-width='{th}' stroke-linecap='round'/>")
    out.append(f"<text x='{cx}' y='{cy - r * 0.10}' text-anchor='middle' "
               f"dominant-baseline='central' class='svg-gauge-c'>{_e(label)}</text>")
    out.append(svg_close())
    return "".join(out)


def hbars(rows, width: float = 520, bar_h: float = 16, gap: float = 9, max_label: int = 22) -> str:
    """rows: [(label, value, color)] → labeled horizontal bars."""
    rows = list(rows)
    mx = max((v for _, v, _ in rows), default=1) or 1
    lab_w = 150
    track = width - lab_w - 46
    h = len(rows) * (bar_h + gap) + gap
    out = [svg_open(width, h, "svg-hbars")]
    y = gap
    for label, v, color in rows:
        lab = str(label)[:max_label]
        out.append(f"<text x='{lab_w - 6}' y='{y + bar_h * 0.8}' text-anchor='end' "
                   f"class='svg-lab'>{_e(lab)}</text>")
        out.append(f"<rect x='{lab_w}' y='{y}' width='{track}' height='{bar_h}' rx='4' class='svg-track'/>")
        out.append(f"<rect x='{lab_w}' y='{y}' width='{max(2, track * v / mx):.1f}' "
                   f"height='{bar_h}' rx='4' fill='{color}'/>")
        out.append(f"<text x='{lab_w + track + 6}' y='{y + bar_h * 0.8}' class='svg-val'>{_e(v)}</text>")
        y += bar_h + gap
    out.append(svg_close())
    return "".join(out)


def ribbon(x1: float, y1: float, h1: float, x2: float, y2: float, h2: float, color: str) -> str:
    """A tapering band from (x1,y1,height h1) to (x2,y2,height h2)."""
    mx = (x1 + x2) / 2
    d = (f"M{x1:.1f},{y1:.1f} C{mx:.1f},{y1:.1f} {mx:.1f},{y2:.1f} {x2:.1f},{y2:.1f} "
         f"L{x2:.1f},{y2 + h2:.1f} C{mx:.1f},{y2 + h2:.1f} {mx:.1f},{y1 + h1:.1f} {x1:.1f},{y1 + h1:.1f} Z")
    return f"<path d='{d}' fill='{color}' fill-opacity='.55'/>"


def node_box(x: float, y: float, w: float, h: float, text: str, cls: str = "") -> str:
    c = f" {cls}" if cls else ""
    return (f"<g class='svg-node{c}'><rect x='{x:.1f}' y='{y:.1f}' width='{w:.1f}' height='{h:.1f}' rx='6'/>"
            f"<text x='{x + w / 2:.1f}' y='{y + h / 2:.1f}' text-anchor='middle' "
            f"dominant-baseline='central'>{_e(text)}</text></g>")


def edge_line(x1: float, y1: float, x2: float, y2: float, label: str = "") -> str:
    out = [f"<line x1='{x1:.1f}' y1='{y1:.1f}' x2='{x2:.1f}' y2='{y2:.1f}' class='svg-edge'/>"]
    if label:
        out.append(f"<text x='{(x1 + x2) / 2:.1f}' y='{(y1 + y2) / 2 - 3:.1f}' "
                   f"text-anchor='middle' class='svg-edge-lab'>{_e(label)}</text>")
    return "".join(out)


def radar(labels, values, max_value: float | None = None, size: float = 320, rings: int = 4) -> str:
    """A radar/spider chart: `rings` concentric grid polygons, one axis per
    label, a filled data polygon at each value/max radius. Degenerate-safe."""
    labels = list(labels)
    values = list(values)
    n = len(labels)
    cx = cy = size / 2
    r = size * 0.36
    mx = max_value or (max(values) if values else 1) or 1
    out = [svg_open(size, size, "svg-radar")]
    if n == 0:
        out.append(svg_close())
        return "".join(out)

    def _pts(radius_frac):
        pts = []
        for i in range(n):
            deg = 360 * i / n
            x, y = _polar(cx, cy, r * radius_frac, deg)
            pts.append(f"{x:.1f},{y:.1f}")
        return " ".join(pts)

    for g in range(1, rings + 1):
        out.append(f"<polygon points='{_pts(g / rings)}' fill='none' "
                   f"stroke='rgba(127,127,127,.20)' stroke-width='1'/>")
    for i, lab in enumerate(labels):
        deg = 360 * i / n
        x, y = _polar(cx, cy, r, deg)
        lx, ly = _polar(cx, cy, r + 16, deg)
        out.append(f"<line x1='{cx}' y1='{cy}' x2='{x:.1f}' y2='{y:.1f}' "
                   f"stroke='rgba(127,127,127,.20)'/>")
        anchor = "middle" if abs(lx - cx) < 4 else ("start" if lx > cx else "end")
        out.append(f"<text x='{lx:.1f}' y='{ly:.1f}' text-anchor='{anchor}' "
                   f"dominant-baseline='central' class='svg-radar-lab'>{_e(lab)}</text>")
    dpts = []
    for i, v in enumerate(values):
        deg = 360 * i / n
        x, y = _polar(cx, cy, r * (v / mx), deg)
        dpts.append(f"{x:.1f},{y:.1f}")
    out.append(f"<polygon points='{' '.join(dpts)}' class='svg-radar-area'/>")
    out.append(svg_close())
    return "".join(out)
