"""Tier-Zero Bullseye report (report run --type target).

Concentric rings centered on Tier Zero; ring N = principals N hops away
(from shortest-path depth), dots colored by severity. Pure SVG, offline.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone

from lazyhound.finder.collect.analyzer import Category
from lazyhound.finder.reports.html_unified_report import (
    STYLES, _THEME_VARS, _BASE_CSS, _SEV_COLOR, _e)
from lazyhound.finder.reports.attackpaths_report import _sev, _SEV_ORDER

_CSS = """
.target-wrap{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);
box-shadow:var(--shadow);padding:16px;margin:14px 0;text-align:center}
.target-wrap svg{max-width:560px}
.tg-ring{fill:none;stroke:rgba(127,127,127,.25)}
.tg-ringlab{font-size:10px;fill:var(--muted)}
.tg-dotlab{font-size:9px;fill:var(--text)}
.tg-center{font-weight:800;fill:#fff}
.legend{display:flex;gap:14px;flex-wrap:wrap;justify-content:center;font-size:.8rem;color:var(--muted);margin:8px 0}
.legend .k{display:inline-block;width:11px;height:11px;border-radius:50%;margin-right:5px;vertical-align:middle}
"""


def _shortest(result):
    return [f for f in (result.actionable if result else [])
            if f.category == Category.SHORTEST_PATH]


def _rings(paths, per_ring: int = 12, max_total: int = 40):
    """{depth: [(name, sev), ...]} + truncated count. Dedup principal→closest depth."""
    closest: dict[str, tuple[int, str]] = {}
    for f in paths:
        d = int(f.details.get("depth", 1) or 1)
        nm = f.principal_name
        if nm not in closest or d < closest[nm][0]:
            closest[nm] = (d, _sev(f))
    rings: dict[int, list] = {}
    for nm, (d, s) in closest.items():
        rings.setdefault(d, []).append((nm, s))
    truncated = 0
    for d in sorted(rings):
        if len(rings[d]) > per_ring:
            truncated += len(rings[d]) - per_ring
            rings[d] = rings[d][:per_ring]
    return rings, truncated


def build_target_html(result, domain: str = "", style: int = 1, generated: str | None = None) -> str:
    if style not in _THEME_VARS:
        style = 1
    ts = generated or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    title = domain or getattr(result, "domain", "") or "unknown realm"
    paths = _shortest(result)
    css = f":root{{{_THEME_VARS[style]}}}\n" + _BASE_CSS + _CSS
    o = ["<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>",
         "<meta name='viewport' content='width=device-width,initial-scale=1'>",
         f"<title>LazyHound Tier-Zero Bullseye — {_e(title)}</title>",
         f"<style>{css}</style></head><body class='style-{style}'><div class='wrap'>",
         f"<header class='rpt'><h1>Tier-Zero Bullseye</h1><div class='sub'>{_e(title)} · "
         f"generated {_e(ts)} · rings = hops to Tier Zero</div></header>"]
    if not paths:
        o.append("<p class='muted'>No attack paths to Tier Zero were found.</p></div></body></html>")
        return "\n".join(o)

    rings, trunc = _rings(paths)
    maxd = max(rings)
    size = 560
    cx = cy = size / 2
    step = (size * 0.42) / maxd
    from lazyhound.finder.reports import svg
    body = [svg.svg_open(size, size, "tg-svg")]
    for d in range(1, maxd + 1):
        rr = step * d
        body.append(f"<circle class='tg-ring' cx='{cx}' cy='{cy}' r='{rr:.1f}'/>")
        body.append(f"<text x='{cx}' y='{cy - rr - 4:.1f}' text-anchor='middle' "
                    f"class='tg-ringlab'>{d} hop(s)</text>")
    for d, people in rings.items():
        rr = step * d
        for i, (nm, s) in enumerate(people):
            ang = math.radians(360 * i / max(1, len(people)))
            x = cx + rr * math.sin(ang)
            y = cy - rr * math.cos(ang)
            body.append(f"<circle cx='{x:.1f}' cy='{y:.1f}' r='5' fill='{_SEV_COLOR.get(s, '#888')}'/>")
            body.append(f"<text x='{x:.1f}' y='{y - 8:.1f}' text-anchor='middle' "
                        f"class='tg-dotlab'>{_e(nm)}</text>")
    body.append(f"<circle cx='{cx}' cy='{cy}' r='26' fill='{_SEV_COLOR.get('critical', '#e5484d')}'/>")
    body.append(f"<text x='{cx}' y='{cy}' text-anchor='middle' dominant-baseline='central' "
                f"class='tg-center'>🎯</text>")
    body.append(f"<text x='{cx}' y='{cy + 40}' text-anchor='middle' class='tg-ringlab'>Tier Zero</text>")
    body.append(svg.svg_close())
    o.append(f"<div class='target-wrap'>{''.join(body)}</div>")
    o.append("<div class='legend'>" + "".join(
        f"<span><span class='k' style='background:{_SEV_COLOR[s]}'></span>{s.capitalize()}</span>"
        for s in _SEV_ORDER if any(sv == s for ppl in rings.values() for _, sv in ppl)) + "</div>")
    if trunc:
        o.append(f"<p class='muted'>…{trunc} principal(s) hidden (ring cap).</p>")
    o.append("</div></body></html>")
    return "\n".join(o)


def build_target_markdown(result, domain: str = "") -> str:
    title = domain or getattr(result, "domain", "") or "unknown"
    paths = _shortest(result)
    lines = [f"# Tier-Zero Bullseye — {title}", ""]
    if not paths:
        lines.append("_No attack paths to Tier Zero were found._")
        return "\n".join(lines)
    rings, _ = _rings(paths)
    for d in sorted(rings):
        names = ", ".join(nm for nm, _ in rings[d])
        lines.append(f"- **{d} hop(s):** {names}")
    return "\n".join(lines)
