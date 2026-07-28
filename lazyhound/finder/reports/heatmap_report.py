"""Standalone MITRE ATT&CK Heatmap report (``report run --type heatmap``).

Landscape-oriented — just the full ATT&CK Enterprise matrix, techniques
heat-colored by finding count. Pure CSS / offline; reuses the analyze findings
and the shared heatmap renderer.
"""
from __future__ import annotations

from datetime import datetime, timezone

from lazyhound.finder.reports.html_unified_report import (
    STYLES, _THEME_VARS, _BASE_CSS, _SEV_COLOR, _e,
)
from lazyhound.finder.reports.attackpaths_report import (
    _EXTRA_CSS, _collect, _heatmap_html, _technique_counts,
)
from lazyhound.finder.reports.attack_matrix import load_attack_matrix

# Full-width / landscape overrides + the pure-CSS toggles (no JavaScript):
#  #hm-only  — show only techniques/tactics with findings
#  #hm-mode  — colour by MAX SEVERITY instead of finding COUNT
_LANDSCAPE_CSS = """
.wrap{max-width:none}
@page{size:A4 landscape;margin:12mm}
@media print{.heatmap-wrap{overflow:visible}}
.hm-controls{display:flex;flex-wrap:wrap;gap:12px;margin:10px 0}
.hm-only-cb{position:absolute;opacity:0;width:0;height:0;pointer-events:none}
.hm-toggle{cursor:pointer;user-select:none;font-size:.85rem;font-weight:600;color:var(--text);
border:1px solid var(--border);border-radius:999px;padding:5px 14px;background:var(--panel)}
#hm-only:checked ~ .hm-controls label[for="hm-only"],
#hm-mode:checked ~ .hm-controls label[for="hm-mode"]{background:var(--accent);color:#fff;border-color:var(--accent)}
/* only-findings toggle */
#hm-only:checked ~ .heatmap-wrap .hm-cell.hm-empty{display:none}
#hm-only:checked ~ .heatmap-wrap .hm-col.hm-col-empty{display:none}
/* count-vs-severity toggle: recolour cells by severity when #hm-mode is on */
#hm-mode:checked ~ .heatmap-wrap .hm-cell.sev-info{background:#2f9e44;color:#08140b}
#hm-mode:checked ~ .heatmap-wrap .hm-cell.sev-low{background:#82c91e;color:#0f1a06}
#hm-mode:checked ~ .heatmap-wrap .hm-cell.sev-medium{background:#f2c744;color:#241c00}
#hm-mode:checked ~ .heatmap-wrap .hm-cell.sev-high{background:#f5871f;color:#fff}
#hm-mode:checked ~ .heatmap-wrap .hm-cell.sev-critical{background:#e5484d;color:#fff;font-weight:700}
/* swap the legend to match the active mode */
.hm-legend-sev{display:none}
#hm-mode:checked ~ .hm-legend-count{display:none}
#hm-mode:checked ~ .hm-legend-sev{display:flex}
"""


def _legends_html() -> str:
    def k(bg):
        return f"<span class='k' style='background:{bg}'></span>"
    count = ("<div class='hm-legend hm-legend-count'>"
             f"<span>{k('rgba(127,127,127,.06)')}0</span>"
             f"<span>{k('#2f9e44')}1&ndash;2</span>"
             f"<span>{k('#82c91e')}3&ndash;5</span>"
             f"<span>{k('#f2c744')}6&ndash;10</span>"
             f"<span>{k('#f5871f')}11&ndash;20</span>"
             f"<span>{k('#e5484d')}21+</span></div>")
    sev = ("<div class='hm-legend hm-legend-sev'>"
           f"<span>{k('#2f9e44')}Info</span>"
           f"<span>{k('#f2c744')}Medium</span>"
           f"<span>{k('#f5871f')}High</span>"
           f"<span>{k('#e5484d')}Critical</span></div>")
    return count + sev


def build_heatmap_html(result, domain: str = "", style: int = 1,
                       generated: str | None = None) -> str:
    if style not in _THEME_VARS:
        style = 1
    _findings, _paths, tech = _collect(result)
    ts = generated or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    title = domain or getattr(result, "domain", "") or "unknown realm"
    counts = _technique_counts(tech)
    n_tech, n_find = len(counts), sum(counts.values())

    css = (f":root{{{_THEME_VARS[style]}}}\n"
           f":root{{--sev-critical:{_SEV_COLOR['critical']};--sev-high:{_SEV_COLOR['high']};"
           f"--sev-medium:{_SEV_COLOR['medium']};--sev-low:{_SEV_COLOR['low']};--sev-info:{_SEV_COLOR['info']};}}\n"
           + _BASE_CSS + _EXTRA_CSS + _LANDSCAPE_CSS)

    o = ["<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>",
         "<meta name='viewport' content='width=device-width,initial-scale=1'>",
         f"<title>LazyHound ATT&amp;CK Heatmap — {_e(title)}</title>",
         f"<style>{css}</style></head><body class='style-{style}'><div class='wrap'>",
         f"<header class='rpt'><h1>MITRE ATT&amp;CK Heatmap</h1>"
         f"<div class='sub'>{_e(title)} · generated {_e(ts)} · "
         f"{n_tech} technique(s) with findings · {n_find} technique finding(s) · "
         f"style {style} ({_e(STYLES[style])})</div></header>",
         # Pure-CSS toggles: the inputs are siblings of the legends/heatmap so
         # the :checked rules can hide cells and swap colours. No JavaScript.
         "<input type='checkbox' id='hm-only' class='hm-only-cb'>"
         "<input type='checkbox' id='hm-mode' class='hm-only-cb'>"
         "<div class='hm-controls'>"
         "<label for='hm-only' class='hm-toggle'>▤ Show only techniques with findings</label>"
         "<label for='hm-mode' class='hm-toggle'>🎨 Colour by max severity (instead of count)</label>"
         "</div>",
         _legends_html(),
         _heatmap_html(tech, heading=False),
         "<footer class='rpt'>Generated by LazyHound · MITRE ATT&amp;CK Enterprise heatmap</footer>",
         "</div></body></html>"]
    return "\n".join(o)


def build_heatmap_markdown(result, domain: str = "") -> str:
    _findings, _paths, tech = _collect(result)
    title = domain or getattr(result, "domain", "") or "unknown"
    counts = _technique_counts(tech)
    lines = [f"# MITRE ATT&CK Heatmap — {title}", "",
             f"_{len(counts)} technique(s) with findings, {sum(counts.values())} "
             f"technique finding(s)._", "",
             "| Technique | Findings |", "|---|---|"]
    if counts:
        names = {t["id"]: t["name"] for tac in load_attack_matrix().get("tactics", [])
                 for t in tac["techniques"]}
        for tid, n in sorted(counts.items(), key=lambda kv: -kv[1]):
            lines.append(f"| {tid} {names.get(tid, '')} | {n} |")
    else:
        lines.append("| _none_ | 0 |")
    return "\n".join(lines)
