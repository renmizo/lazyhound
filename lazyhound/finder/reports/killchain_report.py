"""Kill-Chain Flow report (report run --type killchain).

A left→right SVG flow of the ATT&CK tactics present in the findings, ending in
a Tier Zero goal. Stage height ∝ finding count, segmented by severity; ribbons
express kill-chain progression (a flow/funnel, NOT a strict data-conserving
Sankey). Pure SVG — offline & PDF-safe.
"""
from __future__ import annotations

from datetime import datetime, timezone

from lazyhound.finder.reports.html_unified_report import (
    STYLES, _THEME_VARS, _BASE_CSS, _SEV_COLOR, _e)
from lazyhound.finder.reports.attackpaths_report import _collect, _TTPS, _sev, _SEV_ORDER
from lazyhound.finder.reports import svg

# Canonical kill-chain order (AD-relevant subset).
_ORDER = ["Initial Access", "Execution", "Persistence", "Privilege Escalation",
          "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
          "Collection", "Command and Control", "Exfiltration", "Impact"]

_CSS = """
.kc-wrap{overflow-x:auto;background:var(--panel);border:1px solid var(--border);
border-radius:var(--radius);padding:16px;margin:14px 0}
.kc-note{color:var(--muted);font-size:.82rem;margin:6px 0}
.legend{display:flex;gap:14px;flex-wrap:wrap;font-size:.8rem;color:var(--muted);margin:8px 0}
.legend .k{display:inline-block;width:11px;height:11px;border-radius:3px;margin-right:5px;vertical-align:middle}
.kc-stage-lab{font-size:10px;fill:var(--text);font-weight:600}
.kc-cnt{font-size:12px;fill:var(--text);font-weight:800}
"""


def _tactic_sev_counts(tech):
    """{tactic: {sev: count}} for present tactics."""
    out: dict = {}
    for cat, fs in tech.items():
        for tac in _TTPS[cat].tactic.split("/"):
            tac = tac.strip()
            d = out.setdefault(tac, {s: 0 for s in _SEV_ORDER})
            for f in fs:
                d[_sev(f)] = d.get(_sev(f), 0) + 1
    return out


def build_killchain_html(result, domain: str = "", style: int = 1, generated: str | None = None) -> str:
    if style not in _THEME_VARS:
        style = 1
    ts = generated or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    title = domain or getattr(result, "domain", "") or "unknown realm"
    findings, paths, tech = _collect(result)
    tsc = _tactic_sev_counts(tech)
    stages = [(t, tsc[t]) for t in _ORDER if t in tsc]

    css = f":root{{{_THEME_VARS[style]}}}\n" + _BASE_CSS + _CSS
    o = ["<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>",
         "<meta name='viewport' content='width=device-width,initial-scale=1'>",
         f"<title>LazyHound Kill-Chain Flow — {_e(title)}</title>",
         f"<style>{css}</style></head><body class='style-{style}'><div class='wrap'>",
         f"<header class='rpt'><h1>Kill-Chain Flow</h1><div class='sub'>{_e(title)} · "
         f"generated {_e(ts)}</div></header>",
         "<p class='kc-note'>A flow of the ATT&amp;CK tactics present in the findings toward "
         "Tier Zero. Band size reflects finding volume &mdash; this is a kill-chain "
         "<em>flow/funnel</em>, not a strict data-conserving Sankey.</p>"]
    if not stages:
        o.append("<p class='muted'>No technique-mapped findings to chart.</p></div></body></html>")
        return "\n".join(o)

    COLW, GAP, MAXH, top = 120, 90, 240, 40
    scale = MAXH / max(sum(d.values()) for _, d in stages)
    n = len(stages)
    W = n * (COLW + GAP) + 170
    H = MAXH + 90
    body = [svg.svg_open(W, H, "kc-svg")]
    cx = 20
    centers = []
    for tac, d in stages:
        total = sum(d.values())
        h = max(10, total * scale)
        y = top + (MAXH - h)
        if centers:
            px, py, ph = centers[-1]
            body.append(svg.ribbon(px + COLW, py, ph, cx, y, h, _SEV_COLOR.get("high", "#f5871f")))
        yy = y
        for s in _SEV_ORDER:
            if d.get(s):
                seg = d[s] * scale
                body.append(f"<rect x='{cx}' y='{yy:.1f}' width='{COLW}' height='{seg:.1f}' "
                            f"rx='4' fill='{_SEV_COLOR[s]}'/>")
                yy += seg
        body.append(f"<text x='{cx + COLW / 2}' y='{top + MAXH + 18}' text-anchor='middle' "
                    f"class='kc-stage-lab'>{_e(tac)}</text>")
        body.append(f"<text x='{cx + COLW / 2}' y='{y - 6:.1f}' text-anchor='middle' "
                    f"class='kc-cnt'>{total}</text>")
        centers.append((cx, y, h))
        cx += COLW + GAP
    px, py, ph = centers[-1]
    goalx = cx
    gy = top + MAXH / 2 - 30
    body.append(svg.ribbon(px + COLW, py, ph, goalx, gy, 60, _SEV_COLOR.get("critical", "#e5484d")))
    body.append(f"<rect x='{goalx}' y='{gy:.1f}' width='140' height='60' rx='8' "
                f"fill='{_SEV_COLOR.get('critical', '#e5484d')}'/>")
    body.append(f"<text x='{goalx + 70}' y='{gy + 24:.1f}' text-anchor='middle' "
                f"fill='#fff' font-weight='800'>🎯 Tier Zero</text>")
    body.append(f"<text x='{goalx + 70}' y='{gy + 44:.1f}' text-anchor='middle' "
                f"fill='#fff' font-size='11'>{len(paths)} path(s)</text>")
    body.append(svg.svg_close())
    o.append(f"<div class='kc-wrap'>{''.join(body)}</div>")
    o.append("<div class='legend'>" + "".join(
        f"<span><span class='k' style='background:{_SEV_COLOR[s]}'></span>{s.capitalize()}</span>"
        for s in _SEV_ORDER if any(d.get(s) for _, d in stages)) + "</div>")
    o.append("</div></body></html>")
    return "\n".join(o)


def build_killchain_markdown(result, domain: str = "") -> str:
    title = domain or getattr(result, "domain", "") or "unknown"
    findings, paths, tech = _collect(result)
    tsc = _tactic_sev_counts(tech)
    lines = [f"# Kill-Chain Flow — {title}", "",
             "_ATT&CK tactics present in the findings, in kill-chain order "
             "(flow/funnel, not a strict Sankey)._", "",
             "| Tactic | Findings |", "|---|---|"]
    for t in _ORDER:
        if t in tsc:
            lines.append(f"| {t} | {sum(tsc[t].values())} |")
    lines += ["", f"**→ 🎯 Tier Zero: {len(paths)} path(s)**"]
    return "\n".join(lines)
