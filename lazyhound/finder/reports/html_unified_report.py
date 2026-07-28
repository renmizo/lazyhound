"""Self-contained HTML report — fuses attack paths (Map) with posture findings
(Assess). Offline (no external CDN/fonts): all CSS/JS is inline.

Composable sections (``--sections``): render any subset in any order.
  title    — header block (report name, realm, timestamp, style)
  summary  — count cards + clickable severity-filter chips
  matrix   — a table of finding types (categories) with per-severity counts
  paths    — attack paths to Tier Zero
  findings — every finding as a drill-down card, JS-paginated

Findings use native ``<details>`` and progressive-enhancement JS pagination:
without JS every finding is shown, so PDF export via WeasyPrint renders in full.
Five visual styles; style 1 is a modern, clean light theme.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone

ALL_SECTIONS = ["title", "summary", "matrix", "paths", "findings"]

# Severity ordering (critical first) and fixed accent colors.
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_COLOR = {
    "critical": "#e5484d", "high": "#f76808", "medium": "#f5a623",
    "low": "#3b82f6", "info": "#8b93a7",
}

STYLES = {
    1: "Modern (clean light)",
    2: "Midnight (modern dark)",
    3: "Corporate (formal deliverable)",
    4: "Minimal (print / high-contrast)",
    5: "Terminal (monospace green)",
}

# Per-style CSS variables layered onto the shared base stylesheet.
_THEME_VARS = {
    1: """--bg:#f6f7f9;--panel:#ffffff;--text:#1a1d21;--muted:#5b6472;
--accent:#4f46e5;--border:#e6e8ec;--radius:12px;--shadow:0 1px 3px rgba(16,24,40,.08),0 1px 2px rgba(16,24,40,.06);
--font:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;--hfont:var(--font);""",
    2: """--bg:#0f1117;--panel:#171a22;--text:#e6e8ee;--muted:#9aa3b2;
--accent:#7c5cff;--border:#242835;--radius:12px;--shadow:0 1px 2px rgba(0,0,0,.5);
--font:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;--hfont:var(--font);""",
    3: """--bg:#eef1f5;--panel:#ffffff;--text:#20303f;--muted:#5a6b7b;
--accent:#1f3a5f;--border:#cfd8e3;--radius:4px;--shadow:0 1px 2px rgba(31,58,95,.12);
--font:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;--hfont:Georgia,'Times New Roman',serif;""",
    4: """--bg:#ffffff;--panel:#ffffff;--text:#000000;--muted:#333333;
--accent:#000000;--border:#000000;--radius:0;--shadow:none;
--font:Helvetica,Arial,sans-serif;--hfont:var(--font);""",
    5: """--bg:#000000;--panel:#050b06;--text:#33ff66;--muted:#1f9c47;
--accent:#33ff66;--border:#155e2e;--radius:0;--shadow:none;
--font:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;--hfont:var(--font);""",
}

_BASE_CSS = """
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:var(--font);
line-height:1.5;font-size:15px}
.wrap{max-width:1040px;margin:0 auto;padding:32px 20px 80px}
h1,h2,h3{font-family:var(--hfont);line-height:1.25;margin:0 0 .4em}
h1{font-size:1.9rem}h2{font-size:1.25rem;margin-top:2rem}
a{color:var(--accent)}
header.rpt{border-bottom:1px solid var(--border);padding-bottom:18px;margin-bottom:8px}
header.rpt .sub{color:var(--muted);font-size:.9rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}
.card{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);
box-shadow:var(--shadow);padding:16px}
.card .num{font-size:1.8rem;font-weight:700}
.card .lbl{color:var(--muted);font-size:.8rem;text-transform:uppercase;letter-spacing:.04em}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0}
.chip{cursor:pointer;user-select:none;border:1px solid var(--border);background:var(--panel);
border-radius:999px;padding:6px 14px;font-size:.85rem;font-weight:600;color:var(--text)}
.chip[aria-pressed=true]{outline:2px solid var(--accent);outline-offset:1px}
.chip .dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;vertical-align:middle}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);
border-radius:var(--radius);overflow:hidden;font-size:.9rem}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top}
th{background:rgba(127,127,127,.08);font-size:.78rem;text-transform:uppercase;letter-spacing:.03em;color:var(--muted)}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
tr:last-child td{border-bottom:none}
tr.total td{font-weight:700;border-top:2px solid var(--border)}
.pill{display:inline-block;min-width:20px;text-align:center;border-radius:6px;padding:1px 7px;
color:#fff;font-weight:700;font-size:.8rem}
.finding{background:var(--panel);border:1px solid var(--border);border-left:4px solid var(--sev);
border-radius:var(--radius);box-shadow:var(--shadow);margin:10px 0}
.finding>summary{cursor:pointer;list-style:none;padding:12px 16px;display:flex;align-items:center;gap:10px}
.finding>summary::-webkit-details-marker{display:none}
.finding>summary::after{content:'▸';margin-left:auto;color:var(--muted)}
.finding[open]>summary::after{content:'▾'}
.badge{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.03em;
color:#fff;background:var(--sev);border-radius:6px;padding:2px 8px;white-space:nowrap}
.finding .title{font-weight:600}
.finding .cat{color:var(--muted);font-size:.8rem}
.finding .body{padding:0 16px 16px;border-top:1px solid var(--border);margin-top:2px}
.finding .body p{margin:12px 0}
.tz{color:var(--sev-high);font-weight:600}
.aff{font-family:var(--font);font-size:.85rem;color:var(--muted);word-break:break-word}
.pager{display:flex;gap:8px;align-items:center;justify-content:center;margin:22px 0}
.pager button{cursor:pointer;border:1px solid var(--border);background:var(--panel);color:var(--text);
border-radius:8px;padding:6px 12px}
.pager button:disabled{opacity:.4;cursor:default}
.muted{color:var(--muted)}
footer.rpt{margin-top:40px;color:var(--muted);font-size:.8rem;border-top:1px solid var(--border);padding-top:14px}
@media print{
  .chips,.pager{display:none!important}
  .finding{break-inside:avoid;box-shadow:none}
  .finding .body{display:block!important}
  body{background:#fff}
}
"""

_PAGINATION_JS = """
(function(){
  var PAGE=12, list=document.getElementById('findings-list');
  if(!list) return;
  var all=[].slice.call(list.querySelectorAll('.finding'));
  var filter='all', page=1;
  function shown(){return all.filter(function(el){return filter==='all'||el.dataset.sev===filter;});}
  function render(){
    var items=shown(), pages=Math.max(1,Math.ceil(items.length/PAGE));
    if(page>pages)page=pages;
    all.forEach(function(el){el.style.display='none';});
    items.slice((page-1)*PAGE,page*PAGE).forEach(function(el){el.style.display='';});
    var info=document.getElementById('pg-info');
    if(info)info.textContent='Page '+page+' / '+pages+'  ·  '+items.length+' finding(s)';
    var pv=document.getElementById('pg-prev'),nx=document.getElementById('pg-next');
    if(pv)pv.disabled=page<=1; if(nx)nx.disabled=page>=pages;
  }
  var pv=document.getElementById('pg-prev'),nx=document.getElementById('pg-next');
  if(pv)pv.onclick=function(){page--;render();};
  if(nx)nx.onclick=function(){page++;render();};
  [].slice.call(document.querySelectorAll('.chip[data-filter]')).forEach(function(c){
    c.onclick=function(){
      var f=c.dataset.filter;
      filter=(f===filter)?'all':f;
      document.querySelectorAll('.chip[data-filter]').forEach(function(x){
        x.setAttribute('aria-pressed', (x.dataset.filter===filter)?'true':'false');});
      page=1; render();
    };
  });
  render();
})();
"""


def _e(v) -> str:
    return html.escape(str(v), quote=True)


def _scan_findings(scan_result) -> list:
    if not scan_result:
        return []
    return [f for cr in scan_result.check_results for f in cr.findings]


def _paths(analysis_result) -> list:
    if not analysis_result:
        return []
    from lazyhound.finder.collect.analyzer import Category
    return [f for f in analysis_result.findings if f.category == Category.SHORTEST_PATH]


def _sev_of(f) -> str:
    return getattr(f.severity, "value", str(f.severity))


def normalize_sections(sections) -> list[str]:
    """Return a valid ordered section list; None/empty/'all' -> every section."""
    if not sections:
        return list(ALL_SECTIONS)
    if isinstance(sections, str):
        sections = [s.strip() for s in sections.split(",")]
    picked = [s.strip().lower() for s in sections if s and str(s).strip()]
    if any(s == "all" for s in picked):
        return list(ALL_SECTIONS)
    ordered = [s for s in picked if s in ALL_SECTIONS]
    return ordered or list(ALL_SECTIONS)


def build_unified_html(scan_result, analysis_result, domain: str = "",
                       style: int = 1, expanded: bool = False,
                       generated: str | None = None, sections=None) -> str:
    """Return a complete, self-contained HTML report document."""
    if style not in _THEME_VARS:
        style = 1
    secs = normalize_sections(sections)

    findings = _scan_findings(scan_result)
    paths = _paths(analysis_result)
    reachable = [f for f in findings if f.details.get("reaches_tier_zero")]
    ts = generated or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    sev_counts = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        sev_counts[_sev_of(f)] = sev_counts.get(_sev_of(f), 0) + 1

    # ---- section renderers -------------------------------------------------
    def sec_title() -> list[str]:
        return [
            "<header class='rpt'><h1>LazyHound Report</h1>",
            f"<div class='sub'>{_e(domain or 'unknown realm')} · generated {_e(ts)} · "
            f"style {style} ({_e(STYLES[style])})</div></header>",
        ]

    def sec_summary() -> list[str]:
        o = ["<h2>Summary</h2><div class='grid'>",
             f"<div class='card'><div class='num'>{len(findings)}</div>"
             "<div class='lbl'>Posture findings</div></div>",
             f"<div class='card'><div class='num'>{len(paths)}</div>"
             "<div class='lbl'>Attack paths to Tier Zero</div></div>",
             f"<div class='card'><div class='num'>{len(reachable)}</div>"
             "<div class='lbl'>Findings reaching Tier Zero</div></div>",
             f"<div class='card'><div class='num' style='color:var(--sev-critical)'>{sev_counts['critical']}</div>"
             "<div class='lbl'>Critical</div></div>", "</div>", "<div class='chips'>"]
        for s in _SEV_ORDER:
            o.append(f"<span class='chip' role='button' data-filter='{s}' aria-pressed='false'>"
                     f"<span class='dot' style='background:{_SEV_COLOR[s]}'></span>"
                     f"{s.capitalize()} · {sev_counts.get(s,0)}</span>")
        o.append("</div>")
        return o

    def sec_matrix() -> list[str]:
        # Rows = finding categories (types) with per-severity counts.
        by_cat: dict[str, dict] = {}
        for f in findings:
            label = getattr(f.category, "label", getattr(f.category, "value", str(f.category)))
            row = by_cat.setdefault(label, {"total": 0, **{s: 0 for s in _SEV_ORDER}})
            row["total"] += 1
            row[_sev_of(f)] += 1
        o = ["<h2>Findings Matrix</h2><table><thead><tr><th>Type</th><th class='n'>Total</th>"]
        for s in _SEV_ORDER:
            o.append(f"<th class='n'>{s.capitalize()}</th>")
        o.append("</tr></thead><tbody>")
        if not by_cat and not paths:
            o.append("<tr><td class='muted' colspan='7'>No findings.</td></tr>")
        for label, row in sorted(by_cat.items(), key=lambda kv: -kv[1]["total"]):
            cells = "".join(
                f"<td class='n'>{('<span class=pill style=background:'+_SEV_COLOR[s]+'>'+str(row[s])+'</span>') if row[s] else ''}</td>"
                for s in _SEV_ORDER)
            o.append(f"<tr><td>{_e(label)}</td><td class='n'>{row['total']}</td>{cells}</tr>")
        if paths:
            o.append(f"<tr><td>Attack Paths → Tier Zero</td><td class='n'>{len(paths)}</td>"
                     "<td class='n' colspan='5'></td></tr>")
        # totals row
        tot = {s: sum(r[s] for r in by_cat.values()) for s in _SEV_ORDER}
        o.append(f"<tr class='total'><td>Total</td><td class='n'>{len(findings)}</td>"
                 + "".join(f"<td class='n'>{tot[s] or ''}</td>" for s in _SEV_ORDER) + "</tr>")
        o.append("</tbody></table>")
        return o

    def sec_paths() -> list[str]:
        o = ["<h2>Attack Paths to Tier Zero</h2>"]
        if paths:
            o.append("<table><thead><tr><th>Source</th><th class='n'>Hops</th><th>Target</th><th>Path</th></tr></thead><tbody>")
            for p in sorted(paths, key=lambda x: x.details.get("depth", 99))[:100]:
                path_str = " → ".join(p.details.get("path_names", []) or [p.principal_name])
                o.append(f"<tr><td>{_e(p.principal_name)}</td><td class='n'>{_e(p.details.get('depth',''))}</td>"
                         f"<td>{_e(p.target_name)}</td><td class='aff'>{_e(path_str)}</td></tr>")
            o.append("</tbody></table>")
            if len(paths) > 100:
                o.append(f"<p class='muted'>…and {len(paths)-100} more paths.</p>")
        else:
            o.append("<p class='muted'>None found.</p>")
        return o

    def sec_findings() -> list[str]:
        o = ["<h2>Findings</h2><div id='findings-list'>"]

        def sort_key(f):
            return (0 if f.details.get("reaches_tier_zero") else 1,
                    f.details.get("tier_zero_hops", 99), f.severity.sort_order)

        if not findings:
            o.append("<p class='muted'>No posture findings.</p>")
        for f in sorted(findings, key=sort_key):
            sev = _sev_of(f)
            cat = getattr(f.category, "value", str(f.category))
            openattr = " open" if expanded else ""
            o.append(f"<details class='finding' data-sev='{_e(sev)}' "
                     f"style='--sev:{_SEV_COLOR.get(sev, '#8b93a7')}'{openattr}>")
            tz = ""
            if f.details.get("reaches_tier_zero"):
                tz = f"<span class='tz'>⚠ reaches Tier Zero in {_e(f.details.get('tier_zero_hops'))} hop(s)</span>"
            o.append("<summary>"
                     f"<span class='badge'>{_e(sev)}</span>"
                     f"<span class='title'>{_e(f.title)}</span> "
                     f"<span class='cat'>{_e(cat)}</span> {tz}</summary>")
            o.append("<div class='body'>")
            if f.description:
                o.append(f"<p>{_e(f.description)}</p>")
            aff = f.affected_objects or []
            if aff:
                shown = ", ".join(_e(a) for a in aff[:15])
                more = f" <span class='muted'>(+{len(aff)-15} more)</span>" if len(aff) > 15 else ""
                o.append(f"<p class='aff'><strong>Affected ({len(aff)}):</strong> {shown}{more}</p>")
            rem = getattr(f, "remediation", None)
            if rem is not None:
                rtext = getattr(rem, "summary", None) or getattr(rem, "description", None) or str(rem)
                o.append(f"<p><strong>Remediation:</strong> {_e(rtext)}</p>")
            o.append("</div></details>")
        o.append("</div>")
        o.append("<nav class='pager'><button id='pg-prev'>‹ Prev</button>"
                 "<span id='pg-info' class='muted'></span>"
                 "<button id='pg-next'>Next ›</button></nav>")
        return o

    renderers = {"title": sec_title, "summary": sec_summary, "matrix": sec_matrix,
                 "paths": sec_paths, "findings": sec_findings}

    css = (f":root{{{_THEME_VARS[style]}}}\n"
           f":root{{--sev-critical:{_SEV_COLOR['critical']};--sev-high:{_SEV_COLOR['high']};"
           f"--sev-medium:{_SEV_COLOR['medium']};--sev-low:{_SEV_COLOR['low']};--sev-info:{_SEV_COLOR['info']};}}\n"
           + _BASE_CSS)

    out: list[str] = [
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>LazyHound Report — {_e(domain or 'report')}</title>",
        f"<style>{css}</style></head>",
        f"<body class='style-{style}'><div class='wrap'>",
    ]
    for name in secs:
        out += renderers[name]()
    out.append("<footer class='rpt'>Generated by LazyHound · offline report · "
               f"sections: {_e(', '.join(secs))} · {len(findings)} findings · "
               f"{len(paths)} attack paths</footer>")
    out.append("</div>")
    out.append(f"<script>{_PAGINATION_JS}</script>")
    out.append("</body></html>")
    return "\n".join(out)
