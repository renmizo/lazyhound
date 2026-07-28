"""HTML report for offline analysis results with severity charts."""

from __future__ import annotations

import html as _html
import json
from pathlib import Path

from ..collect.analyzer import AnalysisResult, Severity
from .chartjs import chartjs_script_tag
from .findings_report import generate_findings_report


_GRADE_TO_RATING = {"A": "Excellent", "B": "Good", "C": "Fair", "D": "Poor", "F": "Absent"}

_SEVERITY_COLORS = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "info": "#0d6efd",
}


def _e(text: str) -> str:
    return _html.escape(str(text))


class HTMLAnalysisReport:
    """Generate a self-contained HTML report from offline analysis."""

    @staticmethod
    def to_string(result: AnalysisResult, *, show_builtin: bool = False) -> str:
        return _render(result, show_builtin=show_builtin)

    @staticmethod
    def write(result: AnalysisResult, path: str | Path, *,
              show_builtin: bool = False) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(_render(result, show_builtin=show_builtin), encoding="utf-8")
        return p


def _render(result: AnalysisResult, *, show_builtin: bool = False) -> str:
    report = generate_findings_report(result, show_builtin=show_builtin)

    # Chart data
    sev_labels = json.dumps(list(report["severity_breakdown"].keys()))
    sev_counts = json.dumps(list(report["severity_breakdown"].values()))
    sev_colors = json.dumps([
        _SEVERITY_COLORS.get(s, "#6c757d")
        for s in report["severity_breakdown"]
    ])

    cat_labels = json.dumps(list(report["category_breakdown"].keys()))
    cat_counts = json.dumps([
        v["count"] for v in report["category_breakdown"].values()
    ])

    grade_class = {
        "A": "grade-a", "B": "grade-b", "C": "grade-c",
        "D": "grade-d", "F": "grade-f",
    }.get(report["grade"], "")

    findings_html = _render_findings(result, show_builtin)
    paths_html = _render_attack_paths(report)
    remediation_html = _render_remediation(report)

    domain = _e(report.get("domain") or "Unknown")
    chartjs_tag = chartjs_script_tag()

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LazyHound Analysis Report — {domain}</title>
{chartjs_tag}
<style>
:root {{
  --bg: #1a1a2e; --surface: #16213e; --card: #0f3460;
  --text: #e0e0e0; --text-dim: #a0a0a0; --accent: #53c0f0;
  --critical: #dc3545; --high: #fd7e14; --medium: #ffc107; --info: #0d6efd;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg);
       color: var(--text); line-height: 1.6; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 2rem 1rem; }}
.header {{ text-align: center; margin-bottom: 2rem; }}
.header h1 {{ font-size: 1.8rem; margin-bottom: 0.5rem; }}
.header .domain {{ color: var(--accent); font-size: 1.2rem; }}
.scorecard {{ display: flex; gap: 1.5rem; flex-wrap: wrap; justify-content: center;
              margin: 2rem 0; }}
.scorecard .card {{ background: var(--surface); border-radius: 10px; padding: 1.5rem;
                    text-align: center; min-width: 150px; flex: 1; max-width: 200px; }}
.scorecard .card .value {{ font-size: 2rem; font-weight: 700; }}
.scorecard .card .label {{ font-size: 0.85rem; color: var(--text-dim); }}
.grade-a .value {{ color: #28a745; }} .grade-b .value {{ color: #5cb85c; }}
.grade-c .value {{ color: #ffc107; }} .grade-d .value {{ color: #fd7e14; }}
.grade-f .value {{ color: #dc3545; }}
.charts {{ display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin: 2rem 0; }}
.chart-box {{ background: var(--surface); border-radius: 10px; padding: 1.5rem; }}
.chart-box h3 {{ margin-bottom: 1rem; font-size: 1rem; }}
@media (max-width: 768px) {{ .charts {{ grid-template-columns: 1fr; }} }}
section {{ margin-top: 2rem; }}
section h2 {{ margin-bottom: 1rem; }}
.finding {{ background: var(--surface); border-radius: 8px; padding: 1.2rem;
            margin-bottom: 0.8rem; border-left: 4px solid var(--info); }}
.finding.critical {{ border-left-color: var(--critical); }}
.finding.high {{ border-left-color: var(--high); }}
.finding.medium {{ border-left-color: var(--medium); }}
.finding .f-header {{ display: flex; justify-content: space-between; align-items: center;
                      margin-bottom: 0.5rem; }}
.finding .f-title {{ font-weight: 600; }}
.badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.75rem;
          font-weight: 600; text-transform: uppercase; }}
.badge.critical {{ background: var(--critical); color: #fff; }}
.badge.high {{ background: var(--high); color: #fff; }}
.badge.medium {{ background: var(--medium); color: #111; }}
.badge.info {{ background: var(--info); color: #fff; }}
.finding .desc {{ color: var(--text-dim); font-size: 0.9rem; }}
.path-item {{ background: var(--surface); border-radius: 8px; padding: 1rem;
              margin-bottom: 0.5rem; font-size: 0.9rem; }}
.path-item code {{ background: var(--card); padding: 2px 6px; border-radius: 3px; }}
.remediation {{ background: var(--surface); border-radius: 8px; padding: 1rem;
                margin-bottom: 0.5rem; }}
.remediation .cat {{ font-weight: 600; color: var(--accent); }}
.footer {{ text-align: center; color: var(--text-dim); font-size: 0.8rem; margin-top: 3rem; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>LazyHound Analysis Report</h1>
    <div class="domain">{domain}</div>
  </div>

  <div class="scorecard">
    <div class="card {grade_class}">
      <div class="value">{_GRADE_TO_RATING.get(report['grade'], report['grade'])}</div>
      <div class="label">Rating</div>
    </div>
    <div class="card">
      <div class="value">{report['total_findings']}</div>
      <div class="label">Total Findings</div>
    </div>
    <div class="card">
      <div class="value">{report['total_actionable']}</div>
      <div class="label">Actionable</div>
    </div>
    <div class="card">
      <div class="value">{report['severity_breakdown'].get('critical', 0)}</div>
      <div class="label">Critical</div>
    </div>
  </div>

  <div class="charts">
    <div class="chart-box">
      <h3>Findings by Severity</h3>
      <canvas id="sevChart"></canvas>
    </div>
    <div class="chart-box">
      <h3>Findings by Category</h3>
      <canvas id="catChart"></canvas>
    </div>
  </div>

  {paths_html}
  {findings_html}
  {remediation_html}

  <div class="footer">Report generated by LazyHound</div>
</div>
<script>
new Chart(document.getElementById('sevChart'), {{
  type: 'doughnut',
  data: {{
    labels: {sev_labels},
    datasets: [{{ data: {sev_counts}, backgroundColor: {sev_colors} }}]
  }},
  options: {{ responsive: true, plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#e0e0e0' }} }} }} }}
}});
new Chart(document.getElementById('catChart'), {{
  type: 'bar',
  data: {{
    labels: {cat_labels},
    datasets: [{{ label: 'Findings', data: {cat_counts}, backgroundColor: '#53c0f0' }}]
  }},
  options: {{
    responsive: true, indexAxis: 'y',
    scales: {{ x: {{ ticks: {{ color: '#a0a0a0' }} }}, y: {{ ticks: {{ color: '#a0a0a0' }} }} }},
    plugins: {{ legend: {{ display: false }} }}
  }}
}});
</script>
</body>
</html>"""


def _render_findings(result: AnalysisResult, show_builtin: bool) -> str:
    findings = result.findings if show_builtin else result.actionable
    if not findings:
        return '<section><h2>No findings</h2></section>'

    # Sort by severity
    sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.INFO: 3}
    findings = sorted(findings, key=lambda f: sev_order.get(f.severity, 99))

    parts = [f'<section><h2>Findings ({len(findings)})</h2>']
    for f in findings:
        sc = f.severity.value
        desc = f.description
        parts.append(f'<div class="finding {sc}">')
        parts.append(f'<div class="f-header">'
                     f'<span class="f-title">{_e(f.category.value)}: {_e(desc[:120])}</span>'
                     f'<span class="badge {sc}">{_e(sc)}</span></div>')
        if f.principal_name:
            parts.append(f'<div class="desc">Principal: <code>{_e(f.principal_name)}</code></div>')
        if f.target_name:
            parts.append(f'<div class="desc">Target: <code>{_e(f.target_name)}</code></div>')
        parts.append('</div>')
    parts.append('</section>')
    return "\n".join(parts)


def _render_attack_paths(report: dict) -> str:
    paths = report.get("attack_paths", [])
    if not paths:
        return ""

    parts = ['<section><h2>Top Attack Paths</h2>']
    for i, p in enumerate(paths, 1):
        names = p.get("path", [])
        edges = p.get("edges", [])
        if edges:
            chain_parts = [_e(names[0])] if names else []
            for j, name in enumerate(names[1:]):
                edge = edges[j] if j < len(edges) else ""
                if edge:
                    chain_parts.append(f'<span class="edge">[{_e(edge)}]</span>&rarr; {_e(name)}')
                else:
                    chain_parts.append(f"&rarr; {_e(name)}")
            chain = " ".join(chain_parts)
        else:
            chain = " &rarr; ".join(_e(n) for n in names)
        parts.append(
            f'<div class="path-item">'
            f'<strong>{i}.</strong> [{_e(p["severity"].upper())}] '
            f'<code>{_e(p["from"])}</code> &rarr; <code>{_e(p["to"])}</code> '
            f'({p["depth"]} hops)<br>{chain}</div>'
        )
    parts.append('</section>')
    return "\n".join(parts)


def _render_remediation(report: dict) -> str:
    priorities = report.get("remediation_priorities", [])
    if not priorities:
        return ""

    parts = ['<section><h2>Remediation Priorities</h2>']
    for i, p in enumerate(priorities, 1):
        parts.append(
            f'<div class="remediation">'
            f'<span class="cat">{i}. {_e(p["category"])}</span> '
            f'<span class="badge {p["severity"]}">{_e(p["severity"])}</span> '
            f'— {p["finding_count"]} findings, {p["affected_objects"]} objects<br>'
            f'{_e(p["remediation"])}</div>'
        )
    parts.append('</section>')
    return "\n".join(parts)
