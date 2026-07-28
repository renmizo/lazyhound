"""HTML report with Chart.js visualizations."""

from __future__ import annotations

import html as _html
import json
from pathlib import Path

from lazyhound.finder.finder_models import CheckCategory, ScanResult, Severity
from lazyhound.finder.reports.chartjs import chartjs_script_tag

_SEVERITY_COLORS = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#28a745",
    "info": "#0d6efd",
}


class HTMLReport:
    """Generate a self-contained HTML report."""

    @staticmethod
    def to_string(result: ScanResult) -> str:
        return _render(result)

    @staticmethod
    def write(result: ScanResult, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(_render(result), encoding="utf-8")
        return p


def _e(text: str) -> str:
    return _html.escape(str(text))


def _render(r: ScanResult) -> str:
    by_sev = r.findings_by_severity()
    sev_labels = json.dumps([s.value.title() for s in Severity])
    sev_counts = json.dumps([len(by_sev[s]) for s in Severity])
    sev_colors = json.dumps([_SEVERITY_COLORS[s.value] for s in Severity])

    by_cat = r.findings_by_category()
    cat_labels = json.dumps([c.label for c in CheckCategory if c in by_cat])
    cat_counts = json.dumps([len(by_cat[c]) for c in CheckCategory if c in by_cat])

    findings_html = _render_findings(r)
    errors_html = _render_errors(r)

    grade_class = {
        "A": "grade-a", "B": "grade-b", "C": "grade-c",
        "D": "grade-d", "F": "grade-f",
    }.get(r.grade, "")

    chartjs_tag = chartjs_script_tag()

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LazyHound Report — {_e(r.target_domain)}</title>
{chartjs_tag}
<style>
:root {{
  --bg: #1a1a2e; --surface: #16213e; --card: #0f3460;
  --text: #e0e0e0; --text-dim: #a0a0a0; --accent: #53c0f0;
  --critical: #dc3545; --high: #fd7e14; --medium: #ffc107;
  --low: #28a745; --info: #0d6efd;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg);
       color: var(--text); line-height: 1.6; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 2rem 1rem; }}
.header {{ text-align: center; margin-bottom: 2rem; }}
.header h1 {{ font-size: 1.8rem; margin-bottom: 0.5rem; }}
.header .domain {{ color: var(--accent); font-size: 1.2rem; }}
.meta {{ display: flex; gap: 1rem; flex-wrap: wrap; justify-content: center;
         margin: 1rem 0; color: var(--text-dim); font-size: 0.9rem; }}
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
.findings {{ margin-top: 2rem; }}
.findings h2 {{ margin-bottom: 1rem; }}
.finding {{ background: var(--surface); border-radius: 8px; padding: 1.2rem;
            margin-bottom: 1rem; border-left: 4px solid var(--info); }}
.finding.critical {{ border-left-color: var(--critical); }}
.finding.high {{ border-left-color: var(--high); }}
.finding.medium {{ border-left-color: var(--medium); }}
.finding.low {{ border-left-color: var(--low); }}
.finding .f-header {{ display: flex; justify-content: space-between; align-items: center;
                      margin-bottom: 0.5rem; }}
.finding .f-title {{ font-weight: 600; }}
.finding .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.75rem;
                   font-weight: 600; text-transform: uppercase; }}
.badge.critical {{ background: var(--critical); color: #fff; }}
.badge.high {{ background: var(--high); color: #fff; }}
.badge.medium {{ background: var(--medium); color: #111; }}
.badge.low {{ background: var(--low); color: #fff; }}
.badge.info {{ background: var(--info); color: #fff; }}
.finding .desc {{ color: var(--text-dim); font-size: 0.9rem; }}
.finding .detail {{ font-size: 0.85rem; color: var(--text-dim); margin-top: 0.4rem; }}
.finding code {{ background: var(--card); padding: 2px 6px; border-radius: 3px; font-size: 0.85rem; }}
.errors {{ margin-top: 2rem; }}
.errors .error-item {{ background: #2a1a1a; border-radius: 8px; padding: 0.8rem 1.2rem;
                       margin-bottom: 0.5rem; font-size: 0.9rem; }}
.footer {{ text-align: center; color: var(--text-dim); font-size: 0.8rem; margin-top: 3rem; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>LazyHound Security Assessment</h1>
    <div class="domain">{_e(r.target_domain)}</div>
    <div class="meta">
      <span>Scan ID: {_e(r.scan_id)}</span>
      <span>Started: {r.started_at:%Y-%m-%d %H:%M:%S} UTC</span>
      <span>Duration: {r.duration_ms:.0f} ms</span>
    </div>
  </div>

  <div class="scorecard">
    <div class="card {grade_class}">
      <div class="value">{r.rating}</div>
      <div class="label">Rating</div>
    </div>
    <div class="card">
      <div class="value">{r.risk_score}</div>
      <div class="label">Blended Score (0-100)</div>
    </div>
    <div class="card">
      <div class="value">{r.health_pct:.0f}%</div>
      <div class="label">Healthy Objects</div>
    </div>
    <div class="card">
      <div class="value">{r.total_findings}</div>
      <div class="label">Findings</div>
    </div>
    <div class="card">
      <div class="value">{r.checks_passed}/{r.checks_passed + r.checks_failed}</div>
      <div class="label">Checks Passed</div>
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

  {findings_html}
  {errors_html}

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
    datasets: [{{ label: 'Findings', data: {cat_counts},
                  backgroundColor: '#53c0f0' }}]
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


def _render_findings(r: ScanResult) -> str:
    all_findings = []
    for cr in r.check_results:
        for f in cr.findings:
            all_findings.append(f)
    all_findings.sort(key=lambda f: f.severity.sort_order)

    if not all_findings:
        return '<div class="findings"><h2>No findings</h2></div>'

    parts = [f'<div class="findings"><h2>Findings ({len(all_findings)})</h2>']
    for f in all_findings:
        sc = f.severity.value
        parts.append(f'<div class="finding {sc}">')
        parts.append(f'<div class="f-header"><span class="f-title">[{_e(f.check_id)}] '
                      f'{_e(f.title)}</span><span class="badge {sc}">{_e(sc)}</span></div>')
        parts.append(f'<div class="desc">{_e(f.description)}</div>')
        if f.affected_objects:
            shown = ", ".join(f.affected_objects[:10])
            more = f" ... and {f.affected_count - 10} more" if f.affected_count > 10 else ""
            parts.append(f'<div class="detail">Affected ({f.affected_count}): '
                          f'<code>{_e(shown)}{_e(more)}</code></div>')
        if f.mitre:
            parts.append(f'<div class="detail">MITRE ATT&amp;CK: '
                          f'<a href="{_e(f.mitre.to_dict()["url"])}" style="color:var(--accent)">'
                          f'{_e(f.mitre.technique_id)} — {_e(f.mitre.technique_name)}</a></div>')
        if f.remediation:
            parts.append(f'<div class="detail"><strong>Fix:</strong> '
                          f'{_e(f.remediation.description)}</div>')
            if f.remediation.powershell:
                parts.append(f'<div class="detail"><code>PS&gt; '
                              f'{_e(f.remediation.powershell)}</code></div>')
        parts.append('</div>')
    parts.append('</div>')
    return "\n".join(parts)


def _render_errors(r: ScanResult) -> str:
    errors = [cr for cr in r.check_results if cr.error]
    if not errors:
        return ""
    parts = [f'<div class="errors"><h2>Errors ({len(errors)})</h2>']
    for cr in errors:
        parts.append(f'<div class="error-item"><strong>{_e(cr.check_id)}</strong> '
                      f'({_e(cr.check_name)}): {_e(cr.error)}</div>')
    parts.append('</div>')
    return "\n".join(parts)
