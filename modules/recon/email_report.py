import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class EmailReport:

    def __init__(self, output_dir: str = 'reports'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def save(self, email: str, data: dict) -> dict:
        ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe = email.replace('@', '_at_').replace('.', '_')

        json_path    = self.output_dir / f"email_{safe}_{ts}.json"
        summary_path = self.output_dir / f"email_{safe}_{ts}_summary.txt"
        html_path    = self.output_dir / f"email_{safe}_{ts}.html"

        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        with open(summary_path, 'w') as f:
            f.write(self._build_summary(email, data))

        with open(html_path, 'w') as f:
            f.write(self._build_html(email, data))

        logger.info(f"Email report saved: {json_path}")
        return {'json': str(json_path), 'summary': str(summary_path), 'html': str(html_path)}

    def _build_summary(self, email: str, data: dict) -> str:
        lines = [
            f"{'='*60}",
            f"  EMAIL OSINT REPORT - {email}",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"{'='*60}\n",
            f"Risk Level  : {data.get('risk_level', 'N/A')}",
            f"Valid Format: {'Yes' if data.get('valid_format') else 'No'}",
            f"Domain      : {data.get('domain', 'N/A')}",
            f"Username    : {data.get('username', 'N/A')}",
            f"Disposable  : {'YES ⚠' if data.get('disposable') else 'No'}",
            "",
        ]

        di = data.get('domain_info', {})
        if di:
            lines += [
                "[ DOMAIN INFO ]",
                f"  MX Valid  : {'Yes' if di.get('mx_valid') else 'No'}",
                f"  MX Records: {', '.join(di.get('mx_records', [])[:3])}",
                f"  SPF       : {di.get('spf', 'None')}",
                "",
            ]

        social = data.get('social_hints', [])
        if social:
            lines.append("[ SOCIAL PROFILES ]")
            for s in social:
                icon = '✓' if s['status'] == 'found' else '✗'
                lines.append(f"  {icon} {s['platform']:<12} {s['url']}")
            lines.append("")

        breach = data.get('breach_summary', {})
        if breach:
            lines.append("[ BREACH SUMMARY ]")
            if breach.get('stealer_logs', 0) > 0:
                lines.append(f"  ⚠ Stealer logs: {breach['stealer_logs']}")
            lc = breach.get('leakcheck', {})
            if lc.get('found', 0) > 0:
                lines.append(f"  Found in {lc['found']} breach source(s)")
                for src in lc.get('sources', [])[:10]:
                    lines.append(f"    • {src}")
            lines.append("")

        flags = data.get('risk_flags', [])
        if flags:
            lines.append("[ RISK FLAGS ]")
            for rf in flags:
                lines.append(f"  [{rf['severity']}] {rf['flag']}: {rf['detail']}")
            lines.append("")

        lines.append(f"{'='*60}")
        return '\n'.join(lines)

    def _build_html(self, email: str, data: dict) -> str:
        risk      = data.get('risk_level', 'LOW')
        risk_color = {'CRITICAL': '#e74c3c', 'HIGH': '#e67e22', 'MEDIUM': '#f1c40f', 'LOW': '#2ecc71'}.get(risk, '#95a5a6')
        ts        = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        social_rows = ''
        for s in data.get('social_hints', []):
            icon  = '✓' if s['status'] == 'found' else '✗'
            color = '#2ecc71' if s['status'] == 'found' else '#7f8c8d'
            social_rows += f'<tr><td style="color:{color}">{icon}</td><td>{s["platform"]}</td><td><a href="{s["url"]}">{s["url"]}</a></td></tr>'

        flag_rows = ''
        for rf in data.get('risk_flags', []):
            fc = {'CRITICAL': '#e74c3c', 'HIGH': '#e67e22', 'MEDIUM': '#f1c40f'}.get(rf['severity'], '#95a5a6')
            flag_rows += f'<tr><td style="color:{fc};font-weight:bold">{rf["severity"]}</td><td>{rf["flag"]}</td><td>{rf["detail"]}</td></tr>'

        breach      = data.get('breach_summary', {})
        stealer_cnt = breach.get('stealer_logs', 0)
        lc          = breach.get('leakcheck', {})
        lc_found    = lc.get('found', 0)
        di          = data.get('domain_info', {})

        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Email OSINT - {email}</title>
<style>
  body{{font-family:monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:20px}}
  h1{{color:#58a6ff}} h2{{color:#79c0ff;border-bottom:1px solid #30363d;padding-bottom:6px}}
  .badge{{display:inline-block;padding:4px 12px;border-radius:4px;font-weight:bold;color:#fff;background:{risk_color}}}
  table{{width:100%;border-collapse:collapse;margin-bottom:20px}}
  th{{background:#161b22;color:#8b949e;text-align:left;padding:8px}}
  td{{padding:8px;border-bottom:1px solid #21262d}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:16px;margin-bottom:16px}}
  a{{color:#58a6ff}}
</style></head><body>
<h1>📧 Email OSINT Report</h1>
<div class="card">
  <table>
    <tr><th>Email</th><td>{email}</td><th>Risk Level</th><td><span class="badge">{risk}</span></td></tr>
    <tr><th>Domain</th><td>{data.get('domain','N/A')}</td><th>Username</th><td>{data.get('username','N/A')}</td></tr>
    <tr><th>Disposable</th><td style="color:{'#e74c3c' if data.get('disposable') else '#2ecc71'}">{'YES ⚠' if data.get('disposable') else 'No'}</td>
        <th>MX Valid</th><td style="color:{'#2ecc71' if di.get('mx_valid') else '#e74c3c'}">{'Yes' if di.get('mx_valid') else 'No'}</td></tr>
    <tr><th>Stealer Logs</th><td style="color:{'#e74c3c' if stealer_cnt else '#2ecc71'}">{stealer_cnt}</td>
        <th>Breach Sources</th><td style="color:{'#e74c3c' if lc_found else '#2ecc71'}">{lc_found}</td></tr>
  </table>
</div>

<h2>Social Profile Hints</h2>
<div class="card"><table><tr><th></th><th>Platform</th><th>URL</th></tr>{social_rows or '<tr><td colspan=3>No hints found</td></tr>'}</table></div>

<h2>Risk Flags</h2>
<div class="card"><table><tr><th>Severity</th><th>Flag</th><th>Detail</th></tr>{flag_rows or '<tr><td colspan=3 style="color:#2ecc71">No risk flags</td></tr>'}</table></div>

<p style="color:#484f58;font-size:12px">Generated by The Sentinel Pro | {ts}</p>
</body></html>"""
