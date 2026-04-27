# ============================================================================
# Sentinel Pro v3.0 — Professional OSINT & Bug Bounty Platform
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
#
# Unauthorized copying, distribution, or modification of this software,
# via any medium, is strictly prohibited without written permission.
#
# Licensed users may use this software under the terms of their license.
# For licensing: https://github.com/Mrsultan7890/osints
# ============================================================================

"""
Phone OSINT Report - JSON + Summary + HTML
"""

import json
import logging
import html
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

def _e(s) -> str:
    return html.escape(str(s) if s is not None else '')


class PhoneReport:

    def __init__(self, output_dir: str = 'reports'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def save(self, phone: str, data: dict) -> dict:
        ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe = re.sub(r'[^a-zA-Z0-9]', '_', phone)

        json_path    = self.output_dir / f"phone_{safe}_{ts}.json"
        summary_path = self.output_dir / f"phone_{safe}_{ts}_summary.txt"
        html_path    = self.output_dir / f"phone_{safe}_{ts}.html"

        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        with open(summary_path, 'w') as f:
            f.write(self._build_summary(phone, data))
        with open(html_path, 'w') as f:
            f.write(self._build_html(phone, data))

        logger.info(f"Phone report saved: {json_path}")
        return {'json': str(json_path), 'summary': str(summary_path), 'html': str(html_path)}

    def _build_summary(self, phone: str, data: dict) -> str:
        lines = [
            f"{'='*60}",
            f"  PHONE OSINT REPORT - {phone}",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"{'='*60}\n",
            f"  Normalized  : {data.get('normalized', 'N/A')}",
            f"  Valid       : {'Yes' if data.get('valid') else 'No'}",
            f"  Country     : {data.get('country', 'N/A')} (+{data.get('country_code', '?')})",
            f"  Carrier     : {data.get('carrier', 'N/A')}",
            f"  Line Type   : {data.get('line_type', 'N/A')}",
            f"  Location    : {data.get('location', 'N/A')}",
            f"  Risk Level  : {data.get('risk_level', 'N/A')}",
            "",
        ]

        flags = data.get('risk_flags', [])
        if flags:
            lines.append("[ RISK FLAGS ]")
            for f in flags:
                lines.append(f"  [{f['severity']}] {f['flag']}: {f['detail']}")
            lines.append("")

        social = data.get('social_hints', [])
        found  = [s for s in social if s['status'] == 'found']
        if found:
            lines.append("[ SOCIAL PRESENCE ]")
            for s in found:
                lines.append(f"  ✓ {s['platform']}: {s['url']}")
            lines.append("")

        rep = data.get('reputation', {})
        if rep.get('spam_reports', 0) > 0:
            lines.append(f"[ REPUTATION ] Spam reports: {rep['spam_reports']} | Sources: {', '.join(rep.get('sources', []))}")
            lines.append("")

        lines.append(f"{'='*60}")
        return '\n'.join(lines)

    def _build_html(self, phone: str, data: dict) -> str:
        ts      = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        risk    = data.get('risk_level', 'LOW')
        rc      = {'CRITICAL': '#e74c3c', 'HIGH': '#e67e22', 'MEDIUM': '#f1c40f', 'LOW': '#2ecc71'}.get(risk, '#95a5a6')
        flags   = data.get('risk_flags', [])
        social  = data.get('social_hints', [])
        rep     = data.get('reputation', {})
        nv      = data.get('numverify', {})
        ab      = data.get('abstract', {})

        flag_rows = ''
        for f in flags:
            fc = {'CRITICAL': '#e74c3c', 'HIGH': '#e67e22', 'MEDIUM': '#f1c40f', 'INFO': '#58a6ff'}.get(f['severity'], '#95a5a6')
            flag_rows += f'<tr><td style="color:{fc};font-weight:bold">{_e(f["severity"])}</td><td>{_e(f["flag"])}</td><td>{_e(f["detail"])}</td></tr>'

        social_rows = ''
        for s in social:
            color = '#2ecc71' if s['status'] == 'found' else '#7f8c8d'
            icon  = '✓' if s['status'] == 'found' else '✗'
            social_rows += f'<tr><td style="color:{color}">{icon}</td><td>{_e(s["platform"])}</td><td><a href="{_e(s["url"])}">{_e(s["url"])}</a></td></tr>'

        nv_rows = ''
        if nv and not nv.get('error'):
            for k, v in nv.items():
                if k not in ('valid', 'formats') and v:
                    nv_rows += f'<tr><td style="color:#8b949e">{_e(k)}</td><td>{_e(v)}</td></tr>'

        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Phone OSINT - {_e(phone)}</title>
<style>
  body{{font-family:monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:20px}}
  h1{{color:#58a6ff}} h2{{color:#79c0ff;border-bottom:1px solid #30363d;padding-bottom:6px;margin-top:24px}}
  .badge{{display:inline-block;padding:4px 12px;border-radius:4px;font-weight:bold;color:#fff;background:{rc}}}
  table{{width:100%;border-collapse:collapse;margin-bottom:16px}}
  th{{background:#161b22;color:#8b949e;text-align:left;padding:8px}}
  td{{padding:7px 8px;border-bottom:1px solid #21262d;font-size:13px}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:16px;margin-bottom:16px}}
  .grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
  a{{color:#58a6ff;text-decoration:none}} a:hover{{text-decoration:underline}}
  .stat{{text-align:center;padding:12px}} .stat-num{{font-size:28px;font-weight:bold;color:#58a6ff}} .stat-lbl{{color:#8b949e;font-size:12px}}
</style></head><body>
<h1>📱 Phone OSINT — {_e(phone)}</h1>
<div class="card"><table><tr>
  <td class="stat"><div class="stat-num">{'✓' if data.get('valid') else '✗'}</div><div class="stat-lbl">Valid</div></td>
  <td class="stat"><div class="stat-num">{_e(data.get('country_code','?'))}</div><div class="stat-lbl">Country Code</div></td>
  <td class="stat"><div class="stat-num">{_e(data.get('line_type','?'))}</div><div class="stat-lbl">Line Type</div></td>
  <td class="stat"><div class="stat-num">{rep.get('spam_reports',0)}</div><div class="stat-lbl">Spam Reports</div></td>
  <td class="stat"><div class="stat-num">{len([s for s in social if s['status']=='found'])}</div><div class="stat-lbl">Social Hits</div></td>
  <td class="stat"><div class="stat-num"><span class="badge">{risk}</span></div><div class="stat-lbl">Risk Level</div></td>
</tr></table></div>

<div class="grid">
  <div>
    <h2>Phone Details</h2>
    <div class="card"><table>
      <tr><th>Normalized</th><td>{_e(data.get('normalized','N/A'))}</td></tr>
      <tr><th>Country</th><td>{_e(data.get('country','N/A'))}</td></tr>
      <tr><th>Carrier</th><td>{_e(data.get('carrier','N/A'))}</td></tr>
      <tr><th>Line Type</th><td>{_e(data.get('line_type','N/A'))}</td></tr>
      <tr><th>Location</th><td>{_e(data.get('location','N/A'))}</td></tr>
    </table></div>
  </div>
  <div>
    <h2>Reputation</h2>
    <div class="card"><table>
      <tr><th>Spam Reports</th><td style="color:{'#e74c3c' if rep.get('spam_reports',0) > 0 else '#2ecc71'}">{rep.get('spam_reports',0)}</td></tr>
      <tr><th>Reported On</th><td>{_e(', '.join(rep.get('sources',[])) or 'None')}</td></tr>
    </table></div>
  </div>
</div>

<h2>Risk Flags</h2>
<div class="card"><table><tr><th>Severity</th><th>Flag</th><th>Detail</th></tr>{flag_rows or '<tr><td colspan=3 style="color:#2ecc71">No risk flags</td></tr>'}</table></div>

<h2>Social Presence</h2>
<div class="card"><table><tr><th>Status</th><th>Platform</th><th>URL</th></tr>{social_rows or '<tr><td colspan=3>No social hints checked</td></tr>'}</table></div>

<h2>NumVerify Data</h2>
<div class="card"><table><tr><th>Field</th><th>Value</th></tr>{nv_rows or f'<tr><td colspan=2 style="color:#8b949e">{_e(nv.get("error","No data"))}</td></tr>'}</table></div>

<p style="color:#484f58;font-size:12px">Generated by The Sentinel Pro | {ts}</p>
</body></html>"""


import re  # noqa: E402 — needed for safe filename in save()
