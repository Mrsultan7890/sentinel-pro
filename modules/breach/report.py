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
Breach Report - JSON + Summary + HTML export
"""

import json
import logging
import html
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

def _e(s) -> str:
    return html.escape(str(s) if s is not None else '')


class BreachReport:

    def __init__(self, output_dir: str = 'reports'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def save(self, target: str, data: dict) -> dict:
        ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe = target.replace('@', '_at_').replace('.', '_')

        json_path    = self.output_dir / f"breach_{safe}_{ts}.json"
        summary_path = self.output_dir / f"breach_{safe}_{ts}_summary.txt"
        html_path    = self.output_dir / f"breach_{safe}_{ts}.html"

        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        with open(summary_path, 'w') as f:
            f.write(self._build_summary(target, data))
        with open(html_path, 'w') as f:
            f.write(self._build_html(target, data))

        logger.info(f"Breach report saved: {json_path}")
        return {'json': str(json_path), 'summary': str(summary_path), 'html': str(html_path)}

    # ── summary ─────────────────────────────────────────────────────────

    def _build_summary(self, target: str, data: dict) -> str:
        lines = [
            f"{'='*60}",
            f"  BREACH REPORT - {target}",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"{'='*60}\n",
        ]

        # ── Executive Summary ──────────────────────────────────────────────────
        risk         = data.get('risk_level', 'LOW')
        stealer_cnt  = data.get('total_stealer_logs', 0)
        breach_cnt   = data.get('total_breaches', 0)
        dh           = data.get('dehashed', {})
        plain_count  = sum(1 for e in dh.get('entries', []) if e.get('has_plaintext'))

        critical_items = []
        high_items     = []
        if stealer_cnt > 0:
            critical_items.append(f"{stealer_cnt} infostealer log(s) — machine was compromised")
        if plain_count > 0:
            critical_items.append(f"{plain_count} plaintext password(s) found in Dehashed")
        if breach_cnt > 10:
            high_items.append(f"Found in {breach_cnt} breach databases")
        elif breach_cnt > 0:
            high_items.append(f"Found in {breach_cnt} breach database(s)")

        lines += [
            "[ EXECUTIVE SUMMARY ]",
            f"  Overall Risk  : {risk}",
            f"  Target        : {target}",
        ]
        if critical_items:
            lines.append(f"  CRITICAL      : {' | '.join(critical_items)}")
        if high_items:
            lines.append(f"  HIGH          : {' | '.join(high_items)}")
        lines += ["", "  RECOMMENDED ACTIONS:"]
        if stealer_cnt > 0:
            lines.append("  1. [CRITICAL] Change ALL passwords immediately — machine was infected")
            lines.append("  2. [CRITICAL] Enable 2FA on all accounts")
            lines.append("  3. [CRITICAL] Scan machine for malware")
        elif plain_count > 0:
            lines.append("  1. [CRITICAL] Change exposed passwords immediately")
            lines.append("  2. [HIGH] Enable 2FA on affected accounts")
        elif breach_cnt > 0:
            lines.append("  1. [HIGH] Change passwords for breached services")
            lines.append("  2. [HIGH] Enable 2FA where available")
        else:
            lines.append("  No critical findings — maintain good password hygiene.")
        lines.append("")
        # ── End Executive Summary ──────────────────────────────────────────────
        lines += [
            f"Risk Level   : {data.get('risk_level', 'N/A')}",
            f"Breaches     : {data.get('total_breaches', 0)}",
            f"Pastes       : {data.get('total_pastes', 0)}",
            f"Stealer Logs : {data.get('total_stealer_logs', 0)}",
            "",
        ]

        for s in data.get('summary', []):
            lines.append(f"  {s}")
        lines.append("")

        # HIBP
        hibp = data.get('hibp', {})
        if hibp and not hibp.get('error') and hibp.get('total', 0) > 0:
            lines.append(f"[ HIBP ] {hibp['total']} breach(es) — most trusted source")
            for b in hibp.get('breaches', [])[:10]:
                dc = ', '.join(b.get('DataClasses', [])[:4])
                lines.append(f"  • {b.get('Name','?')} ({b.get('BreachDate','?')}) — {b.get('PwnCount',0):,} accounts")
                if dc:
                    lines.append(f"    Data: {dc}")
            lines.append("")
        elif hibp.get('error'):
            lines.append(f"[ HIBP ] {hibp['error']}\n")

        # Dehashed
        dh = data.get('dehashed', {})
        if dh and not dh.get('error') and dh.get('total', 0) > 0:
            plain_count = sum(1 for e in dh.get('entries', []) if e.get('has_plaintext'))
            lines.append(f"[ DEHASHED ] {dh['total']} record(s) | Plaintext passwords: {plain_count}")
            for e in dh.get('entries', [])[:10]:
                pw = f" | pw: {e['password'][:4]}***" if e.get('has_plaintext') else ''
                lines.append(f"  • {e.get('database_name','?')} | user: {e.get('username','')}{pw}")
            lines.append("")
        elif dh.get('error'):
            lines.append(f"[ DEHASHED ] {dh['error']}\n")

        # Sources
        lines.append("[ SOURCES CHECKED ]")
        for src, status in data.get('sources', {}).items():
            icon = '✓' if status == 'ok' else '✗'
            lines.append(f"  {icon} {src}: {status}")
        lines.append("")

        # Stealer logs
        logs = data.get('stealer_logs', [])
        if logs:
            lines.append("[ INFOSTEALER LOGS ] ⚠️  Machine was compromised!")
            for log in logs:
                lines.append(f"  Computer : {log.get('computer_name', 'N/A')}")
                lines.append(f"  OS       : {log.get('operating_system', 'N/A')}")
                lines.append(f"  Date     : {log.get('date_uploaded', 'N/A')}")
                lines.append(f"  Malware  : {log.get('malware_path', 'N/A')}")
                lines.append("")

        # Breaches
        breaches = data.get('breaches', [])
        if breaches:
            lines.append(f"[ BREACHES ] ({len(breaches)} found)")
            for b in breaches:
                btype = f" [{b.get('type', '')}]" if b.get('type') else ''
                lines.append(f"  • {b.get('name', 'Unknown')}{btype} via {b.get('source', 'N/A')}")
                if b.get('password_hint'):
                    lines.append(f"    Password hint: {b['password_hint']}")
            lines.append("")

        # Pastes
        pastes = data.get('pastes', [])
        if pastes:
            lines.append(f"[ PASTES ] ({len(pastes)} found)")
            for p in pastes[:10]:
                label = p.get('url') or p.get('name') or p.get('content', 'N/A')
                lines.append(f"  • {str(label)[:80]} [{p.get('source', '')}]")
            if len(pastes) > 10:
                lines.append(f"  ... and {len(pastes) - 10} more (see JSON report)")
            lines.append("")

        lines.append(f"{'='*60}")
        return '\n'.join(lines)

    # ── HTML ─────────────────────────────────────────────────────────────

    def _build_html(self, target: str, data: dict) -> str:
        ts         = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        risk       = data.get('risk_level', 'LOW')
        risk_color = {'CRITICAL': '#e74c3c', 'HIGH': '#e67e22', 'MEDIUM': '#f1c40f', 'LOW': '#2ecc71'}.get(risk, '#95a5a6')

        hibp       = data.get('hibp', {})
        dh         = data.get('dehashed', {})
        stealer_cnt = data.get('total_stealer_logs', 0)
        plain_count = sum(1 for e in dh.get('entries', []) if e.get('has_plaintext'))

        # ── row builders ──
        breach_rows = ''
        for b in data.get('breaches', []):
            src_color = '#e74c3c' if b.get('source') in ('hibp', 'dehashed') else '#8b949e'
            breach_rows += (
                f'<tr><td>{_e(b.get("name","Unknown"))}</td>'
                f'<td style="color:{src_color}">{_e(b.get("source","N/A"))}</td>'
                f'<td style="color:#8b949e">{_e(b.get("type",""))}</td>'
                f'<td style="font-family:monospace;font-size:11px">{_e(b.get("password_hint",""))}</td>'
                f'<td style="font-size:11px">{_e(b.get("breach_date",""))}</td></tr>'
            )

        hibp_rows = ''
        for b in hibp.get('breaches', []):
            dc = _e(', '.join(b.get('DataClasses', [])[:5]))
            sens = ' <span style="color:#e74c3c">&#9888; Sensitive</span>' if b.get('IsSensitive') else ''
            hibp_rows += (
                f'<tr><td style="font-weight:bold">{_e(b.get("Name","?"))}</td>'
                f'<td>{_e(b.get("BreachDate","?"))}</td>'
                f'<td>{b.get("PwnCount",0):,}</td>'
                f'<td style="font-size:11px">{dc}</td>'
                f'<td>{"&#10003;" if b.get("IsVerified") else "?"}{sens}</td></tr>'
            )

        dh_rows = ''
        for e in dh.get('entries', []):
            pw_cell = f'<span style="color:#e74c3c;font-family:monospace">{_e(e["password"][:4])}***</span>' if e.get('has_plaintext') else '<span style="color:#8b949e">hashed/none</span>'
            dh_rows += (
                f'<tr><td>{_e(e.get("database_name","?"))}</td>'
                f'<td>{_e(e.get("username",""))}</td>'
                f'<td>{_e(e.get("email",""))}</td>'
                f'<td>{pw_cell}</td>'
                f'<td style="font-size:11px">{_e(e.get("name",""))}</td></tr>'
            )

        paste_rows = ''
        for p in data.get('pastes', [])[:30]:
            url   = _e(p.get('url', ''))
            label = _e(p.get('title') or p.get('name') or p.get('id', 'N/A'))
            link  = f'<a href="{url}">{label[:60]}</a>' if p.get('url') else label[:60]
            paste_rows += (
                f'<tr><td style="color:#8b949e">{_e(p.get("source",""))}</td>'
                f'<td>{link}</td>'
                f'<td style="color:#8b949e">{_e(p.get("date",""))}</td></tr>'
            )

        log_rows = ''
        for log in data.get('stealer_logs', []):
            log_rows += (
                f'<tr><td style="color:#e74c3c">{_e(log.get("computer_name","N/A"))}</td>'
                f'<td>{_e(log.get("operating_system","N/A"))}</td>'
                f'<td>{_e(log.get("date_uploaded","N/A"))}</td>'
                f'<td style="font-size:11px">{_e(log.get("malware_path","N/A"))}</td></tr>'
            )

        src_rows = ''
        for src, status in data.get('sources', {}).items():
            color = '#2ecc71' if status == 'ok' else '#e74c3c' if 'error' in status else '#f1c40f'
            icon  = '&#10003;' if status == 'ok' else '&#10007;'
            src_rows += f'<tr><td>{_e(src)}</td><td style="color:{color}">{icon} {_e(status)}</td></tr>'

        hibp_total  = hibp.get('total', 0)
        dh_total    = dh.get('total', 0)

        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Breach Report - {target}</title>
<style>
  body{{font-family:monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:20px}}
  h1{{color:#58a6ff}} h2{{color:#79c0ff;border-bottom:1px solid #30363d;padding-bottom:6px;margin-top:24px}}
  .badge{{display:inline-block;padding:4px 12px;border-radius:4px;font-weight:bold;color:#fff;background:{risk_color}}}
  table{{width:100%;border-collapse:collapse;margin-bottom:16px}}
  th{{background:#161b22;color:#8b949e;text-align:left;padding:8px}}
  td{{padding:7px 8px;border-bottom:1px solid #21262d;font-size:13px}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:16px;margin-bottom:16px}}
  .stat{{text-align:center;padding:12px}} .stat-num{{font-size:28px;font-weight:bold;color:#58a6ff}} .stat-lbl{{color:#8b949e;font-size:12px}}
  a{{color:#58a6ff;text-decoration:none}}
</style></head><body>
<h1>🔓 Breach Report — {target}</h1>
<div class="card">
  <table><tr>
    <td class="stat"><div class="stat-num" style="color:{risk_color}">{data.get('total_breaches',0)}</div><div class="stat-lbl">Total Breaches</div></td>
    <td class="stat"><div class="stat-num" style="color:{'#e74c3c' if hibp_total else '#2ecc71'}">{hibp_total}</div><div class="stat-lbl">HIBP Breaches</div></td>
    <td class="stat"><div class="stat-num" style="color:{'#e74c3c' if plain_count else '#2ecc71'}">{plain_count}</div><div class="stat-lbl">Plaintext Passwords</div></td>
    <td class="stat"><div class="stat-num" style="color:{'#e74c3c' if stealer_cnt else '#2ecc71'}">{stealer_cnt}</div><div class="stat-lbl">Stealer Logs</div></td>
    <td class="stat"><div class="stat-num">{data.get('total_pastes',0)}</div><div class="stat-lbl">Pastes Found</div></td>
    <td class="stat"><div class="stat-num"><span class="badge">{risk}</span></div><div class="stat-lbl">Risk Level</div></td>
  </tr></table>
</div>

<div class="card" style="border-left:4px solid {risk_color}">
  <h2 style="color:{risk_color};margin-top:0">📋 Executive Summary</h2>
  <table><tr><th>Overall Risk</th><td><span class="badge">{risk}</span></td></tr>
  <tr><th>Target</th><td>{_e(target)}</td></tr>
  <tr><th>Scan Date</th><td>{ts}</td></tr></table>
  <h3 style="color:#79c0ff;margin-top:12px">Recommended Actions</h3>
  <ul style="line-height:1.8;padding-left:20px">
    {'<li style="color:#e74c3c">🔴 Change ALL passwords immediately — machine was infected with infostealer malware</li><li style="color:#e74c3c">🔴 Enable 2FA on all accounts</li><li style="color:#e74c3c">🔴 Scan machine for malware</li>' if stealer_cnt > 0 else ''}
    {'<li style="color:#e74c3c">🔴 Change exposed plaintext passwords immediately</li><li style="color:#e67e22">🟠 Enable 2FA on affected accounts</li>' if plain_count > 0 and stealer_cnt == 0 else ''}
    {'<li style="color:#e67e22">🟠 Change passwords for breached services</li><li style="color:#e67e22">🟠 Enable 2FA where available</li>' if data.get('total_breaches',0) > 0 and plain_count == 0 and stealer_cnt == 0 else ''}
    {'<li style="color:#2ecc71">✅ No critical findings — maintain good password hygiene.</li>' if risk == 'LOW' else ''}
  </ul>
</div>

<h2>🔔 HaveIBeenPwned — {hibp_total} breach(es)</h2>
<div class="card"><table>
  <tr><th>Breach Name</th><th>Date</th><th>Accounts Pwned</th><th>Data Classes</th><th>Verified</th></tr>
  {hibp_rows or '<tr><td colspan=5 style="color:#2ecc71">Not found in HIBP ✓</td></tr>'}
</table></div>

<h2>🔑 Dehashed — {dh_total} record(s) | Plaintext: {plain_count}</h2>
<div class="card"><table>
  <tr><th>Database</th><th>Username</th><th>Email</th><th>Password</th><th>Name</th></tr>
  {dh_rows or '<tr><td colspan=5 style="color:#2ecc71">No records found / API key not set</td></tr>'}
</table></div>

<h2>🦠 Infostealer Logs ({stealer_cnt})</h2>
<div class="card"><table>
  <tr><th>Computer</th><th>OS</th><th>Date</th><th>Malware Path</th></tr>
  {log_rows or '<tr><td colspan=4 style="color:#2ecc71">No stealer logs found</td></tr>'}
</table></div>

<h2>💾 All Breaches ({data.get('total_breaches',0)})</h2>
<div class="card"><table>
  <tr><th>Name</th><th>Source</th><th>Type</th><th>Password Hint</th><th>Date</th></tr>
  {breach_rows or '<tr><td colspan=5 style="color:#2ecc71">No breaches found</td></tr>'}
</table></div>

<h2>📋 Pastes ({data.get('total_pastes',0)})</h2>
<div class="card"><table>
  <tr><th>Source</th><th>URL / Title</th><th>Date</th></tr>
  {paste_rows or '<tr><td colspan=3 style="color:#2ecc71">No pastes found</td></tr>'}
</table></div>

<h2>Sources Checked</h2>
<div class="card"><table><tr><th>Source</th><th>Status</th></tr>{src_rows}</table></div>

<p style="color:#484f58;font-size:12px">Generated by The Sentinel Pro | {ts}</p>
</body></html>"""
