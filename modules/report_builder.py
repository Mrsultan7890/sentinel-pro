"""
Sentinel Report Builder — Improved Reporting Engine
=====================================================
- Groq se executive summary generate karo
- MITRE ATT&CK mapping
- Severity distribution chart (matplotlib)
- Evidence chain of custody
- HTML/PDF export

Author: @who_is_the_black_hat
"""

import hashlib
import json
import logging
import time
from datetime import datetime
from pathlib import Path

import config

logger = logging.getLogger(__name__)

REPORTS_DIR = config.REPORTS_DIR
REPORTS_DIR.mkdir(exist_ok=True)

# MITRE ATT&CK mapping
MITRE_MAP = {
    'nmap':              ('T1046',  'Network Service Discovery'),
    'subfinder':         ('T1590',  'Gather Victim Network Information'),
    'amass':             ('T1590',  'Gather Victim Network Information'),
    'theHarvester':      ('T1589',  'Gather Victim Identity Information'),
    'gobuster':          ('T1083',  'File and Directory Discovery'),
    'ffuf':              ('T1083',  'File and Directory Discovery'),
    'nikto':             ('T1190',  'Exploit Public-Facing Application'),
    'nuclei':            ('T1190',  'Exploit Public-Facing Application'),
    'sqlmap':            ('T1190',  'Exploit Public-Facing Application'),
    'commix':            ('T1059',  'Command and Scripting Interpreter'),
    'hydra':             ('T1110',  'Brute Force'),
    'hashcat':           ('T1110.002', 'Password Cracking'),
    'john':              ('T1110.002', 'Password Cracking'),
    'wpscan':            ('T1190',  'Exploit Public-Facing Application'),
    'searchsploit':      ('T1588.005', 'Exploits'),
    'masscan':           ('T1046',  'Network Service Discovery'),
    'sslscan':           ('T1040',  'Network Sniffing'),
    'wafw00f':           ('T1518',  'Software Discovery'),
    'whatweb':           ('T1518',  'Software Discovery'),
    'enum4linux':        ('T1135',  'Network Share Discovery'),
    'zone_transfer':     ('T1590.002', 'DNS'),
    'smuggling':         ('T1190',  'Exploit Public-Facing Application'),
    'clickjacking':      ('T1185',  'Browser Session Hijacking'),
    'cors':              ('T1539',  'Steal Web Session Cookie'),
    'sqli':              ('T1190',  'Exploit Public-Facing Application'),
    'xss':               ('T1059.007', 'JavaScript'),
    'lfi':               ('T1083',  'File and Directory Discovery'),
    'ssrf':              ('T1090',  'Proxy'),
    'breach':            ('T1589.001', 'Credentials'),
    'shodan_cves':       ('T1588.006', 'Vulnerabilities'),
}

SEV_COLORS = {
    'CRITICAL': '#e74c3c',
    'HIGH':     '#e67e22',
    'MEDIUM':   '#f39c12',
    'LOW':      '#27ae60',
}


class SentinelReportBuilder:
    """
    Improved report builder:
    - Groq executive summary
    - MITRE ATT&CK mapping
    - Severity chart
    - HTML/PDF export
    """

    def __init__(self):
        self._groq = self._load_groq()

    def _load_groq(self):
        try:
            from modules.ml_engine.groq_llm import GroqLLM
            if GroqLLM.is_available():
                g = GroqLLM()
                return g if g.is_ready else None
        except Exception:
            pass
        return None

    # ── Main Build ────────────────────────────────────────────────────────────

    def build(self, target: str, scan_type: str, results: dict,
              findings: list, risk: str) -> dict:
        """
        Full report build karo.
        Returns: {'json': path, 'html': path, 'pdf': path, 'summary': path}
        """
        ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe = target.replace('.', '_').replace('/', '_').replace('@', '_at_')
        base = REPORTS_DIR / f"{scan_type}_{safe}_{ts}"

        # Executive summary
        exec_summary = self._executive_summary(target, findings, risk, results)

        # MITRE ATT&CK mapping
        mitre = self._mitre_mapping(findings, results)

        # Severity chart
        chart_path = self._severity_chart(target, findings, str(base))

        # Evidence hash
        ev_hash = self._evidence_hash(results)

        report = {
            'target':            target,
            'scan_type':         scan_type,
            'timestamp':         datetime.now().isoformat(),
            'risk_level':        risk,
            'total_findings':    len(findings),
            'findings':          findings,
            'executive_summary': exec_summary,
            'mitre_attack':      mitre,
            'chart_path':        chart_path,
            'evidence_hash':     ev_hash,
            'tool':              'The Sentinel Pro v3.0',
            'author':            '@who_is_the_black_hat',
            'standards':         ['ISO 27037', 'NIST SP 800-86', 'RFC 3227'],
        }

        # Save files
        paths = {}
        paths['json']    = self._save_json(report, str(base))
        paths['summary'] = self._save_summary(report, str(base))
        paths['html']    = self._save_html(report, str(base), chart_path)
        paths['pdf']     = self._save_pdf(paths['html'])

        logger.info(f"[ReportBuilder] {scan_type} report: {base.name}")
        return paths

    # ── Executive Summary (Groq) ──────────────────────────────────────────────

    def _executive_summary(self, target: str, findings: list,
                           risk: str, results: dict) -> str:
        critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        high     = sum(1 for f in findings if f.get('severity') == 'HIGH')
        medium   = sum(1 for f in findings if f.get('severity') == 'MEDIUM')

        if self._groq:
            findings_text = '\n'.join(
                f"- [{f.get('severity')}] {f.get('title','')}: {f.get('detail','')[:80]}"
                for f in findings[:8]
            )
            prompt = (
                f"Write a professional security assessment executive summary for:\n"
                f"Target: {target}\n"
                f"Overall Risk: {risk}\n"
                f"Findings: {len(findings)} total "
                f"(CRITICAL={critical}, HIGH={high}, MEDIUM={medium})\n\n"
                f"Key findings:\n{findings_text}\n\n"
                f"Keep it concise (3-4 sentences), professional, actionable."
            )
            try:
                summary = self._groq.ask(prompt, max_tokens=200)
                if summary and len(summary) > 50:
                    return summary
            except Exception:
                pass

        # Fallback
        return (
            f"Security assessment of {target} identified {len(findings)} findings "
            f"with overall risk level {risk}. "
            f"Critical: {critical}, High: {high}, Medium: {medium}. "
            f"{'Immediate remediation required.' if risk in ('CRITICAL','HIGH') else 'Schedule patching in next maintenance window.'}"
        )

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────────

    def _mitre_mapping(self, findings: list, results: dict) -> list:
        """Findings aur tools ko MITRE ATT&CK techniques se map karo."""
        seen       = set()
        techniques = []

        # Findings se
        for f in findings:
            ftype = f.get('type', '').lower()
            for key, (tid, tname) in MITRE_MAP.items():
                if key in ftype and tid not in seen:
                    seen.add(tid)
                    techniques.append({
                        'technique_id':   tid,
                        'technique_name': tname,
                        'finding':        f.get('title', ''),
                        'severity':       f.get('severity', 'MEDIUM'),
                    })

        # Results mein tools se
        for tool in results.keys():
            tool_lower = tool.lower().replace('kali_', '')
            for key, (tid, tname) in MITRE_MAP.items():
                if key in tool_lower and tid not in seen:
                    seen.add(tid)
                    techniques.append({
                        'technique_id':   tid,
                        'technique_name': tname,
                        'finding':        f'Tool: {tool}',
                        'severity':       'LOW',
                    })

        return techniques

    # ── Severity Chart ────────────────────────────────────────────────────────

    def _severity_chart(self, target: str, findings: list,
                        base_path: str) -> str:
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
            from collections import Counter

            counts = Counter(f.get('severity', 'LOW') for f in findings)
            sevs   = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            vals   = [counts.get(s, 0) for s in sevs]
            colors = [SEV_COLORS[s] for s in sevs]

            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
            fig.patch.set_facecolor('#0d1117')

            # Bar chart
            bars = ax1.bar(sevs, vals, color=colors, edgecolor='white', linewidth=0.5)
            ax1.set_facecolor('#161b22')
            ax1.set_title(f'Findings by Severity\n{target}',
                          color='white', fontsize=12, fontweight='bold')
            ax1.set_ylabel('Count', color='white')
            ax1.tick_params(colors='white')
            ax1.spines['bottom'].set_color('#30363d')
            ax1.spines['left'].set_color('#30363d')
            ax1.spines['top'].set_visible(False)
            ax1.spines['right'].set_visible(False)
            for bar, val in zip(bars, vals):
                if val > 0:
                    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.05,
                             str(val), ha='center', color='white', fontweight='bold')

            # Pie chart
            non_zero = [(s, v) for s, v in zip(sevs, vals) if v > 0]
            if non_zero:
                pie_labels = [s for s, _ in non_zero]
                pie_vals   = [v for _, v in non_zero]
                pie_colors = [SEV_COLORS[s] for s in pie_labels]
                ax2.pie(pie_vals, labels=pie_labels, colors=pie_colors,
                        autopct='%1.0f%%', textprops={'color': 'white'},
                        wedgeprops={'edgecolor': '#0d1117', 'linewidth': 2})
                ax2.set_facecolor('#161b22')
                ax2.set_title('Distribution', color='white',
                              fontsize=12, fontweight='bold')
            else:
                ax2.text(0.5, 0.5, 'No Findings', ha='center', va='center',
                         color='white', transform=ax2.transAxes)
                ax2.set_facecolor('#161b22')

            plt.tight_layout()
            chart_path = f"{base_path}_chart.png"
            plt.savefig(chart_path, dpi=150, bbox_inches='tight',
                        facecolor='#0d1117')
            plt.close(fig)
            return chart_path
        except Exception as e:
            logger.debug(f"Chart error: {e}")
            return ''

    # ── Evidence Hash ─────────────────────────────────────────────────────────

    def _evidence_hash(self, results: dict) -> str:
        try:
            data = json.dumps(results, sort_keys=True, default=str)
            return hashlib.sha256(data.encode()).hexdigest()
        except Exception:
            return ''

    # ── Save Files ────────────────────────────────────────────────────────────

    def _save_json(self, report: dict, base: str) -> str:
        path = f"{base}.json"
        with open(path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        return path

    def _save_summary(self, report: dict, base: str) -> str:
        path = f"{base}_summary.txt"
        lines = [
            f"SENTINEL PRO — {report['scan_type'].upper()} REPORT",
            "=" * 60,
            f"Target    : {report['target']}",
            f"Risk      : {report['risk_level']}",
            f"Findings  : {report['total_findings']}",
            f"Time      : {report['timestamp'][:19]}",
            "",
            "EXECUTIVE SUMMARY:",
            report['executive_summary'],
            "",
            "FINDINGS:",
        ]
        for f in report['findings']:
            lines.append(f"  [{f.get('severity','?'):8s}] {f.get('title','')}")
            if f.get('detail'):
                lines.append(f"             {f.get('detail','')[:80]}")
            if f.get('fix'):
                lines.append(f"             FIX: {f.get('fix','')[:80]}")

        if report.get('mitre_attack'):
            lines += ["", "MITRE ATT&CK:"]
            for t in report['mitre_attack']:
                lines.append(f"  {t['technique_id']:12s} {t['technique_name']}")

        lines += [
            "",
            f"Evidence Hash: {report['evidence_hash'][:32]}...",
            f"Standards: {', '.join(report['standards'])}",
        ]
        with open(path, 'w') as f:
            f.write('\n'.join(lines))
        return path

    def _save_html(self, report: dict, base: str, chart_path: str) -> str:
        path = f"{base}.html"

        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_findings = sorted(
            report['findings'],
            key=lambda x: sev_order.get(x.get('severity', 'LOW'), 4)
        )

        findings_html = ''
        for f in sorted_findings:
            sev   = f.get('severity', 'LOW')
            color = SEV_COLORS.get(sev, '#888')
            findings_html += f"""
            <div class="finding" style="border-left:4px solid {color}">
                <span class="badge" style="background:{color}">{sev}</span>
                <strong>{f.get('title','')}</strong>
                <p class="detail">{f.get('detail','')}</p>
                {'<p class="fix">🔧 ' + f.get('fix','') + '</p>' if f.get('fix') else ''}
            </div>"""

        mitre_html = ''
        for t in report.get('mitre_attack', []):
            sev   = t.get('severity', 'LOW')
            color = SEV_COLORS.get(sev, '#888')
            mitre_html += f"""
            <tr>
                <td><a href="https://attack.mitre.org/techniques/{t['technique_id'].replace('.','/')}/"
                       target="_blank" style="color:#58a6ff">{t['technique_id']}</a></td>
                <td>{t['technique_name']}</td>
                <td>{t['finding']}</td>
                <td><span class="badge" style="background:{color}">{sev}</span></td>
            </tr>"""

        chart_img = ''
        if chart_path and Path(chart_path).exists():
            import base64
            with open(chart_path, 'rb') as f:
                b64 = base64.b64encode(f.read()).decode()
            chart_img = f'<img src="data:image/png;base64,{b64}" style="max-width:100%;border-radius:8px">'

        risk_color = SEV_COLORS.get(report['risk_level'], '#888')

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Sentinel Pro — {report['scan_type'].upper()} — {report['target']}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', sans-serif; padding: 24px; }}
  .header {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; margin-bottom: 20px; }}
  .header h1 {{ color: #58a6ff; font-size: 22px; }}
  .header h2 {{ color: #8b949e; font-size: 14px; font-weight: normal; margin-top: 4px; }}
  .risk-badge {{ display: inline-block; padding: 6px 16px; border-radius: 20px;
                 background: {risk_color}; color: white; font-weight: bold; font-size: 16px; margin-top: 10px; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 16px; }}
  .card h3 {{ color: #58a6ff; margin-bottom: 12px; font-size: 15px; border-bottom: 1px solid #30363d; padding-bottom: 8px; }}
  .finding {{ background: #0d1117; border-radius: 6px; padding: 12px; margin-bottom: 10px; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; color: white;
            font-size: 11px; font-weight: bold; margin-right: 8px; }}
  .detail {{ color: #8b949e; font-size: 13px; margin-top: 6px; margin-left: 4px; }}
  .fix {{ color: #3fb950; font-size: 12px; margin-top: 4px; margin-left: 4px; }}
  .exec-summary {{ background: #1c2128; border-left: 4px solid #58a6ff;
                   padding: 16px; border-radius: 0 6px 6px 0; line-height: 1.6; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ background: #21262d; color: #8b949e; padding: 8px 12px; text-align: left; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #21262d; }}
  tr:hover td {{ background: #1c2128; }}
  .meta {{ color: #8b949e; font-size: 12px; margin-top: 8px; }}
  .hash {{ font-family: monospace; font-size: 11px; color: #6e7681; word-break: break-all; }}
  .stats {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 16px; }}
  .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
           padding: 12px 20px; text-align: center; flex: 1; min-width: 100px; }}
  .stat-num {{ font-size: 28px; font-weight: bold; }}
  .stat-label {{ font-size: 12px; color: #8b949e; margin-top: 4px; }}
</style>
</head>
<body>

<div class="header">
  <h1>🛡️ The Sentinel Pro v3.0 — {report['scan_type'].upper()} Report</h1>
  <h2>Target: {report['target']} | {report['timestamp'][:19]}</h2>
  <div class="risk-badge">Risk: {report['risk_level']}</div>
  <p class="meta">Author: {report['author']} | Standards: {', '.join(report['standards'])}</p>
</div>

<div class="stats">
  <div class="stat">
    <div class="stat-num" style="color:{SEV_COLORS.get('CRITICAL','#e74c3c')}">{sum(1 for f in report['findings'] if f.get('severity')=='CRITICAL')}</div>
    <div class="stat-label">CRITICAL</div>
  </div>
  <div class="stat">
    <div class="stat-num" style="color:{SEV_COLORS.get('HIGH','#e67e22')}">{sum(1 for f in report['findings'] if f.get('severity')=='HIGH')}</div>
    <div class="stat-label">HIGH</div>
  </div>
  <div class="stat">
    <div class="stat-num" style="color:{SEV_COLORS.get('MEDIUM','#f39c12')}">{sum(1 for f in report['findings'] if f.get('severity')=='MEDIUM')}</div>
    <div class="stat-label">MEDIUM</div>
  </div>
  <div class="stat">
    <div class="stat-num" style="color:{SEV_COLORS.get('LOW','#27ae60')}">{sum(1 for f in report['findings'] if f.get('severity')=='LOW')}</div>
    <div class="stat-label">LOW</div>
  </div>
  <div class="stat">
    <div class="stat-num" style="color:#58a6ff">{len(report.get('mitre_attack',[]))}</div>
    <div class="stat-label">MITRE TTPs</div>
  </div>
</div>

<div class="card">
  <h3>📋 Executive Summary</h3>
  <div class="exec-summary">{report['executive_summary']}</div>
</div>

{'<div class="card"><h3>📊 Severity Distribution</h3>' + chart_img + '</div>' if chart_img else ''}

<div class="card">
  <h3>🔍 Findings ({len(report['findings'])})</h3>
  {findings_html if findings_html else '<p style="color:#8b949e">No findings.</p>'}
</div>

{'<div class="card"><h3>🎯 MITRE ATT&CK Mapping</h3><table><thead><tr><th>Technique ID</th><th>Technique</th><th>Finding</th><th>Severity</th></tr></thead><tbody>' + mitre_html + '</tbody></table></div>' if mitre_html else ''}

<div class="card">
  <h3>🔐 Evidence Integrity</h3>
  <p>SHA-256: <span class="hash">{report['evidence_hash']}</span></p>
  <p class="meta">Generated: {report['timestamp']} | Tool: {report['tool']}</p>
</div>

</body>
</html>"""

        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)
        return path

    def _save_pdf(self, html_path: str) -> str:
        try:
            from modules.pdf_export import PDFExporter
            exporter = PDFExporter()
            if exporter.available:
                return exporter.html_to_pdf(html_path) or ''
        except Exception:
            pass
        return ''
