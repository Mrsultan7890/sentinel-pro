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
Recon Report - JSON + Summary export
"""

import json
import logging
import html
from datetime import datetime
from pathlib import Path

from modules.report_signature import sign_json, get_html_footer, get_txt_footer

logger = logging.getLogger(__name__)

def _e(s) -> str:
    return html.escape(str(s) if s is not None else '')


class ReconReport:

    def __init__(self, output_dir: str = 'reports'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def save(self, domain: str, data: dict) -> dict:
        """Save full JSON report + summary + HTML. Returns file paths."""
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe = domain.replace('.', '_')

        json_path    = self.output_dir / f"recon_{safe}_{ts}.json"
        summary_path = self.output_dir / f"recon_{safe}_{ts}_summary.txt"
        html_path    = self.output_dir / f"recon_{safe}_{ts}.html"

        with open(json_path, 'w') as f:
            json.dump(sign_json(data), f, indent=2, default=str)

        with open(summary_path, 'w') as f:
            f.write(self._build_summary(domain, data) + get_txt_footer())

        with open(html_path, 'w') as f:
            f.write(self._build_html(domain, data))

        logger.info(f"Recon report saved: {json_path}")
        return {'json': str(json_path), 'summary': str(summary_path), 'html': str(html_path)}

    def _build_summary(self, domain: str, data: dict) -> str:
        lines = [
            f"{'='*60}",
            f"  RECON REPORT - {domain}",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"{'='*60}\n",
        ]

        # ── Executive Summary ──────────────────────────────────────────────────
        subs  = data.get('subdomains', {})
        ghd   = data.get('github_dorks', {})
        ca    = data.get('cloud_assets', {})
        flags = data.get('whois', {}).get('risk_flags', [])

        critical_items = []
        high_items     = []
        if ghd.get('total_secrets', 0) > 0:
            critical_items.append(f"{ghd['total_secrets']} GitHub secret(s) exposed")
        if ca.get('risk_level') == 'CRITICAL':
            critical_items.append(f"{ca.get('total',0)} public cloud asset(s) found")
        if any(f['severity'] == 'CRITICAL' for f in flags):
            critical_items.append("Critical WHOIS/DNS risk flags")
        if subs.get('total_found', 0) > 50:
            high_items.append(f"{subs['total_found']} subdomains discovered")
        if ca.get('risk_level') == 'HIGH':
            high_items.append(f"{ca.get('total',0)} cloud asset(s) found")

        overall = 'CRITICAL' if critical_items else 'HIGH' if high_items else 'MEDIUM' if subs.get('total_found',0) > 0 else 'LOW'
        lines += [
            "[ EXECUTIVE SUMMARY ]",
            f"  Overall Risk  : {overall}",
            f"  Target        : {domain}",
            f"  Subdomains    : {subs.get('total_found', 0)} found | Alive: {len([s for s in subs.get('subdomains',[]) if s.get('alive')])}",
        ]
        if critical_items:
            lines.append(f"  CRITICAL      : {' | '.join(critical_items)}")
        if high_items:
            lines.append(f"  HIGH          : {' | '.join(high_items)}")
        lines += ["", "  REMEDIATION PRIORITY:"]
        priority = 1
        for item in critical_items:
            lines.append(f"  {priority}. [CRITICAL] Fix immediately: {item}")
            priority += 1
        for item in high_items:
            lines.append(f"  {priority}. [HIGH] Review within 7 days: {item}")
            priority += 1
        if not critical_items and not high_items:
            lines.append("  No critical/high findings — review full report for medium findings.")
        lines.append("")
        # ── End Executive Summary ──────────────────────────────────────────────

        # WHOIS
        whois = data.get('whois', {}).get('whois', {})
        if whois and not whois.get('error'):
            lines += [
                "[ WHOIS ]",
                f"  Registrar    : {whois.get('registrar', 'N/A')}",
                f"  Created      : {whois.get('creation_date', 'N/A')}",
                f"  Expires      : {whois.get('expiration_date', 'N/A')}",
                f"  Org          : {whois.get('org', 'N/A')}",
                f"  Country      : {whois.get('country', 'N/A')}",
                f"  Name Servers : {', '.join(whois.get('name_servers', [])[:3])}",
                "",
            ]

        # DNS
        dns = data.get('whois', {}).get('dns', {})
        if dns:
            lines.append("[ DNS RECORDS ]")
            for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SPF', 'DMARC']:
                vals = dns.get(rtype, [])
                if vals:
                    lines.append(f"  {rtype:<8}: {', '.join(str(v) for v in vals[:3])}")
            lines.append("")

        # Risk flags
        flags = data.get('whois', {}).get('risk_flags', [])
        if flags:
            lines.append("[ RISK FLAGS ]")
            for f in flags:
                lines.append(f"  [{f['severity']}] {f['flag']}: {f['detail']}")
            lines.append("")

        # Subdomains
        subs = data.get('subdomains', {})
        total = subs.get('total_found', 0)
        lines.append(f"[ SUBDOMAINS ] Total: {total}")
        sources = subs.get('sources', {})
        for src, count in sources.items():
            lines.append(f"  {src}: {count} found")
        lines.append("")
        for s in subs.get('subdomains', [])[:20]:
            alive = '✓' if s.get('alive') else '✗'
            lines.append(f"  {alive} {s['subdomain']:<40} {s['ip']}")
        if total > 20:
            lines.append(f"  ... and {total - 20} more (see JSON report)")

        lines.append(f"\n{'='*60}")
        return '\n'.join(lines)

    def _build_html(self, domain: str, data: dict) -> str:
        ts  = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        def _payment_trail_html(d: dict) -> str:
            pay = d.get('payment_profiles', {})
            found = [r for r in pay.get('results', []) if r.get('found')]
            if not found:
                return ''
            rows = ''.join(
                f'<tr><td style="color:#00b894;font-weight:bold">{_e(r["app"])}</td>'
                f'<td>{_e(r["country"])}</td>'
                f'<td style="color:#79c0ff">{_e(r["name"])}</td>'
                f'<td>{"<img src=\'" + _e(r["profile_pic"]) + "\' style=\'height:32px;border-radius:50%\'>" if r.get("profile_pic") else "N/A"}</td>'
                f'<td><a href="{_e(r.get("source_url",""))}" style="color:#58a6ff">{_e(r.get("source_url","")[:50])}</a></td>'
                f'<td style="color:{"#e74c3c" if r["risk_level"]=="HIGH" else "#f1c40f"}">{_e(r["risk_level"])}</td></tr>'
                for r in found
            )
            return f'''<h2>💳 Financial Trail ({len(found)} payment app profile(s) found)</h2>
<div class="card">
  <table><tr><th>App</th><th>Country</th><th>Real Name</th><th>Photo</th><th>URL</th><th>Risk</th></tr>{rows}</table>
</div>'''

        subs = data.get('subdomains', {})
        whois_d = data.get('whois', {}).get('whois', {})
        dns   = data.get('whois', {}).get('dns', {})
        flags = data.get('whois', {}).get('risk_flags', [])
        wb    = data.get('wayback', {})
        dh    = data.get('dns_history', {})
        gd    = data.get('google_dorks', {})
        ghd   = data.get('github_dorks', {})
        go    = data.get('go_scraper', {})
        asn   = data.get('asn', {})
        ca    = data.get('cloud_assets', {})
        ct    = data.get('cert_transparency', {})
        jo    = data.get('job_osint', {})

        # Risk level from flags
        severities = [f['severity'] for f in flags]
        all_risk_flags = flags + asn.get('risk_flags',[]) + (ca.get('risk_flags',[]) if isinstance(ca,dict) else []) + ct.get('risk_flags',[])
        severities = [f['severity'] for f in all_risk_flags if isinstance(f,dict)]
        risk = 'CRITICAL' if 'CRITICAL' in severities else 'HIGH' if 'HIGH' in severities else 'MEDIUM' if 'MEDIUM' in severities else 'LOW'
        if ca.get('risk_level') == 'CRITICAL':
            risk = 'CRITICAL'
        elif ca.get('risk_level') == 'HIGH' and risk not in ('CRITICAL',):
            risk = 'HIGH'
        risk_color = {'CRITICAL': '#e74c3c', 'HIGH': '#e67e22', 'MEDIUM': '#f1c40f', 'LOW': '#2ecc71'}.get(risk, '#95a5a6')

        # Subdomain rows
        sub_rows = ''
        for s in subs.get('subdomains', [])[:50]:
            alive_color = '#2ecc71' if s.get('alive') else '#7f8c8d'
            alive_txt   = 'Alive' if s.get('alive') else 'Dead'
            sub_rows += f'<tr><td style="color:{alive_color}">{alive_txt}</td><td>{_e(s["subdomain"])}</td><td>{_e(s.get("ip","N/A"))}</td></tr>'

        # DNS rows
        dns_rows = ''
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SPF', 'DMARC']:
            vals = dns.get(rtype, [])
            if vals:
                dns_rows += f'<tr><td style="color:#79c0ff">{rtype}</td><td>{"<br>".join(_e(v) for v in vals[:3])}</td></tr>'

        # Flag rows
        flag_rows = ''
        for rf in flags:
            fc = {'CRITICAL': '#e74c3c', 'HIGH': '#e67e22', 'MEDIUM': '#f1c40f'}.get(rf['severity'], '#95a5a6')
            flag_rows += f'<tr><td style="color:{fc};font-weight:bold">{_e(rf["severity"])}</td><td>{_e(rf["flag"])}</td><td>{_e(rf["detail"])}</td></tr>'

        # Wayback interesting
        wb_rows = ''
        for u in wb.get('interesting_urls', [])[:20]:
            wb_rows += f'<tr><td><a href="{_e(u["url"])}">{_e(u["url"][:80])}</a></td><td>{_e(u.get("timestamp","N/A"))}</td></tr>'

        # GitHub findings
        gh_rows = ''
        for f in ghd.get('findings', [])[:20]:
            fc = '#e74c3c' if f['severity'] == 'CRITICAL' else '#e67e22'
            gh_rows += f'<tr><td style="color:{fc}">{_e(f["secret_type"])}</td><td><a href="{_e(f["url"])}">{_e(f["repo"])}/{_e(f["path"])}</a></td><td style="font-family:monospace;font-size:11px">{_e(f["match"][:60])}</td></tr>'

        # Google dork rows
        gd_rows = ''
        for cat, findings in gd.get('by_category', {}).items():
            for f in findings[:3]:
                sev = f.get('severity', 'LOW')
                sc  = {'CRITICAL': '#e74c3c', 'HIGH': '#e67e22', 'MEDIUM': '#f1c40f'}.get(sev, '#7f8c8d')
                gd_rows += f'<tr><td style="color:{sc}">{_e(cat)}</td><td><a href="{_e(f["url"])}">{_e(f["title"][:60])}</a></td></tr>'

        # ASN rows
        asn_rows = ''
        for a in asn.get('asns', []):
            cloud_tag = f" ({_e(a['cloud_provider'])})" if a.get('is_cloud') else ''
            asn_rows += '<tr><td style="color:#79c0ff">' + _e(a['asn']) + '</td><td>' + _e(a['name'][:50]) + cloud_tag + '</td><td>' + _e(a.get('country','')) + '</td><td>' + _e(a.get('city','')) + '</td></tr>'

        prefix_rows = ''
        for p in asn.get('prefixes', [])[:30]:
            prefix_rows += '<tr><td style="font-family:monospace">' + _e(p['prefix']) + '</td><td>' + _e(p.get('description','')[:50]) + '</td><td>' + _e(p.get('country','')) + '</td></tr>'

        # Cloud asset rows
        ca_rows = ''
        for f in ca.get('findings', []):
            cc = '#e74c3c' if f['severity'] == 'CRITICAL' else '#e67e22' if f['severity'] == 'HIGH' else '#f1c40f'
            pub = 'PUBLIC' if f.get('public') else 'Private'
            ca_rows += '<tr><td style="color:' + cc + ';font-weight:bold">' + _e(f['severity']) + '</td><td>' + _e(f['provider']) + '</td><td><a href="' + _e(f['url']) + '">' + _e(f['name']) + '</a></td><td style="color:' + cc + '">' + pub + '</td><td style="font-size:11px">' + _e(f['evidence']) + '</td></tr>'

        # CT subdomain rows
        ct_rows = ''
        for s in ct.get('subdomains', [])[:50]:
            ct_rows += '<tr><td>' + _e(s) + '</td></tr>'

        ct_cert_rows = ''
        for c in ct.get('certificates', [])[:20]:
            exp_color = '#e74c3c' if c.get('expired') else '#c9d1d9'
            ct_cert_rows += '<tr><td style="color:' + exp_color + '">' + _e(c['common_name']) + '</td><td>' + _e(c['issuer']) + '</td><td>' + _e(c['not_after'][:10]) + '</td><td>' + ('EXPIRED' if c.get('expired') else 'Valid') + '</td></tr>'

        # Job OSINT rows
        job_rows = ''
        for j in jo.get('jobs_found', [])[:20]:
            job_rows += '<tr><td>' + _e(j['source']) + '</td><td>' + _e(j['title']) + '</td><td>' + _e(j.get('location','')) + '</td><td><a href="' + _e(j.get('url','#')) + '">Link</a></td></tr>'

        tech_rows = ''
        for cat, techs in jo.get('tech_stack', {}).items():
            tech_rows += '<tr><td style="color:#79c0ff">' + _e(cat) + '</td><td>' + _e(', '.join(techs[:10])) + '</td></tr>'

        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Recon - {domain}</title>
<style>
  body{{font-family:monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:20px}}
  h1{{color:#58a6ff}} h2{{color:#79c0ff;border-bottom:1px solid #30363d;padding-bottom:6px;margin-top:24px}}
  .badge{{display:inline-block;padding:4px 12px;border-radius:4px;font-weight:bold;color:#fff;background:{risk_color}}}
  table{{width:100%;border-collapse:collapse;margin-bottom:16px}}
  th{{background:#161b22;color:#8b949e;text-align:left;padding:8px}}
  td{{padding:7px 8px;border-bottom:1px solid #21262d;font-size:13px}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:16px;margin-bottom:16px}}
  .grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
  a{{color:#58a6ff;text-decoration:none}} a:hover{{text-decoration:underline}}
  .stat{{text-align:center;padding:12px}} .stat-num{{font-size:28px;font-weight:bold;color:#58a6ff}} .stat-lbl{{color:#8b949e;font-size:12px}}
</style></head><body>
<h1>🔍 Recon Report — {domain}</h1>
<div class="card">
  <table><tr>
    <td class="stat"><div class="stat-num">{subs.get('total_found',0)}</div><div class="stat-lbl">Subdomains</div></td>
    <td class="stat"><div class="stat-num">{wb.get('total_urls',0)}</div><div class="stat-lbl">Wayback URLs</div></td>
    <td class="stat"><div class="stat-num">{len(flags)}</div><div class="stat-lbl">Risk Flags</div></td>
    <td class="stat"><div class="stat-num">{ghd.get('total_secrets',0)}</div><div class="stat-lbl">GitHub Secrets</div></td>
    <td class="stat"><div class="stat-num">{ct.get('total_unique_subdomains',0)}</div><div class="stat-lbl">CT Subdomains</div></td>
    <td class="stat"><div class="stat-num" style="color:#{'e74c3c' if ca.get('total',0) > 0 else '2ecc71'}">{ca.get('total',0)}</div><div class="stat-lbl">Cloud Assets</div></td>
    <td class="stat"><div class="stat-num">{len(asn.get('prefixes',[]))}</div><div class="stat-lbl">IP Prefixes</div></td>
    <td class="stat"><div class="stat-num"><span class="badge">{risk}</span></div><div class="stat-lbl">Risk Level</div></td>
  </tr></table>
</div>

<div class="card" style="border-left:4px solid {risk_color}">
  <h2 style="color:{risk_color};margin-top:0">📋 Executive Summary</h2>
  <table><tr><th>Overall Risk</th><td><span class="badge">{risk}</span></td></tr>
  <tr><th>Target</th><td>{_e(domain)}</td></tr>
  <tr><th>Subdomains Found</th><td>{subs.get('total_found',0)} total | {len([s for s in subs.get('subdomains',[]) if s.get('alive')])} alive</td></tr>
  <tr><th>Scan Date</th><td>{ts}</td></tr></table>
  <h3 style="color:#79c0ff;margin-top:12px">Remediation Priority</h3>
  <ul style="line-height:1.8;padding-left:20px">
    {''.join(f"<li style='color:#e74c3c'>🔴 Fix immediately: {_e(i)}</li>" for i in ([f"{ghd.get('total_secrets',0)} GitHub secret(s) exposed"] if ghd.get('total_secrets',0) > 0 else []) + ([f"{ca.get('total',0)} public cloud asset(s) found"] if ca.get('risk_level') in ('CRITICAL',) else []) + (["Critical WHOIS/DNS risk flags"] if any(f['severity']=='CRITICAL' for f in flags) else []))}
    {''.join(f"<li style='color:#e67e22'>🟠 Review within 7 days: {_e(i)}</li>" for i in ([f"{subs.get('total_found',0)} subdomains discovered"] if subs.get('total_found',0) > 50 else []) + ([f"{ca.get('total',0)} cloud asset(s) found"] if ca.get('risk_level') == 'HIGH' else []))}
    {'<li style="color:#2ecc71">✅ No critical/high findings — review full report for medium findings.</li>' if risk == 'LOW' else ''}
  </ul>
</div>
  <div>
    <h2>WHOIS</h2>
    <div class="card"><table>
      <tr><th>Registrar</th><td>{whois_d.get('registrar','N/A')}</td></tr>
      <tr><th>Created</th><td>{whois_d.get('creation_date','N/A')}</td></tr>
      <tr><th>Expires</th><td>{whois_d.get('expiration_date','N/A')}</td></tr>
      <tr><th>Org</th><td>{whois_d.get('org','N/A')}</td></tr>
      <tr><th>Country</th><td>{whois_d.get('country','N/A')}</td></tr>
    </table></div>
  </div>
  <div>
    <h2>DNS Records</h2>
    <div class="card"><table><tr><th>Type</th><th>Value</th></tr>{dns_rows or '<tr><td colspan=2>No records</td></tr>'}</table></div>
  </div>
</div>

<h2>Risk Flags</h2>
<div class="card"><table><tr><th>Severity</th><th>Flag</th><th>Detail</th></tr>{flag_rows or '<tr><td colspan=3 style="color:#2ecc71">No risk flags</td></tr>'}</table></div>

<h2>Subdomains ({subs.get('total_found',0)} found)</h2>
<div class="card"><table><tr><th>Status</th><th>Subdomain</th><th>IP</th></tr>{sub_rows or '<tr><td colspan=3>None found</td></tr>'}</table></div>

<h2>Wayback Machine — Interesting URLs</h2>
<div class="card"><table><tr><th>URL</th><th>Timestamp</th></tr>{wb_rows or '<tr><td colspan=2>None found</td></tr>'}</table></div>

<h2>GitHub Secrets Found</h2>
<div class="card"><table><tr><th>Type</th><th>File</th><th>Match</th></tr>{gh_rows or '<tr><td colspan=3 style="color:#2ecc71">No secrets found</td></tr>'}</table></div>

<h2>Google Dork Results</h2>
<div class="card"><table><tr><th>Category</th><th>URL</th></tr>{gd_rows or '<tr><td colspan=2>No results / SERPAPI_KEY not set</td></tr>'}</table></div>

<h2>🌐 ASN / IP Range Mapper ({len(asn.get('asns',[]))} ASN(s) | {asn.get('total_ips_in_range',0):,} IPs)</h2>
<div class="card">
  <table><tr><th>ASN</th><th>Organization</th><th>Country</th><th>City</th></tr>{asn_rows or '<tr><td colspan=4 style="color:#8b949e">No ASN data</td></tr>'}</table>
  <h3 style="color:#79c0ff;margin-top:12px">Announced Prefixes ({len(asn.get('prefixes',[]))})</h3>
  <table><tr><th>Prefix</th><th>Description</th><th>Country</th></tr>{prefix_rows or '<tr><td colspan=3 style="color:#8b949e">No prefixes</td></tr>'}</table>
</div>

<h2>☁️ Cloud Asset Discovery ({ca.get('total',0)} asset(s) found)</h2>
<div class="card"><table><tr><th>Severity</th><th>Provider</th><th>Name</th><th>Access</th><th>Evidence</th></tr>{ca_rows or '<tr><td colspan=5 style="color:#2ecc71">No exposed cloud assets found</td></tr>'}</table></div>

<h2>📜 Certificate Transparency ({ct.get('total_certs',0)} certs | {ct.get('total_unique_subdomains',0)} subdomains)</h2>
<div class="card">
  <h3 style="color:#79c0ff">Subdomains from CT Logs</h3>
  <table><tr><th>Subdomain</th></tr>{ct_rows or '<tr><td style="color:#8b949e">None found</td></tr>'}</table>
  <h3 style="color:#79c0ff;margin-top:12px">Recent Certificates</h3>
  <table><tr><th>Common Name</th><th>Issuer</th><th>Expires</th><th>Status</th></tr>{ct_cert_rows or '<tr><td colspan=4 style="color:#8b949e">None</td></tr>'}</table>
</div>

<h2>💼 Job Posting OSINT ({jo.get('total_jobs',0)} jobs | Tech Stack Leaked)</h2>
<div class="card">
  <table><tr><th>Category</th><th>Technologies</th></tr>{tech_rows or '<tr><td colspan=2 style="color:#8b949e">No tech stack data found</td></tr>'}</table>
  <h3 style="color:#79c0ff;margin-top:12px">Job Postings Found</h3>
  <table><tr><th>Source</th><th>Title</th><th>Location</th><th>URL</th></tr>{job_rows or '<tr><td colspan=4 style="color:#8b949e">No job postings found</td></tr>'}</table>
</div>

{_payment_trail_html(data)}

{get_html_footer()}
</body></html>"""
