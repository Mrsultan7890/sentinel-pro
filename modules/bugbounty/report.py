"""
Bug Bounty Report - JSON + Summary export
"""

import json
import logging
import html
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

def _e(s) -> str:
    """HTML-escape any value safely."""
    return html.escape(str(s) if s is not None else '')


class BugBountyReport:

    def __init__(self, output_dir: str = 'reports'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def save(self, domain: str, data: dict) -> dict:
        ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe = domain.replace('.', '_')

        json_path    = self.output_dir / f"bugbounty_{safe}_{ts}.json"
        summary_path = self.output_dir / f"bugbounty_{safe}_{ts}_summary.txt"
        html_path    = self.output_dir / f"bugbounty_{safe}_{ts}.html"

        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        with open(summary_path, 'w') as f:
            f.write(self._build_summary(domain, data))

        with open(html_path, 'w') as f:
            f.write(self._build_html(domain, data))

        logger.info(f"BugBounty report saved: {json_path}")
        return {'json': str(json_path), 'summary': str(summary_path), 'html': str(html_path)}

    def _build_summary(self, domain: str, data: dict) -> str:
        lines = [
            f"{'='*60}",
            f"  BUG BOUNTY REPORT - {domain}",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"{'='*60}\n",
        ]

        # ── Executive Summary ──────────────────────────────────────────────────
        ssl   = data.get('ssl', {})
        hdrs  = data.get('headers', {})
        eps   = data.get('endpoints', {})
        vulns = data.get('vulns', {})
        cves  = data.get('cves', {})
        nuc   = data.get('nuclei', {})
        tkover = data.get('takeover', {})
        smug  = data.get('smuggling', {})

        critical_items = []
        high_items     = []
        if tkover.get('vulnerable'):
            critical_items.append(f"{len(tkover['vulnerable'])} subdomain takeover(s)")
        if smug.get('findings'):
            critical_items.append("HTTP request smuggling confirmed")
        if cves.get('critical_count', 0) > 0:
            critical_items.append(f"{cves['critical_count']} critical CVE(s)")
        if vulns.get('risk_level') == 'CRITICAL':
            critical_items.append("SQL injection / XSS confirmed")
        if eps.get('critical_count', 0) > 0:
            high_items.append(f"{eps['critical_count']} critical exposed endpoint(s)")
        if ssl.get('grade') == 'F':
            high_items.append("SSL/TLS grade F")
        if nuc.get('high', 0) > 0:
            high_items.append(f"{nuc['high']} high-severity Nuclei finding(s)")

        overall = 'CRITICAL' if critical_items else 'HIGH' if high_items else 'MEDIUM' if eps.get('total_exposed', 0) > 0 else 'LOW'
        lines += [
            "[ EXECUTIVE SUMMARY ]",
            f"  Overall Risk  : {overall}",
            f"  Target        : {domain}",
        ]
        if critical_items:
            lines.append(f"  CRITICAL      : {' | '.join(critical_items)}")
        if high_items:
            lines.append(f"  HIGH          : {' | '.join(high_items)}")
        lines += [
            "",
            "  REMEDIATION PRIORITY:",
        ]
        priority = 1
        for item in critical_items:
            lines.append(f"  {priority}. [CRITICAL] Fix immediately: {item}")
            priority += 1
        for item in high_items:
            lines.append(f"  {priority}. [HIGH] Fix within 7 days: {item}")
            priority += 1
        if not critical_items and not high_items:
            lines.append("  No critical/high findings — review medium findings in full report.")
        lines.append("")
        # ── End Executive Summary ──────────────────────────────────────────────

        # SSL
        ssl = data.get('ssl', {})
        if ssl and not ssl.get('error'):
            lines += [
                f"[ SSL/TLS ] Grade: {ssl.get('grade', 'N/A')}",
                f"  Protocol    : {ssl.get('protocol', 'N/A')}",
                f"  Cipher      : {ssl.get('cipher_name', 'N/A')} ({ssl.get('cipher_bits', 'N/A')} bits)",
                f"  Expires     : {ssl.get('not_after', 'N/A')} ({ssl.get('days_remaining', 'N/A')} days left)",
                f"  Issuer      : {ssl.get('issuer_cn', 'N/A')}",
            ]
            for f in ssl.get('risk_flags', []):
                lines.append(f"  [{f['severity']}] {f['flag']}: {f['detail']}")
            lines.append("")
        elif ssl.get('error'):
            lines += [f"[ SSL/TLS ] ERROR: {ssl['error']}", ""]

        # Headers
        hdrs = data.get('headers', {})
        if hdrs:
            lines += [
                f"[ HTTP HEADERS ] Grade: {hdrs.get('grade', 'N/A')} | Score: {hdrs.get('score', 'N/A')}/100",
            ]
            missing = hdrs.get('missing', [])
            if missing:
                lines.append(f"  Missing ({len(missing)}):")
                for m in missing:
                    lines.append(f"    [{m['severity']}] {m['header']}")
            leaky = hdrs.get('leaky', {})
            if leaky:
                lines.append(f"  Info Leakage:")
                for k, v in leaky.items():
                    lines.append(f"    {k}: {v}")
            cors = hdrs.get('cors', {})
            if cors.get('risk'):
                lines.append(f"  CORS: {cors['risk']}")
            lines.append("")

        # Ports
        ports = data.get('ports', {})
        if ports:
            lines += [
                f"[ PORTS ] Open: {ports.get('total_open', 0)} | High Risk: {ports.get('total_high_risk', 0)}",
            ]
            for p in ports.get('open_ports', []):
                risk_tag = f" ⚠ {p['risk_detail']}" if p['risk'] == 'HIGH' else ''
                lines.append(f"  {p['port']:<6} {p['service']:<20}{risk_tag}")
            lines.append("")

        # Endpoints
        eps = data.get('endpoints', {})
        if eps:
            waf = eps.get('waf', {})
            waf_str = f"WAF: {waf['name']}" if waf.get('detected') else "WAF: Not detected"
            tech = eps.get('technologies', {})
            tech_str = ' | '.join(f"{k}: {v}" for k, v in tech.items()) if tech else 'N/A'
            lines += [
                f"[ ENDPOINTS ] Exposed: {eps.get('total_exposed', 0)} | Critical: {eps.get('critical_count', 0)} | {waf_str}",
                f"  Technologies: {tech_str}",
            ]
            for e in eps.get('exposed', []):
                lines.append(f"  [{e['risk']}] {e['path']} (HTTP {e['status_code']})")
                if e.get('snippet'):
                    lines.append(f"    Preview: {e['snippet'][:80]}")
            lines.append("")

        lines.append(f"{'='*60}")
        return '\n'.join(lines)

    def _build_html(self, domain: str, data: dict) -> str:
        ts      = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ssl     = data.get('ssl', {})
        hdrs    = data.get('headers', {})
        ports   = data.get('ports', {})
        eps     = data.get('endpoints', {})
        shod    = data.get('shodan', {})
        vulns   = data.get('vulns', {})
        js      = data.get('js', {})
        cves    = data.get('cves', {})
        cors    = data.get('cors', {})
        tkover  = data.get('takeover', {})
        oredir  = data.get('open_redirect', {})
        smug    = data.get('smuggling', {})
        dirb    = data.get('dirbuster', {})
        nuc     = data.get('nuclei', {})
        ck      = data.get('cookies', {})
        zt      = data.get('zone_transfer', {})
        fz      = data.get('fuzzer', {})
        tf      = data.get('tech_fingerprint', {})
        ab      = data.get('auth_bypass', {})
        api     = data.get('api', {})
        lfi     = data.get('lfi', {})
        xxe     = data.get('xxe', {})
        ssti    = data.get('ssti', {})
        cj      = data.get('clickjacking', {})
        pp      = data.get('proto_pollution', {})
        oauth   = data.get('oauth', {})

        # Overall risk — now includes new scanners
        risk = 'LOW'
        if (cves.get('critical_count', 0) > 0 or vulns.get('risk_level') == 'CRITICAL'
                or js.get('risk_level') == 'CRITICAL' or tkover.get('vulnerable')
                or smug.get('findings') or nuc.get('critical', 0) > 0
                or cors.get('risk_level') == 'CRITICAL'
                or fz.get('total_findings', 0) > 0):
            risk = 'CRITICAL'
        elif (eps.get('critical_count', 0) > 0 or ssl.get('grade') == 'F'
                or oredir.get('findings') or nuc.get('high', 0) > 0
                or lfi.get('total', 0) > 0 or ab.get('total', 0) > 0
                or cj.get('total', 0) > 0 or oauth.get('total', 0) > 0):
            risk = 'HIGH'
        elif hdrs.get('grade') in ('D', 'F') or ports.get('total_high_risk', 0) > 0:
            risk = 'MEDIUM'
        risk_color = {'CRITICAL': '#e74c3c', 'HIGH': '#e67e22', 'MEDIUM': '#f1c40f', 'LOW': '#2ecc71'}.get(risk, '#95a5a6')

        ssl_grade_color = {'A+': '#2ecc71', 'A': '#2ecc71', 'B': '#f1c40f', 'C': '#e67e22', 'F': '#e74c3c'}.get(ssl.get('grade', 'F'), '#e74c3c')
        hdr_grade_color = {'A+': '#2ecc71', 'A': '#2ecc71', 'B': '#f1c40f', 'C': '#e67e22', 'D': '#e67e22', 'F': '#e74c3c'}.get(hdrs.get('grade', 'F'), '#e74c3c')

        def _rc(risk):
            return {'CRITICAL': '#e74c3c', 'HIGH': '#e67e22', 'MEDIUM': '#f1c40f'}.get(risk, '#7f8c8d')

        def _cc(sev):
            return {'CRITICAL': '#e74c3c', 'HIGH': '#e67e22'}.get(sev.upper(), '#f1c40f')

        ep_rows = ''
        for e in eps.get('exposed', []):
            c = _rc(e['risk'])
            ep_rows += '<tr><td style="color:' + c + ';font-weight:bold">' + _e(e['risk']) + '</td><td>' + _e(e['path']) + '</td><td>' + _e(e['status_code']) + '</td><td style="font-size:11px">' + _e(e.get('snippet','')[:60]) + '</td></tr>'

        port_rows = ''
        for p in ports.get('open_ports', []):
            c = '#e74c3c' if p.get('risk') == 'HIGH' else '#c9d1d9'
            port_rows += '<tr><td style="color:' + c + '">' + _e(p['port']) + '</td><td>' + _e(p['service']) + '</td><td>' + _e(p.get('banner','')[:50]) + '</td><td style="color:' + c + '">' + _e(p.get('risk_detail','')) + '</td></tr>'

        cve_rows = ''
        for c in cves.get('cves', [])[:20]:
            cc = _cc(c['severity'])
            cve_rows += '<tr><td style="color:' + cc + '"><a href="' + _e(c['url']) + '" style="color:' + cc + '">' + _e(c['cve_id']) + '</a></td><td>' + _e(c['severity']) + ' (' + _e(c['score']) + ')</td><td>' + _e(c['tech']) + ' ' + _e(c.get('version') or '') + '</td><td style="font-size:11px">' + _e(c['description'][:80]) + '</td></tr>'

        js_rows = ''
        for s in js.get('secrets', [])[:20]:
            sc = '#e74c3c' if s['severity'] == 'CRITICAL' else '#e67e22'
            js_rows += '<tr><td style="color:' + sc + '">' + _e(s['type']) + '</td><td style="font-size:11px">' + _e(s['file'].split('/')[-1]) + '</td><td style="font-family:monospace;font-size:11px">' + _e(s['match'][:60]) + '</td></tr>'

        vuln_rows = ''
        for v in (vulns.get('sqli', []) + vulns.get('xss', []) + vulns.get('ssrf', [])):
            vc = '#e74c3c' if v['severity'] == 'CRITICAL' else '#e67e22'
            vuln_rows += '<tr><td style="color:' + vc + ';font-weight:bold">' + _e(v['type']) + '</td><td style="font-size:11px">' + _e(v['url'][:60]) + '</td><td>' + _e(v['param']) + '</td><td style="font-size:11px">' + _e(v['evidence']) + '</td></tr>'

        cors_rows = ''
        for fi in cors.get('findings', []):
            fc = '#e74c3c' if fi['severity'] == 'CRITICAL' else '#e67e22'
            cors_rows += '<tr><td style="color:' + fc + ';font-weight:bold">' + _e(fi['severity']) + '</td><td>' + _e(fi['issue']) + '</td><td style="font-size:11px">' + _e(fi['url'][:60]) + '</td><td style="font-size:11px">' + _e(fi['evidence']) + '</td></tr>'

        takeover_rows = ''
        for v in tkover.get('vulnerable', []):
            takeover_rows += '<tr><td style="color:#e74c3c;font-weight:bold">CRITICAL</td><td>' + _e(v['subdomain']) + '</td><td>' + _e(v['service']) + '</td><td style="font-size:11px">' + _e(v['evidence']) + '</td></tr>'

        oredir_rows = ''
        for fi in oredir.get('findings', []):
            oredir_rows += '<tr><td style="color:#e67e22">' + _e(fi['param']) + '</td><td style="font-size:11px">' + _e(fi['payload']) + '</td><td style="font-size:11px">' + _e(fi['location'][:60]) + '</td><td>' + _e(fi['status']) + '</td></tr>'

        smug_rows = ''
        for fi in smug.get('findings', []):
            smug_rows += '<tr><td style="color:#e74c3c;font-weight:bold">' + _e(fi['technique']) + '</td><td style="font-size:11px">' + _e(fi['evidence']) + '</td><td>' + _e(round(fi['time_delta_ms'])) + 'ms</td></tr>'

        dirb_rows = ''
        for r in dirb.get('results', [])[:30]:
            rc = _rc(r['risk'])
            dirb_rows += '<tr><td style="color:' + rc + ';font-weight:bold">' + _e(r['risk']) + '</td><td>' + _e(r['path']) + '</td><td>' + _e(r['status_code']) + '</td><td style="font-size:11px">' + _e(r.get('content_type','')[:40]) + '</td></tr>'

        nuc_rows = ''
        for fi in nuc.get('findings', [])[:30]:
            nc = _cc(fi['severity'])
            nuc_rows += '<tr><td style="color:' + nc + ';font-weight:bold">' + _e(fi['severity'].upper()) + '</td><td>' + _e(fi['name']) + '</td><td style="font-size:11px">' + _e(fi['url'][:60]) + '</td><td style="font-size:11px">' + _e(fi['description'][:80]) + '</td></tr>'

        ck_rows = ''
        for fi in ck.get('findings', []):
            cc2 = '#e74c3c' if fi['severity'] == 'CRITICAL' else '#e67e22' if fi['severity'] == 'HIGH' else '#f1c40f'
            ck_rows += '<tr><td style="color:' + cc2 + ';font-weight:bold">' + _e(fi['severity']) + '</td><td>' + _e(fi['cookie']) + '</td><td>' + _e(fi['issue']) + '</td></tr>'

        zt_rows = ''
        for v in zt.get('vulnerable', []):
            zt_rows += '<tr><td style="color:#e74c3c;font-weight:bold">CRITICAL</td><td>' + _e(v['ns']) + '</td><td>' + _e(v['ns_ip']) + '</td><td>' + _e(v['records_count']) + ' records</td></tr>'

        fz_rows = ''
        for r in fz.get('findings', [])[:30]:
            fc2 = _rc(r['risk'])
            fz_rows += '<tr><td style="color:' + fc2 + ';font-weight:bold">' + _e(r['risk']) + '</td><td style="font-size:11px">' + _e(r['url'][:70]) + '</td><td>' + _e(r['status_code']) + '</td><td style="font-size:11px">' + _e(r['finding_type']) + '</td></tr>'

        tf_rows = ''
        for entry in tf.get('all_findings', []):
            tf_rows += '<tr><td>' + _e(entry['category']) + '</td><td style="font-weight:bold">' + _e(entry['name']) + '</td><td>' + _e(entry.get('version','')) + '</td><td style="color:#8b949e">' + _e(entry['confidence']) + '</td><td style="font-size:11px">' + _e(entry['source']) + '</td></tr>'

        ab_rows = ''
        for f in ab.get('findings', []):
            ac = '#e74c3c' if f['severity'] == 'CRITICAL' else '#e67e22'
            ab_rows += '<tr><td style="color:' + ac + ';font-weight:bold">' + _e(f['severity']) + '</td><td>' + _e(f['type']) + '</td><td style="font-size:11px">' + _e(f['evidence'][:100]) + '</td></tr>'

        api_rows = ''
        for f in api.get('findings', []):
            ac = '#e74c3c' if f['severity'] == 'CRITICAL' else '#e67e22'
            api_rows += '<tr><td style="color:' + ac + ';font-weight:bold">' + _e(f['severity']) + '</td><td>' + _e(f['type']) + '</td><td style="font-size:11px">' + _e(f.get('url','')[:60]) + '</td><td style="font-size:11px">' + _e(f['evidence'][:80]) + '</td></tr>'

        lfi_rows = ''
        for f in lfi.get('findings', []):
            lc = '#e74c3c' if f['severity'] == 'CRITICAL' else '#e67e22'
            lfi_rows += '<tr><td style="color:' + lc + ';font-weight:bold">' + _e(f['severity']) + '</td><td>' + _e(f['param']) + '</td><td style="font-family:monospace;font-size:11px">' + _e(f['payload'][:50]) + '</td><td style="font-size:11px">' + _e(f['evidence']) + '</td></tr>'

        xxe_rows = ''
        for f in xxe.get('findings', []):
            xc = '#e74c3c' if f['severity'] == 'CRITICAL' else '#e67e22'
            xxe_rows += '<tr><td style="color:' + xc + ';font-weight:bold">' + _e(f['severity']) + '</td><td>' + _e(f['type']) + '</td><td style="font-size:11px">' + _e(f.get('url','')[:60]) + '</td><td style="font-size:11px">' + _e(f['evidence']) + '</td></tr>'

        ssti_rows = ''
        for f in ssti.get('findings', []):
            sc2 = '#e74c3c' if f['severity'] == 'CRITICAL' else '#e67e22'
            ssti_rows += '<tr><td style="color:' + sc2 + ';font-weight:bold">' + _e(f['severity']) + '</td><td>' + _e(f['engine']) + '</td><td>' + _e(f['param']) + '</td><td style="font-family:monospace;font-size:11px">' + _e(f['payload'][:40]) + '</td></tr>'

        cj_rows = ''
        for f in cj.get('findings', []):
            cc3 = '#e74c3c' if f['severity'] == 'CRITICAL' else '#e67e22'
            cj_rows += '<tr><td style="color:' + cc3 + ';font-weight:bold">' + _e(f['severity']) + '</td><td>' + _e(f['path']) + '</td><td style="font-size:11px">' + _e(f['detail'][:80]) + '</td><td style="font-size:11px">' + _e(f.get('x_frame_options','')) + '</td></tr>'

        pp_rows = ''
        for f in pp.get('findings', []):
            pc = '#e74c3c' if f['severity'] == 'CRITICAL' else '#e67e22'
            pp_rows += '<tr><td style="color:' + pc + ';font-weight:bold">' + _e(f['severity']) + '</td><td>' + _e(f['method']) + '</td><td style="font-size:11px">' + _e(f['payload'][:60]) + '</td><td style="font-size:11px">' + _e(f['evidence']) + '</td></tr>'

        oauth_rows = ''
        for f in oauth.get('findings', []):
            oc = '#e74c3c' if f['severity'] == 'CRITICAL' else '#e67e22'
            oauth_rows += '<tr><td style="color:' + oc + ';font-weight:bold">' + _e(f['severity']) + '</td><td>' + _e(f['type']) + '</td><td style="font-size:11px">' + _e(f.get('url','')[:60]) + '</td><td style="font-size:11px">' + _e(f['evidence'][:80]) + '</td></tr>'

        # Executive Summary data
        critical_items = []
        high_items = []
        if tkover.get('vulnerable'):
            critical_items.append(f"{len(tkover['vulnerable'])} subdomain takeover(s)")
        if smug.get('findings'):
            critical_items.append("HTTP request smuggling confirmed")
        if cves.get('critical_count', 0) > 0:
            critical_items.append(f"{cves['critical_count']} critical CVE(s)")
        if vulns.get('risk_level') == 'CRITICAL':
            critical_items.append("SQL injection / XSS confirmed")
        if fz.get('total_findings', 0) > 0:
            critical_items.append(f"{fz['total_findings']} sensitive files exposed (fuzzer)")
        if eps.get('critical_count', 0) > 0:  high_items.append(f"{eps['critical_count']} critical exposed endpoint(s)")
        if ssl.get('grade') == 'F':           high_items.append('SSL/TLS grade F')
        if nuc.get('high', 0) > 0:            high_items.append(f"{nuc['high']} high-severity Nuclei finding(s)")
        if zt.get('vulnerable'):              critical_items.append(f"{len(zt['vulnerable'])} DNS zone transfer(s) exposed")
        if lfi.get('total', 0) > 0:           high_items.append(f"{lfi['total']} LFI/RFI finding(s)")
        if ab.get('total', 0) > 0:            high_items.append(f"{ab['total']} auth bypass finding(s)")
        if cj.get('total', 0) > 0:            high_items.append(f"{cj['total']} clickjacking vulnerable page(s)")
        if oauth.get('total', 0) > 0:         high_items.append(f"{oauth['total']} OAuth misconfiguration(s)")
        exec_risk = 'CRITICAL' if critical_items else 'HIGH' if high_items else 'MEDIUM' if eps.get('total_exposed',0) > 0 else 'LOW'
        exec_color = {'CRITICAL':'#e74c3c','HIGH':'#e67e22','MEDIUM':'#f1c40f','LOW':'#2ecc71'}.get(exec_risk,'#95a5a6')
        exec_critical_html = ''.join(f'<li style="color:#e74c3c">🔴 Fix immediately: {_e(i)}</li>' for i in critical_items)
        exec_high_html     = ''.join(f'<li style="color:#e67e22">🟠 Fix within 7 days: {_e(i)}</li>' for i in high_items)
        exec_none_html     = '<li style="color:#2ecc71">✅ No critical/high findings — review medium findings below.</li>' if not critical_items and not high_items else ''

        waf      = eps.get('waf', {})
        waf_str  = _e(waf.get('name', 'Not detected')) if waf.get('detected') else 'Not detected'
        tech     = eps.get('technologies', {})
        tech_str = _e(' | '.join(f'{k}: {v}' for k, v in tech.items())) if tech else 'N/A'
        shodan_str = _e(f"{shod.get('ip','N/A')} | {shod.get('org','N/A')} | {shod.get('country','N/A')}") if shod and not shod.get('error') else _e(shod.get('error', 'N/A'))

        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Bug Bounty - {domain}</title>
<style>
  body{{font-family:monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:20px}}
  h1{{color:#58a6ff}} h2{{color:#79c0ff;border-bottom:1px solid #30363d;padding-bottom:6px;margin-top:24px}}
  .badge{{display:inline-block;padding:4px 12px;border-radius:4px;font-weight:bold;color:#fff;background:{risk_color}}}
  .grade{{display:inline-block;padding:2px 10px;border-radius:4px;font-weight:bold;color:#fff}}
  table{{width:100%;border-collapse:collapse;margin-bottom:16px}}
  th{{background:#161b22;color:#8b949e;text-align:left;padding:8px}}
  td{{padding:7px 8px;border-bottom:1px solid #21262d;font-size:13px}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:16px;margin-bottom:16px}}
  .grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
  a{{color:#58a6ff;text-decoration:none}}
  .stat{{text-align:center;padding:12px}} .stat-num{{font-size:28px;font-weight:bold;color:#58a6ff}} .stat-lbl{{color:#8b949e;font-size:12px}}
</style></head><body>
<h1>🐛 Bug Bounty Report — {domain}</h1>
<div class="card"><table><tr>
  <td class="stat"><div class="stat-num"><span class="grade" style="background:{ssl_grade_color}">{ssl.get('grade','?')}</span></div><div class="stat-lbl">SSL Grade</div></td>
  <td class="stat"><div class="stat-num"><span class="grade" style="background:{hdr_grade_color}">{hdrs.get('grade','?')}</span></div><div class="stat-lbl">Headers Grade</div></td>
  <td class="stat"><div class="stat-num" style="color:#e74c3c">{eps.get('critical_count',0)}</div><div class="stat-lbl">Critical Endpoints</div></td>
  <td class="stat"><div class="stat-num" style="color:#e74c3c">{len(tkover.get('vulnerable',[]))}</div><div class="stat-lbl">Takeovers</div></td>
  <td class="stat"><div class="stat-num" style="color:#e74c3c">{nuc.get('total',0)}</div><div class="stat-lbl">Nuclei Findings</div></td>
  <td class="stat"><div class="stat-num" style="color:#e74c3c">{ck.get('total',0)}</div><div class="stat-lbl">Cookie Issues</div></td>
  <td class="stat"><div class="stat-num" style="color:#{'e74c3c' if zt.get('vulnerable') else '2ecc71'}">{len(zt.get('vulnerable',[]))}</div><div class="stat-lbl">Zone Transfers</div></td>
  <td class="stat"><div class="stat-num" style="color:#e74c3c">{fz.get('total_findings',0)}</div><div class="stat-lbl">Fuzz Findings</div></td>
  <td class="stat"><div class="stat-num" style="color:#58a6ff">{tf.get('total',0)}</div><div class="stat-lbl">Tech Detected</div></td>
  <td class="stat"><div class="stat-num" style="color:#e74c3c">{ab.get('total',0)}</div><div class="stat-lbl">Auth Issues</div></td>
  <td class="stat"><div class="stat-num" style="color:#e74c3c">{api.get('total',0)}</div><div class="stat-lbl">API Issues</div></td>
  <td class="stat"><div class="stat-num" style="color:#e74c3c">{lfi.get('total',0) + xxe.get('total',0) + ssti.get('total',0)}</div><div class="stat-lbl">Injection</div></td>
  <td class="stat"><div class="stat-num" style="color:#e74c3c">{cves.get('total_cves',0)}</div><div class="stat-lbl">CVEs</div></td>
  <td class="stat"><div class="stat-num" style="color:#e74c3c">{len(js.get('secrets',[]))}</div><div class="stat-lbl">JS Secrets</div></td>
  <td class="stat"><div class="stat-num" style="color:#{'e74c3c' if oauth.get('total',0) > 0 else '2ecc71'}">{oauth.get('total',0)}</div><div class="stat-lbl">OAuth Issues</div></td>
  <td class="stat"><div class="stat-num"><span class="badge">{risk}</span></div><div class="stat-lbl">Overall Risk</div></td>
</tr></table></div>

<div class="card" style="border-left:4px solid {exec_color}">
  <h2 style="color:{exec_color};margin-top:0">📋 Executive Summary</h2>
  <table><tr><th>Overall Risk</th><td><span class="badge" style="background:{exec_color}">{exec_risk}</span></td></tr>
  <tr><th>Target</th><td>{_e(domain)}</td></tr>
  <tr><th>Scan Date</th><td>{ts}</td></tr></table>
  <h3 style="color:#79c0ff;margin-top:12px">Remediation Priority</h3>
  <ul style="line-height:1.8;padding-left:20px">{exec_critical_html}{exec_high_html}{exec_none_html}</ul>
</div>

<div class="grid">
  <div><h2>SSL / TLS</h2><div class="card"><table>
    <tr><th>Grade</th><td><span class="grade" style="background:{ssl_grade_color}">{ssl.get('grade','N/A')}</span></td></tr>
    <tr><th>Protocol</th><td>{ssl.get('protocol','N/A')}</td></tr>
    <tr><th>Cipher</th><td>{ssl.get('cipher_name','N/A')} ({ssl.get('cipher_bits','N/A')} bits)</td></tr>
    <tr><th>Expires</th><td>{ssl.get('not_after','N/A')} ({ssl.get('days_remaining','N/A')} days)</td></tr>
    <tr><th>Issuer</th><td>{ssl.get('issuer_cn','N/A')}</td></tr>
  </table></div></div>
  <div><h2>Security Headers</h2><div class="card"><table>
    <tr><th>Grade</th><td><span class="grade" style="background:{hdr_grade_color}">{hdrs.get('grade','N/A')}</span></td></tr>
    <tr><th>Score</th><td>{hdrs.get('score','N/A')}/100</td></tr>
    <tr><th>WAF</th><td>{waf_str}</td></tr>
    <tr><th>Technologies</th><td style="font-size:11px">{tech_str}</td></tr>
    <tr><th>Shodan</th><td style="font-size:11px">{shodan_str}</td></tr>
  </table></div></div>
</div>

<h2>🔴 Subdomain Takeover ({len(tkover.get('vulnerable',[]))})</h2>
<div class="card"><table><tr><th>Severity</th><th>Subdomain</th><th>Service</th><th>Evidence</th></tr>{takeover_rows or '<tr><td colspan=4 style="color:#2ecc71">No takeovers found</td></tr>'}</table></div>

<h2>🔴 HTTP Request Smuggling ({len(smug.get('findings',[]))})</h2>
<div class="card"><table><tr><th>Technique</th><th>Evidence</th><th>Time Delta</th></tr>{smug_rows or '<tr><td colspan=3 style="color:#2ecc71">Not vulnerable</td></tr>'}</table></div>

<h2>🟠 CORS Misconfigurations ({cors.get('total',0)})</h2>
<div class="card"><table><tr><th>Severity</th><th>Issue</th><th>URL</th><th>Evidence</th></tr>{cors_rows or '<tr><td colspan=4 style="color:#2ecc71">No CORS issues found</td></tr>'}</table></div>

<h2>🟠 Open Redirects ({oredir.get('total',0)})</h2>
<div class="card"><table><tr><th>Param</th><th>Payload</th><th>Redirect Location</th><th>Status</th></tr>{oredir_rows or '<tr><td colspan=4 style="color:#2ecc71">No open redirects found</td></tr>'}</table></div>

<h2>🔴 Nuclei Findings ({nuc.get('total',0)}) — Critical: {nuc.get('critical',0)} High: {nuc.get('high',0)}</h2>
<div class="card"><table><tr><th>Severity</th><th>Name</th><th>URL</th><th>Description</th></tr>{nuc_rows or '<tr><td colspan=4 style="color:#2ecc71">No nuclei findings</td></tr>'}</table></div>

<h2>🍪 Cookie Security ({ck.get('total',0)} issue(s) across {len(ck.get('cookies',[]))} cookies)</h2>
<div class="card"><table><tr><th>Severity</th><th>Cookie</th><th>Issue</th></tr>{ck_rows or '<tr><td colspan=3 style="color:#2ecc71">All cookies properly secured</td></tr>'}</table></div>

<h2>🔴 DNS Zone Transfer ({len(zt.get('vulnerable',[]))} vulnerable NS)</h2>
<div class="card"><table><tr><th>Severity</th><th>NS Server</th><th>IP</th><th>Records Leaked</th></tr>{zt_rows or '<tr><td colspan=4 style="color:#2ecc71">All NS servers refused AXFR ✓</td></tr>'}</table></div>

<h2>⚡ Rust Parallel Fuzzer ({fz.get('total_findings',0)} found / {fz.get('total_requests',0)} requests)</h2>
<div class="card"><table><tr><th>Risk</th><th>URL</th><th>Status</th><th>Finding</th></tr>{fz_rows or '<tr><td colspan=4 style="color:#2ecc71">Nothing found</td></tr>'}</table></div>

<h2>🔍 Tech Stack Fingerprint ({tf.get('total',0)} technologies)</h2>
<div class="card"><table><tr><th>Category</th><th>Technology</th><th>Version</th><th>Confidence</th><th>Source</th></tr>{tf_rows or '<tr><td colspan=5 style="color:#8b949e">No technologies detected</td></tr>'}</table></div>

<h2>🔴 Auth Bypass / 2FA ({ab.get('total',0)} finding(s))</h2>
<div class="card"><table><tr><th>Severity</th><th>Type</th><th>Evidence</th></tr>{ab_rows or '<tr><td colspan=3 style="color:#2ecc71">No auth bypass found</td></tr>'}</table></div>

<h2>🔴 API Security ({api.get('total',0)} finding(s) | {len(api.get('endpoints_found',[]))} endpoints)</h2>
<div class="card"><table><tr><th>Severity</th><th>Type</th><th>URL</th><th>Evidence</th></tr>{api_rows or '<tr><td colspan=4 style="color:#2ecc71">No API issues found</td></tr>'}</table></div>

<h2>🔴 LFI / RFI ({lfi.get('total',0)} finding(s))</h2>
<div class="card"><table><tr><th>Severity</th><th>Param</th><th>Payload</th><th>Evidence</th></tr>{lfi_rows or '<tr><td colspan=4 style="color:#2ecc71">No file inclusion vulnerabilities</td></tr>'}</table></div>

<h2>🔴 XXE Injection ({xxe.get('total',0)} finding(s))</h2>
<div class="card"><table><tr><th>Severity</th><th>Type</th><th>URL</th><th>Evidence</th></tr>{xxe_rows or '<tr><td colspan=4 style="color:#2ecc71">No XXE vulnerabilities found</td></tr>'}</table></div>

<h2>🔴 SSTI ({ssti.get('total',0)} finding(s))</h2>
<div class="card"><table><tr><th>Severity</th><th>Engine</th><th>Param</th><th>Payload</th></tr>{ssti_rows or '<tr><td colspan=4 style="color:#2ecc71">No template injection found</td></tr>'}</table></div>

<h2>🟠 Clickjacking ({cj.get('total',0)} vulnerable page(s))</h2>
<div class="card"><table><tr><th>Severity</th><th>Path</th><th>Detail</th><th>X-Frame-Options</th></tr>{cj_rows or '<tr><td colspan=4 style="color:#2ecc71">All pages protected against framing</td></tr>'}</table></div>

<h2>🔴 Prototype Pollution ({pp.get('total',0)} finding(s))</h2>
<div class="card"><table><tr><th>Severity</th><th>Method</th><th>Payload</th><th>Evidence</th></tr>{pp_rows or '<tr><td colspan=4 style="color:#2ecc71">No prototype pollution found</td></tr>'}</table></div>

<h2>🔴 OAuth Misconfigurations ({oauth.get('total',0)} finding(s) | {len(oauth.get('endpoints_found',[]))} endpoint(s) found)</h2>
<div class="card"><table><tr><th>Severity</th><th>Type</th><th>URL</th><th>Evidence</th></tr>{oauth_rows or '<tr><td colspan=4 style="color:#2ecc71">No OAuth misconfigurations found</td></tr>'}</table></div>

<h2>Directory Brute-Force ({dirb.get('total',0)} found / {dirb.get('scanned',0)} scanned)</h2>
<div class="card"><table><tr><th>Risk</th><th>Path</th><th>Status</th><th>Content-Type</th></tr>{dirb_rows or '<tr><td colspan=4 style="color:#2ecc71">Nothing found</td></tr>'}</table></div>

<h2>Exposed Endpoints ({eps.get('total_exposed',0)})</h2>
<div class="card"><table><tr><th>Risk</th><th>Path</th><th>Status</th><th>Preview</th></tr>{ep_rows or '<tr><td colspan=4 style="color:#2ecc71">No exposed endpoints</td></tr>'}</table></div>

<h2>Open Ports ({ports.get('total_open',0)})</h2>
<div class="card"><table><tr><th>Port</th><th>Service</th><th>Banner</th><th>Risk</th></tr>{port_rows or '<tr><td colspan=4>No open ports found</td></tr>'}</table></div>

<h2>Vulnerabilities (SQLi/XSS/SSRF)</h2>
<div class="card"><table><tr><th>Type</th><th>URL</th><th>Param</th><th>Evidence</th></tr>{vuln_rows or '<tr><td colspan=4 style="color:#2ecc71">No vulnerabilities detected</td></tr>'}</table></div>

<h2>JS Secrets ({len(js.get('secrets',[]))})</h2>
<div class="card"><table><tr><th>Type</th><th>File</th><th>Match</th></tr>{js_rows or '<tr><td colspan=3 style="color:#2ecc71">No secrets found</td></tr>'}</table></div>

<h2>CVEs ({cves.get('total_cves',0)}) — Critical: {cves.get('critical_count',0)} High: {cves.get('high_count',0)}</h2>
<div class="card"><table><tr><th>CVE ID</th><th>Severity</th><th>Technology</th><th>Description</th></tr>{cve_rows or '<tr><td colspan=4 style="color:#2ecc71">No CVEs found</td></tr>'}</table></div>

<p style="color:#484f58;font-size:12px">Generated by The Sentinel Pro | {ts}</p>
</body></html>"""
        ts    = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ssl   = data.get('ssl', {})
        hdrs  = data.get('headers', {})
        ports = data.get('ports', {})
        eps   = data.get('endpoints', {})
        shod  = data.get('shodan', {})
        vulns = data.get('vulns', {})
        js    = data.get('js', {})
        cves  = data.get('cves', {})

        # Overall risk
        risk = 'LOW'
        if cves.get('critical_count', 0) > 0 or vulns.get('risk_level') == 'CRITICAL' or js.get('risk_level') == 'CRITICAL':
            risk = 'CRITICAL'
        elif eps.get('critical_count', 0) > 0 or ssl.get('grade') == 'F':
            risk = 'HIGH'
        elif hdrs.get('grade') in ('D', 'F') or ports.get('total_high_risk', 0) > 0:
            risk = 'MEDIUM'
        risk_color = {'CRITICAL': '#e74c3c', 'HIGH': '#e67e22', 'MEDIUM': '#f1c40f', 'LOW': '#2ecc71'}.get(risk, '#95a5a6')

        ssl_grade_color = {'A+': '#2ecc71', 'A': '#2ecc71', 'B': '#f1c40f', 'C': '#e67e22', 'F': '#e74c3c'}.get(ssl.get('grade', 'F'), '#e74c3c')
        hdr_grade_color = {'A+': '#2ecc71', 'A': '#2ecc71', 'B': '#f1c40f', 'C': '#e67e22', 'D': '#e67e22', 'F': '#e74c3c'}.get(hdrs.get('grade', 'F'), '#e74c3c')

        # Endpoint rows
        ep_rows = ''
        for e in eps.get('exposed', []):
            rc = {'CRITICAL': '#e74c3c', 'HIGH': '#e67e22', 'MEDIUM': '#f1c40f'}.get(e['risk'], '#7f8c8d')
            ep_rows += f'<tr><td style="color:{rc};font-weight:bold">{e["risk"]}</td><td>{e["path"]}</td><td>{e["status_code"]}</td><td style="font-size:11px">{e.get("snippet","")[:60]}</td></tr>'

        # Port rows
        port_rows = ''
        for p in ports.get('open_ports', []):
            rc = '#e74c3c' if p.get('risk') == 'HIGH' else '#c9d1d9'
            port_rows += f'<tr><td style="color:{rc}">{p["port"]}</td><td>{p["service"]}</td><td>{p.get("banner","")[:50]}</td><td style="color:{rc}">{p.get("risk_detail","")}</td></tr>'

        # CVE rows
        cve_rows = ''
        for c in cves.get('cves', [])[:20]:
            cc = '#e74c3c' if c['severity'] == 'CRITICAL' else '#e67e22' if c['severity'] == 'HIGH' else '#f1c40f'
            cve_rows += f'<tr><td style="color:{cc}"><a href="{c["url"]}" style="color:{cc}">{c["cve_id"]}</a></td><td style="color:{cc}">{c["severity"]} ({c["score"]})</td><td>{c["tech"]} {c.get("version") or ""}</td><td style="font-size:11px">{c["description"][:80]}</td></tr>'

        # JS secret rows
        js_rows = ''
        for s in js.get('secrets', [])[:20]:
            sc = '#e74c3c' if s['severity'] == 'CRITICAL' else '#e67e22'
            js_rows += f'<tr><td style="color:{sc}">{s["type"]}</td><td style="font-size:11px">{s["file"].split("/")[-1]}</td><td style="font-family:monospace;font-size:11px">{s["match"][:60]}</td></tr>'

        # Vuln rows
        vuln_rows = ''
        for v in (vulns.get('sqli', []) + vulns.get('xss', []) + vulns.get('ssrf', [])):
            vc = '#e74c3c' if v['severity'] == 'CRITICAL' else '#e67e22'
            vuln_rows += f'<tr><td style="color:{vc};font-weight:bold">{v["type"]}</td><td style="font-size:11px">{v["url"][:60]}</td><td>{v["param"]}</td><td style="font-size:11px">{v["evidence"]}</td></tr>'

        waf     = eps.get('waf', {})
        waf_str = waf.get('name', 'Not detected') if waf.get('detected') else 'Not detected'
        tech    = eps.get('technologies', {})
        tech_str = ' | '.join(f'{k}: {v}' for k, v in tech.items()) if tech else 'N/A'
        shodan_str = f"{shod.get('ip','N/A')} | {shod.get('org','N/A')} | {shod.get('country','N/A')}" if shod and not shod.get('error') else shod.get('error', 'N/A')

        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Bug Bounty - {domain}</title>
<style>
  body{{font-family:monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:20px}}
  h1{{color:#58a6ff}} h2{{color:#79c0ff;border-bottom:1px solid #30363d;padding-bottom:6px;margin-top:24px}}
  .badge{{display:inline-block;padding:4px 12px;border-radius:4px;font-weight:bold;color:#fff;background:{risk_color}}}
  .grade{{display:inline-block;padding:2px 10px;border-radius:4px;font-weight:bold;color:#fff}}
  table{{width:100%;border-collapse:collapse;margin-bottom:16px}}
  th{{background:#161b22;color:#8b949e;text-align:left;padding:8px}}
  td{{padding:7px 8px;border-bottom:1px solid #21262d;font-size:13px}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:16px;margin-bottom:16px}}
  .grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
  a{{color:#58a6ff;text-decoration:none}}
  .stat{{text-align:center;padding:12px}} .stat-num{{font-size:28px;font-weight:bold;color:#58a6ff}} .stat-lbl{{color:#8b949e;font-size:12px}}
</style></head><body>
<h1>🐛 Bug Bounty Report — {domain}</h1>
<div class="card">
  <table><tr>
    <td class="stat"><div class="stat-num"><span class="grade" style="background:{ssl_grade_color}">{ssl.get('grade','?')}</span></div><div class="stat-lbl">SSL Grade</div></td>
    <td class="stat"><div class="stat-num"><span class="grade" style="background:{hdr_grade_color}">{hdrs.get('grade','?')}</span></div><div class="stat-lbl">Headers Grade</div></td>
    <td class="stat"><div class="stat-num" style="color:#e74c3c">{eps.get('critical_count',0)}</div><div class="stat-lbl">Critical Endpoints</div></td>
    <td class="stat"><div class="stat-num" style="color:#e74c3c">{cves.get('total_cves',0)}</div><div class="stat-lbl">CVEs Found</div></td>
    <td class="stat"><div class="stat-num" style="color:#e74c3c">{len(js.get('secrets',[]))}</div><div class="stat-lbl">JS Secrets</div></td>
    <td class="stat"><div class="stat-num"><span class="badge">{risk}</span></div><div class="stat-lbl">Overall Risk</div></td>
  </tr></table>
</div>

<div class="grid">
  <div>
    <h2>SSL / TLS</h2>
    <div class="card"><table>
      <tr><th>Grade</th><td><span class="grade" style="background:{ssl_grade_color}">{ssl.get('grade','N/A')}</span></td></tr>
      <tr><th>Protocol</th><td>{ssl.get('protocol','N/A')}</td></tr>
      <tr><th>Cipher</th><td>{ssl.get('cipher_name','N/A')} ({ssl.get('cipher_bits','N/A')} bits)</td></tr>
      <tr><th>Expires</th><td>{ssl.get('not_after','N/A')} ({ssl.get('days_remaining','N/A')} days)</td></tr>
      <tr><th>Issuer</th><td>{ssl.get('issuer_cn','N/A')}</td></tr>
    </table></div>
  </div>
  <div>
    <h2>Security Headers</h2>
    <div class="card"><table>
      <tr><th>Grade</th><td><span class="grade" style="background:{hdr_grade_color}">{hdrs.get('grade','N/A')}</span></td></tr>
      <tr><th>Score</th><td>{hdrs.get('score','N/A')}/100</td></tr>
      <tr><th>WAF</th><td>{waf_str}</td></tr>
      <tr><th>Technologies</th><td style="font-size:11px">{tech_str}</td></tr>
      <tr><th>Shodan</th><td style="font-size:11px">{shodan_str}</td></tr>
    </table></div>
  </div>
</div>

<h2>Exposed Endpoints ({eps.get('total_exposed',0)})</h2>
<div class="card"><table><tr><th>Risk</th><th>Path</th><th>Status</th><th>Preview</th></tr>{ep_rows or '<tr><td colspan=4 style="color:#2ecc71">No exposed endpoints</td></tr>'}</table></div>

<h2>Open Ports ({ports.get('total_open',0)})</h2>
<div class="card"><table><tr><th>Port</th><th>Service</th><th>Banner</th><th>Risk</th></tr>{port_rows or '<tr><td colspan=4>No open ports found</td></tr>'}</table></div>

<h2>Vulnerabilities Found</h2>
<div class="card"><table><tr><th>Type</th><th>URL</th><th>Param</th><th>Evidence</th></tr>{vuln_rows or '<tr><td colspan=4 style="color:#2ecc71">No vulnerabilities detected</td></tr>'}</table></div>

<h2>JS Secrets ({len(js.get('secrets',[]))})</h2>
<div class="card"><table><tr><th>Type</th><th>File</th><th>Match</th></tr>{js_rows or '<tr><td colspan=3 style="color:#2ecc71">No secrets found</td></tr>'}</table></div>

<h2>CVEs ({cves.get('total_cves',0)}) — Critical: {cves.get('critical_count',0)} High: {cves.get('high_count',0)}</h2>
<div class="card"><table><tr><th>CVE ID</th><th>Severity</th><th>Technology</th><th>Description</th></tr>{cve_rows or '<tr><td colspan=4 style="color:#2ecc71">No CVEs found</td></tr>'}</table></div>

<p style="color:#484f58;font-size:12px">Generated by The Sentinel Pro | {ts}</p>
</body></html>"""
