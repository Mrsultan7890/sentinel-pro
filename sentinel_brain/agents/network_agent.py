"""
Network Agent — Deep Network Scanning
======================================
- masscan: fast full port discovery
- nmap: deep service fingerprinting
- SSL/TLS audit
- Firewall/WAF detection
- Internal network discovery

Author: @who_is_the_black_hat
"""

import logging
from sentinel_brain.kali_controller import KaliController
from sentinel_brain.memory import Memory

logger = logging.getLogger(__name__)

_SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

RISKY_PORTS = {
    21:    ('FTP',        'HIGH',     'Anonymous FTP possible'),
    22:    ('SSH',        'MEDIUM',   'Brute force possible'),
    23:    ('Telnet',     'CRITICAL', 'Unencrypted protocol'),
    25:    ('SMTP',       'MEDIUM',   'Email relay possible'),
    53:    ('DNS',        'MEDIUM',   'Zone transfer possible'),
    80:    ('HTTP',       'LOW',      'Web server'),
    443:   ('HTTPS',      'LOW',      'Web server'),
    445:   ('SMB',        'HIGH',     'EternalBlue/ransomware risk'),
    1433:  ('MSSQL',      'HIGH',     'Database exposed'),
    3306:  ('MySQL',      'HIGH',     'Database exposed'),
    3389:  ('RDP',        'HIGH',     'Remote desktop exposed'),
    5432:  ('PostgreSQL', 'HIGH',     'Database exposed'),
    5900:  ('VNC',        'CRITICAL', 'Remote desktop unencrypted'),
    6379:  ('Redis',      'CRITICAL', 'No auth by default'),
    8080:  ('HTTP-Alt',   'MEDIUM',   'Web server alternate port'),
    8443:  ('HTTPS-Alt',  'MEDIUM',   'Web server alternate port'),
    9200:  ('Elasticsearch','CRITICAL','No auth by default'),
    27017: ('MongoDB',    'CRITICAL', 'No auth by default'),
    2375:  ('Docker',     'CRITICAL', 'Docker API exposed'),
}


class NetworkAgent:
    NAME = 'network_agent'

    def __init__(self, kali: KaliController, memory: Memory, sentinel=None):
        self.kali     = kali
        self.memory   = memory
        self.sentinel = sentinel

    def run(self, target: str, fast: bool = False) -> dict:
        logger.info(f"[NetworkAgent] {target} fast={fast}")
        result = {}

        # ── Step 1: masscan fast discovery ────────────────────────────────────
        if self.kali.tool_available('masscan') and not fast:
            result['masscan'] = self._run_masscan(target)
            open_ports = result['masscan'].get('ports', [])
        else:
            open_ports = []

        # ── Step 2: nmap deep scan ────────────────────────────────────────────
        result['nmap'] = self._run_nmap_deep(target, open_ports)

        # ── Step 3: SSL/TLS audit ─────────────────────────────────────────────
        nmap_ports = result['nmap'].get('open_ports', [])
        https_ports = [p['port'] for p in nmap_ports
                       if p.get('service', '') in ('https', 'ssl', 'http') and p['port'] in (443, 8443)]
        if https_ports:
            result['sslscan'] = self._run_sslscan(target, https_ports[0])

        # ── Step 4: Service-specific scans ────────────────────────────────────
        result['service_scans'] = self._service_specific_scans(target, nmap_ports)

        # ── Findings ──────────────────────────────────────────────────────────
        findings = self._extract_findings(target, result)
        risk     = self._overall_risk(findings)

        all_ports = [p['port'] for p in nmap_ports]
        summary   = (
            f"{len(all_ports)} open ports: {all_ports[:10]} | "
            f"{len(findings)} findings | risk={risk}"
        )

        self.memory.remember_scan(target, 'network', risk, summary, result)
        for f in findings:
            self.memory.remember_finding(
                target, self.NAME, f['severity'], f['title'], f['detail'], f.get('fix', '')
            )
        self.memory.remember_decision(target, self.NAME, 'network', 'Network scan', summary)

        result['_findings']      = findings
        result['_risk']          = risk
        result['_agent_summary'] = summary
        return result

    # ── masscan ───────────────────────────────────────────────────────────────

    def _run_masscan(self, target: str) -> dict:
        result = {'ports': [], 'total': 0}
        r = self.kali.run(
            f'masscan {target} -p1-65535 --rate=1000 2>/dev/null | head -100',
            timeout=120
        )
        import re
        for line in r['stdout'].splitlines():
            m = re.search(r'port (\d+)/(\w+)', line)
            if m:
                result['ports'].append(int(m.group(1)))
        result['total'] = len(result['ports'])
        logger.info(f"[NetworkAgent] masscan: {result['total']} ports")
        return result

    # ── nmap deep ─────────────────────────────────────────────────────────────

    def _run_nmap_deep(self, target: str, ports: list = None) -> dict:
        if ports:
            port_str = ','.join(str(p) for p in ports[:100])
            cmd = f'nmap -sV -sC -A -p {port_str} {target} 2>/dev/null'
        else:
            cmd = f'nmap -sV -sC -T4 --open -p- --min-rate 1000 {target} 2>/dev/null'

        r = self.kali.run(cmd, timeout=180)
        parsed = r.get('parsed', {})
        logger.info(f"[NetworkAgent] nmap: {parsed.get('total', 0)} open ports")
        return parsed

    # ── SSL/TLS ───────────────────────────────────────────────────────────────

    def _run_sslscan(self, target: str, port: int = 443) -> dict:
        result = {'grade': 'Unknown', 'issues': []}
        r = self.kali.run(
            f'sslscan --no-colour {target}:{port} 2>/dev/null',
            timeout=30
        )
        out = r['stdout']

        import re
        # TLS versions
        if re.search(r'TLSv1\.0.*enabled', out, re.I):
            result['issues'].append({'severity': 'HIGH', 'issue': 'TLS 1.0 enabled'})
        if re.search(r'TLSv1\.1.*enabled', out, re.I):
            result['issues'].append({'severity': 'MEDIUM', 'issue': 'TLS 1.1 enabled'})
        if re.search(r'SSLv[23].*enabled', out, re.I):
            result['issues'].append({'severity': 'CRITICAL', 'issue': 'SSLv2/3 enabled'})

        # Weak ciphers
        if re.search(r'RC4|DES|NULL|EXPORT|anon', out, re.I):
            result['issues'].append({'severity': 'HIGH', 'issue': 'Weak cipher suites'})

        # Certificate
        if re.search(r'expired', out, re.I):
            result['issues'].append({'severity': 'HIGH', 'issue': 'Certificate expired'})

        result['raw'] = out[:500]
        return result

    # ── Service-specific scans ────────────────────────────────────────────────

    def _service_specific_scans(self, target: str, ports: list) -> dict:
        results = {}
        for port_info in ports[:10]:
            port = port_info.get('port')
            svc  = port_info.get('service', '').lower()

            if port == 21 or 'ftp' in svc:
                r = self.kali.run(
                    f'nmap --script ftp-anon,ftp-vuln* -p 21 {target} 2>/dev/null',
                    timeout=20
                )
                results['ftp'] = r['stdout'][:300]

            elif port == 445 or 'smb' in svc:
                r = self.kali.run(
                    f'nmap --script smb-vuln*,smb-security-mode -p 445 {target} 2>/dev/null',
                    timeout=30
                )
                results['smb'] = r['stdout'][:300]

            elif port == 3306 or 'mysql' in svc:
                r = self.kali.run(
                    f'nmap --script mysql-info,mysql-empty-password -p 3306 {target} 2>/dev/null',
                    timeout=20
                )
                results['mysql'] = r['stdout'][:300]

            elif port == 6379 or 'redis' in svc:
                r = self.kali.run(
                    f'redis-cli -h {target} ping 2>/dev/null',
                    timeout=10
                )
                if 'PONG' in r['stdout']:
                    results['redis'] = 'UNAUTHENTICATED — redis responds to PING'

            elif port == 27017 or 'mongo' in svc:
                r = self.kali.run(
                    f'nmap --script mongodb-info -p 27017 {target} 2>/dev/null',
                    timeout=20
                )
                results['mongodb'] = r['stdout'][:300]

        return results

    # ── Findings ──────────────────────────────────────────────────────────────

    def _extract_findings(self, target: str, data: dict) -> list:
        findings = []

        # Risky open ports
        nmap = data.get('nmap', {})
        for port_info in nmap.get('open_ports', []):
            port = port_info.get('port')
            if port in RISKY_PORTS:
                svc_name, sev, reason = RISKY_PORTS[port]
                findings.append({
                    'type': f'port_{port}',
                    'title': f'{svc_name} Port Open ({port})',
                    'severity': sev,
                    'detail': f"Port {port} ({svc_name}) open — {reason} | "
                              f"version: {port_info.get('version','unknown')}",
                    'fix': f'Close port {port} if not needed, or restrict with firewall',
                })

        # SSL issues
        for issue in data.get('sslscan', {}).get('issues', []):
            findings.append({
                'type': 'ssl_issue',
                'title': f"SSL/TLS Issue: {issue['issue']}",
                'severity': issue['severity'],
                'detail': issue['issue'],
                'fix': 'Disable legacy protocols, use TLS 1.2+ with strong ciphers',
            })

        # Redis unauthenticated
        if 'UNAUTHENTICATED' in str(data.get('service_scans', {}).get('redis', '')):
            findings.append({
                'type': 'redis_unauth',
                'title': 'Redis Unauthenticated Access',
                'severity': 'CRITICAL',
                'detail': f'Redis on {target}:6379 responds without authentication',
                'fix': 'Set requirepass in redis.conf, bind to localhost only',
            })

        # SMB vulnerabilities
        smb_out = data.get('service_scans', {}).get('smb', '')
        if 'VULNERABLE' in str(smb_out).upper():
            findings.append({
                'type': 'smb_vuln',
                'title': 'SMB Vulnerability Detected',
                'severity': 'CRITICAL',
                'detail': str(smb_out)[:200],
                'fix': 'Apply MS17-010 patch, disable SMBv1',
            })

        return findings

    def _overall_risk(self, findings: list) -> str:
        if not findings:
            return 'LOW'
        return min(findings, key=lambda f: _SEV_ORDER.get(f['severity'], 4))['severity']
