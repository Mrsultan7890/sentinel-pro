"""
Threat Intel Agent — CVE Lookup + Shodan + IOC Extraction
==========================================================
- NVD CVE database se vulnerabilities dhundho
- Shodan se host intelligence lo
- IOCs extract karo (IPs, domains, hashes)
- MITRE ATT&CK mapping karo

Author: @who_is_the_black_hat
"""

import logging
from sentinel_brain.kali_controller import KaliController
from sentinel_brain.memory import Memory

logger = logging.getLogger(__name__)

_SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}


class ThreatIntelAgent:
    NAME = 'threat_intel_agent'

    def __init__(self, kali: KaliController, memory: Memory, sentinel=None):
        self.kali     = kali
        self.memory   = memory
        self.sentinel = sentinel

    def run(self, target: str, tech_stack: dict = None) -> dict:
        logger.info(f"[ThreatIntelAgent] {target}")
        result = {}

        # ── Shodan ────────────────────────────────────────────────────────────
        shodan_result = self._run_shodan(target)
        result['shodan'] = shodan_result

        # ── CVE Lookup ────────────────────────────────────────────────────────
        # Tech stack recon se lo ya shodan se
        techs = tech_stack or self._extract_techs(shodan_result)
        cve_result = self._run_cve_lookup(techs)
        result['cves'] = cve_result

        # ── Searchsploit ──────────────────────────────────────────────────────
        sploit_result = self._run_searchsploit(shodan_result, techs)
        result['searchsploit'] = sploit_result

        # ── IOC Extraction ────────────────────────────────────────────────────
        iocs = self._extract_iocs(target, shodan_result, cve_result)
        result['iocs'] = iocs

        # ── MITRE ATT&CK Mapping ──────────────────────────────────────────────
        result['mitre'] = self._mitre_mapping(cve_result, shodan_result)

        # ── Findings ──────────────────────────────────────────────────────────
        findings = self._extract_findings(target, result)
        risk     = self._overall_risk(findings)
        summary  = (
            f"Shodan: {len(shodan_result.get('open_ports',[]))} ports, "
            f"{len(shodan_result.get('vulns',[]))} CVEs | "
            f"NVD: {cve_result.get('total_cves',0)} CVEs | "
            f"Exploits: {sploit_result.get('total',0)}"
        )

        self.memory.remember_scan(target, 'threat_intel', risk, summary, result)
        for f in findings:
            self.memory.remember_finding(
                target, self.NAME, f['severity'], f['title'], f['detail'], f.get('fix','')
            )
        self.memory.remember_decision(target, self.NAME, 'threat_intel', 'Threat Intel', summary)

        result['_findings']      = findings
        result['_risk']          = risk
        result['_agent_summary'] = summary
        return result

    # ── Shodan ────────────────────────────────────────────────────────────────

    def _run_shodan(self, target: str) -> dict:
        try:
            from modules.bugbounty.shodan_scanner import ShodanScanner
            scanner = ShodanScanner()
            r = scanner.run(target)
            if not r.get('error'):
                logger.info(f"[ThreatIntel] Shodan: {len(r.get('open_ports',[]))} ports, "
                            f"{len(r.get('vulns',[]))} CVEs")
            return r
        except Exception as e:
            logger.debug(f"Shodan error: {e}")
            return {'error': str(e), 'open_ports': [], 'vulns': []}

    # ── CVE Lookup ────────────────────────────────────────────────────────────

    def _run_cve_lookup(self, techs: dict) -> dict:
        if not techs:
            return {'total_cves': 0, 'cves': [], 'risk_level': 'LOW'}
        try:
            from modules.bugbounty.cve_lookup import CVELookup
            lookup = CVELookup()
            r = lookup.run(techs)
            logger.info(f"[ThreatIntel] CVEs: {r.get('total_cves',0)} "
                        f"(critical={r.get('critical_count',0)}, high={r.get('high_count',0)})")
            return r
        except Exception as e:
            logger.debug(f"CVE lookup error: {e}")
            return {'total_cves': 0, 'cves': [], 'risk_level': 'LOW', 'error': str(e)}

    # ── Searchsploit ──────────────────────────────────────────────────────────

    def _run_searchsploit(self, shodan: dict, techs: dict) -> dict:
        result = {'exploits': [], 'total': 0}
        if not self.kali.tool_available('searchsploit'):
            return result

        # Services from shodan
        queries = set()
        for svc in shodan.get('services', [])[:5]:
            product = svc.get('product', '')
            version = svc.get('version', '')
            if product:
                queries.add(f"{product} {version}".strip())

        # Tech stack
        for k, v in (techs or {}).items():
            if v:
                queries.add(str(v)[:40])

        for q in list(queries)[:4]:
            r = self.kali.run(
                f'searchsploit "{q}" --disable-colour 2>/dev/null | head -10',
                timeout=15
            )
            lines = [l for l in r['stdout'].splitlines()
                     if '|' in l and 'Exploit Title' not in l and '---' not in l]
            for line in lines[:3]:
                parts = line.split('|')
                if len(parts) >= 2:
                    result['exploits'].append({
                        'title': parts[0].strip()[:100],
                        'path':  parts[-1].strip(),
                        'query': q,
                    })

        result['total'] = len(result['exploits'])
        return result

    # ── IOC Extraction ────────────────────────────────────────────────────────

    def _extract_iocs(self, target: str, shodan: dict, cves: dict) -> dict:
        import re, socket
        iocs = {'ips': [], 'domains': [], 'cve_ids': [], 'ports': []}

        # IP
        ip = shodan.get('ip')
        if ip:
            iocs['ips'].append(ip)

        # Hostnames from shodan
        for h in shodan.get('hostnames', []):
            iocs['domains'].append(h)

        # CVE IDs
        for c in cves.get('cves', []):
            cve_id = c.get('cve_id', '')
            if cve_id and cve_id not in iocs['cve_ids']:
                iocs['cve_ids'].append(cve_id)

        # Risky ports
        risky = {21, 22, 23, 25, 3389, 5900, 6379, 27017, 9200, 2375, 4243}
        for p in shodan.get('open_ports', []):
            if p in risky:
                iocs['ports'].append(p)

        # Save to DB
        try:
            from modules.database import SentinelDB
            db = SentinelDB()
            for ip in iocs['ips']:
                db.save_ioc(target, 'ip', ip, 'shodan')
            for domain in iocs['domains']:
                db.save_ioc(target, 'domain', domain, 'shodan')
            for cve in iocs['cve_ids']:
                db.save_ioc(target, 'cve', cve, 'nvd')
        except Exception:
            pass

        return iocs

    # ── MITRE ATT&CK Mapping ─────────────────────────────────────────────────

    def _mitre_mapping(self, cves: dict, shodan: dict) -> list:
        """CVEs aur services ko MITRE ATT&CK techniques se map karo."""
        mappings = []

        # Port-based mapping
        port_technique = {
            22:    ('T1021.004', 'Remote Services: SSH'),
            3389:  ('T1021.001', 'Remote Services: RDP'),
            445:   ('T1021.002', 'Remote Services: SMB'),
            21:    ('T1021.003', 'Remote Services: FTP'),
            23:    ('T1021.005', 'Remote Services: Telnet'),
            6379:  ('T1505.003', 'Server Software Component: Redis'),
            27017: ('T1505.003', 'Server Software Component: MongoDB'),
            9200:  ('T1505.003', 'Server Software Component: Elasticsearch'),
        }
        for port in shodan.get('open_ports', []):
            if port in port_technique:
                tid, tname = port_technique[port]
                mappings.append({'technique_id': tid, 'technique': tname,
                                 'reason': f'Port {port} open'})

        # CVE-based mapping
        for cve in cves.get('cves', [])[:5]:
            desc = cve.get('description', '').lower()
            if 'remote code' in desc or 'rce' in desc:
                mappings.append({'technique_id': 'T1190',
                                 'technique': 'Exploit Public-Facing Application',
                                 'reason': cve.get('cve_id', '')})
            elif 'privilege' in desc:
                mappings.append({'technique_id': 'T1068',
                                 'technique': 'Exploitation for Privilege Escalation',
                                 'reason': cve.get('cve_id', '')})
            elif 'denial' in desc or 'dos' in desc:
                mappings.append({'technique_id': 'T1499',
                                 'technique': 'Endpoint Denial of Service',
                                 'reason': cve.get('cve_id', '')})

        # Deduplicate
        seen = set()
        unique = []
        for m in mappings:
            if m['technique_id'] not in seen:
                seen.add(m['technique_id'])
                unique.append(m)
        return unique

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _extract_techs(self, shodan: dict) -> dict:
        techs = {}
        for svc in shodan.get('services', []):
            product = svc.get('product', '')
            version = svc.get('version', '')
            if product:
                techs[product] = f"{product} {version}".strip()
        return techs

    def _extract_findings(self, target: str, data: dict) -> list:
        findings = []

        # Shodan CVEs
        shodan_vulns = data.get('shodan', {}).get('vulns', [])
        if shodan_vulns:
            findings.append({
                'type': 'shodan_cves', 'title': 'Known CVEs (Shodan)',
                'severity': 'CRITICAL',
                'detail': f"{len(shodan_vulns)} CVEs: {', '.join(shodan_vulns[:5])}",
                'fix': 'Patch all listed CVEs immediately',
            })

        # NVD CVEs
        cve_data = data.get('cves', {})
        for cve in cve_data.get('cves', [])[:5]:
            sev = cve.get('severity', 'MEDIUM')
            if sev in ('CRITICAL', 'HIGH'):
                findings.append({
                    'type': 'cve', 'title': f"CVE: {cve.get('cve_id','')}",
                    'severity': sev,
                    'detail': f"{cve.get('cve_id','')} (CVSS {cve.get('score',0)}) — {cve.get('description','')[:120]}",
                    'fix': f"Patch {cve.get('tech','')} to latest version",
                })

        # Searchsploit exploits
        exploits = data.get('searchsploit', {}).get('exploits', [])
        if exploits:
            findings.append({
                'type': 'public_exploit', 'title': 'Public Exploits Available',
                'severity': 'HIGH',
                'detail': f"{len(exploits)} exploits: {exploits[0]['title'][:80]}",
                'fix': 'Patch affected services, implement WAF rules',
            })

        # Risky ports
        risky_ports = data.get('iocs', {}).get('ports', [])
        if risky_ports:
            findings.append({
                'type': 'risky_ports', 'title': 'Risky Ports Exposed',
                'severity': 'HIGH',
                'detail': f"Ports: {risky_ports}",
                'fix': 'Close unnecessary ports, use firewall rules',
            })

        return findings

    def _overall_risk(self, findings: list) -> str:
        if not findings:
            return 'LOW'
        return min(findings, key=lambda f: _SEV_ORDER.get(f['severity'], 4))['severity']
