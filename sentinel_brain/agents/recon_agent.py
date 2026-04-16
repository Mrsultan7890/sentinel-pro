"""
Recon Agent v2 — KaliController directly use karta hai
Subdomains, WHOIS, DNS, cloud assets, GitHub dorks, Wayback + Kali tools
"""

import logging
from sentinel_brain.kali_controller import KaliController
from sentinel_brain.memory import Memory

logger = logging.getLogger(__name__)


class ReconAgent:
    NAME = 'recon_agent'

    def __init__(self, kali: KaliController, memory: Memory, sentinel=None):
        self.kali     = kali
        self.memory   = memory
        self.sentinel = sentinel
        # backward compat
        self.terminal = kali

    def run(self, target: str) -> dict:
        logger.info(f"[ReconAgent] {target}")
        result = {}

        # Sentinel modules (full featured)
        if self.sentinel:
            try:
                self.sentinel._handle_recon(f'recon {target}')
                result = self.sentinel.session_data.get('recon', {})
            except Exception as e:
                logger.error(f"[ReconAgent] sentinel failed: {e}")
                result = self._kali_recon(target)
        else:
            result = self._kali_recon(target)

        subs  = result.get('subdomains', {}).get('total_found', 0)
        cloud = result.get('cloud_assets', {}).get('total', 0)
        gh    = result.get('github_dorks', {}).get('total_secrets', 0)
        risk  = 'CRITICAL' if gh > 0 else ('HIGH' if cloud > 0 else 'MEDIUM')
        summary = f"{subs} subdomains, {cloud} cloud assets, {gh} GitHub secrets"

        self.memory.remember_scan(target, 'recon', risk, summary, result)
        if gh > 0:
            self.memory.remember_finding(target, self.NAME, 'CRITICAL',
                'GitHub Secrets', f'{gh} secrets in public repos', 'Rotate credentials immediately')
        if cloud > 0:
            self.memory.remember_finding(target, self.NAME, 'HIGH',
                'Cloud Assets Exposed', f'{cloud} assets found', 'Disable public access')
        self.memory.remember_decision(target, self.NAME, 'recon', 'Reconnaissance', summary)

        result['_agent_summary'] = summary
        result['_risk'] = risk
        return result

    def _kali_recon(self, target: str) -> dict:
        """Direct Kali tools — sentinel nahi hai to"""
        results = {}

        # WHOIS
        r = self.kali.run(f'whois {target} 2>/dev/null | head -30', timeout=15)
        results['whois_raw'] = r['stdout']

        # DNS
        r = self.kali.run(f'dig +short {target} A && dig +short {target} MX && dig +short {target} NS', timeout=10)
        results['dns_raw'] = r['stdout']
        results['dns']     = r['parsed']

        # Subfinder
        if self.kali.tool_available('subfinder'):
            r = self.kali.run(f'subfinder -d {target} -silent 2>/dev/null | head -100', timeout=60)
            parsed = r['parsed']
            results['subdomains'] = {
                'subdomains': [{'subdomain': s} for s in parsed.get('subdomains', [])],
                'total_found': parsed.get('total', 0)
            }

        # httpx
        if self.kali.tool_available('httpx'):
            r = self.kali.run(f'httpx -u {target} -title -status-code -silent 2>/dev/null', timeout=20)
            results['httpx'] = r['stdout']

        # theHarvester
        if self.kali.tool_available('theHarvester'):
            r = self.kali.run(f'theHarvester -d {target} -b bing,google -l 50 2>/dev/null | tail -20', timeout=60)
            results['harvester'] = r['stdout']

        results['risk_level'] = 'MEDIUM'
        return results
