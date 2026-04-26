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
        self.terminal = kali
        # Groq singleton — recon findings ka context analysis
        from modules.ml_engine.groq_llm import get_groq
        self._groq = get_groq()

    def run(self, target: str, skip_nmap: bool = False) -> dict:
        logger.info(f"[ReconAgent] {target}{' (nmap skipped — already done)' if skip_nmap else ''}")
        result = {}

        # Sentinel modules (full featured)
        if self.sentinel:
            try:
                self.sentinel._handle_recon(f'recon {target}')
                result = self.sentinel.session_data.get('recon', {})
            except Exception as e:
                logger.error(f"[ReconAgent] sentinel failed: {e}")
                result = self._kali_recon(target, skip_nmap=skip_nmap)
        else:
            result = self._kali_recon(target, skip_nmap=skip_nmap)

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

        # Groq — high-value recon findings ka next-step suggest karo
        if self._groq and (gh > 0 or cloud > 0):
            try:
                context = f"Recon on {target}: {subs} subdomains, {cloud} cloud assets, {gh} GitHub secrets"
                next_step = self._groq.ask(
                    f"{context}. In 1 sentence: what is the most critical next pentest step?",
                    max_tokens=60
                )
                if next_step:
                    result['_groq_next_step'] = next_step
                    logger.info(f"[ReconAgent] Groq next step: {next_step[:80]}")
            except Exception as e:
                logger.debug(f"[ReconAgent] Groq suggestion failed: {e}")

        return result

    def _kali_recon(self, target: str, skip_nmap: bool = False) -> dict:
        """Direct Kali tools — sentinel nahi hai to"""
        results = {}

        # WHOIS
        r = self.kali.run(f'whois {target} 2>/dev/null | head -30', timeout=15)
        results['whois_raw'] = r['stdout']

        # DNS
        r = self.kali.run(f'dig +short {target} A && dig +short {target} MX && dig +short {target} NS', timeout=10)
        results['dns_raw'] = r['stdout']
        results['dns']     = r['parsed']

        # Nmap — skip karo agar kali_recon already run kar chuka hai
        if not skip_nmap and self.kali.tool_available('nmap'):
            r = self.kali.run(f'nmap -sV -sC -T4 --open {target} 2>/dev/null', timeout=120)
            results['nmap'] = r['parsed']
        elif skip_nmap:
            logger.info(f'[ReconAgent] nmap skipped — already done in kali_recon')

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
