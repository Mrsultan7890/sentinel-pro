"""
Dark Web Agent — Tor + .onion Crawling + Paste Monitor
=======================================================
- Tor se dark web search karo
- Target ke mentions dhundo
- Leaked credentials check karo
- Paste sites monitor karo

Author: @who_is_the_black_hat
"""

import logging
from sentinel_brain.memory import Memory

logger = logging.getLogger(__name__)

_SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}


class DarkWebAgent:
    NAME = 'darkweb_agent'

    def __init__(self, memory: Memory, sentinel=None):
        self.memory   = memory
        self.sentinel = sentinel

    def run(self, target: str) -> dict:
        logger.info(f"[DarkWebAgent] {target}")
        result = {}

        # ── Tor check ─────────────────────────────────────────────────────────
        tor_active = self._check_tor()
        result['tor_active'] = tor_active

        if not tor_active:
            logger.warning("[DarkWebAgent] Tor not running — limited dark web scan")

        # ── Dark web crawler ──────────────────────────────────────────────────
        result['darkweb'] = self._run_darkweb_crawler(target)

        # ── Paste monitor ─────────────────────────────────────────────────────
        result['pastes'] = self._check_pastes(target)

        # ── Findings ──────────────────────────────────────────────────────────
        findings = self._extract_findings(target, result)
        risk     = self._overall_risk(findings)

        dw_mentions = result['darkweb'].get('mentions', 0)
        paste_count = result['pastes'].get('total', 0)
        summary = (
            f"Dark web: {dw_mentions} mentions | "
            f"Pastes: {paste_count} | "
            f"Tor: {'active' if tor_active else 'inactive'} | "
            f"risk={risk}"
        )

        self.memory.remember_scan(target, 'darkweb', risk, summary, result)
        for f in findings:
            self.memory.remember_finding(
                target, self.NAME, f['severity'], f['title'], f['detail'], f.get('fix', '')
            )
        self.memory.remember_decision(target, self.NAME, 'darkweb', 'Dark Web', summary)

        result['_findings']      = findings
        result['_risk']          = risk
        result['_agent_summary'] = summary
        return result

    # ── Tor check ─────────────────────────────────────────────────────────────

    def _check_tor(self) -> bool:
        try:
            import socket
            s = socket.socket()
            s.settimeout(2)
            s.connect(('127.0.0.1', 9050))
            s.close()
            return True
        except Exception:
            return False

    # ── Dark web crawler ──────────────────────────────────────────────────────

    def _run_darkweb_crawler(self, target: str) -> dict:
        result = {'mentions': 0, 'results': [], 'error': None}
        try:
            from modules.darkweb_crawler import DarkWebCrawler
            crawler = DarkWebCrawler()
            r = crawler.search(target)
            result['mentions'] = r.get('total_results', 0)
            result['results']  = r.get('results', [])[:10]
            result['risk']     = r.get('risk_level', 'LOW')
        except Exception as e:
            result['error'] = str(e)
            logger.debug(f"[DarkWebAgent] crawler error: {e}")
        return result

    # ── Paste monitor ─────────────────────────────────────────────────────────

    def _check_pastes(self, target: str) -> dict:
        result = {'total': 0, 'pastes': [], 'error': None}
        try:
            import requests, config
            session = requests.Session()
            if config.is_tor_active():
                session.proxies = config.get_proxies()

            # Pastebin search (public API)
            domain = target.replace('www.', '')
            r = session.get(
                f'https://psbdmp.ws/api/v3/search/{domain}',
                timeout=10,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            if r.status_code == 200:
                data = r.json()
                pastes = data.get('data', [])[:10]
                result['total']  = len(pastes)
                result['pastes'] = [{'id': p.get('id'), 'date': p.get('date')} for p in pastes]
        except Exception as e:
            result['error'] = str(e)
            logger.debug(f"[DarkWebAgent] paste check error: {e}")
        return result

    # ── Findings ──────────────────────────────────────────────────────────────

    def _extract_findings(self, target: str, data: dict) -> list:
        findings = []

        # Dark web mentions
        dw = data.get('darkweb', {})
        mentions = dw.get('mentions', 0)
        if mentions > 0:
            findings.append({
                'type':     'darkweb_mention',
                'title':    'Dark Web Mentions Found',
                'severity': 'HIGH',
                'detail':   f"{mentions} mentions of {target} on dark web",
                'fix':      'Investigate dark web mentions, check for data leaks',
            })

        # Paste sites
        pastes = data.get('pastes', {}).get('total', 0)
        if pastes > 0:
            findings.append({
                'type':     'paste_exposure',
                'title':    'Target Found on Paste Sites',
                'severity': 'HIGH',
                'detail':   f"{pastes} pastes found containing {target}",
                'fix':      'Review paste content, rotate any exposed credentials',
            })

        # Tor not active warning
        if not data.get('tor_active'):
            findings.append({
                'type':     'tor_inactive',
                'title':    'Tor Not Active — Limited Dark Web Scan',
                'severity': 'LOW',
                'detail':   'Run: tor on — for full dark web scanning',
                'fix':      'Enable Tor: sentinel-pro> tor on',
            })

        return findings

    def _overall_risk(self, findings: list) -> str:
        real = [f for f in findings if f['type'] != 'tor_inactive']
        if not real:
            return 'LOW'
        return min(real, key=lambda f: _SEV_ORDER.get(f['severity'], 4))['severity']
