"""
CORS Misconfiguration Scanner
Tests endpoints for dangerous Access-Control-Allow-Origin policies.
"""

import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.utils import tor_session

logger = logging.getLogger(__name__)

TEST_ORIGINS = [
    'https://evil.com',
    'https://attacker.com',
    'null',
]

HEADERS = {'User-Agent': 'Mozilla/5.0 (compatible; SentinelPro/2.1)'}


class CORSScanner:

    TIMEOUT = 8

    def __init__(self):
        self.session = tor_session(pool_size=20)
        self.session.verify = False
        self.session.headers['User-Agent'] = 'Mozilla/5.0'
    def run(self, domain: str, endpoints: list = None) -> dict:
        result = {
            'domain':     domain,
            'findings':   [],
            'total':      0,
            'risk_level': 'LOW',
            'error':      None
        }

        urls = self._build_urls(domain, endpoints)

        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = {ex.submit(self._test_url, url): url for url in urls}
            for future in as_completed(futures):
                finding = future.result()
                if finding:
                    result['findings'].append(finding)

        # Deduplicate by issue type
        seen = set()
        deduped = []
        for f in result['findings']:
            key = (f['url'], f['issue'])
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        result['findings'] = sorted(deduped,
            key=lambda x: 0 if x['severity'] == 'CRITICAL' else 1)
        result['total'] = len(result['findings'])

        if result['findings']:
            sevs = [f['severity'] for f in result['findings']]
            result['risk_level'] = 'CRITICAL' if 'CRITICAL' in sevs else 'HIGH'

        return result

    def _build_urls(self, domain: str, endpoints: list) -> list:
        base  = f'https://{domain}'
        paths = ['/'] + [e['path'] for e in (endpoints or []) if e.get('path')]
        # Prioritise API paths — most likely to have CORS
        api_first = sorted(paths, key=lambda p: 0 if '/api' in p else 1)
        return [base + p for p in api_first[:30]]

    def _test_url(self, url: str) -> dict | None:
        findings = []

        for origin in TEST_ORIGINS:
            try:
                resp = self.session.get(
                    url, timeout=self.TIMEOUT,
                    headers={**HEADERS, 'Origin': origin},
                    allow_redirects=True
                )
            except Exception:
                continue

            acao  = resp.headers.get('Access-Control-Allow-Origin', '')
            acac  = resp.headers.get('Access-Control-Allow-Credentials', '').lower()

            if not acao:
                continue

            # CRITICAL: reflects attacker origin + allows credentials
            if acao == origin and acac == 'true':
                return {
                    'url':       url,
                    'origin':    origin,
                    'acao':      acao,
                    'acac':      acac,
                    'issue':     'Reflects arbitrary origin with credentials',
                    'severity':  'CRITICAL',
                    'impact':    'Full credential theft — attacker can make authenticated requests on behalf of victim',
                    'evidence':  f'Origin: {origin} → ACAO: {acao} | ACAC: {acac}'
                }

            # HIGH: wildcard with credentials (invalid but some servers do it)
            if acao == '*' and acac == 'true':
                return {
                    'url':       url,
                    'origin':    origin,
                    'acao':      acao,
                    'acac':      acac,
                    'issue':     'Wildcard ACAO with credentials',
                    'severity':  'HIGH',
                    'impact':    'Browsers block this but misconfigured proxies may not',
                    'evidence':  f'ACAO: * | ACAC: true'
                }

            # HIGH: reflects arbitrary origin (no credentials but still bad)
            if acao == origin:
                return {
                    'url':       url,
                    'origin':    origin,
                    'acao':      acao,
                    'acac':      acac,
                    'issue':     'Reflects arbitrary origin (no credentials)',
                    'severity':  'HIGH',
                    'impact':    'Attacker can read non-credentialed responses cross-origin',
                    'evidence':  f'Origin: {origin} → ACAO: {acao}'
                }

            # MEDIUM: null origin accepted
            if origin == 'null' and acao == 'null':
                return {
                    'url':       url,
                    'origin':    'null',
                    'acao':      'null',
                    'acac':      acac,
                    'issue':     'Null origin accepted',
                    'severity':  'MEDIUM',
                    'impact':    'Sandboxed iframes or local files can make cross-origin requests',
                    'evidence':  'Origin: null → ACAO: null'
                }

        return None
