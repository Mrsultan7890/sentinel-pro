"""
Open Redirect Scanner
Tests common redirect parameters for unvalidated external redirects.
"""

import logging
import requests
from urllib.parse import urlencode, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

REDIRECT_PARAMS = [
    'next', 'url', 'redirect', 'redirect_url', 'redirect_uri',
    'return', 'return_url', 'returnUrl', 'returnTo', 'goto',
    'dest', 'destination', 'target', 'redir', 'r', 'u',
    'link', 'forward', 'continue', 'callback', 'back',
    'location', 'ref', 'referer', 'out', 'view', 'to',
]

PAYLOADS = [
    'https://evil.com',
    '//evil.com',
    '///evil.com',
    'https://evil.com%2F@legitimate.com',
    '/\\evil.com',
]

HEADERS = {'User-Agent': 'Mozilla/5.0 (compatible; SentinelPro/2.1)'}


class OpenRedirectScanner:

    TIMEOUT = 8

    def run(self, domain: str, endpoints: list = None) -> dict:
        result = {
            'domain':     domain,
            'findings':   [],
            'total':      0,
            'risk_level': 'LOW',
            'error':      None
        }

        targets = self._build_targets(domain, endpoints)

        with ThreadPoolExecutor(max_workers=15) as ex:
            futures = {ex.submit(self._test, url, param): (url, param)
                       for url, param in targets}
            for future in as_completed(futures):
                finding = future.result()
                if finding:
                    result['findings'].append(finding)

        # Deduplicate
        seen = set()
        deduped = []
        for f in result['findings']:
            key = (f['param'], f['payload'])
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        result['findings'] = deduped
        result['total']    = len(result['findings'])
        if result['findings']:
            result['risk_level'] = 'HIGH'

        return result

    def _build_targets(self, domain: str, endpoints: list) -> list:
        """Build (url, param) pairs to test."""
        base  = f'https://{domain}'
        paths = ['/'] + [e['path'] for e in (endpoints or []) if e.get('path')]

        targets = []
        for path in paths[:20]:
            url = base + path
            for param in REDIRECT_PARAMS:
                targets.append((url, param))
        return targets

    def _test(self, url: str, param: str) -> dict | None:
        for payload in PAYLOADS[:3]:  # limit requests per param
            test_url = f"{url}{'&' if '?' in url else '?'}{param}={requests.utils.quote(payload)}"
            try:
                resp = requests.get(
                    test_url, timeout=self.TIMEOUT, verify=False,
                    allow_redirects=False, headers=HEADERS
                )
                location = resp.headers.get('Location', '')

                if resp.status_code in (301, 302, 303, 307, 308) and location:
                    parsed = urlparse(location)
                    # Confirm redirect goes to external domain
                    if parsed.netloc and 'evil.com' in parsed.netloc:
                        return {
                            'url':       test_url,
                            'param':     param,
                            'payload':   payload,
                            'location':  location,
                            'status':    resp.status_code,
                            'severity':  'HIGH',
                            'evidence':  f'HTTP {resp.status_code} → Location: {location}'
                        }
            except Exception:
                pass
        return None
