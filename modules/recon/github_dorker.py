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

import logging
import re
import requests
import config
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.utils import rate_limited_get

logger = logging.getLogger(__name__)

DORKS = [
    '{target} password',
    '{target} secret_key',
    '{target} api_key',
    '{target} access_token',
    '{target} private_key',
    '{target} db_password',
    '{target} aws_secret',
    '{target} credentials',
    '{target} .env',
    '{target} config',
]

SECRET_PATTERNS = {
    'aws_key':        re.compile(r'AKIA[0-9A-Z]{16}'),
    'aws_secret':     re.compile(r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']'),
    'github_token':   re.compile(r'ghp_[A-Za-z0-9]{36}'),
    'generic_api':    re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?'),
    'private_key':    re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'password':       re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']'),
    'db_url':         re.compile(r'(?i)(mysql|postgres|mongodb|redis)://[^\s"\'<>]+'),
    'slack_token':    re.compile(r'xox[baprs]-[A-Za-z0-9\-]{10,}'),
    'stripe_key':     re.compile(r'(?:sk|pk)_(live|test)_[A-Za-z0-9]{24,}'),
    'jwt':            re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
}

class GitHubDorker:
    API_BASE = 'https://api.github.com/search/code'
    TIMEOUT  = 10

    def __init__(self):
        self.token = config.GITHUB_TOKEN
        self.headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'SentinelPro-OSINT'
        }
        if self.token:
            self.headers['Authorization'] = f'token {self.token}'

    def run(self, target: str) -> dict:
        result = {
            'target': target,
            'findings': [],
            'total_secrets': 0,
            'repos_found': set(),
            'secret_types': {},
            'risk_level': 'LOW',
            'error': None
        }

        if not self.token:
            result['error'] = 'GITHUB_TOKEN not set — rate limit will be very low (10 req/min unauthenticated)'

        dorks = [d.format(target=target) for d in DORKS]

        with ThreadPoolExecutor(max_workers=3) as ex:
            futures = {ex.submit(self._search, dork): dork for dork in dorks[:5]}
            for future in as_completed(futures):
                try:
                    items = future.result()
                    for item in items:
                        findings = self._scan_item(item)
                        result['findings'].extend(findings)
                        if findings:
                            result['repos_found'].add(item.get('repository', {}).get('full_name', ''))
                except Exception as e:
                    logger.debug(f"GitHub dork error: {e}")

        result['repos_found'] = list(result['repos_found'])

        # Deduplicate by url+type
        seen = set()
        deduped = []
        for f in result['findings']:
            key = (f['repo'], f['secret_type'], f['match'][:30])
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        result['findings'] = deduped

        result['total_secrets'] = len(result['findings'])
        for f in result['findings']:
            t = f['secret_type']
            result['secret_types'][t] = result['secret_types'].get(t, 0) + 1

        if result['total_secrets'] > 0:
            critical_types = {'aws_key', 'private_key', 'github_token', 'stripe_key'}
            if any(f['secret_type'] in critical_types for f in result['findings']):
                result['risk_level'] = 'CRITICAL'
            else:
                result['risk_level'] = 'HIGH'

        return result

    def _search(self, query: str) -> list:
        resp = rate_limited_get(self.API_BASE, namespace='github',
                                params={'q': query, 'per_page': 10},
                                headers=self.headers, timeout=self.TIMEOUT)
        if resp and resp.status_code == 200:
            return resp.json().get('items', [])
        if resp and resp.status_code == 403:
            logger.warning("GitHub rate limit hit")
        return []

    def _scan_item(self, item: dict) -> list:
        findings = []
        # Get raw file content
        raw_url = item.get('html_url', '').replace('github.com', 'raw.githubusercontent.com')\
                                          .replace('/blob/', '/')
        repo    = item.get('repository', {}).get('full_name', '')
        path    = item.get('path', '')

        resp = rate_limited_get(raw_url, namespace='github',
                                headers=self.headers, timeout=self.TIMEOUT)
        if not resp or resp.status_code != 200:
            return findings
        content = resp.text

        for secret_type, pattern in SECRET_PATTERNS.items():
            matches = pattern.findall(content)
            for match in matches:
                match_str = match if isinstance(match, str) else match[-1]
                findings.append({
                    'repo':        repo,
                    'path':        path,
                    'url':         item.get('html_url', ''),
                    'secret_type': secret_type,
                    'match':       match_str[:80],
                    'severity':    'CRITICAL' if secret_type in ('aws_key', 'private_key', 'github_token') else 'HIGH'
                })

        return findings
