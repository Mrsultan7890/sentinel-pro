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
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.utils import rate_limited_get

logger = logging.getLogger(__name__)

SECRET_PATTERNS = {
    'aws_key':       re.compile(r'AKIA[0-9A-Z]{16}'),
    'aws_secret':    re.compile(r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']'),
    'github_token':  re.compile(r'ghp_[A-Za-z0-9]{36}'),
    'api_key':       re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']'),
    'private_key':   re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'password':      re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']'),
    'db_url':        re.compile(r'(?i)(mysql|postgres|mongodb|redis)://[^\s"\'<>]{8,}'),
    'slack_token':   re.compile(r'xox[baprs]-[A-Za-z0-9\-]{10,}'),
    'stripe_key':    re.compile(r'(?:sk|pk)_(live|test)_[A-Za-z0-9]{24,}'),
    'jwt':           re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    'google_api':    re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    'firebase':      re.compile(r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'),
    'bearer_token':  re.compile(r'(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}'),
}

ENDPOINT_PATTERNS = [
    re.compile(r'["\'](/(?:api|v\d|rest|graphql|admin|auth|user|account|payment)[^\s"\'<>]{0,100})["\']'),
    re.compile(r'(?:fetch|axios\.get|axios\.post|http\.get|\.ajax)\s*\(\s*["\']([^"\']{5,100})["\']'),
    re.compile(r'url\s*[=:]\s*["\']([^"\']{5,100})["\']'),
]

INTERNAL_PATH_PATTERN = re.compile(
    r'(?:\/\/|#sourceMappingURL=|\/\*\s*@)([a-zA-Z]:[\\\/]|\/home\/|\/Users\/|\/var\/|\/opt\/)[^\s"\'*]{3,100}'
)

JS_LINK_PATTERN = re.compile(r'(?:src|href)=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']')

class JSAnalyzer:
    TIMEOUT  = 10
    MAX_JS   = 20   # max JS files to analyze per domain
    MAX_SIZE = 2 * 1024 * 1024  # 2MB per file

    def run(self, domain: str) -> dict:
        result = {
            'domain': domain,
            'js_files': [],
            'endpoints': [],
            'secrets': [],
            'internal_paths': [],
            'total_js': 0,
            'risk_level': 'LOW',
            'error': None
        }

        js_urls = self._discover_js(domain)
        result['total_js'] = len(js_urls)

        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = {ex.submit(self._analyze_file, url): url for url in js_urls[:self.MAX_JS]}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    file_result = future.result()
                    if file_result:
                        result['js_files'].append(file_result['url'])
                        result['endpoints'].extend(file_result['endpoints'])
                        result['secrets'].extend(file_result['secrets'])
                        result['internal_paths'].extend(file_result['internal_paths'])
                except Exception as e:
                    logger.debug(f"JS analyze error {url}: {e}")

        # Deduplicate
        result['endpoints']      = list(dict.fromkeys(result['endpoints']))[:100]
        result['internal_paths'] = list(dict.fromkeys(result['internal_paths']))[:50]

        seen = set()
        deduped_secrets = []
        for s in result['secrets']:
            key = (s['type'], s['match'][:20])
            if key not in seen:
                seen.add(key)
                deduped_secrets.append(s)
        result['secrets'] = deduped_secrets

        # Risk
        critical_types = {'aws_key', 'private_key', 'github_token', 'stripe_key'}
        if any(s['type'] in critical_types for s in result['secrets']):
            result['risk_level'] = 'CRITICAL'
        elif result['secrets']:
            result['risk_level'] = 'HIGH'
        elif result['internal_paths']:
            result['risk_level'] = 'MEDIUM'
        elif result['endpoints']:
            result['risk_level'] = 'LOW'

        return result

    def _discover_js(self, domain: str) -> list:
        js_urls = set()
        for scheme in ('https', 'http'):
            resp = rate_limited_get(f"{scheme}://{domain}", namespace='js',
                                    headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
            if resp:
                base = f"{scheme}://{domain}"
                for match in JS_LINK_PATTERN.finditer(resp.text):
                    src  = match.group(1)
                    full = urljoin(base, src)
                    if urlparse(full).netloc in (domain, f'www.{domain}'):
                        js_urls.add(full)
                if js_urls:
                    break

        # Common JS paths fallback
        if not js_urls:
            for path in ['/app.js', '/main.js', '/bundle.js', '/static/js/main.js',
                         '/assets/js/app.js', '/js/app.js']:
                js_urls.add(f"https://{domain}{path}")

        return list(js_urls)

    def _analyze_file(self, url: str) -> dict | None:
        try:
            resp = requests.get(url, timeout=self.TIMEOUT,
                                headers={'User-Agent': 'Mozilla/5.0'}, verify=False,
                                stream=True)
            if resp.status_code != 200:
                return None

            content = b''
            for chunk in resp.iter_content(8192):
                content += chunk
                if len(content) > self.MAX_SIZE:
                    break
            text = content.decode('utf-8', errors='ignore')

        except Exception as e:
            logger.debug(f"JS fetch error {url}: {e}")
            return None

        file_result = {'url': url, 'endpoints': [], 'secrets': [], 'internal_paths': []}

        # Endpoints
        for pattern in ENDPOINT_PATTERNS:
            for match in pattern.finditer(text):
                ep = match.group(1)
                if len(ep) > 4 and not ep.startswith('//'):
                    file_result['endpoints'].append(ep)

        # Secrets
        for secret_type, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(text):
                m = match.group(0) if not match.lastindex else match.group(match.lastindex)
                file_result['secrets'].append({
                    'type':     secret_type,
                    'match':    m[:80],
                    'file':     url,
                    'severity': 'CRITICAL' if secret_type in ('aws_key', 'private_key', 'github_token') else 'HIGH'
                })

        # Internal paths (info leak)
        for match in INTERNAL_PATH_PATTERN.finditer(text):
            file_result['internal_paths'].append(match.group(0)[:100])

        return file_result
