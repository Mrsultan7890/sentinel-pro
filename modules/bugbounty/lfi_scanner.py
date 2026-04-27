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

"""
LFI / RFI Scanner
- Local File Inclusion via path/file params
- Remote File Inclusion probes
- Path traversal variants (URL encoded, double encoded, null byte)
"""

import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.utils import tor_session
from modules.bugbounty.payload_loader import load_payloads

logger = logging.getLogger(__name__)

LFI_PARAMS = [
    'file', 'page', 'path', 'include', 'inc', 'load', 'template',
    'view', 'doc', 'document', 'folder', 'root', 'pg', 'style',
    'pdf', 'read', 'content', 'lang', 'language', 'module',
]

# Load from proxy payloads (4778) → SecLists → hardcoded fallback
# path_traversal has 22662 payloads — merge both for maximum coverage
_LFI_RAW        = load_payloads('lfi')
_PATH_RAW       = load_payloads('path_traversal', limit=500)  # top 500 traversal variants
LFI_PAYLOADS    = list(dict.fromkeys(_LFI_RAW + _PATH_RAW))  # deduplicated, LFI first

LFI_SIGNATURES = [
    (r'root:x:0:0',                    'CRITICAL', 'Linux /etc/passwd leaked'),
    (r'\[boot loader\]',               'CRITICAL', 'Windows win.ini leaked'),
    (r'\[extensions\]',                'CRITICAL', 'Windows win.ini leaked'),
    (r'<\?php',                        'CRITICAL', 'PHP source code leaked via wrapper'),
    (r'[A-Za-z0-9+/]{40,}={0,2}',     'HIGH',     'Base64 encoded file content (PHP wrapper)'),
    (r'/bin/bash|/bin/sh',             'HIGH',     'Unix shell path in response'),
    (r'proc/self/environ',             'HIGH',     'Process environment leaked'),
    (r'HTTP_USER_AGENT',               'HIGH',     'Environment variable leaked'),
    (r'instance-id|ami-id',            'CRITICAL', 'AWS metadata leaked via SSRF/RFI'),
]


class LFIScanner:

    TIMEOUT     = (2, 4)
    MAX_WORKERS = 30
    MAX_TARGETS = 3
    MAX_PARAMS  = 6
    # Top payloads for fast scan — full LFI_PAYLOADS list used in deep mode
    FAST_PAYLOADS = LFI_PAYLOADS[:50] if len(LFI_PAYLOADS) >= 50 else LFI_PAYLOADS

    def run(self, domain: str, endpoints: list = None) -> dict:
        result = {
            'domain': domain,
            'findings': [],
            'total': 0,
            'risk_level': 'LOW',
            'error': None,
        }

        session = tor_session()
        session.verify = False
        session.headers['User-Agent'] = 'Mozilla/5.0'

        base = f"https://{domain}"

        # Build target URLs — limit to MAX_TARGETS
        targets = []
        if endpoints:
            for ep in endpoints[:self.MAX_TARGETS]:
                targets.append(ep.get('url') or f"{base}{ep.get('path','')}")
        if not targets:
            targets = [base + '/']
        for param in LFI_PARAMS[:2]:
            targets.append(f"{base}/?{param}=index")
        targets = list(dict.fromkeys(targets))[:self.MAX_TARGETS]

        # Build jobs: 1 target × 6 params × 9 payloads = 54 jobs max
        # With 30 workers + 4s read timeout = ~8s worst case
        jobs = []
        for target_url in targets[:1]:   # only probe base URL — param URLs already have param
            for param in LFI_PARAMS[:self.MAX_PARAMS]:
                for payload in self.FAST_PAYLOADS:
                    sep = '&' if '?' in target_url else '?'
                    jobs.append((f"{target_url}{sep}{param}={payload}", param, payload))
        # Also probe the param-seeded targets (already have ?param=index)
        for target_url in targets[1:]:
            try:
                base_url = target_url.rsplit('=', 1)[0]
                param_name = target_url.split('?')[1].split('=')[0] if '?' in target_url and '=' in target_url else 'file'
                for payload in self.FAST_PAYLOADS:
                    jobs.append((f"{base_url}={payload}", param_name, payload))
            except (IndexError, ValueError):
                continue

        # Run all in parallel
        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as ex:
            futures = {ex.submit(self._probe, session, url, param, payload): (param, payload)
                       for url, param, payload in jobs}
            seen_params = set()
            for future in as_completed(futures):
                finding = future.result()
                if finding and finding['param'] not in seen_params:
                    seen_params.add(finding['param'])
                    result['findings'].append(finding)

        # Deduplicate by (param, evidence)
        seen, deduped = set(), []
        for f in result['findings']:
            key = (f['param'], f['evidence'])
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        result['findings'] = deduped
        result['total'] = len(result['findings'])

        if any(f['severity'] == 'CRITICAL' for f in result['findings']):
            result['risk_level'] = 'CRITICAL'
        elif any(f['severity'] == 'HIGH' for f in result['findings']):
            result['risk_level'] = 'HIGH'
        elif result['findings']:
            result['risk_level'] = 'MEDIUM'
        return result

    def _probe(self, session, url: str, param: str, payload: str) -> dict:
        try:
            r = session.get(url, timeout=self.TIMEOUT, allow_redirects=True)
            for sig, sev, desc in LFI_SIGNATURES:
                if re.search(sig, r.text):
                    return {
                        'severity': sev, 'type': 'LFI',
                        'url': url, 'param': param,
                        'payload': payload, 'evidence': desc,
                    }
        except Exception:
            pass
        return {}

