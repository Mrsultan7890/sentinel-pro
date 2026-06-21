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
Cloud Asset Discovery
Permutation-based enumeration of:
- AWS S3 buckets
- Azure Blob Storage containers
- Google Cloud Storage buckets
- Firebase databases
- DigitalOcean Spaces
"""

import re
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.utils import tor_session

logger = logging.getLogger(__name__)

PERMUTATIONS = [
    '{word}', '{word}-backup', '{word}-dev', '{word}-prod', '{word}-staging',
    '{word}-test', '{word}-data', '{word}-assets', '{word}-static', '{word}-media',
    '{word}-files', '{word}-uploads', '{word}-images', '{word}-logs', '{word}-archive',
    '{word}-public', '{word}-private', '{word}-internal', '{word}-api', '{word}-cdn',
    '{word}-storage', '{word}-bucket', '{word}-store', '{word}-web', '{word}-app',
    'backup-{word}', 'dev-{word}', 'prod-{word}', 'staging-{word}', 'test-{word}',
    'assets-{word}', 'static-{word}', 'media-{word}', 'files-{word}', 'data-{word}',
    '{word}backup', '{word}dev', '{word}prod', '{word}test', '{word}data',
]

TIMEOUT  = 3    # tight timeout — non-existent hosts fail fast
WORKERS  = 30   # parallel threads


class CloudAssetDiscovery:

    def __init__(self):
        self.session = tor_session(pool_size=30)
        self.session.verify = False
        self.session.headers['User-Agent'] = 'Mozilla/5.0'
    def run(self, domain: str) -> dict:
        result = {
            'domain':   domain,
            'findings': [],
            's3':       [],
            'azure':    [],
            'gcp':      [],
            'firebase': [],
            'spaces':   [],
            'total':    0,
            'risk_level': 'LOW',
            'error':    None,
        }

        words      = self._extract_words(domain)
        candidates = self._build_candidates(words)

        # Build all (checker_fn, name) tasks
        tasks = []
        for name in candidates:
            tasks.append((self._check_s3,       name, 's3'))
            tasks.append((self._check_azure,    name, 'azure'))
            tasks.append((self._check_gcp,      name, 'gcp'))
        for name in candidates[:30]:
            tasks.append((self._check_firebase, name, 'firebase'))
            tasks.append((self._check_spaces,   name, 'spaces'))

        # Run all checks in parallel
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            futures = {
                pool.submit(fn, name): (name, bucket)
                for fn, name, bucket in tasks
            }
            for future in as_completed(futures):
                try:
                    finding = future.result()
                    if finding:
                        _, bucket = futures[future]
                        result[bucket].append(finding)
                        result['findings'].append(finding)
                except Exception:
                    pass

        result['total'] = len(result['findings'])
        if any(f['severity'] == 'CRITICAL' for f in result['findings']):
            result['risk_level'] = 'CRITICAL'
        elif any(f['severity'] == 'HIGH' for f in result['findings']):
            result['risk_level'] = 'HIGH'
        elif result['findings']:
            result['risk_level'] = 'MEDIUM'

        return result

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_candidates(self, words: list) -> list:
        candidates = []
        for word in words:
            for tmpl in PERMUTATIONS:
                name = re.sub(r'[^a-z0-9-]', '-', tmpl.format(word=word).lower())[:63].strip('-')
                if len(name) >= 3:
                    candidates.append(name)
        return list(dict.fromkeys(candidates))[:80]

    def _get(self, url: str) -> requests.Response | None:
        """Fast GET — routes through Tor if active."""
        try:
            return self.session.get(url, timeout=TIMEOUT,
                                allow_redirects=False)
        except Exception:
            return None

    # ── Checkers ──────────────────────────────────────────────────────────────

    def _check_s3(self, name: str) -> dict:
        url = f"https://{name}.s3.amazonaws.com"
        r = self._get(url)
        if not r:
            return {}
        if r.status_code == 403:
            return {'provider': 'AWS S3', 'name': name, 'url': url,
                    'status': 'EXISTS (Access Denied)', 'severity': 'MEDIUM',
                    'evidence': 'HTTP 403 — bucket exists, access restricted', 'public': False}
        if r.status_code == 200:
            public = '<ListBucketResult' in r.text or '<Key>' in r.text
            return {'provider': 'AWS S3', 'name': name, 'url': url,
                    'status': 'PUBLIC' if public else 'EXISTS',
                    'severity': 'CRITICAL' if public else 'HIGH',
                    'evidence': 'HTTP 200 — bucket publicly accessible' + (' with listing' if public else ''),
                    'public': public, 'file_count': r.text.count('<Key>')}
        return {}

    def _check_azure(self, name: str) -> dict:
        url = f"https://{name}.blob.core.windows.net"
        r = self._get(url)
        if not r:
            return {}
        if r.status_code in (200, 400, 403, 409):
            public = r.status_code == 200 and 'EnumerationResults' in r.text
            return {'provider': 'Azure Blob', 'name': name, 'url': url,
                    'status': 'PUBLIC' if public else 'EXISTS',
                    'severity': 'CRITICAL' if public else 'MEDIUM',
                    'evidence': f'HTTP {r.status_code} — Azure storage account found',
                    'public': public}
        return {}

    def _check_gcp(self, name: str) -> dict:
        url = f"https://storage.googleapis.com/{name}"
        r = self._get(url)
        if not r:
            return {}
        if r.status_code == 403:
            return {'provider': 'GCP Storage', 'name': name, 'url': url,
                    'status': 'EXISTS (Access Denied)', 'severity': 'MEDIUM',
                    'evidence': 'HTTP 403 — GCP bucket exists, access restricted', 'public': False}
        if r.status_code == 200:
            public = '<ListBucketResult' in r.text or '<Contents>' in r.text
            return {'provider': 'GCP Storage', 'name': name, 'url': url,
                    'status': 'PUBLIC' if public else 'EXISTS',
                    'severity': 'CRITICAL' if public else 'HIGH',
                    'evidence': 'HTTP 200 — GCP bucket publicly accessible',
                    'public': public, 'file_count': r.text.count('<Key>')}
        return {}

    def _check_firebase(self, name: str) -> dict:
        url = f"https://{name}.firebaseio.com/.json"
        r = self._get(url)
        if not r:
            return {}
        if r.status_code == 200 and r.text.strip() not in ('null', ''):
            return {'provider': 'Firebase', 'name': name, 'url': url,
                    'status': 'PUBLIC', 'severity': 'CRITICAL',
                    'evidence': 'Firebase database publicly readable', 'public': True}
        if r.status_code == 401:
            return {'provider': 'Firebase', 'name': name, 'url': url,
                    'status': 'EXISTS (Auth Required)', 'severity': 'LOW',
                    'evidence': 'Firebase database exists, auth required', 'public': False}
        return {}

    def _check_spaces(self, name: str) -> dict:
        url = f"https://{name}.nyc3.digitaloceanspaces.com"
        r = self._get(url)
        if not r:
            return {}
        if r.status_code in (200, 403):
            public = r.status_code == 200
            return {'provider': 'DigitalOcean Spaces', 'name': name, 'url': url,
                    'status': 'PUBLIC' if public else 'EXISTS',
                    'severity': 'CRITICAL' if public else 'MEDIUM',
                    'evidence': f'HTTP {r.status_code} — DO Space found', 'public': public}
        return {}

    def _extract_words(self, domain: str) -> list:
        parts = domain.lower().split('.')
        parts = [p for p in parts if p not in ('www','com','net','org','io','co','uk','in','de')]
        words = []
        for part in parts:
            words.append(part)
            words.extend(part.split('-'))
        return list(dict.fromkeys(w for w in words if len(w) >= 3))


# Alias for backward compatibility
CloudAssets = CloudAssetDiscovery

