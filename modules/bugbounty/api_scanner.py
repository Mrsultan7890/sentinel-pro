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
API Security Scanner
- Unauthenticated endpoint discovery
- BOLA / IDOR detection (object ID manipulation)
- Mass assignment probing
- HTTP method enumeration (PUT/DELETE/PATCH on REST endpoints)
- Sensitive data exposure in API responses
"""

import re
import logging
import requests
from modules.utils import tor_session

logger = logging.getLogger(__name__)

API_PATHS = [
    # REST discovery
    '/api', '/api/v1', '/api/v2', '/api/v3', '/api/latest',
    '/v1', '/v2', '/v3',
    '/rest', '/rest/v1', '/rest/api',
    # Common resources
    '/api/v1/users', '/api/v1/user', '/api/v1/accounts', '/api/v1/account',
    '/api/v1/admin', '/api/v1/config', '/api/v1/settings',
    '/api/v1/orders', '/api/v1/products', '/api/v1/items',
    '/api/v1/profile', '/api/v1/me', '/api/v1/whoami',
    '/api/v1/keys', '/api/v1/tokens', '/api/v1/secrets',
    '/api/v1/logs', '/api/v1/debug', '/api/v1/health',
    # Juice Shop / OWASP specific
    '/rest/products/search', '/rest/user/login', '/rest/user/whoami',
    '/rest/basket', '/rest/products', '/rest/challenges',
    '/api/Challenges', '/api/Users', '/api/Products',
    '/api/BasketItems', '/api/Feedbacks', '/api/Complaints',
    # GraphQL
    '/graphql', '/graphiql', '/api/graphql', '/v1/graphql',
    # Swagger / OpenAPI
    '/swagger.json', '/swagger/v1/swagger.json', '/openapi.json',
    '/api-docs', '/api/docs', '/docs',
    # Spring Boot actuator
    '/actuator', '/actuator/env', '/actuator/mappings',
    '/actuator/beans', '/actuator/heapdump',
    # Django / Rails
    '/api/schema', '/api/schema.json',
]

# ── Wordlist-based API path loading ──────────────────────────────────────────

API_WORDLISTS = [
    '/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt',
    '/usr/share/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt',
    '/usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt',
    '/usr/share/seclists/Discovery/Web-Content/common.txt',
    '/usr/share/wordlists/dirb/common.txt',
]

def _load_api_paths() -> list:
    """Wordlists se API paths load karo + hardcoded paths merge karo."""
    paths = list(API_PATHS)
    seen  = set(paths)

    # Depth-based limit
    try:
        from modules.bugbounty.payload_loader import SCAN_DEPTH
    except Exception:
        SCAN_DEPTH = 'NORMAL'
    LIMITS = {'FAST': 0, 'NORMAL': 500, 'DEEP': 0}  # FAST = hardcoded only
    limit = LIMITS.get(SCAN_DEPTH, 500)

    if SCAN_DEPTH == 'FAST':
        return paths  # hardcoded API_PATHS only — fast enough

    added = 0
    for wl in API_WORDLISTS:
        try:
            from pathlib import Path as _P
            if not _P(wl).exists():
                continue
            for line in _P(wl).read_text(errors='ignore').splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                path = line if line.startswith('/') else '/' + line
                if path not in seen:
                    paths.append(path)
                    seen.add(path)
                    added += 1
                    if limit and added >= limit:
                        break
            logger.debug(f'API wordlist loaded: {wl} ({added} paths, depth={SCAN_DEPTH})')
            if limit and added >= limit:
                break
        except Exception:
            pass
    return paths


API_PATHS = API_PATHS  # noqa — keep reference

SENSITIVE_PATTERNS = [
    (r'"secret"\s*:\s*"[^"]+"',            'CRITICAL', 'Secret in API response'),
    (r'"api_key"\s*:\s*"[^"]+"',           'CRITICAL', 'API key in response'),
    (r'"token"\s*:\s*"[A-Za-z0-9._-]{20,}', 'CRITICAL', 'Token in API response'),
    (r'"ssn"\s*:\s*"\d{3}-\d{2}-\d{4}"',  'CRITICAL', 'SSN in API response'),
    (r'"credit_card"\s*:\s*"[\d ]{13,19}"','CRITICAL', 'Credit card in API response'),
    (r'"email"\s*:\s*"[^@"]+@[^"]+"',      'HIGH',     'Email addresses exposed'),
    (r'"phone"\s*:\s*"[\d\s+()-]{7,}"',    'HIGH',     'Phone numbers exposed'),
    (r'"role"\s*:\s*"admin"',              'HIGH',     'Admin role visible in response'),
    (r'"is_admin"\s*:\s*true',             'HIGH',     'Admin flag visible in response'),
    (r'"internal_id"\s*:\s*\d+',           'MEDIUM',   'Internal IDs exposed'),
]

METHODS_TO_TEST = ['PUT', 'DELETE', 'PATCH']


class APIScanner:

    def run(self, domain: str) -> dict:
        result = {
            'domain': domain,
            'endpoints_found': [],
            'findings': [],
            'idor_candidates': [],
            'total': 0,
            'risk_level': 'LOW',
            'error': None,
        }

        session = tor_session()
        session.verify = False
        session.headers.update({'User-Agent': 'Mozilla/5.0',
                                'Accept': 'application/json'})

        base = f"https://{domain}"

        # Wordlist-based paths load karo
        all_api_paths = _load_api_paths()
        logger.info(f'APIScanner: {len(all_api_paths)} paths for {domain}')

        # ── 1. Discover API endpoints ─────────────────────────────────────────
        for path in all_api_paths:
            url = base + path
            try:
                r = session.get(url, timeout=7, allow_redirects=False)
                if r.status_code in (200, 201, 401, 403):
                    ct = r.headers.get('Content-Type', '')
                    is_json = 'json' in ct or self._looks_json(r.text)
                    ep = {
                        'url': url,
                        'status': r.status_code,
                        'content_type': ct[:60],
                        'is_json': is_json,
                        'size': len(r.content),
                    }
                    result['endpoints_found'].append(ep)

                    # Unauthenticated access to sensitive endpoint
                    if r.status_code == 200 and is_json:
                        sev, issue = self._classify_path_risk(path)
                        if sev:
                            result['findings'].append({
                                'severity': sev,
                                'type': 'Unauthenticated Access',
                                'url': url,
                                'evidence': f"HTTP 200 JSON — {issue}",
                            })

                        # Sensitive data in response
                        for pattern, psev, pdesc in SENSITIVE_PATTERNS:
                            if re.search(pattern, r.text[:5000], re.IGNORECASE):
                                result['findings'].append({
                                    'severity': psev,
                                    'type': 'Sensitive Data Exposure',
                                    'url': url,
                                    'evidence': pdesc,
                                })

                        # IDOR candidates — endpoints with numeric IDs
                        if re.search(r'/\d+', path):
                            result['idor_candidates'].append(url)

            except Exception:
                pass

        # ── 2. BOLA / IDOR probing ────────────────────────────────────────────
        idor_findings = self._probe_idor(session, base)
        result['findings'].extend(idor_findings)

        # ── 3. HTTP method enumeration on found endpoints ─────────────────────
        for ep in result['endpoints_found'][:5]:
            method_findings = self._test_methods(session, ep['url'])
            result['findings'].extend(method_findings)

        # ── 4. GraphQL introspection ──────────────────────────────────────────
        gql = self._test_graphql(session, base)
        if gql:
            result['findings'].append(gql)

        # ── 5. Mass assignment probe ──────────────────────────────────────────
        ma = self._test_mass_assignment(session, base)
        result['findings'].extend(ma)

        result['total'] = len(result['findings'])
        if any(f['severity'] == 'CRITICAL' for f in result['findings']):
            result['risk_level'] = 'CRITICAL'
        elif any(f['severity'] == 'HIGH' for f in result['findings']):
            result['risk_level'] = 'HIGH'
        elif result['findings']:
            result['risk_level'] = 'MEDIUM'

        return result

    def _classify_path_risk(self, path: str):
        p = path.lower()
        if any(k in p for k in ('admin', 'config', 'secret', 'key', 'token', 'env', 'heapdump')):
            return 'CRITICAL', 'Admin/config endpoint accessible without auth'
        if any(k in p for k in ('user', 'account', 'profile', 'order', 'log')):
            return 'HIGH', 'User data endpoint accessible without auth'
        if any(k in p for k in ('graphql', 'swagger', 'openapi', 'docs', 'actuator')):
            return 'MEDIUM', 'API documentation/introspection exposed'
        return None, None

    def _looks_json(self, text: str) -> bool:
        t = text.strip()
        return t.startswith(('{', '['))

    def _probe_idor(self, session, base: str) -> list:
        findings = []
        idor_paths = [
            '/api/v1/users/1', '/api/v1/users/2',
            '/api/v1/orders/1', '/api/v1/orders/2',
            '/api/v1/accounts/1', '/api/v1/accounts/2',
            '/api/v1/profile/1', '/api/v1/profile/2',
        ]
        responses = {}
        for path in idor_paths:
            try:
                r = session.get(base + path, timeout=6)
                if r.status_code == 200 and self._looks_json(r.text):
                    responses[path] = r.text[:500]
            except Exception:
                pass

        # If both /1 and /2 return 200 with different content → IDOR
        for resource in ('users', 'orders', 'accounts', 'profile'):
            p1 = f'/api/v1/{resource}/1'
            p2 = f'/api/v1/{resource}/2'
            if p1 in responses and p2 in responses and responses[p1] != responses[p2]:
                findings.append({
                    'severity': 'HIGH',
                    'type': 'BOLA / IDOR',
                    'url': base + p1,
                    'evidence': f"Both /{resource}/1 and /{resource}/2 return different 200 responses without auth",
                })
        return findings

    def _test_methods(self, session, url: str) -> list:
        findings = []
        dangerous = {
            'PUT':    'Data modification',
            'DELETE': 'Data deletion',
            'PATCH':  'Partial modification',
        }
        for method in METHODS_TO_TEST:
            desc = dangerous[method]
            try:
                r = session.request(method, url, timeout=5,
                                    json={'test': 'sentinel_probe'})
                if r.status_code not in (405, 501, 404, 400):
                    findings.append({
                        'severity': 'HIGH',
                        'type': f'Dangerous HTTP Method: {method}',
                        'url': url,
                        'evidence': f"{method} returned HTTP {r.status_code} — {desc} possible",
                    })
            except Exception:
                pass
        return findings

    def _test_graphql(self, session, base: str) -> dict:
        for path in ('/graphql', '/api/graphql', '/graphiql'):
            try:
                r = session.post(base + path,
                                 json={'query': '{__schema{types{name}}}'},
                                 timeout=8)
                if r.status_code == 200 and '__schema' in r.text:
                    return {
                        'severity': 'HIGH',
                        'type': 'GraphQL Introspection Enabled',
                        'url': base + path,
                        'evidence': 'Full schema exposed via __schema introspection query',
                    }
            except Exception:
                pass
        return {}

    def _test_mass_assignment(self, session, base: str) -> list:
        findings = []
        for path in ('/api/v1/users', '/api/v1/profile', '/api/v1/account'):
            try:
                r = session.post(base + path,
                                 json={'username': 'sentinel_test',
                                       'role': 'admin',
                                       'is_admin': True},
                                 timeout=6)
                if r.status_code in (200, 201):
                    body = r.text
                    # Check for specific JSON patterns, not generic word match
                    if re.search(r'"role"\s*:\s*"admin"', body) or \
                       re.search(r'"is_admin"\s*:\s*true', body, re.IGNORECASE):
                        findings.append({
                            'severity': 'CRITICAL',
                            'type': 'Mass Assignment',
                            'url': base + path,
                            'evidence': f"POST with role:admin returned HTTP {r.status_code} — privileged field reflected in response",
                        })
            except Exception:
                pass
        return findings
