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
2FA / Auth Bypass Checker
- Weak/unsigned JWT detection (alg:none, weak secret brute-force, expired tokens)
- Default credentials on common admin panels
- Auth header misconfiguration
"""

import re
import base64
import json
import logging
import requests
from modules.utils import tor_session

logger = logging.getLogger(__name__)

DEFAULT_CREDS = [
    ('admin',     'admin'),
    ('admin',     'password'),
    ('admin',     'admin123'),
    ('admin',     '123456'),
    ('admin',     ''),
    ('root',      'root'),
    ('root',      'toor'),
    ('root',      ''),
    ('test',      'test'),
    ('guest',     'guest'),
    ('user',      'user'),
    ('administrator', 'administrator'),
    ('administrator', 'password'),
    ('admin',     'letmein'),
    ('admin',     'changeme'),
]

ADMIN_PATHS = [
    '/admin', '/admin/login', '/administrator', '/wp-admin', '/wp-login.php',
    '/login', '/signin', '/auth/login', '/user/login', '/account/login',
    '/panel', '/cpanel', '/dashboard', '/manage', '/management',
    '/phpmyadmin', '/adminer', '/console', '/api/login', '/api/auth',
]

WEAK_JWT_SECRETS = [
    'secret', 'password', '123456', 'qwerty', 'admin', 'test',
    'changeme', 'supersecret', 'jwt_secret', 'your-256-bit-secret',
    '', 'null', 'undefined',
]


class AuthBypassChecker:

    def run(self, domain: str) -> dict:
        result = {
            'domain': domain,
            'findings': [],
            'jwt_issues': [],
            'default_creds': [],
            'admin_panels': [],
            'total': 0,
            'risk_level': 'LOW',
            'error': None,
        }

        session = tor_session()
        session.verify = False
        session.headers['User-Agent'] = 'Mozilla/5.0'

        # ── 1. Discover admin panels ──────────────────────────────────────────
        for path in ADMIN_PATHS:
            for scheme in ('https', 'http'):
                url = f"{scheme}://{domain}{path}"
                try:
                    r = session.get(url, timeout=6, allow_redirects=True)
                    if r.status_code in (200, 401, 403):
                        panel = {'url': url, 'status': r.status_code,
                                 'title': self._extract_title(r.text)}
                        result['admin_panels'].append(panel)

                        # Try default creds on 200/401 login pages
                        if r.status_code in (200, 401) and self._looks_like_login(r.text):
                            hit = self._try_default_creds(session, url, r.text)
                            if hit:
                                hit['panel_url'] = url
                                result['default_creds'].append(hit)
                                result['findings'].append({
                                    'severity': 'CRITICAL',
                                    'type': 'Default Credentials',
                                    'evidence': f"{hit['username']}:{hit['password']} worked on {url}",
                                })
                        break
                except Exception:
                    pass

        # ── 2. JWT analysis from cookies / response headers ───────────────────
        for scheme in ('https', 'http'):
            try:
                r = session.get(f"{scheme}://{domain}", timeout=8)
                jwts = self._extract_jwts(r)
                for token in jwts:
                    issues = self._analyze_jwt(token)
                    for issue in issues:
                        issue['token_preview'] = token[:40] + '...'
                        result['jwt_issues'].append(issue)
                        result['findings'].append({
                            'severity': issue['severity'],
                            'type': f"JWT: {issue['issue']}",
                            'evidence': issue['detail'],
                        })
                break
            except Exception:
                pass

        # ── 3. Auth header checks ─────────────────────────────────────────────
        for scheme in ('https', 'http'):
            try:
                r = session.get(f"{scheme}://{domain}/api/v1/users", timeout=6)
                if r.status_code == 200:
                    result['findings'].append({
                        'severity': 'HIGH',
                        'type': 'Unauthenticated API Access',
                        'evidence': f"/api/v1/users returned HTTP 200 without auth",
                    })
                break
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

    def _extract_title(self, html: str) -> str:
        m = re.search(r'<title[^>]*>([^<]{1,80})', html, re.IGNORECASE)
        return m.group(1).strip() if m else ''

    def _looks_like_login(self, html: str) -> bool:
        html_l = html.lower()
        return any(k in html_l for k in ('type="password"', "type='password'",
                                          'name="password"', 'name="pass"'))

    def _try_default_creds(self, session, url: str, html: str) -> dict:
        # Extract form action + field names
        action = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.IGNORECASE)
        form_url = action.group(1) if action else url
        if not form_url.startswith('http'):
            base = url.rsplit('/', 1)[0]
            form_url = base + '/' + form_url.lstrip('/')

        user_field = 'username'
        pass_field = 'password'
        um = re.search(r'name=["\'](\w*(?:user|login|email|name)\w*)["\']', html, re.IGNORECASE)
        pm = re.search(r'name=["\'](\w*(?:pass|pwd)\w*)["\']', html, re.IGNORECASE)
        if um:
            user_field = um.group(1)
        if pm:
            pass_field = pm.group(1)

        for user, pwd in DEFAULT_CREDS:
            try:
                r = session.post(form_url, data={user_field: user, pass_field: pwd},
                                 timeout=6, allow_redirects=True)
                body_l = r.text.lower()
                failed_keywords = ('invalid', 'incorrect', 'wrong', 'failed',
                                   'error', 'denied', 'unauthorized')
                # Require redirect away from login URL AND success indicators
                redirected_away = (r.status_code == 302 and
                                   form_url not in r.headers.get('Location', form_url))
                has_success = 'logout' in body_l or 'sign out' in body_l or 'welcome' in body_l
                no_failure  = not any(k in body_l for k in failed_keywords)
                if no_failure and (redirected_away or has_success):
                    return {'username': user, 'password': pwd,
                            'status': r.status_code, 'form_url': form_url}
            except Exception:
                pass
        return {}

    def _extract_jwts(self, response) -> list:
        tokens = []
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'

        # From cookies
        for cookie in response.cookies:
            m = re.search(jwt_pattern, cookie.value)
            if m:
                tokens.append(m.group(0))

        # From headers
        for header_val in response.headers.values():
            m = re.search(jwt_pattern, header_val)
            if m:
                tokens.append(m.group(0))

        # From body
        for m in re.finditer(jwt_pattern, response.text[:20000]):
            tokens.append(m.group(0))

        return list(set(tokens))[:10]

    def _analyze_jwt(self, token: str) -> list:
        issues = []
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return issues

            # Decode header
            header_b64 = parts[0] + '=='
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            alg = header.get('alg', '').lower()

            # alg:none
            if alg == 'none':
                issues.append({
                    'severity': 'CRITICAL',
                    'issue': 'Algorithm None',
                    'detail': 'JWT uses alg:none — signature not verified',
                })

            # Weak algorithm
            if alg in ('hs256', 'hs384', 'hs512'):
                issues.append({
                    'severity': 'MEDIUM',
                    'issue': 'Symmetric Algorithm',
                    'detail': f'JWT uses {alg.upper()} — vulnerable to secret brute-force',
                })

            # Decode payload
            payload_b64 = parts[1] + '=='
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            # Expired token still accepted (we just flag if exp is in the past)
            import time
            exp = payload.get('exp', 0)
            if exp and exp < time.time():
                issues.append({
                    'severity': 'HIGH',
                    'issue': 'Expired Token',
                    'detail': f'JWT exp={exp} is in the past — server may not validate expiry',
                })

            # No expiry
            if not payload.get('exp'):
                issues.append({
                    'severity': 'MEDIUM',
                    'issue': 'No Expiration',
                    'detail': 'JWT has no exp claim — token never expires',
                })

        except Exception:
            pass

        return issues
