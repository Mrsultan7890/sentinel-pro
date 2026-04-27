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
Cookie Security Analyzer
Fetches cookies from HTTP/HTTPS and audits security flags.
"""

import logging
import requests
from modules.utils import tor_session

logger = logging.getLogger(__name__)

ISSUES = {
    'missing_secure':    ('CRITICAL', 'Missing Secure flag — cookie sent over HTTP'),
    'missing_httponly':  ('HIGH',     'Missing HttpOnly flag — accessible via JavaScript'),
    'missing_samesite':  ('MEDIUM',   'Missing SameSite flag — CSRF risk'),
    'samesite_none_no_secure': ('HIGH', 'SameSite=None without Secure flag'),
    'session_no_httponly': ('CRITICAL', 'Session cookie missing HttpOnly'),
}

SESSION_NAMES = {'sessionid', 'session', 'sess', 'phpsessid', 'jsessionid', 'asp.net_sessionid', 'connect.sid', 'auth', 'token', 'jwt'}


class CookieAnalyzer:

    def run(self, domain: str) -> dict:
        result = {
            'domain': domain,
            'cookies': [],
            'findings': [],
            'total': 0,
            'risk_level': 'LOW',
            'error': None,
        }

        cookies_seen = {}
        for scheme in ('https', 'http'):
            url = f"{scheme}://{domain}"
            try:
                resp = requests.get(url, timeout=10, allow_redirects=True,
                                    headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
                # requests.cookies object se cookies lo
                for c in resp.cookies:
                    if c.name not in cookies_seen:
                        cookies_seen[c.name] = c

                # Set-Cookie headers directly parse karo — more accurate flags
                # requests mein get_all nahi hoti, urllib3 raw headers use karo
                raw_headers = resp.raw.headers.getlist('Set-Cookie') if hasattr(resp.raw, 'headers') and hasattr(resp.raw.headers, 'getlist') else []
                if not raw_headers:
                    # Fallback: single Set-Cookie header
                    sc = resp.headers.get('Set-Cookie', '')
                    raw_headers = [sc] if sc else []

                for raw in raw_headers:
                    if raw:
                        parsed = self._parse_set_cookie(raw)
                        if parsed and parsed['name'] not in cookies_seen:
                            cookies_seen[parsed['name']] = parsed

                if cookies_seen:
                    break  # https pe cookies mile, http skip karo
            except Exception as e:
                logger.debug(f"CookieAnalyzer {scheme}://{domain}: {e}")

        if not cookies_seen:
            result['error'] = 'No cookies found or target unreachable'
            return result

        findings = []
        cookie_list = []

        for name, c in cookies_seen.items():
            # Normalise — always use parsed dict from Set-Cookie header for accuracy
            if isinstance(c, dict):
                secure   = c.get('secure', False)
                httponly = c.get('httponly', False)
                samesite = (c.get('samesite') or '').lower()
                path     = c.get('path', '/')
                domain_attr = c.get('domain', '')
            else:
                # Fallback for requests cookie object — re-parse from raw header not available
                # Use secure attribute directly; httponly not reliably exposed by requests
                secure      = bool(c.secure)
                httponly    = False  # conservative — flag as missing
                samesite    = ''
                path        = c.path or '/'
                domain_attr = c.domain or ''

            is_session = name.lower() in SESSION_NAMES

            cookie_info = {
                'name': name,
                'secure': secure,
                'httponly': httponly,
                'samesite': samesite or 'not set',
                'path': path,
                'domain': domain_attr,
                'is_session': is_session,
            }
            cookie_list.append(cookie_info)

            if not secure:
                sev, msg = ISSUES['missing_secure']
                if is_session:
                    sev = 'CRITICAL'
                findings.append({'cookie': name, 'severity': sev, 'issue': msg})

            if not httponly:
                sev, msg = ISSUES['missing_httponly']
                if is_session:
                    sev, msg = ISSUES['session_no_httponly']
                findings.append({'cookie': name, 'severity': sev, 'issue': msg})

            if not samesite:
                findings.append({'cookie': name, **dict(zip(('severity','issue'), ISSUES['missing_samesite']))} )

            if samesite == 'none' and not secure:
                findings.append({'cookie': name, **dict(zip(('severity','issue'), ISSUES['samesite_none_no_secure']))})

        result['cookies']  = cookie_list
        result['findings'] = findings
        result['total']    = len(findings)

        if any(f['severity'] == 'CRITICAL' for f in findings):
            result['risk_level'] = 'CRITICAL'
        elif any(f['severity'] == 'HIGH' for f in findings):
            result['risk_level'] = 'HIGH'
        elif findings:
            result['risk_level'] = 'MEDIUM'

        return result

    def _parse_set_cookie(self, raw: str) -> dict:
        parts = [p.strip() for p in raw.split(';')]
        if not parts or '=' not in parts[0]:
            return {}
        name, _, value = parts[0].partition('=')
        attrs = {p.split('=')[0].lower(): (p.split('=')[1] if '=' in p else True) for p in parts[1:]}
        return {
            'name': name.strip(),
            'value': value,
            'secure':   'secure'   in attrs,
            'httponly': 'httponly' in attrs,
            'samesite': attrs.get('samesite', ''),
            'path':     attrs.get('path', '/'),
            'domain':   attrs.get('domain', ''),
        }
