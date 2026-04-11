"""
HTTP Security Headers Checker
HSTS, CSP, X-Frame-Options, X-Content-Type, Referrer-Policy,
Permissions-Policy, CORS, Cookie flags, Server info leakage
"""

import logging
import requests
from modules.utils import tor_session
from datetime import datetime

logger = logging.getLogger(__name__)

HEADERS = {'User-Agent': 'Mozilla/5.0 (compatible; SentinelPro/2.1)'}

# Header definitions: (header_name, severity_if_missing, description)
SECURITY_HEADERS = [
    ('Strict-Transport-Security',  'HIGH',   'HSTS - forces HTTPS, prevents downgrade attacks'),
    ('Content-Security-Policy',    'HIGH',   'CSP - prevents XSS and data injection'),
    ('X-Frame-Options',            'MEDIUM', 'Prevents clickjacking attacks'),
    ('X-Content-Type-Options',     'MEDIUM', 'Prevents MIME-type sniffing'),
    ('Referrer-Policy',            'LOW',    'Controls referrer information leakage'),
    ('Permissions-Policy',         'LOW',    'Controls browser feature access'),
    ('X-XSS-Protection',           'LOW',    'Legacy XSS filter (deprecated but checked)'),
]

LEAKY_HEADERS = ['Server', 'X-Powered-By', 'X-AspNet-Version',
                 'X-AspNetMvc-Version', 'X-Generator', 'X-Drupal-Cache']


class HeadersChecker:

    def __init__(self):
        self.session = tor_session()
        self.session.headers.update(HEADERS)

    def run(self, domain: str) -> dict:
        result = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'present': {},
            'missing': [],
            'leaky': {},
            'cors': {},
            'cookies': [],
            'risk_flags': [],
            'grade': 'F'
        }

        url = f"https://{domain}" if not domain.startswith('http') else domain

        try:
            resp = self.session.get(url, timeout=10, verify=False,
                                    allow_redirects=True)
            headers = resp.headers
        except Exception as e:
            # Try HTTP fallback
            try:
                url_http = url.replace('https://', 'http://')
                resp = self.session.get(url_http, timeout=10, verify=False,
                                        allow_redirects=True)
                headers = resp.headers
                result['risk_flags'].append({
                    'flag': 'NO_HTTPS',
                    'severity': 'CRITICAL',
                    'detail': 'Site does not support HTTPS'
                })
            except Exception as e2:
                result['error'] = str(e2)
                return result

        # Check security headers
        for hdr, severity, desc in SECURITY_HEADERS:
            val = headers.get(hdr)
            if val:
                result['present'][hdr] = val
                # Validate HSTS
                if hdr == 'Strict-Transport-Security':
                    issues = self._validate_hsts(val)
                    result['risk_flags'].extend(issues)
                # Validate CSP
                if hdr == 'Content-Security-Policy':
                    issues = self._validate_csp(val)
                    result['risk_flags'].extend(issues)
            else:
                result['missing'].append({
                    'header': hdr,
                    'severity': severity,
                    'description': desc
                })
                result['risk_flags'].append({
                    'flag': f'MISSING_{hdr.upper().replace("-","_")}',
                    'severity': severity,
                    'detail': f'Missing {hdr}: {desc}'
                })

        # Leaky headers
        for hdr in LEAKY_HEADERS:
            val = headers.get(hdr)
            if val:
                result['leaky'][hdr] = val
                result['risk_flags'].append({
                    'flag': 'INFO_LEAKAGE',
                    'severity': 'LOW',
                    'detail': f'{hdr}: {val} - reveals server technology'
                })

        # CORS check
        result['cors'] = self._check_cors(domain, headers)

        # Cookie security
        result['cookies'] = self._check_cookies(resp)

        # Grade
        result['grade'] = self._grade(result)
        result['score'] = self._score(result)

        return result

    # ------------------------------------------------------------------ #
    #  Validators                                                          #
    # ------------------------------------------------------------------ #

    def _validate_hsts(self, val: str) -> list:
        flags = []
        val_lower = val.lower()
        if 'max-age' not in val_lower:
            flags.append({'flag': 'HSTS_NO_MAX_AGE', 'severity': 'HIGH',
                          'detail': 'HSTS header missing max-age directive'})
        else:
            try:
                age = int(val_lower.split('max-age=')[1].split(';')[0].strip())
                if age < 31536000:  # 1 year
                    flags.append({'flag': 'HSTS_SHORT_MAX_AGE', 'severity': 'MEDIUM',
                                  'detail': f'HSTS max-age {age}s is less than 1 year'})
            except Exception:
                pass
        if 'includesubdomains' not in val_lower:
            flags.append({'flag': 'HSTS_NO_SUBDOMAINS', 'severity': 'LOW',
                          'detail': 'HSTS does not include subdomains'})
        return flags

    def _validate_csp(self, val: str) -> list:
        flags = []
        if 'unsafe-inline' in val:
            flags.append({'flag': 'CSP_UNSAFE_INLINE', 'severity': 'HIGH',
                          'detail': "CSP allows 'unsafe-inline' - XSS risk"})
        if 'unsafe-eval' in val:
            flags.append({'flag': 'CSP_UNSAFE_EVAL', 'severity': 'HIGH',
                          'detail': "CSP allows 'unsafe-eval' - code injection risk"})
        if '*' in val:
            flags.append({'flag': 'CSP_WILDCARD', 'severity': 'MEDIUM',
                          'detail': 'CSP contains wildcard (*) - too permissive'})
        return flags

    def _check_cors(self, domain: str, headers) -> dict:
        cors = {}
        acao = headers.get('Access-Control-Allow-Origin', '')
        if acao:
            cors['Access-Control-Allow-Origin'] = acao
            cors['Access-Control-Allow-Credentials'] = headers.get(
                'Access-Control-Allow-Credentials', '')
            if acao == '*':
                cors['risk'] = 'CRITICAL - Wildcard CORS allows any origin'
            elif acao != f'https://{domain}':
                cors['risk'] = f'MEDIUM - CORS allows external origin: {acao}'
        return cors

    def _check_cookies(self, resp) -> list:
        cookies = []
        for cookie in resp.cookies:
            info = {
                'name':     cookie.name,
                'secure':   cookie.secure,
                'httponly': cookie.has_nonstandard_attr('HttpOnly') or
                            'httponly' in str(cookie._rest).lower(),
                'samesite': cookie._rest.get('SameSite', ''),
                'flags':    []
            }
            if not cookie.secure:
                info['flags'].append({'flag': 'COOKIE_NO_SECURE', 'severity': 'HIGH',
                                      'detail': f'Cookie {cookie.name} missing Secure flag'})
            if not info['httponly']:
                info['flags'].append({'flag': 'COOKIE_NO_HTTPONLY', 'severity': 'HIGH',
                                      'detail': f'Cookie {cookie.name} missing HttpOnly flag'})
            if not info['samesite']:
                info['flags'].append({'flag': 'COOKIE_NO_SAMESITE', 'severity': 'MEDIUM',
                                      'detail': f'Cookie {cookie.name} missing SameSite flag'})
            cookies.append(info)
        return cookies

    # ------------------------------------------------------------------ #
    #  Grading                                                             #
    # ------------------------------------------------------------------ #

    def _score(self, r: dict) -> int:
        score = 100
        for flag in r['risk_flags']:
            sev = flag.get('severity', '')
            if sev == 'CRITICAL': score -= 25
            elif sev == 'HIGH':   score -= 15
            elif sev == 'MEDIUM': score -= 8
            elif sev == 'LOW':    score -= 3
        return max(score, 0)

    def _grade(self, r: dict) -> str:
        score = self._score(r)
        if score >= 90: return 'A+'
        if score >= 80: return 'A'
        if score >= 70: return 'B'
        if score >= 50: return 'C'
        if score >= 30: return 'D'
        return 'F'
