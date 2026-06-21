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
OAuth 2.0 Misconfiguration Scanner
Tests: open redirect in redirect_uri, implicit flow, state param missing,
token leakage in referrer, PKCE bypass, client_secret exposure
"""

import logging
import re
import urllib.parse
from modules.utils import rate_limited_get, tor_session

logger = logging.getLogger(__name__)

OAUTH_PATHS = [
    '/oauth/authorize', '/oauth/token', '/oauth/callback',
    '/auth/oauth', '/auth/authorize', '/auth/callback',
    '/connect/authorize', '/connect/token',
    '/api/oauth/authorize', '/api/oauth/token',
    '/.well-known/oauth-authorization-server',
    '/.well-known/openid-configuration',
    '/openid/connect/authorize',
    '/v1/oauth/authorize', '/v2/oauth/authorize',
]

EVIL_REDIRECT = 'https://evil.example.com/callback'
EVIL_REDIRECT_ENCODED = urllib.parse.quote(EVIL_REDIRECT, safe='')


class OAuthScanner:

    def run(self, target: str) -> dict:
        result = {
            'target':          target,
            'endpoints_found': [],
            'findings':        [],
            'total':           0,
            'risk_level':      'LOW',
            'error':           None,
        }
        base = f"https://{target}"
        try:
            session = tor_session()
            self._discover_endpoints(session, base, result)
            if result['endpoints_found']:
                self._test_open_redirect(session, base, result)
                self._test_implicit_flow(session, base, result)
                self._test_state_param(session, base, result)
                self._test_token_leakage(session, base, result)
                self._test_pkce_bypass(session, base, result)
            self._check_client_secret_exposure(session, base, result)
            self._check_oidc_config(session, base, result)
        except Exception as e:
            logger.error(f"OAuthScanner error for {target}: {e}")
            result['error'] = str(e)

        result['total'] = len(result['findings'])
        result['risk_level'] = self._calc_risk(result['findings'])
        return result

    # ── Discovery ─────────────────────────────────────────────────────────────

    def _discover_endpoints(self, session, base: str, result: dict):
        for path in OAUTH_PATHS:
            resp = self._get(session, base + path)
            if resp and resp.status_code not in (404, 410):
                # Verify it's actually an OAuth endpoint, not a false 200
                body_lower = resp.text.lower()
                has_oauth_content = any([
                    'oauth' in body_lower,
                    'authorize' in body_lower,
                    'token' in body_lower,
                    'openid' in body_lower,
                    'client_id' in body_lower,
                ])
                if resp.status_code == 200 and not has_oauth_content:
                    continue  # Skip false positive (static hosting 200s)
                result['endpoints_found'].append(path)
                logger.debug(f"OAuth endpoint found: {path} ({resp.status_code})")

    # ── Tests ─────────────────────────────────────────────────────────────────

    def _test_open_redirect(self, session, base: str, result: dict):
        """Test if redirect_uri is validated — open redirect in OAuth flow."""
        for path in ['/oauth/authorize', '/auth/authorize', '/connect/authorize']:
            if path not in result['endpoints_found']:
                continue
            url = f"{base}{path}?response_type=code&client_id=test&redirect_uri={EVIL_REDIRECT_ENCODED}&scope=openid"
            resp = self._get(session, url, allow_redirects=False)
            if not resp:
                continue
            location = resp.headers.get('Location', '')
            if 'evil.example.com' in location:
                result['findings'].append({
                    'severity': 'CRITICAL',
                    'type':     'OAuth Open Redirect',
                    'url':      url,
                    'evidence': f'redirect_uri not validated — Location: {location[:80]}',
                    'detail':   'Attacker can steal authorization codes by injecting malicious redirect_uri',
                })

    def _test_implicit_flow(self, session, base: str, result: dict):
        """Implicit flow (response_type=token) exposes access tokens in URL fragment."""
        for path in ['/oauth/authorize', '/auth/authorize', '/connect/authorize']:
            if path not in result['endpoints_found']:
                continue
            url = f"{base}{path}?response_type=token&client_id=test&redirect_uri={EVIL_REDIRECT_ENCODED}&scope=openid"
            resp = self._get(session, url, allow_redirects=False)
            if not resp:
                continue
            
            # Static sites often return 200 for everything - check for OAuth indicators
            body_lower = resp.text.lower()
            has_oauth_indicators = any([
                'oauth' in body_lower,
                'authorize' in body_lower,
                'client_id' in body_lower,
                'access_token' in body_lower,
                'grant_type' in body_lower,
            ])
            
            # If no OAuth indicators in response, skip false positive
            if not has_oauth_indicators and resp.status_code == 200:
                continue
            
            # If server doesn't reject implicit flow with 400/error
            if resp.status_code not in (400, 401, 403):
                if 'unsupported_response_type' not in body_lower and 'error' not in body_lower[:200]:
                    result['findings'].append({
                        'severity': 'HIGH',
                        'type':     'Implicit Flow Enabled',
                        'url':      url,
                        'evidence': f'Server accepted response_type=token (HTTP {resp.status_code})',
                        'detail':   'Implicit flow exposes access tokens in URL — deprecated in OAuth 2.1',
                    })

    def _test_state_param(self, session, base: str, result: dict):
        """Missing state parameter allows CSRF on OAuth callback."""
        for path in ['/oauth/authorize', '/auth/authorize', '/connect/authorize']:
            if path not in result['endpoints_found']:
                continue
            # Request without state param
            url = f"{base}{path}?response_type=code&client_id=test&redirect_uri={EVIL_REDIRECT_ENCODED}&scope=openid"
            resp = self._get(session, url, allow_redirects=False)
            if not resp:
                continue
            body = resp.text.lower()
            # If server doesn't complain about missing state
            if resp.status_code not in (400, 401) and 'state' not in body[:500] and 'invalid_request' not in body:
                result['findings'].append({
                    'severity': 'MEDIUM',
                    'type':     'Missing State Parameter Enforcement',
                    'url':      url,
                    'evidence': f'Server did not require state param (HTTP {resp.status_code})',
                    'detail':   'Missing state parameter allows CSRF attacks on OAuth callback',
                })

    def _test_token_leakage(self, session, base: str, result: dict):
        """Check if access tokens appear in Referer headers via token endpoint."""
        for path in ['/oauth/token', '/auth/token', '/connect/token']:
            if path not in result['endpoints_found']:
                continue
            resp = self._get(session, base + path)
            if not resp:
                continue
            # Check referrer policy
            rp = resp.headers.get('Referrer-Policy', '')
            if not rp or rp in ('', 'unsafe-url', 'no-referrer-when-downgrade'):
                result['findings'].append({
                    'severity': 'MEDIUM',
                    'type':     'Token Endpoint Referrer Leakage Risk',
                    'url':      base + path,
                    'evidence': f'Referrer-Policy: {rp or "not set"}',
                    'detail':   'Tokens in URL may leak via Referer header to third-party resources',
                })

    def _test_pkce_bypass(self, session, base: str, result: dict):
        """Test if PKCE is enforced for public clients."""
        for path in ['/oauth/token', '/connect/token']:
            if path not in result['endpoints_found']:
                continue
            # Try token exchange without code_verifier
            resp = self._post(session, base + path, data={
                'grant_type':   'authorization_code',
                'code':         'test_code_12345',
                'redirect_uri': EVIL_REDIRECT,
                'client_id':    'test',
            })
            if not resp:
                continue
            body = resp.text.lower()
            # If error is about invalid code (not about missing PKCE), PKCE not enforced
            if resp.status_code in (400, 401) and 'code_verifier' not in body and 'pkce' not in body:
                if 'invalid_grant' in body or 'invalid_client' in body:
                    result['findings'].append({
                        'severity': 'MEDIUM',
                        'type':     'PKCE Not Enforced',
                        'url':      base + path,
                        'evidence': f'Token endpoint accepted request without code_verifier',
                        'detail':   'PKCE should be required for all public clients (RFC 7636)',
                    })

    def _check_client_secret_exposure(self, session, base: str, result: dict):
        """Check if client_secret appears in JS files or config endpoints."""
        check_paths = [
            '/static/js/main.js', '/assets/js/app.js', '/js/config.js',
            '/config.js', '/env.js', '/.env', '/api/config',
        ]
        for path in check_paths:
            resp = self._get(session, base + path)
            if not resp or resp.status_code != 200:
                continue
            text = resp.text
            if re.search(r'client_secret\s*[:=]\s*["\'][^"\']{8,}["\']', text, re.I):
                match = re.search(r'client_secret\s*[:=]\s*["\']([^"\']{4})[^"\']*["\']', text, re.I)
                preview = match.group(1) + '***' if match else '***'
                result['findings'].append({
                    'severity': 'CRITICAL',
                    'type':     'Client Secret Exposed',
                    'url':      base + path,
                    'evidence': f'client_secret found in {path}: {preview}',
                    'detail':   'OAuth client_secret exposed in frontend code — full account takeover possible',
                })

    def _check_oidc_config(self, session, base: str, result: dict):
        """Check OpenID Connect discovery document for misconfigurations."""
        for path in ('/.well-known/openid-configuration', '/.well-known/oauth-authorization-server'):
            resp = self._get(session, base + path)
            if not resp or resp.status_code != 200:
                continue
            try:
                cfg = resp.json()
            except Exception:
                continue
            result['endpoints_found'].append(path)

            # Implicit flow in supported response types
            response_types = cfg.get('response_types_supported', [])
            if 'token' in response_types or 'id_token token' in response_types:
                result['findings'].append({
                    'severity': 'HIGH',
                    'type':     'OIDC Implicit Flow Advertised',
                    'url':      base + path,
                    'evidence': f'response_types_supported includes: {response_types}',
                    'detail':   'Implicit flow advertised in OIDC discovery — deprecated and insecure',
                })

            # No PKCE methods advertised
            pkce_methods = cfg.get('code_challenge_methods_supported', [])
            if not pkce_methods:
                result['findings'].append({
                    'severity': 'MEDIUM',
                    'type':     'PKCE Not Advertised in OIDC Config',
                    'url':      base + path,
                    'evidence': 'code_challenge_methods_supported not present in discovery document',
                    'detail':   'PKCE support should be advertised for public clients',
                })
            break  # Only need one successful config

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get(self, session, url: str, allow_redirects: bool = True):
        try:
            return session.get(url, timeout=10, verify=False,
                               allow_redirects=allow_redirects,
                               headers={'User-Agent': 'Mozilla/5.0'})
        except Exception:
            return None

    def _post(self, session, url: str, data: dict):
        try:
            return session.post(url, data=data, timeout=10, verify=False,
                                headers={'User-Agent': 'Mozilla/5.0'})
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
