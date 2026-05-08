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
Email OSINT - Email address investigation
Domain validation, social profile hints, breach check, disposable detection
"""

import logging
import re
import requests
import dns.resolver
from datetime import datetime
from modules.utils import rate_limited_get

logger = logging.getLogger(__name__)

# (url_template, body_markers_that_confirm_profile_exists)
SOCIAL_PATTERNS = {
    'github':    ('https://github.com/{user}',           ['itemprop="name"', 'class="p-name"', 'class="avatar"']),
    'instagram': ('https://www.instagram.com/{user}/',   ['"username":', '"is_private"', 'og:title']),
    'twitter':   ('https://twitter.com/{user}',          ['data-screen-name', 'og:title', 'twitter:title']),
    'reddit':    ('https://www.reddit.com/user/{user}',  ['"is_employee"', 'karma', 'redditor']),
    'linkedin':  ('https://www.linkedin.com/in/{user}',  ['public-profile', 'linkedin', 'profile']),
    'tiktok':    ('https://www.tiktok.com/@{user}',      ['"uniqueId"', 'tiktok', 'follower']),
    'youtube':   ('https://www.youtube.com/@{user}',     ['"channelId"', 'subscribers', 'youtube']),
    'pinterest': ('https://www.pinterest.com/{user}/',   ['pinterestapp', 'og:type', 'profile']),
}

class EmailOSINT:
    TIMEOUT = 8

    def run(self, email: str) -> dict:
        if not email or not isinstance(email, str):
            return {'error': 'Invalid email parameter', 'valid_format': False}
        
        email = email.strip().lower()
        if len(email) > 320:  # RFC 5321 limit
            return {'error': 'Email too long', 'valid_format': False}
        
        result = {
            'email': email,
            'valid_format': False,
            'domain': None,
            'username': None,
            'domain_info': {},
            'social_hints': [],
            'breach_summary': {},
            'disposable': False,
            'risk_level': 'LOW',
            'risk_flags': [],
            'timestamp': datetime.now().isoformat(),
            'error': None
        }

        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            result['error'] = 'Invalid email format'
            return result

        result['valid_format'] = True
        result['username']     = email.split('@')[0]
        result['domain']       = email.split('@')[1]

        self._validate_domain(result)
        self._check_disposable(result)
        self._social_hints(result)
        self._breach_check(result)
        self._calc_risk(result)
        return result

    def _validate_domain(self, result: dict):
        if not isinstance(result, dict) or 'domain' not in result:
            return
        
        domain = result['domain']
        if not domain or not isinstance(domain, str):
            return
        
        info   = {}
        try:
            mx = dns.resolver.resolve(domain, 'MX', lifetime=5)
            info['mx_records'] = [str(r.exchange) for r in mx]
            info['mx_valid']   = True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers) as e:
            info['mx_valid']   = False
            info['mx_records'] = []
            result['risk_flags'].append({'severity': 'HIGH', 'flag': 'No MX records', 'detail': f'{domain} has no mail server'})
            logger.debug(f'MX lookup failed for {domain}: {e}')
        except Exception as e:
            info['mx_valid']   = False
            info['mx_records'] = []
            logger.error(f'MX lookup error for {domain}: {e}')

        try:
            txt = dns.resolver.resolve(domain, 'TXT', lifetime=5)
            spf = [str(r) for r in txt if 'v=spf1' in str(r)]
            info['spf'] = spf[0] if spf else None
        except Exception as e:
            info['spf'] = None
            logger.debug(f'TXT lookup failed for {domain}: {e}')

        result['domain_info'] = info

    def _check_disposable(self, result: dict):
        DISPOSABLE = {'mailinator.com', 'guerrillamail.com', 'tempmail.com',
                      'throwaway.email', 'yopmail.com', '10minutemail.com',
                      'trashmail.com', 'sharklasers.com', 'guerrillamailblock.com',
                      'grr.la', 'guerrillamail.info', 'spam4.me', 'dispostable.com'}
        if result['domain'] in DISPOSABLE:
            result['disposable'] = True
            result['risk_flags'].append({
                'severity': 'HIGH',
                'flag': 'Disposable email',
                'detail': f"{result['domain']} is a known disposable email provider"
            })

    def _social_hints(self, result: dict):
        if not isinstance(result, dict) or 'username' not in result:
            return
        
        username = result.get('username', '')
        if not username or not isinstance(username, str):
            result['social_hints'] = []
            return
        
        hints    = []
        for platform, (url_tpl, markers) in SOCIAL_PATTERNS.items():
            try:
                url  = url_tpl.format(user=username)
                resp = rate_limited_get(url, namespace='social',
                                        headers={'User-Agent': 'Mozilla/5.0'},
                                        allow_redirects=True)
                if resp and resp.status_code == 200 and any(m in resp.text for m in markers):
                    hints.append({'platform': platform, 'url': url, 'status': 'found'})
                else:
                    hints.append({'platform': platform, 'url': url, 'status': 'not_found'})
            except Exception as e:
                logger.debug(f'Social hint check failed for {platform}: {e}')
                hints.append({'platform': platform, 'url': '', 'status': 'error'})
        result['social_hints'] = hints

    def _breach_check(self, result: dict):
        if not isinstance(result, dict) or 'email' not in result:
            return
        
        # HudsonRock — correct email endpoint
        try:
            resp = rate_limited_get(
                'https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email',
                namespace='breach', params={'email': result['email']}
            )
            if resp and resp.status_code == 200:
                data     = resp.json()
                if not isinstance(data, dict):
                    return
                stealers = data.get('stealers', [])
                if not isinstance(stealers, list):
                    stealers = []
                result['breach_summary']['stealer_logs'] = len(stealers)
                if stealers:
                    result['risk_flags'].append({
                        'severity': 'CRITICAL',
                        'flag': 'Infostealer logs found',
                        'detail': f"{len(stealers)} stealer log(s) contain this email"
                    })
        except (requests.Timeout, requests.ConnectionError) as e:
            logger.debug(f'HudsonRock network error: {e}')
        except requests.exceptions.JSONDecodeError as e:
            logger.debug(f'HudsonRock JSON parse error: {e}')
        except Exception as e:
            logger.error(f'HudsonRock error: {e}')

        try:
            resp = rate_limited_get(f'https://leakcheck.io/api/public?check={result["email"]}',
                                    namespace='breach')
            if resp and resp.status_code == 200:
                data = resp.json()
                if not isinstance(data, dict):
                    return
                result['breach_summary']['leakcheck'] = {
                    'found': data.get('found', 0),
                    'sources': data.get('sources', [])
                }
                if data.get('found', 0) > 0:
                    result['risk_flags'].append({
                        'severity': 'HIGH',
                        'flag': 'Found in breach databases',
                        'detail': f"Found in {data['found']} breach source(s)"
                    })
        except (requests.Timeout, requests.ConnectionError) as e:
            logger.debug(f'LeakCheck network error: {e}')
        except requests.exceptions.JSONDecodeError as e:
            logger.debug(f'LeakCheck JSON parse error: {e}')
        except Exception as e:
            logger.error(f'LeakCheck error: {e}')

    def _calc_risk(self, result: dict):
        severities = [f['severity'] for f in result['risk_flags']]
        if 'CRITICAL' in severities:
            result['risk_level'] = 'CRITICAL'
        elif 'HIGH' in severities:
            result['risk_level'] = 'HIGH'
        elif 'MEDIUM' in severities:
            result['risk_level'] = 'MEDIUM'
