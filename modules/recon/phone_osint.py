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
Phone Number OSINT - Carrier, country, line type, social hints, reputation
Sources: NumVerify, AbstractAPI, HLR Lookup, social profile probing
"""

import logging
import re
import config
from modules.utils import rate_limited_get

logger = logging.getLogger(__name__)

# E.164 country code → country name
COUNTRY_CODES = {
    '1': 'United States / Canada', '7': 'Russia / Kazakhstan',
    '20': 'Egypt', '27': 'South Africa', '30': 'Greece', '31': 'Netherlands',
    '32': 'Belgium', '33': 'France', '34': 'Spain', '36': 'Hungary',
    '39': 'Italy', '40': 'Romania', '41': 'Switzerland', '43': 'Austria',
    '44': 'United Kingdom', '45': 'Denmark', '46': 'Sweden', '47': 'Norway',
    '48': 'Poland', '49': 'Germany', '51': 'Peru', '52': 'Mexico',
    '53': 'Cuba', '54': 'Argentina', '55': 'Brazil', '56': 'Chile',
    '57': 'Colombia', '58': 'Venezuela', '60': 'Malaysia', '61': 'Australia',
    '62': 'Indonesia', '63': 'Philippines', '64': 'New Zealand', '65': 'Singapore',
    '66': 'Thailand', '81': 'Japan', '82': 'South Korea', '84': 'Vietnam',
    '86': 'China', '90': 'Turkey', '91': 'India', '92': 'Pakistan',
    '93': 'Afghanistan', '94': 'Sri Lanka', '95': 'Myanmar', '98': 'Iran',
    '212': 'Morocco', '213': 'Algeria', '216': 'Tunisia', '218': 'Libya',
    '220': 'Gambia', '221': 'Senegal', '234': 'Nigeria', '254': 'Kenya',
    '255': 'Tanzania', '256': 'Uganda', '260': 'Zambia', '263': 'Zimbabwe',
    '351': 'Portugal', '352': 'Luxembourg', '353': 'Ireland', '354': 'Iceland',
    '358': 'Finland', '380': 'Ukraine', '381': 'Serbia', '385': 'Croatia',
    '386': 'Slovenia', '420': 'Czech Republic', '421': 'Slovakia',
    '880': 'Bangladesh', '886': 'Taiwan', '960': 'Maldives', '966': 'Saudi Arabia',
    '971': 'UAE', '972': 'Israel', '973': 'Bahrain', '974': 'Qatar',
    '975': 'Bhutan', '976': 'Mongolia', '977': 'Nepal', '992': 'Tajikistan',
    '993': 'Turkmenistan', '994': 'Azerbaijan', '995': 'Georgia',
    '996': 'Kyrgyzstan', '998': 'Uzbekistan',
}

# (url_template, status_that_means_found)
# WhatsApp/Telegram return 200 for any number (redirect to app), so we just record the link
# Truecaller/Sync.me are JS-rendered — removed from social hints, handled in reputation check
SOCIAL_PATTERNS = {
    'whatsapp': 'https://wa.me/{number}',
    'telegram': 'https://t.me/+{number}',
}

VOIP_PREFIXES = {'google voice', 'twilio', 'vonage', 'bandwidth', 'telnyx', 'voip', 'virtual'}


class PhoneOSINT:

    def run(self, phone: str) -> dict:
        if not phone or not isinstance(phone, str):
            return {'error': 'Invalid phone parameter', 'valid': False}
        
        phone = phone.strip()
        if len(phone) > 20:
            return {'error': 'Phone number too long', 'valid': False}
        
        result = {
            'phone':        phone,
            'normalized':   None,
            'valid':        False,
            'country':      None,
            'country_code': None,
            'carrier':      None,
            'line_type':    None,   # mobile / landline / voip / unknown
            'location':     None,
            'numverify':    {},
            'abstract':     {},
            'social_hints': [],
            'reputation':   {},
            'risk_level':   'LOW',
            'risk_flags':   [],
            'error':        None,
        }

        normalized = self._normalize(phone)
        if not normalized:
            result['error'] = 'Invalid phone number format'
            return result

        result['normalized'] = normalized
        result['valid']      = True
        result['country_code'], result['country'] = self._detect_country(normalized)

        self._numverify_lookup(result)
        self._abstract_lookup(result)
        self._social_hints(result)
        self._reputation_check(result)
        self._payment_lookup(result)
        self._calc_risk(result)
        return result

    # ── Normalization ──────────────────────────────────────────────────────────

    def _normalize(self, phone: str) -> str | None:
        """Strip everything except digits and leading +, return E.164 or None."""
        cleaned = re.sub(r'[\s\-\(\)\.]+', '', phone)
        if not cleaned.startswith('+'):
            # Try to detect if it's a raw number without country code
            if re.match(r'^\d{10,15}$', cleaned):
                cleaned = '+' + cleaned
            else:
                return None
        if re.match(r'^\+\d{7,15}$', cleaned):
            return cleaned
        return None

    def _detect_country(self, normalized: str) -> tuple[str, str]:
        digits = normalized.lstrip('+')
        # Try longest prefix first (3 digits → 2 → 1)
        for length in (3, 2, 1):
            prefix = digits[:length]
            if prefix in COUNTRY_CODES:
                return prefix, COUNTRY_CODES[prefix]
        return 'unknown', 'Unknown'

    # ── API Lookups ────────────────────────────────────────────────────────────

    def _numverify_lookup(self, result: dict):
        """NumVerify API — free tier: 100 req/month."""
        if not isinstance(result, dict):
            return
        
        api_key = config.NUMVERIFY_API_KEY if hasattr(config, 'NUMVERIFY_API_KEY') else ''
        if not api_key or not isinstance(api_key, str) or api_key.startswith('<'):
            result['numverify'] = {'error': 'NUMVERIFY_API_KEY not set'}
            return
        
        number = result.get('normalized', '')
        if not number:
            return
        number = number.lstrip('+')
        
        try:
            resp = rate_limited_get(
                'https://apilayer.net/api/validate',
                namespace='phone',
                params={'access_key': api_key, 'number': number, 'format': 1},
            )
            if not resp or resp.status_code != 200:
                result['numverify'] = {'error': 'NumVerify request failed'}
                return
            data = resp.json()
            if not isinstance(data, dict):
                result['numverify'] = {'error': 'Invalid response format'}
                return
            if not data.get('valid'):
                result['numverify'] = {'error': data.get('error', {}).get('info', 'Invalid number')}
                return
            result['numverify'] = data
            # Enrich main result
            if data.get('carrier'):
                result['carrier']   = data['carrier']
            if data.get('line_type'):
                result['line_type'] = data['line_type']
            if data.get('location'):
                result['location']  = data['location']
            if data.get('country_name'):
                result['country']   = data['country_name']
        except (requests.Timeout, requests.ConnectionError) as e:
            result['numverify'] = {'error': f'Network error: {e}'}
            logger.debug(f'NumVerify network error: {e}')
        except requests.exceptions.JSONDecodeError as e:
            result['numverify'] = {'error': 'JSON parse error'}
            logger.debug(f'NumVerify JSON error: {e}')
        except Exception as e:
            result['numverify'] = {'error': str(e)}
            logger.error(f'NumVerify error: {e}')

    def _abstract_lookup(self, result: dict):
        """AbstractAPI Phone Validation — free tier: 250 req/month."""
        if not isinstance(result, dict):
            return
        
        api_key = config.ABSTRACTAPI_PHONE_KEY if hasattr(config, 'ABSTRACTAPI_PHONE_KEY') else ''
        if not api_key or not isinstance(api_key, str) or api_key.startswith('<'):
            result['abstract'] = {'error': 'ABSTRACTAPI_PHONE_KEY not set'}
            return
        
        number = result.get('normalized', '')
        if not number:
            return
        
        try:
            resp = rate_limited_get(
                'https://phonevalidation.abstractapi.com/v1/',
                namespace='phone',
                params={'api_key': api_key, 'phone': number.lstrip('+')},
            )
            if not resp or resp.status_code != 200:
                result['abstract'] = {'error': 'AbstractAPI request failed'}
                return
            data = resp.json()
            if not isinstance(data, dict):
                result['abstract'] = {'error': 'Invalid response format'}
                return
            result['abstract'] = data
            # Fill gaps from numverify
            if not result.get('carrier') and data.get('carrier'):
                result['carrier']   = data['carrier']
            if not result.get('line_type') and data.get('type'):
                result['line_type'] = data['type']
            if not result.get('location') and data.get('location'):
                result['location']  = data['location']
        except (requests.Timeout, requests.ConnectionError) as e:
            result['abstract'] = {'error': f'Network error: {e}'}
            logger.debug(f'AbstractAPI network error: {e}')
        except requests.exceptions.JSONDecodeError as e:
            result['abstract'] = {'error': 'JSON parse error'}
            logger.debug(f'AbstractAPI JSON error: {e}')
        except Exception as e:
            result['abstract'] = {'error': str(e)}
            logger.error(f'AbstractAPI error: {e}')

    # ── Social Hints ──────────────────────────────────────────────────────────

    def _social_hints(self, result: dict):
        if not isinstance(result, dict) or 'normalized' not in result:
            return
        
        number_clean = result.get('normalized', '').lstrip('+')
        if not number_clean:
            result['social_hints'] = []
            return
        
        hints = []
        for platform, url_tpl in SOCIAL_PATTERNS.items():
            try:
                url  = url_tpl.format(number=number_clean)
                resp = rate_limited_get(url, namespace='social',
                                        headers={'User-Agent': 'Mozilla/5.0'},
                                        allow_redirects=True)
                status = 'found' if (resp and resp.status_code == 200) else 'not_found'
                hints.append({'platform': platform, 'url': url, 'status': status})
            except Exception as e:
                logger.debug(f'Social hint check failed for {platform}: {e}')
                hints.append({'platform': platform, 'url': '', 'status': 'error'})
        result['social_hints'] = hints

    # ── Reputation ────────────────────────────────────────────────────────────

    def _reputation_check(self, result: dict):
        """Check phone reputation via shouldianswer.com + spamcalls.net (no key needed)."""
        number = result['normalized'].lstrip('+')
        rep = {'spam_reports': 0, 'sources': [], 'details': []}

        # shouldianswer.com — real HTML page with spam ratings
        try:
            resp = rate_limited_get(
                f'https://www.shouldianswer.com/phone-number/{number}',
                namespace='phone',
                headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html'},
            )
            if resp and resp.status_code == 200:
                text = resp.text.lower()
                if any(kw in text for kw in ('spam', 'scam', 'fraud', 'dangerous', 'negative')):
                    rep['spam_reports'] += 1
                    rep['sources'].append('shouldianswer')
                    m = re.search(r'(\d+)\s*negative', text)
                    if m:
                        rep['details'].append(f"shouldianswer: {m.group(1)} negative reports")
        except Exception:
            pass

        # spamcalls.net — free, no key
        try:
            resp2 = rate_limited_get(
                f'https://spamcalls.net/en/search?q={number}',
                namespace='phone',
                headers={'User-Agent': 'Mozilla/5.0'},
            )
            if resp2 and resp2.status_code == 200:
                text2 = resp2.text.lower()
                if any(kw in text2 for kw in ('spam', 'scam', 'reported', 'fraud')):
                    rep['spam_reports'] += 1
                    rep['sources'].append('spamcalls.net')
        except Exception:
            pass

        result['reputation'] = rep

    # ── Payment Lookup ─────────────────────────────────────────────────────────

    def _payment_lookup(self, result: dict):
        try:
            from modules.recon.payment_osint import run_all
            pay = run_all(result['normalized'], 'phone')
            result['payment_profiles'] = pay
            if pay['found_count'] > 0:
                result['risk_flags'].append({
                    'severity': 'HIGH',
                    'flag': f"Found on {pay['found_count']} payment app(s)",
                    'detail': ', '.join(
                        f"{r['app']} ({r['country']}): {r['name']}"
                        for r in pay['results'] if r.get('found')
                    ),
                })
        except Exception as e:
            logger.debug(f'Payment lookup error: {e}')

    # ── Risk Calculation ──────────────────────────────────────────────────────

    def _calc_risk(self, result: dict):
        flags = result['risk_flags']

        # VOIP / virtual number
        carrier_lower = (result.get('carrier') or '').lower()
        line_type     = (result.get('line_type') or '').lower()
        if any(v in carrier_lower for v in VOIP_PREFIXES) or 'voip' in line_type:
            flags.append({'severity': 'HIGH', 'flag': 'VoIP / Virtual number',
                          'detail': f"Carrier: {result.get('carrier','unknown')} — often used for fraud/spam"})

        # Spam reports
        spam = result['reputation'].get('spam_reports', 0)
        if spam > 0:
            flags.append({'severity': 'HIGH', 'flag': 'Spam / Scam reports',
                          'detail': f"Reported on {', '.join(result['reputation']['sources'])}"})

        # Social presence
        found_on = [h['platform'] for h in result['social_hints'] if h['status'] == 'found']
        if found_on:
            flags.append({'severity': 'INFO', 'flag': 'Social presence detected',
                          'detail': f"Active on: {', '.join(found_on)}"})

        severities = [f['severity'] for f in flags]
        if 'CRITICAL' in severities:
            result['risk_level'] = 'CRITICAL'
        elif 'HIGH' in severities:
            result['risk_level'] = 'HIGH'
        elif 'MEDIUM' in severities:
            result['risk_level'] = 'MEDIUM'
        else:
            result['risk_level'] = 'LOW'
