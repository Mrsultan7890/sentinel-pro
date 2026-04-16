"""
Breach Checker
Sources: BreachDirectory · HudsonRock · LeakCheck · IntelX · HIBP · Dehashed · Paste Monitor
"""

import re
import logging
import requests
from modules.utils import tor_session
from datetime import datetime
import config

logger = logging.getLogger(__name__)

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (compatible; SentinelPro/2.1)',
    'Accept': 'application/json'
}


class BreachChecker:

    def __init__(self):
        self.session = tor_session()
        self.session.headers.update(HEADERS)

    def run(self, target: str) -> dict:
        is_email = bool(re.match(r'^[^@]+@[^@]+\.[^@]+$', target))

        # Fresh session har run pe — Tor toggle ke baad bhi correct proxy use ho
        self.session = tor_session()
        self.session.headers.update(HEADERS)

        result = {
            'target':       target,
            'type':         'email' if is_email else 'username',
            'breaches':     [],
            'pastes':       [],
            'stealer_logs': [],
            'hibp':         {},
            'dehashed':     {},
            'sources':      {},
            'timestamp':    datetime.now().isoformat()
        }

        self._check_breachdirectory(target, result)
        self._check_hudsonrock(target, result, is_email)
        self._check_leakcheck(target, result)
        self._check_intelx_public(target, result)

        if is_email:
            self._check_hibp(target, result)
            self._check_dehashed(target, result)
            self._check_pastes(target, result)

        # Deduplicate breaches by name+source
        seen, unique = set(), []
        for b in result['breaches']:
            key = b.get('name', '') + b.get('source', '')
            if key not in seen:
                seen.add(key)
                unique.append(b)
        result['breaches'] = unique

        result['total_breaches']     = len(result['breaches'])
        result['total_pastes']       = len(result['pastes'])
        result['total_stealer_logs'] = len(result['stealer_logs'])
        result['risk_level']         = self._risk_level(result)
        result['summary']            = self._summary(result)
        return result

    # ------------------------------------------------------------------ #
    #  Source 1: BreachDirectory                                          #
    # ------------------------------------------------------------------ #

    def _check_breachdirectory(self, target: str, result: dict):
        """BreachDirectory — Cloudflare protected, browser-like headers use karo."""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'application/json, text/plain, */*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Referer': 'https://breachdirectory.org/',
                'Origin': 'https://breachdirectory.org',
                'sec-ch-ua': '"Chromium";v="120", "Google Chrome";v="120"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Linux"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
            }
            resp = self.session.get(
                f"https://breachdirectory.org/api?func=auto&term={target}",
                headers=headers, timeout=15, verify=False
            )
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    result['sources']['breachdirectory'] = 'ok'
                    for item in data.get('result', []):
                        result['breaches'].append({
                            'name':          item.get('sources', ['Unknown'])[0] if item.get('sources') else 'Unknown',
                            'source':        'breachdirectory',
                            'password_hint': item.get('password', ''),
                            'sha1':          item.get('sha1', ''),
                            'has_password':  item.get('has_password', False)
                        })
                except Exception:
                    result['sources']['breachdirectory'] = 'parse_error'
            elif resp.status_code == 403:
                # Cloudflare block — bot protection, skip gracefully
                result['sources']['breachdirectory'] = 'cloudflare_blocked'
                logger.debug("BreachDirectory: Cloudflare bot protection active")
            else:
                result['sources']['breachdirectory'] = f"http_{resp.status_code}"
        except Exception as e:
            result['sources']['breachdirectory'] = f"error: {str(e)[:50]}"
            logger.warning(f"BreachDirectory failed: {e}")

    # ------------------------------------------------------------------ #
    #  Source 2: HudsonRock (infostealer logs)                           #
    # ------------------------------------------------------------------ #

    def _check_hudsonrock(self, target: str, result: dict, is_email: bool):
        try:
            if is_email:
                url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={target}"
            else:
                url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username={target}"

            resp = self.session.get(url, timeout=10, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                result['sources']['hudsonrock'] = 'ok'
                for item in data.get('stealers', []):
                    result['stealer_logs'].append({
                        'computer_name':    item.get('computer_name', ''),
                        'operating_system': item.get('operating_system', ''),
                        'date_uploaded':    item.get('date_uploaded', ''),
                        'malware_path':     item.get('malware_path', ''),
                        'antiviruses':      item.get('antiviruses', []),
                        'source':           'hudsonrock'
                    })
                for cred in data.get('credentials', []):
                    result['breaches'].append({
                        'name':     cred.get('url', 'Unknown site'),
                        'source':   'hudsonrock_stealer',
                        'username': cred.get('username', ''),
                        'url':      cred.get('url', ''),
                        'type':     'infostealer_log'
                    })
            else:
                result['sources']['hudsonrock'] = f"http_{resp.status_code}"
        except Exception as e:
            result['sources']['hudsonrock'] = f"error: {str(e)[:50]}"
            logger.warning(f"HudsonRock failed: {e}")

    # ------------------------------------------------------------------ #
    #  Source 3: LeakCheck                                                #
    # ------------------------------------------------------------------ #

    def _check_leakcheck(self, target: str, result: dict):
        try:
            resp = self.session.get(
                f"https://leakcheck.io/api/public?check={target}",
                timeout=10, verify=False
            )
            if resp.status_code == 200:
                data = resp.json()
                result['sources']['leakcheck'] = 'ok'
                if data.get('found'):
                    for src in data.get('sources', []):
                        result['breaches'].append({
                            'name':   src if isinstance(src, str) else src.get('name', 'Unknown'),
                            'source': 'leakcheck',
                            'type':   'breach'
                        })
                    result['pastes'].extend([
                        {'source': 'leakcheck', 'content': p}
                        for p in data.get('pastes', [])
                    ])
            else:
                result['sources']['leakcheck'] = f"http_{resp.status_code}"
        except Exception as e:
            result['sources']['leakcheck'] = f"error: {str(e)[:50]}"
            logger.warning(f"LeakCheck failed: {e}")

    # ------------------------------------------------------------------ #
    #  Source 4: IntelX public                                           #
    # ------------------------------------------------------------------ #

    def _check_intelx_public(self, target: str, result: dict):
        """IntelX — public API ab 403 deta hai, API key required. Gracefully skip."""
        api_key = getattr(config, 'INTELX_API_KEY', '') or ''
        try:
            if api_key:
                # Authenticated request
                resp = self.session.post(
                    "https://2.intelx.io/intelligent/search",
                    json={"term": target, "buckets": [], "lookuplevel": 0,
                          "maxresults": 10, "timeout": 0, "datefrom": "",
                          "dateto": "", "sort": 4, "media": 0, "terminate": []},
                    headers={'x-key': api_key},
                    timeout=10, verify=False
                )
            else:
                # No key — try public endpoint
                resp = self.session.post(
                    "https://2.intelx.io/intelligent/search",
                    json={"term": target, "buckets": [], "lookuplevel": 0,
                          "maxresults": 10, "timeout": 0, "datefrom": "",
                          "dateto": "", "sort": 4, "media": 0, "terminate": []},
                    timeout=10, verify=False
                )

            if resp.status_code == 200:
                data = resp.json()
                search_id = data.get('id')
                result['sources']['intelx'] = 'ok'
                if search_id:
                    res_resp = self.session.get(
                        f"https://2.intelx.io/intelligent/search/result?id={search_id}&limit=10",
                        headers={'x-key': api_key} if api_key else {},
                        timeout=10, verify=False
                    )
                    if res_resp.status_code == 200:
                        for record in res_resp.json().get('records', []):
                            result['pastes'].append({
                                'source': 'intelx',
                                'name':   record.get('name', ''),
                                'date':   record.get('date', ''),
                                'bucket': record.get('bucket', ''),
                                'size':   record.get('size', 0)
                            })
            elif resp.status_code == 403:
                result['sources']['intelx'] = 'api_key_required'
                logger.debug("IntelX: public API requires key now — set INTELX_API_KEY in .env")
            else:
                result['sources']['intelx'] = f"http_{resp.status_code}"
        except Exception as e:
            result['sources']['intelx'] = f"error: {str(e)[:50]}"
            logger.warning(f"IntelX failed: {e}")

    # ------------------------------------------------------------------ #
    #  Source 5: HaveIBeenPwned (HIBP) — requires API key                #
    # ------------------------------------------------------------------ #

    def _check_hibp(self, target: str, result: dict):
        api_key = config.HIBP_API_KEY
        if not api_key:
            result['sources']['hibp'] = 'no_api_key'
            result['hibp'] = {'error': 'HIBP_API_KEY not set'}
            return
        try:
            # Breaches
            resp = self.session.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}",
                headers={
                    'hibp-api-key': api_key,
                    'User-Agent':   'SentinelPro/2.1'
                },
                params={'truncateResponse': 'false'},
                timeout=10
            )
            hibp_data = {'breaches': [], 'pastes': [], 'total': 0}

            if resp.status_code == 200:
                breaches = resp.json()
                hibp_data['breaches'] = breaches
                hibp_data['total']    = len(breaches)
                for b in breaches:
                    result['breaches'].append({
                        'name':          b.get('Name', 'Unknown'),
                        'source':        'hibp',
                        'breach_date':   b.get('BreachDate', ''),
                        'pwn_count':     b.get('PwnCount', 0),
                        'data_classes':  b.get('DataClasses', []),
                        'is_verified':   b.get('IsVerified', False),
                        'is_sensitive':  b.get('IsSensitive', False),
                        'description':   re.sub(r'<[^>]+>', '', b.get('Description', ''))[:200],
                        'type':          'hibp_breach'
                    })
                result['sources']['hibp'] = 'ok'
            elif resp.status_code == 404:
                result['sources']['hibp'] = 'ok'  # clean — not found
            elif resp.status_code == 401:
                result['sources']['hibp'] = 'invalid_api_key'
                hibp_data['error'] = 'Invalid HIBP API key'
            elif resp.status_code == 429:
                result['sources']['hibp'] = 'rate_limited'
                hibp_data['error'] = 'HIBP rate limited'
            else:
                result['sources']['hibp'] = f"http_{resp.status_code}"

            # Pastes (separate endpoint)
            paste_resp = self.session.get(
                f"https://haveibeenpwned.com/api/v3/pasteaccount/{target}",
                headers={'hibp-api-key': api_key, 'User-Agent': 'SentinelPro/2.1'},
                timeout=10
            )
            if paste_resp.status_code == 200:
                pastes = paste_resp.json()
                hibp_data['pastes'] = pastes
                for p in pastes:
                    result['pastes'].append({
                        'source':  'hibp',
                        'service': p.get('Source', ''),
                        'id':      p.get('Id', ''),
                        'date':    p.get('Date', ''),
                        'count':   p.get('EmailCount', 0),
                        'title':   p.get('Title', '')
                    })

            result['hibp'] = hibp_data

        except Exception as e:
            result['sources']['hibp'] = f"error: {str(e)[:50]}"
            result['hibp'] = {'error': str(e)[:100]}
            logger.warning(f"HIBP failed: {e}")

    # ------------------------------------------------------------------ #
    #  Source 6: Dehashed — plaintext passwords (requires API key)       #
    # ------------------------------------------------------------------ #

    def _check_dehashed(self, target: str, result: dict):
        email    = config.DEHASHED_EMAIL
        api_key  = config.DEHASHED_API_KEY
        if not (email and api_key):
            result['sources']['dehashed'] = 'no_api_key'
            result['dehashed'] = {'error': 'DEHASHED_EMAIL + DEHASHED_API_KEY not set'}
            return
        try:
            resp = self.session.get(
                "https://api.dehashed.com/search",
                params={'query': f"email:{target}", 'size': 100},
                auth=(email, api_key),
                headers={'Accept': 'application/json'},
                timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                entries = data.get('entries') or []
                dehashed_data = {
                    'total':    data.get('total', 0),
                    'entries':  [],
                    'has_plaintext': False
                }
                for entry in entries[:50]:
                    password    = entry.get('password', '')
                    hashed_pass = entry.get('hashed_password', '')
                    has_plain   = bool(password and password not in ('', 'null', None))
                    if has_plain:
                        dehashed_data['has_plaintext'] = True
                    dehashed_data['entries'].append({
                        'id':              entry.get('id', ''),
                        'email':           entry.get('email', ''),
                        'username':        entry.get('username', ''),
                        'password':        password,
                        'hashed_password': hashed_pass,
                        'name':            entry.get('name', ''),
                        'database_name':   entry.get('database_name', ''),
                        'address':         entry.get('address', ''),
                        'phone':           entry.get('phone', ''),
                        'has_plaintext':   has_plain
                    })
                    # Also push into main breaches list
                    result['breaches'].append({
                        'name':          entry.get('database_name', 'Unknown DB'),
                        'source':        'dehashed',
                        'username':      entry.get('username', ''),
                        'password_hint': password[:4] + '***' if has_plain else '',
                        'has_password':  has_plain,
                        'type':          'dehashed'
                    })
                result['dehashed']          = dehashed_data
                result['sources']['dehashed'] = 'ok'
            elif resp.status_code == 401:
                result['sources']['dehashed'] = 'invalid_credentials'
                result['dehashed'] = {'error': 'Invalid Dehashed credentials'}
            elif resp.status_code == 429:
                result['sources']['dehashed'] = 'rate_limited'
                result['dehashed'] = {'error': 'Dehashed rate limited'}
            else:
                result['sources']['dehashed'] = f"http_{resp.status_code}"
                result['dehashed'] = {'error': f"HTTP {resp.status_code}"}
        except Exception as e:
            result['sources']['dehashed'] = f"error: {str(e)[:50]}"
            result['dehashed'] = {'error': str(e)[:100]}
            logger.warning(f"Dehashed failed: {e}")

    # ------------------------------------------------------------------ #
    #  Source 7: Paste Monitor — Pastebin + Ghostbin                     #
    # ------------------------------------------------------------------ #

    def _check_pastes(self, target: str, result: dict):
        """Search paste sites for email mentions — psbdmp.ws only (reliable, no bot detection)."""
        found = []

        # psbdmp.ws — indexes Pastebin dumps, free, no key
        try:
            resp = self.session.get(
                f"https://psbdmp.ws/api/search/{target}",
                timeout=10, verify=False
            )
            if resp.status_code == 200:
                data = resp.json()
                items = data if isinstance(data, list) else data.get('data', [])
                for item in items[:20]:
                    paste_id = item.get('id', item) if isinstance(item, dict) else item
                    found.append({
                        'source': 'pastebin',
                        'id':     str(paste_id),
                        'url':    f"https://pastebin.com/{paste_id}",
                        'date':   item.get('time', '') if isinstance(item, dict) else '',
                        'title':  item.get('title', '') if isinstance(item, dict) else ''
                    })
                result['sources']['pastebin'] = 'ok'
            else:
                result['sources']['pastebin'] = f"http_{resp.status_code}"
        except Exception as e:
            result['sources']['pastebin'] = f"error: {str(e)[:50]}"
            logger.warning(f"psbdmp search failed: {e}")

        result['pastes'].extend(found)

    # ------------------------------------------------------------------ #
    #  Risk & Summary                                                     #
    # ------------------------------------------------------------------ #

    def _risk_level(self, result: dict) -> str:
        logs  = result['total_stealer_logs']
        total = result['total_breaches']
        dh    = result.get('dehashed', {})
        hibp  = result.get('hibp', {})

        if logs > 0 or dh.get('has_plaintext'):
            return 'CRITICAL'
        if total > 5 or hibp.get('total', 0) > 5:
            return 'CRITICAL'
        if total > 2 or hibp.get('total', 0) > 2:
            return 'HIGH'
        if total > 0 or hibp.get('total', 0) > 0:
            return 'MEDIUM'
        return 'LOW'

    def _summary(self, result: dict) -> list:
        lines = []
        risk  = result['risk_level']

        if risk == 'CRITICAL':
            lines.append('🚨 CRITICAL: Credentials actively compromised')
        elif risk == 'HIGH':
            lines.append('⚠️  HIGH: Multiple breach exposures found')
        elif risk == 'MEDIUM':
            lines.append('⚡ MEDIUM: Breach exposure detected')
        else:
            lines.append('✅ LOW: No breaches found in checked sources')

        if result['total_stealer_logs'] > 0:
            lines.append(f"🦠 {result['total_stealer_logs']} infostealer log(s) — machine was compromised")
        if result.get('dehashed', {}).get('has_plaintext'):
            lines.append(f"🔑 Dehashed: plaintext passwords found!")
        hibp_total = result.get('hibp', {}).get('total', 0)
        if hibp_total > 0:
            lines.append(f"🔔 HIBP: found in {hibp_total} breach(es)")
        if result['total_breaches'] > 0:
            lines.append(f"💾 {result['total_breaches']} breach record(s) found")
        if result['total_pastes'] > 0:
            lines.append(f"📋 {result['total_pastes']} paste(s) found")

        return lines
