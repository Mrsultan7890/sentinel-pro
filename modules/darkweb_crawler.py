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
Dark Web Integration Module
Real Tor SOCKS5 + Ahmia.fi .onion search
"""

import requests
import re
import base64
import os
import time
import random
from urllib.parse import quote_plus

TOR_PROXIES = {
    'http':  'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050',
}
AHMIA_ONION   = 'http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion'
AHMIA_CLEAR   = 'https://ahmia.fi'
TIMEOUT       = 20
UA            = 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0'


class DarkWebCrawler:
    def __init__(self):
        self.tor_session = None
        self.encryption_patterns = [
            r'-----BEGIN PGP MESSAGE-----.*?-----END PGP MESSAGE-----',
            r'[A-Za-z0-9+/]{40,}={0,2}',
            r'[0-9a-fA-F]{64}',
        ]

    # ------------------------------------------------------------------ #
    #  Tor connection                                                       #
    # ------------------------------------------------------------------ #
    def connect_tor(self):
        """Establish real Tor SOCKS5 session and verify connectivity."""
        session = requests.Session()
        session.proxies  = TOR_PROXIES
        session.headers['User-Agent'] = UA

        try:
            r = session.get('http://check.torproject.org/', timeout=TIMEOUT)
            if 'Congratulations' in r.text or 'tor' in r.text.lower():
                print('[+] Tor connection verified via check.torproject.org')
            else:
                print('[*] Tor proxy reachable (torproject check inconclusive)')
        except Exception as e:
            # Tor may still work for .onion even if clearnet check fails
            print(f'[*] Tor proxy at 9050 active (clearnet check: {e})')

        self.tor_session = session
        return True

    # ------------------------------------------------------------------ #
    #  Ahmia search                                                         #
    # ------------------------------------------------------------------ #
    def _ahmia_search(self, query):
        """Search Ahmia via .onion first, fallback to clearnet."""
        results = []
        encoded = quote_plus(query)

        for base in [AHMIA_ONION, AHMIA_CLEAR]:
            url = f'{base}/search/?q={encoded}'
            try:
                r = self.tor_session.get(url, timeout=TIMEOUT)
                if r.status_code != 200:
                    continue

                # Extract .onion links and titles from Ahmia results
                links  = re.findall(r'href="(http://[a-z2-7]{16,56}\.onion[^"]*)"', r.text)
                titles = re.findall(r'<h4[^>]*>(.*?)</h4>', r.text, re.DOTALL)

                for i, link in enumerate(links[:10]):
                    title = re.sub(r'<[^>]+>', '', titles[i]).strip() if i < len(titles) else link
                    results.append({'url': link, 'title': title, 'query': query, 'source': 'ahmia'})

                if results:
                    break  # Got results from first working source
            except Exception as e:
                continue

        return results

    # ------------------------------------------------------------------ #
    #  Crawl .onion pages                                                   #
    # ------------------------------------------------------------------ #
    def crawl_onion_sites(self, target):
        """Search Ahmia for target, then fetch top .onion pages."""
        if not self.tor_session:
            return []

        queries = [target, f'"{target}"', f'{target} leak', f'{target} breach']
        all_links = []
        seen = set()

        for q in queries:
            for item in self._ahmia_search(q):
                if item['url'] not in seen:
                    seen.add(item['url'])
                    all_links.append(item)
            time.sleep(random.uniform(1, 2))

        results = []
        for item in all_links[:8]:  # Fetch top 8 unique .onion pages
            try:
                time.sleep(random.uniform(1, 3))
                r = self.tor_session.get(item['url'], timeout=TIMEOUT)
                results.append({
                    'site':    item['url'],
                    'title':   item['title'],
                    'query':   item['query'],
                    'content': r.text[:5000],
                    'status':  'success',
                })
            except Exception as e:
                results.append({
                    'site':    item['url'],
                    'title':   item['title'],
                    'query':   item['query'],
                    'content': '',
                    'status':  f'error: {e}',
                })

        return results

    # ------------------------------------------------------------------ #
    #  Encrypted content analysis                                           #
    # ------------------------------------------------------------------ #
    def analyze_encrypted_content(self, onion_results):
        decrypted_data = []
        for result in onion_results:
            content = result.get('content', '')
            for pattern in self.encryption_patterns:
                for match in re.findall(pattern, content, re.DOTALL):
                    analysis = self._analyze_encryption_type(match)
                    decrypted_data.append({
                        'original':          match[:100] + ('...' if len(match) > 100 else ''),
                        'type':              analysis['type'],
                        'confidence':        analysis['confidence'],
                        'source_site':       result['site'],
                        'decryption_attempt': analysis.get('decrypted'),
                    })
        return decrypted_data

    def _analyze_encryption_type(self, text):
        if 'BEGIN PGP' in text:
            return {'type': 'pgp',         'confidence': 0.95, 'decrypted': 'PGP — private key required'}
        if re.match(r'^[0-9a-fA-F]+$', text):
            try:    dec = bytes.fromhex(text).decode('utf-8', errors='replace')
            except Exception as e:
                logger.debug(f"Hex decode failed: {e}")
                dec = 'hex decode failed'
            return {'type': 'hexadecimal', 'confidence': 0.80, 'decrypted': dec}
        if re.match(r'^[A-Za-z0-9+/]*={0,2}$', text):
            try:    dec = base64.b64decode(text).decode('utf-8', errors='replace')
            except Exception as e:
                logger.debug(f"Base64 decode failed: {e}")
                dec = 'base64 decode failed'
            return {'type': 'base64',      'confidence': 0.75, 'decrypted': dec}
        return {'type': 'unknown', 'confidence': 0.3, 'decrypted': None}

    # ------------------------------------------------------------------ #
    #  Paste sites via Tor                                                  #
    # ------------------------------------------------------------------ #
    def search_paste_sites(self, target):
        """Search real paste .onion sites for target mentions."""
        if not self.tor_session:
            return []

        # Real paste .onion sites (publicly known)
        paste_sites = [
            'http://pastes7j2opfxrx5.onion',
            'http://strongerw2ise74v3duebgsvug4mehyhlpa7f6kfwnas7zofs3kov7yd.onion',
        ]
        results = []
        for site in paste_sites:
            try:
                r = self.tor_session.get(f'{site}/search/{quote_plus(target)}', timeout=TIMEOUT)
                if r.status_code == 200 and target.lower() in r.text.lower():
                    paste_links = re.findall(r'/paste/[a-zA-Z0-9]+', r.text)
                    for link in paste_links[:3]:
                        try:
                            pr = self.tor_session.get(f'{site}{link}', timeout=TIMEOUT)
                            if pr.status_code == 200:
                                results.append({'site': site, 'url': f'{site}{link}',
                                                'content': pr.text[:2000], 'timestamp': time.time()})
                            time.sleep(random.uniform(1, 2))
                        except (ConnectionError, requests.exceptions.RequestException) as e:
                            logger.debug(f"Failed to fetch {site}{link}: {e}")
                        except Exception as e:
                            logger.warning(f"Unexpected error fetching {site}{link}: {e}")
            except Exception as e:
                logger.warning(f"Error searching pastebin mirrors: {e}")
        return results

    # ------------------------------------------------------------------ #
    #  Forum monitoring                                                     #
    # ------------------------------------------------------------------ #
    def monitor_forums(self, target):
        """Search known dark web forum .onion sites for target mentions."""
        if not self.tor_session:
            return []

        # Use Ahmia to find forum pages mentioning target
        forum_results = self._ahmia_search(f'{target} forum')
        mentions = []
        for item in forum_results[:5]:
            try:
                r = self.tor_session.get(item['url'], timeout=TIMEOUT)
                if r.status_code == 200 and target.lower() in r.text.lower():
                    mentions.append({
                        'forum':        item['url'],
                        'title':        item['title'],
                        'post_content': r.text[:500],
                        'timestamp':    time.time(),
                        'relevance':    'high',
                    })
                time.sleep(random.uniform(1, 2))
            except (ConnectionError, requests.exceptions.RequestException) as e:
                logger.debug(f"Failed to fetch forum {item['url']}: {e}")
            except Exception as e:
                logger.warning(f"Error checking forum {item.get('url', 'unknown')}: {e}")
        return mentions
