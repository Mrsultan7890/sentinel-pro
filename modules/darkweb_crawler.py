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
import logging
from urllib.parse import quote_plus

logger = logging.getLogger(__name__)

TOR_PROXIES = {
    'http':  'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050',
}

# Multiple .onion search engines for better coverage
SEARCH_ENGINES = [
    {
        'name': 'Ahmia',
        'onion': 'http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion',
        'clearnet': 'https://ahmia.fi',
        'search_path': '/search/?q={}'
    },
    {
        'name': 'Torch',
        'onion': 'http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion',
        'clearnet': None,
        'search_path': '/search?query={}'
    },
    {
        'name': 'Not Evil',
        'onion': 'http://hss3uro2hsxfogfq.onion',
        'clearnet': None,
        'search_path': '/index.php?q={}'
    },
    {
        'name': 'DarkSearch',
        'onion': None,
        'clearnet': 'https://darksearch.io',
        'search_path': '/api/search?query={}'
    }
]

# Dark web dorks (similar to Google dorks)
DARK_DORKS = [
    '"{}" leak',
    '"{}" breach',
    '"{}" dump',
    '"{}" database',
    '"{}" password',
    '"{}" email',
    '"{}" credentials',
    '"{}" personal',
    '{} site:pastebin',
    '{} site:ghostbin',
    'inurl:"{}"',
    'intitle:"{}"',
]

# Known paste .onion sites (updated)
PASTE_SITES = [
    'http://nzxj65x32vh2fkhk.onion',  # stronghold paste
    'http://zw3crggtadila2sg.onion',  # 0bin
    'http://paste2vljrisjhtqu3h6hjnbopi2nqnx6v23o6kquls66ryxhatyd.onion',  # Paste2
]

# Hidden Wiki mirrors for discovery
HIDDEN_WIKIS = [
    'http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/wiki/',
    'http://s4k4ceiapwwgcm3mkb6e4diqecpo7kvdnfr5gg7sph7jjppqkvwwqtyd.onion/',
]

TIMEOUT = 20
UA = 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0'


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
                self.tor_session = session
                return True
            else:
                print('[!] Tor proxy reachable but verification failed')
                print('[!] Please start Tor: sudo systemctl start tor')
                return False
        except Exception as e:
            print(f'[!] Tor connection failed: {str(e)[:80]}')
            print('[!] Please start Tor: sudo systemctl start tor')
            print('[!] Or check if Tor is running: systemctl status tor')
            return False

    # ------------------------------------------------------------------ #
    #  Multi-engine search with dorking                                   #
    # ------------------------------------------------------------------ #
    def _multi_engine_search(self, query):
        """Search across multiple dark web search engines"""
        results = []
        seen_urls = set()
        
        for engine in SEARCH_ENGINES:
            try:
                # Try .onion first, fallback to clearnet
                base_url = engine['onion'] if engine['onion'] else engine['clearnet']
                if not base_url:
                    continue
                
                search_url = base_url + engine['search_path'].format(quote_plus(query))
                
                r = self.tor_session.get(search_url, timeout=TIMEOUT)
                if r.status_code != 200:
                    continue
                
                # Extract .onion links
                links = re.findall(r'href="(http://[a-z2-7]{16,56}\.onion[^"]*)"', r.text)
                titles = re.findall(r'<h[3-5][^>]*>(.*?)</h[3-5]>', r.text, re.DOTALL)
                
                for i, link in enumerate(links[:5]):
                    if link not in seen_urls:
                        seen_urls.add(link)
                        title = re.sub(r'<[^>]+>', '', titles[i]).strip() if i < len(titles) else link
                        results.append({
                            'url': link,
                            'title': title,
                            'query': query,
                            'source': engine['name']
                        })
                
                time.sleep(random.uniform(1, 2))
                
            except Exception as e:
                logger.debug(f"{engine['name']} search failed: {e}")
                continue
        
        return results

    # ------------------------------------------------------------------ #
    #  Advanced crawl with dorking                                         #
    # ------------------------------------------------------------------ #
    def crawl_onion_sites(self, target):
        """Search with advanced dorking, then fetch .onion pages."""
        if not self.tor_session:
            return []

        all_links = []
        seen = set()
        
        # Use dark web dorks for comprehensive search
        for dork_template in DARK_DORKS[:6]:  # Top 6 dorks
            query = dork_template.format(target)
            try:
                for item in self._multi_engine_search(query):
                    if item['url'] not in seen:
                        seen.add(item['url'])
                        all_links.append(item)
                time.sleep(random.uniform(1, 2))
            except Exception as e:
                logger.debug(f"Dork search failed for '{query}': {e}")
                continue
        
        # Also try Hidden Wiki for discovery
        try:
            wiki_results = self._search_hidden_wiki(target)
            for item in wiki_results:
                if item['url'] not in seen:
                    seen.add(item['url'])
                    all_links.append(item)
        except Exception as e:
            logger.debug(f"Hidden Wiki search failed: {e}")

        results = []
        for item in all_links[:12]:  # Fetch top 12 unique pages
            try:
                time.sleep(random.uniform(2, 4))
                r = self.tor_session.get(item['url'], timeout=TIMEOUT)
                results.append({
                    'site':    item['url'],
                    'title':   item['title'],
                    'query':   item['query'],
                    'source':  item.get('source', 'unknown'),
                    'content': r.text[:5000],
                    'status':  'success',
                })
            except Exception as e:
                results.append({
                    'site':    item['url'],
                    'title':   item['title'],
                    'query':   item['query'],
                    'source':  item.get('source', 'unknown'),
                    'content': '',
                    'status':  f'error: {str(e)[:50]}',
                })

        return results
    
    def _search_hidden_wiki(self, target):
        """Search Hidden Wiki mirrors for target mentions"""
        results = []
        
        for wiki_url in HIDDEN_WIKIS:
            try:
                r = self.tor_session.get(wiki_url, timeout=TIMEOUT)
                if r.status_code == 200 and target.lower() in r.text.lower():
                    # Extract .onion links from wiki page
                    links = re.findall(r'href="(http://[a-z2-7]{16,56}\.onion[^"]*)"', r.text)
                    for link in links[:5]:
                        results.append({
                            'url': link,
                            'title': f'Hidden Wiki: {link[-20:]}',
                            'query': target,
                            'source': 'hidden_wiki'
                        })
                time.sleep(random.uniform(1, 2))
            except Exception as e:
                logger.debug(f"Hidden Wiki error: {e}")
        
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
    #  Paste sites via Tor (improved)                                      #
    # ------------------------------------------------------------------ #
    def search_paste_sites(self, target):
        """Search real paste .onion sites for target mentions."""
        if not self.tor_session:
            return []

        results = []
        for site in PASTE_SITES:
            try:
                # Try direct search
                search_url = f'{site}/search/{quote_plus(target)}'
                r = self.tor_session.get(search_url, timeout=TIMEOUT)
                
                if r.status_code == 200 and target.lower() in r.text.lower():
                    paste_links = re.findall(r'/paste/[a-zA-Z0-9]+', r.text)
                    for link in paste_links[:3]:
                        try:
                            pr = self.tor_session.get(f'{site}{link}', timeout=TIMEOUT)
                            if pr.status_code == 200:
                                results.append({
                                    'site': site,
                                    'url': f'{site}{link}',
                                    'content': pr.text[:2000],
                                    'timestamp': time.time()
                                })
                            time.sleep(random.uniform(2, 3))
                        except Exception as e:
                            logger.debug(f"Failed to fetch {site}{link}: {e}")
            except Exception as e:
                logger.debug(f"Paste site {site} error: {e}")
        
        return results

    # ------------------------------------------------------------------ #
    #  Forum monitoring (improved)                                          #
    # ------------------------------------------------------------------ #
    def monitor_forums(self, target):
        """Search dark web forums for target mentions."""
        if not self.tor_session:
            return []

        # Use multi-engine search with 'forum' keyword
        forum_queries = [f'{target} forum', f'{target} discussion', f'{target} thread']
        mentions = []
        seen_urls = set()
        
        for query in forum_queries:
            try:
                results = self._multi_engine_search(query)
                for item in results[:3]:
                    if item['url'] in seen_urls:
                        continue
                    seen_urls.add(item['url'])
                    
                    try:
                        r = self.tor_session.get(item['url'], timeout=TIMEOUT)
                        if r.status_code == 200 and target.lower() in r.text.lower():
                            mentions.append({
                                'forum': item['url'],
                                'title': item['title'],
                                'post_content': r.text[:500],
                                'timestamp': time.time(),
                                'relevance': 'high',
                                'source': item.get('source', 'unknown')
                            })
                        time.sleep(random.uniform(2, 3))
                    except Exception as e:
                        logger.debug(f"Failed to fetch forum {item['url']}: {e}")
            except Exception as e:
                logger.debug(f"Forum search error for '{query}': {e}")
        
        return mentions
