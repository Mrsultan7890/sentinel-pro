"""
Ransomware Leak Site Tracker
Checks ransomware.live + ransomlook.io APIs for target mentions
"""

import requests
import logging
import time
from urllib.parse import quote

logger = logging.getLogger(__name__)

TIMEOUT = 15
UA = 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0'

# ransomware.live API — free, no key
RANSOMWARE_LIVE_API = 'https://api.ransomware.live/v2'

# ransomlook.io API — free, no key
RANSOMLOOK_API = 'https://www.ransomlook.io/api'

# Known ransomware groups with their .onion leak sites
RANSOMWARE_GROUPS = {
    'lockbit':     'http://lockbit3olp7oetlc4tl5zydnoluphh7fvdt5oa6arcp2757r7xkutid.onion',
    'blackcat':    'http://alphvmmm27o3abo3r2mlmjrpdmzle3rykajqc5xsj7j7ejksbpsa36ad.onion',
    'clop':        'http://santat7kpllt6iyvqbr7q4amdv6dzrh6paatvyrzl7ry3zm72zigf4ad.onion',
    'ransomhub':   'http://ransomxifxwc5eteopdobynonjctkxxvap77yqifu2emfbecgbqdw6qd.onion',
    'play':        'http://mbrlkbtq5jonaqkurdefo3multjdndvsryoobriqkwwctc3d7dflpad.onion',
    'akira':       'http://akiral2iz6a7qgd3ayp3l6yub7xx7isenvnoutonruaqnkhl75irsiad.onion',
    'blackbasta':  'http://stniiomyjliimcgkvdszvgen3eaaoz55hreqqx6o77yvmpwt7gklffqd.onion',
    'medusa':      'http://medusaxko7jxtrojdkxo66j9cvpxzrd3tip7oi6bjiaqxcilkxiix2yd.onion',
    'hunters':     'http://hunters55rdxciehoqzwv7vgyv6nt37tbwax2reroyzxhou7my5ejkid.onion',
    'rhysida':     'http://rhysidafohrhyy2aszi7bm32tnjat5xri65fopcxkdfxhi4tidsg7cad.onion',
}


class RansomwareTracker:

    def __init__(self, tor_session=None):
        self.tor_session = tor_session
        self.session = requests.Session()
        self.session.headers['User-Agent'] = UA

    def search(self, target: str) -> dict:
        """Main search — check all sources for target"""
        result = {
            'target': target,
            'victims': [],
            'groups_checked': 0,
            'total_hits': 0,
            'risk': 'LOW',
            'sources': {}
        }

        # 1. ransomware.live API
        live_hits = self._search_ransomware_live(target)
        result['sources']['ransomware_live'] = live_hits
        result['victims'].extend(live_hits.get('victims', []))

        # 2. ransomlook.io API
        look_hits = self._search_ransomlook(target)
        result['sources']['ransomlook'] = look_hits
        result['victims'].extend(look_hits.get('victims', []))

        # 3. Direct .onion crawl via Tor (if available)
        if self.tor_session:
            onion_hits = self._crawl_onion_sites(target)
            result['sources']['onion_direct'] = onion_hits
            result['victims'].extend(onion_hits.get('victims', []))

        # Deduplicate
        seen = set()
        unique = []
        for v in result['victims']:
            key = f"{v.get('group','')}_{v.get('victim','')}"
            if key not in seen:
                seen.add(key)
                unique.append(v)
        result['victims'] = unique

        result['total_hits'] = len(result['victims'])
        result['groups_checked'] = len(RANSOMWARE_GROUPS)
        result['risk'] = 'CRITICAL' if result['total_hits'] > 0 else 'LOW'

        return result

    def _search_ransomware_live(self, target: str) -> dict:
        """Search ransomware.live API"""
        result = {'victims': [], 'error': None}
        try:
            # Get recent victims
            r = self.session.get(
                f'{RANSOMWARE_LIVE_API}/recentvictims',
                timeout=TIMEOUT
            )
            if r.status_code != 200:
                result['error'] = f'HTTP {r.status_code}'
                return result

            victims = r.json()
            domain = target.lower().replace('www.', '').split('/')[0]

            for v in victims:
                victim_name = str(v.get('victim', '') or v.get('post_title', '')).lower()
                victim_url  = str(v.get('website', '') or v.get('url', '')).lower()

                if domain in victim_name or domain in victim_url:
                    result['victims'].append({
                        'group':       v.get('group_name', 'unknown'),
                        'victim':      v.get('victim', v.get('post_title', 'N/A')),
                        'date':        v.get('discovered', v.get('published', 'N/A')),
                        'website':     v.get('website', 'N/A'),
                        'description': str(v.get('description', ''))[:200],
                        'source':      'ransomware.live',
                        'severity':    'CRITICAL'
                    })

        except Exception as e:
            result['error'] = str(e)
            logger.debug(f'[RansomwareTracker] ransomware.live error: {e}')
        return result

    def _search_ransomlook(self, target: str) -> dict:
        """Search ransomlook.io API"""
        result = {'victims': [], 'error': None}
        try:
            domain = target.lower().replace('www.', '').split('/')[0]
            r = self.session.get(
                f'{RANSOMLOOK_API}/victims/{quote(domain)}',
                timeout=TIMEOUT
            )
            if r.status_code == 200:
                data = r.json()
                for v in (data if isinstance(data, list) else [data]):
                    if not v:
                        continue
                    result['victims'].append({
                        'group':       v.get('group', 'unknown'),
                        'victim':      v.get('post_title', domain),
                        'date':        v.get('published', 'N/A'),
                        'website':     v.get('website', 'N/A'),
                        'description': str(v.get('description', ''))[:200],
                        'source':      'ransomlook.io',
                        'severity':    'CRITICAL'
                    })
        except Exception as e:
            result['error'] = str(e)
            logger.debug(f'[RansomwareTracker] ransomlook error: {e}')
        return result

    def _crawl_onion_sites(self, target: str) -> dict:
        """Direct .onion crawl for target mentions"""
        result = {'victims': [], 'error': None}
        domain = target.lower().replace('www.', '').split('/')[0]

        for group, onion_url in RANSOMWARE_GROUPS.items():
            try:
                r = self.tor_session.get(onion_url, timeout=20)
                if r.status_code == 200 and domain in r.text.lower():
                    result['victims'].append({
                        'group':    group,
                        'victim':   target,
                        'date':     'N/A',
                        'website':  onion_url,
                        'description': f'Target found on {group} leak site',
                        'source':   'onion_direct',
                        'severity': 'CRITICAL'
                    })
                time.sleep(1)
            except Exception as e:
                logger.debug(f'[RansomwareTracker] {group} onion error: {e}')

        return result

    def get_active_groups(self) -> list:
        """Get list of currently active ransomware groups"""
        try:
            r = self.session.get(f'{RANSOMWARE_LIVE_API}/groups', timeout=TIMEOUT)
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            logger.debug(f'[RansomwareTracker] groups fetch error: {e}')
        return list(RANSOMWARE_GROUPS.keys())
