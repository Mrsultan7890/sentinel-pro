"""
Telegram Dark Channel Monitor
Public Telegram leak/breach channels scrape karo — no auth needed
"""

import requests
import re
import logging
import time
from datetime import datetime

logger = logging.getLogger(__name__)

TIMEOUT = 15
UA = 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0'

# Public dark web / leak / breach Telegram channels
DARK_CHANNELS = [
    {'name': 'DarkWebInformer',    'handle': 'DarkWebInformer',    'type': 'threat_intel'},
    {'name': 'LeakBase',           'handle': 'leakbase',           'type': 'breach'},
    {'name': 'RansomwareLeaks',    'handle': 'ransomwareleaks',    'type': 'ransomware'},
    {'name': 'BreachDetector',     'handle': 'breachdetector',     'type': 'breach'},
    {'name': 'DailyDarkWeb',       'handle': 'DailyDarkWeb',       'type': 'threat_intel'},
    {'name': 'CyberSecurityNews',  'handle': 'cybersecuritynews',  'type': 'news'},
    {'name': 'VXUnderground',      'handle': 'vxunderground',      'type': 'malware'},
    {'name': 'ThreatIntelligence', 'handle': 'threatintelligence', 'type': 'threat_intel'},
    {'name': 'DataBreaches',       'handle': 'databreaches',       'type': 'breach'},
    {'name': 'LeakLookup',         'handle': 'leaklookup',         'type': 'breach'},
]


class TelegramMonitor:

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': UA,
            'Accept-Language': 'en-US,en;q=0.9',
        })

    def search(self, target: str) -> dict:
        """Search all dark channels for target mentions"""
        result = {
            'target':         target,
            'mentions':       [],
            'channels_checked': 0,
            'total_hits':     0,
            'risk':           'LOW',
        }

        keywords = self._build_keywords(target)

        for channel in DARK_CHANNELS:
            try:
                hits = self._scrape_channel(channel, keywords)
                result['channels_checked'] += 1
                result['mentions'].extend(hits)
                if hits:
                    logger.info(f"[TelegramMonitor] {channel['handle']}: {len(hits)} hits")
                time.sleep(0.5)
            except Exception as e:
                logger.debug(f"[TelegramMonitor] {channel['handle']} error: {e}")

        result['total_hits'] = len(result['mentions'])
        if result['total_hits'] > 0:
            result['risk'] = 'CRITICAL' if any(
                m.get('channel_type') == 'ransomware' for m in result['mentions']
            ) else 'HIGH'

        return result

    def _build_keywords(self, target: str) -> list:
        """Build search keywords from target"""
        domain = target.lower().replace('www.', '').split('/')[0]
        parts = domain.split('.')
        company = parts[0] if parts else domain
        return [domain, company]

    def _scrape_channel(self, channel: dict, keywords: list) -> list:
        """Scrape public Telegram channel via t.me/s/ preview"""
        hits = []
        handle = channel['handle']

        try:
            # t.me/s/CHANNEL gives public preview (no auth)
            r = self.session.get(
                f'https://t.me/s/{handle}',
                timeout=TIMEOUT
            )
            if r.status_code != 200:
                return hits

            # Extract message texts
            messages = re.findall(
                r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>',
                r.text, re.DOTALL
            )

            for msg_html in messages:
                msg_text = re.sub(r'<[^>]+>', ' ', msg_html).strip()
                msg_text = re.sub(r'\s+', ' ', msg_text)

                for kw in keywords:
                    if kw.lower() in msg_text.lower():
                        # Extract date
                        date_match = re.search(
                            r'datetime="([^"]+)"', r.text
                        )
                        date = date_match.group(1)[:10] if date_match else 'N/A'

                        hits.append({
                            'channel':      channel['name'],
                            'channel_handle': handle,
                            'channel_type': channel['type'],
                            'keyword':      kw,
                            'message':      msg_text[:300],
                            'date':         date,
                            'url':          f'https://t.me/{handle}',
                            'severity':     'CRITICAL' if channel['type'] == 'ransomware' else 'HIGH',
                        })
                        break  # one hit per message

        except Exception as e:
            logger.debug(f'[TelegramMonitor] scrape error {handle}: {e}')

        return hits

    def search_single_channel(self, handle: str, target: str) -> list:
        """Search a specific channel by handle"""
        channel = {'name': handle, 'handle': handle, 'type': 'custom'}
        keywords = self._build_keywords(target)
        return self._scrape_channel(channel, keywords)
