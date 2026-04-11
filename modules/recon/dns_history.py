import logging
import requests
import config
from collections import defaultdict
from modules.utils import rate_limited_get

logger = logging.getLogger(__name__)

class DNSHistory:
    ST_BASE  = 'https://api.securitytrails.com/v1'
    HT_BASE  = 'https://api.hackertarget.com'
    TIMEOUT  = 6

    def __init__(self):
        self.st_key = config.SECURITYTRAILS_API_KEY

    def run(self, domain: str) -> dict:
        result = {
            'domain': domain,
            'current_ips': [],
            'historical_ips': [],
            'historical_dns': {},
            'ip_changes': [],
            'nameserver_changes': [],
            'risk_flags': [],
            'sources': {},
            'error': None
        }

        # Always try HackerTarget (free, no key)
        self._hackertarget(domain, result)

        # SecurityTrails if key available
        if self.st_key:
            self._securitytrails(domain, result)
        else:
            result['sources']['securitytrails'] = 'no_api_key'

        self._analyze_risk(result)
        return result

    def _hackertarget(self, domain: str, result: dict):
        resp = rate_limited_get(f"{self.HT_BASE}/api/hostsearch/",
                                namespace='hackertarget', params={'q': domain}, timeout=self.TIMEOUT)
        try:
            if resp and resp.status_code == 200 and 'error' not in resp.text.lower():
                ips = []
                for line in resp.text.strip().splitlines():
                    parts = line.split(',')
                    if len(parts) >= 2:
                        ips.append({'ip': parts[1].strip(), 'hostname': parts[0].strip()})
                result['current_ips'] = ips
                result['sources']['hackertarget'] = 'ok'
            else:
                result['sources']['hackertarget'] = resp.text[:100] if resp else 'no_response'
        except Exception as e:
            result['sources']['hackertarget'] = str(e)
            logger.debug(f"HackerTarget error: {e}")

        resp2 = rate_limited_get(f"{self.HT_BASE}/api/passiverecon/",
                                 namespace='hackertarget', params={'q': domain}, timeout=self.TIMEOUT)
        try:
            if resp2 and resp2.status_code == 200 and 'error' not in resp2.text.lower():
                for line in resp2.text.strip().splitlines():
                    parts = line.split(',')
                    if len(parts) >= 2:
                        result['historical_ips'].append({
                            'ip': parts[1].strip(),
                            'hostname': parts[0].strip(),
                            'source': 'hackertarget_passive'
                        })
        except Exception as e:
            logger.debug(f"HackerTarget passive DNS error: {e}")

    def _securitytrails(self, domain: str, result: dict):
        headers = {'APIKEY': self.st_key, 'Content-Type': 'application/json'}
        try:
            resp = rate_limited_get(f"{self.ST_BASE}/history/{domain}/dns/a",
                                    namespace='securitytrails', headers=headers, timeout=self.TIMEOUT)
            if resp and resp.status_code == 200:
                data = resp.json()
                records = data.get('records', [])
                seen_ips = set()
                for rec in records:
                    for val in rec.get('values', []):
                        ip = val.get('ip', '')
                        if ip and ip not in seen_ips:
                            seen_ips.add(ip)
                            result['historical_ips'].append({
                                'ip': ip,
                                'first_seen': rec.get('first_seen'),
                                'last_seen': rec.get('last_seen'),
                                'source': 'securitytrails'
                            })
                result['sources']['securitytrails_a'] = 'ok'

            resp = rate_limited_get(f"{self.ST_BASE}/history/{domain}/dns/ns",
                                    namespace='securitytrails', headers=headers, timeout=self.TIMEOUT)
            if resp and resp.status_code == 200:
                data = resp.json()
                for rec in data.get('records', []):
                    ns_vals = [v.get('nameserver', '') for v in rec.get('values', [])]
                    result['nameserver_changes'].append({
                        'nameservers': ns_vals,
                        'first_seen': rec.get('first_seen'),
                        'last_seen': rec.get('last_seen')
                    })
                result['sources']['securitytrails_ns'] = 'ok'

            resp = rate_limited_get(f"{self.ST_BASE}/domain/{domain}/associated",
                                    namespace='securitytrails', headers=headers, timeout=self.TIMEOUT)
            if resp and resp.status_code == 200:
                result['historical_dns']['associated_domains'] = resp.json().get('records', [])

        except Exception as e:
            result['sources']['securitytrails'] = str(e)
            logger.error(f"SecurityTrails error: {e}")

    def _analyze_risk(self, result: dict):
        # Detect IP changes
        all_ips = {e['ip'] for e in result['historical_ips']}
        current = {e['ip'] for e in result['current_ips']}
        old_ips = all_ips - current

        if old_ips:
            result['ip_changes'] = list(old_ips)
            result['risk_flags'].append({
                'severity': 'MEDIUM',
                'flag': 'Historical IP changes',
                'detail': f"Previously hosted on: {', '.join(list(old_ips)[:5])}"
            })

        if len(result['nameserver_changes']) > 3:
            result['risk_flags'].append({
                'severity': 'HIGH',
                'flag': 'Frequent NS changes',
                'detail': f"{len(result['nameserver_changes'])} nameserver changes detected"
            })
