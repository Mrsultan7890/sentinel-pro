import logging
import config

logger = logging.getLogger(__name__)

class ShodanScanner:
    def __init__(self):
        self.api_key = config.SHODAN_API_KEY

    def run(self, domain: str) -> dict:
        result = {
            'domain': domain,
            'ip': None,
            'org': None,
            'isp': None,
            'country': None,
            'city': None,
            'open_ports': [],
            'vulns': [],
            'hostnames': [],
            'tags': [],
            'os': None,
            'last_update': None,
            'services': [],
            'risk_flags': [],
            'error': None
        }

        if not self.api_key:
            result['error'] = 'SHODAN_API_KEY not set'
            return result

        try:
            import shodan
            import socket

            api = shodan.Shodan(self.api_key)

            # Resolve domain to IP
            try:
                ip = socket.gethostbyname(domain)
            except socket.gaierror:
                result['error'] = f'Cannot resolve {domain}'
                return result

            result['ip'] = ip

            host = api.host(ip)

            result['org']         = host.get('org')
            result['isp']         = host.get('isp')
            result['country']     = host.get('country_name')
            result['city']        = host.get('city')
            result['os']          = host.get('os')
            result['last_update'] = host.get('last_update')
            result['hostnames']   = host.get('hostnames', [])
            result['tags']        = host.get('tags', [])
            result['open_ports']  = host.get('ports', [])

            # CVEs
            vulns = host.get('vulns', [])
            result['vulns'] = list(vulns) if vulns else []

            # Service banners
            for item in host.get('data', []):
                svc = {
                    'port':      item.get('port'),
                    'transport': item.get('transport', 'tcp'),
                    'product':   item.get('product'),
                    'version':   item.get('version'),
                    'banner':    (item.get('data', '') or '')[:200]
                }
                result['services'].append(svc)

            # Risk flags
            if result['vulns']:
                result['risk_flags'].append({
                    'severity': 'CRITICAL',
                    'flag': 'Known CVEs',
                    'detail': f"{len(result['vulns'])} CVEs: {', '.join(result['vulns'][:5])}"
                })

            RISKY_PORTS = {21, 23, 3389, 5900, 6379, 27017, 9200, 2375, 4243}
            exposed_risky = [p for p in result['open_ports'] if p in RISKY_PORTS]
            if exposed_risky:
                result['risk_flags'].append({
                    'severity': 'HIGH',
                    'flag': 'Risky ports exposed',
                    'detail': f"Ports: {exposed_risky}"
                })

            if 'honeypot' in result['tags']:
                result['risk_flags'].append({
                    'severity': 'MEDIUM',
                    'flag': 'Honeypot tag',
                    'detail': 'Shodan tagged this host as honeypot'
                })

        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Shodan scan failed for {domain}: {e}")

        return result
