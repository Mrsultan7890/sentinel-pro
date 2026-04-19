"""
Subdomain Enumeration
DNS brute-force + crt.sh + HackerTarget + VirusTotal + AlienVault OTX + RapidDNS
"""

import socket
import logging
import requests
from modules.utils import tor_session
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import config

logger = logging.getLogger(__name__)

HEADERS = {'User-Agent': 'Mozilla/5.0 (compatible; SentinelPro/2.1)'}

WORDLIST = [
    # Common
    'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 'test',
    'beta', 'app', 'portal', 'dashboard', 'login', 'auth', 'cdn',
    'static', 'assets', 'media', 'blog', 'shop', 'store', 'support',
    'help', 'docs', 'wiki', 'forum', 'vpn', 'remote', 'webmail',
    'smtp', 'pop', 'imap', 'ns1', 'ns2', 'ns3', 'ns4', 'mx', 'mx1', 'mx2',
    'git', 'gitlab', 'github', 'bitbucket', 'svn',
    'jenkins', 'jira', 'confluence', 'grafana', 'kibana', 'elastic',
    'internal', 'intranet', 'corp', 'office', 'secure', 'vault',
    'backup', 'old', 'new', 'v2', 'v3', 'v4', 'mobile', 'wap', 'ws',
    'api2', 'api3', 'api4', 'sandbox', 'uat', 'qa', 'preprod', 'prod',
    'db', 'database', 'mysql', 'postgres', 'redis', 'mongo', 'elastic',
    'ci', 'cd', 'build', 'deploy', 'monitor', 'status', 'health',
    'smtp2', 'relay', 'bounce', 'newsletter', 'marketing',
    'crm', 'erp', 'hr', 'finance', 'legal', 'it', 'helpdesk',
    # Infrastructure
    'proxy', 'gateway', 'firewall', 'router', 'switch', 'load',
    'lb', 'lb1', 'lb2', 'haproxy', 'nginx', 'apache',
    'web', 'web1', 'web2', 'web3', 'node1', 'node2', 'node3',
    'server', 'server1', 'server2', 'host', 'host1', 'host2',
    'cloud', 'aws', 'azure', 'gcp', 'k8s', 'docker', 'rancher',
    'vpn2', 'vpn3', 'remote2', 'access', 'sso', 'oauth', 'saml',
    'ldap', 'ad', 'dc', 'dc1', 'dc2', 'exchange', 'owa',
    # Dev/DevOps
    'dev2', 'dev3', 'develop', 'development', 'local', 'localhost',
    'test2', 'test3', 'testing', 'stage', 'stage2', 'stg',
    'demo', 'demo2', 'preview', 'review', 'rc', 'alpha',
    'sonar', 'sonarqube', 'nexus', 'artifactory', 'registry',
    'prometheus', 'alertmanager', 'jaeger', 'zipkin', 'consul',
    'vault2', 'secrets', 'config', 'configs',
    # Security
    'siem', 'splunk', 'waf', 'ids', 'ips', 'scan', 'pentest',
    'bug', 'bounty', 'security', 'sec', 'infosec', 'csirt',
    # Business
    'pay', 'payment', 'payments', 'billing', 'invoice', 'checkout',
    'cart', 'order', 'orders', 'account', 'accounts', 'user', 'users',
    'customer', 'customers', 'partner', 'partners', 'vendor', 'vendors',
    'report', 'reports', 'analytics', 'stats', 'metrics', 'data',
    'upload', 'uploads', 'download', 'downloads', 'files', 'file',
    'img', 'images', 'image', 'video', 'videos', 'audio',
    'search', 'index', 'home', 'main', 'public', 'private',
    # Misc
    'autodiscover', 'autoconfig', 'cpanel', 'whm', 'plesk', 'webmin',
    'phpmyadmin', 'pma', 'adminer', 'roundcube', 'squirrelmail',
    'owa', 'exchange', 'lync', 'skype', 'teams', 'zoom',
    'ftp2', 'sftp', 'ssh', 'rdp', 'vnc', 'telnet',
    'ntp', 'dns', 'dns1', 'dns2', 'resolver',
    'mail2', 'mail3', 'smtp3', 'imap2', 'pop3',
    'list', 'lists', 'ml', 'mailman', 'majordomo',
    'news', 'rss', 'feed', 'feeds', 'atom',
    'chat', 'irc', 'slack', 'discord', 'matrix',
    'meet', 'meeting', 'conference', 'webinar',
    'ticket', 'tickets', 'service', 'servicedesk',
    'kb', 'knowledge', 'faq', 'community',
    'social', 'connect', 'network', 'hub',
    'cdn2', 'cdn3', 'edge', 'edge1', 'edge2',
    'cache', 'cache1', 'cache2', 'memcache',
    'queue', 'mq', 'rabbitmq', 'kafka', 'nats',
    'log', 'logs', 'logging', 'audit', 'trace',
    'backup2', 'bak', 'archive', 'archives', 'old2',
    'legacy', 'classic', 'v1', 'v0',
    'internal2', 'private2', 'corp2', 'lan',
    'extranet', 'dmz', 'bastion', 'jump',
    'mgmt', 'management', 'manage', 'control',
    'panel', 'cp', 'console2', 'ui', 'gui',
    'mobile2', 'app2', 'app3', 'ios', 'android',
    'api-dev', 'api-staging', 'api-prod', 'api-v1', 'api-v2',
    'graphql', 'rest', 'soap', 'grpc', 'websocket',
    'webhook', 'webhooks', 'callback', 'notify', 'notification',
    'push', 'pull', 'sync', 'async', 'worker', 'workers',
    'cron', 'scheduler', 'task', 'tasks', 'job', 'jobs',
    'ml', 'ai', 'model', 'predict', 'inference',
    'test-api', 'dev-api', 'staging-api',
    'www2', 'www3', 'web4', 'web5',
]


class SubdomainEnum:

    def __init__(self):
        self.session = tor_session(pool_size=50)
        self.session.headers.update(HEADERS)

    def run(self, domain: str) -> dict:
        result = {
            'domain':    domain,
            'subdomains': [],
            'sources':   {},
            'timestamp': datetime.now().isoformat()
        }
        found = set()

        # Shared hosting check — subdomain enum useless hoga
        SHARED_HOSTING = [
            'netlify.app', 'render.com', 'vercel.app', 'github.io',
            'pages.dev', 'herokuapp.com', 'azurewebsites.net',
            'appspot.com', 'amplifyapp.com', 'surge.sh', 'glitch.me',
        ]
        for suffix in SHARED_HOSTING:
            if domain.endswith(suffix):
                result['total_found'] = 0
                result['note'] = (
                    f'Shared hosting ({suffix}) — subdomain enumeration '
                    f'would return provider subdomains, not site-specific ones'
                )
                return result

        # Source 1: DNS brute-force (500+ words, 50 threads)
        brute = self._dns_brute(domain)
        for item in brute:
            if item['subdomain'] not in found:
                found.add(item['subdomain'])
                result['subdomains'].append(item)
        result['sources']['dns_brute'] = len(brute)

        # Source 2: crt.sh
        crt = self._crtsh(domain, found)
        result['subdomains'].extend(crt)
        result['sources']['crt_sh'] = len(crt)

        # Source 3: HackerTarget
        ht = self._hackertarget(domain, found)
        result['subdomains'].extend(ht)
        result['sources']['hackertarget'] = len(ht)

        # Source 4: VirusTotal (free, no key needed for basic)
        vt = self._virustotal(domain, found)
        result['subdomains'].extend(vt)
        result['sources']['virustotal'] = len(vt)

        # Source 5: AlienVault OTX (free, no key needed)
        otx = self._alienvault(domain, found)
        result['subdomains'].extend(otx)
        result['sources']['alienvault_otx'] = len(otx)

        # Source 6: RapidDNS (free)
        rdns = self._rapiddns(domain, found)
        result['subdomains'].extend(rdns)
        result['sources']['rapiddns'] = len(rdns)

        result['total_found'] = len(result['subdomains'])
        return result

    # ------------------------------------------------------------------ #
    #  Source 1: DNS brute-force                                          #
    # ------------------------------------------------------------------ #

    def _dns_brute(self, domain: str) -> list:
        results = []

        # Wildcard detection — agar random subdomain resolve ho to wildcard hai
        import random, string
        rand_sub  = ''.join(random.choices(string.ascii_lowercase, k=12))
        wildcard_ips = set()
        try:
            wc_ip = socket.gethostbyname(f"{rand_sub}.{domain}")
            wildcard_ips.add(wc_ip)
            # Second check
            rand_sub2 = ''.join(random.choices(string.ascii_lowercase, k=10))
            wc_ip2 = socket.gethostbyname(f"{rand_sub2}.{domain}")
            wildcard_ips.add(wc_ip2)
            logger.info(f"Wildcard DNS detected for {domain}: {wildcard_ips} — filtering")
        except socket.gaierror:
            pass  # No wildcard

        def resolve(sub):
            fqdn = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                # Wildcard IP se match karta hai to skip karo
                if ip in wildcard_ips:
                    return None
                return {'subdomain': fqdn, 'ip': ip, 'source': 'dns_brute', 'alive': True}
            except socket.gaierror:
                return None

        with ThreadPoolExecutor(max_workers=30) as ex:
            futures = {ex.submit(resolve, s): s for s in WORDLIST}
            for f in as_completed(futures):
                r = f.result()
                if r:
                    results.append(r)
        return results

    # ------------------------------------------------------------------ #
    #  Source 2: crt.sh                                                   #
    # ------------------------------------------------------------------ #

    def _crtsh(self, domain: str, found: set) -> list:
        results = []
        try:
            resp = self.session.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=20, verify=False
            )
            if resp.status_code == 200:
                for entry in resp.json():
                    for n in entry.get('name_value', '').split('\n'):
                        n = n.strip().lstrip('*.')
                        if n.endswith(domain) and n not in found:
                            found.add(n)
                            ip = self._resolve(n)
                            results.append({
                                'subdomain': n, 'ip': ip,
                                'source': 'crt.sh', 'alive': ip != 'unresolved'
                            })
        except Exception as e:
            logger.warning(f"crt.sh failed: {e}")
        return results

    # ------------------------------------------------------------------ #
    #  Source 3: HackerTarget                                             #
    # ------------------------------------------------------------------ #

    def _hackertarget(self, domain: str, found: set) -> list:
        results = []
        try:
            resp = self.session.get(
                f"https://api.hackertarget.com/hostsearch/?q={domain}",
                timeout=10, verify=False
            )
            if resp.status_code == 200 and 'error' not in resp.text.lower():
                for line in resp.text.strip().split('\n'):
                    parts = line.split(',')
                    if len(parts) == 2:
                        sub, ip = parts[0].strip(), parts[1].strip()
                        if sub.endswith(domain) and sub not in found:
                            found.add(sub)
                            results.append({
                                'subdomain': sub, 'ip': ip,
                                'source': 'hackertarget', 'alive': True
                            })
        except Exception as e:
            logger.warning(f"HackerTarget failed: {e}")
        return results

    # ------------------------------------------------------------------ #
    #  Source 4: VirusTotal (free public endpoint)                        #
    # ------------------------------------------------------------------ #

    def _virustotal(self, domain: str, found: set) -> list:
        results = []
        try:
            # VT v3 UI endpoint — no API key, uses browser-like headers
            resp = self.session.get(
                f"https://www.virustotal.com/ui/domains/{domain}/subdomains?limit=40",
                headers={**HEADERS, 'x-tool': 'vt-ui-main', 'Accept': 'application/json'},
                timeout=15, verify=False
            )
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get('data', []):
                    sub = item.get('id', '')
                    if sub.endswith(domain) and sub not in found:
                        found.add(sub)
                        ip = self._resolve(sub)
                        results.append({
                            'subdomain': sub, 'ip': ip,
                            'source': 'virustotal', 'alive': ip != 'unresolved'
                        })
        except Exception as e:
            logger.warning(f"VirusTotal failed: {e}")
        return results

    # ------------------------------------------------------------------ #
    #  Source 5: AlienVault OTX (free, no key)                           #
    # ------------------------------------------------------------------ #

    def _alienvault(self, domain: str, found: set) -> list:
        results = []
        try:
            resp = self.session.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                timeout=15, verify=False
            )
            if resp.status_code == 200:
                for entry in resp.json().get('passive_dns', []):
                    hostname = entry.get('hostname', '').strip()
                    if hostname.endswith(domain) and hostname not in found:
                        found.add(hostname)
                        ip = entry.get('address', self._resolve(hostname))
                        results.append({
                            'subdomain': hostname, 'ip': ip,
                            'source': 'alienvault_otx', 'alive': bool(ip and ip != 'unresolved')
                        })
        except Exception as e:
            logger.warning(f"AlienVault OTX failed: {e}")
        return results

    # ------------------------------------------------------------------ #
    #  Source 6: RapidDNS (free)                                         #
    # ------------------------------------------------------------------ #

    def _rapiddns(self, domain: str, found: set) -> list:
        results = []
        try:
            resp = self.session.get(
                f"https://rapiddns.io/subdomain/{domain}?full=1",
                timeout=15, verify=False,
                headers={**HEADERS, 'Accept': 'text/html'}
            )
            if resp.status_code == 200:
                import re
                # Extract subdomains from HTML table
                for match in re.finditer(r'<td>([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')</td>', resp.text):
                    sub = match.group(1).strip()
                    if sub not in found:
                        found.add(sub)
                        ip = self._resolve(sub)
                        results.append({
                            'subdomain': sub, 'ip': ip,
                            'source': 'rapiddns', 'alive': ip != 'unresolved'
                        })
        except Exception as e:
            logger.warning(f"RapidDNS failed: {e}")
        return results

    # ------------------------------------------------------------------ #
    #  Helper                                                             #
    # ------------------------------------------------------------------ #

    def _resolve(self, hostname: str) -> str:
        try:
            return socket.gethostbyname(hostname)
        except Exception:
            return 'unresolved'
