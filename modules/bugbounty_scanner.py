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
Bug Bounty & Recon Module
Subdomain enumeration, port scanning, endpoint discovery, breach checking
"""

import re
import socket
import logging
import requests
from modules.utils import tor_session
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

HEADERS = {'User-Agent': 'Mozilla/5.0 (compatible; SentinelPro/2.1)'}


class BugBountyScanner:

    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 'test',
        'beta', 'app', 'portal', 'dashboard', 'login', 'auth', 'cdn',
        'static', 'assets', 'media', 'blog', 'shop', 'store', 'support',
        'help', 'docs', 'wiki', 'forum', 'vpn', 'remote', 'webmail',
        'smtp', 'pop', 'imap', 'ns1', 'ns2', 'mx', 'git', 'gitlab',
        'jenkins', 'jira', 'confluence', 'grafana', 'kibana', 'elastic'
    ]

    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389,
                    5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017]

    SENSITIVE_ENDPOINTS = [
        '/.git/config', '/.env', '/config.php', '/wp-config.php',
        '/admin', '/admin/login', '/administrator', '/phpmyadmin',
        '/api/v1', '/api/v2', '/swagger', '/swagger-ui.html',
        '/api-docs', '/.well-known/security.txt', '/robots.txt',
        '/sitemap.xml', '/backup.zip', '/backup.sql', '/dump.sql',
        '/server-status', '/server-info', '/.htaccess',
        '/web.config', '/crossdomain.xml', '/clientaccesspolicy.xml'
    ]

    def __init__(self):
        self.session = tor_session()
        self.session.headers.update(HEADERS)

    # ------------------------------------------------------------------ #
    #  Subdomain Enumeration                                               #
    # ------------------------------------------------------------------ #

    def enumerate_subdomains(self, domain):
        """Enumerate subdomains via DNS resolution + crt.sh certificate logs"""
        results = {'domain': domain, 'subdomains': [], 'timestamp': datetime.now().isoformat()}
        found = set()

        # 1. Brute-force common subdomains via DNS
        def resolve(sub):
            fqdn = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                return {'subdomain': fqdn, 'ip': ip, 'source': 'dns_brute'}
            except socket.gaierror:
                return None

        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(resolve, s): s for s in self.COMMON_SUBDOMAINS}
            for f in as_completed(futures):
                r = f.result()
                if r and r['subdomain'] not in found:
                    found.add(r['subdomain'])
                    results['subdomains'].append(r)

        # 2. Certificate Transparency logs (crt.sh)
        try:
            resp = self.session.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=10, verify=False
            )
            if resp.status_code == 200:
                for entry in resp.json():
                    name = entry.get('name_value', '').strip()
                    for n in name.split('\n'):
                        n = n.strip().lstrip('*.')
                        if n.endswith(domain) and n not in found:
                            found.add(n)
                            results['subdomains'].append({
                                'subdomain': n,
                                'ip': self._resolve_ip(n),
                                'source': 'crt.sh'
                            })
        except Exception as e:
            logger.warning(f"crt.sh lookup failed: {e}")

        results['total_found'] = len(results['subdomains'])
        return results

    def _resolve_ip(self, hostname):
        try:
            return socket.gethostbyname(hostname)
        except Exception:
            return 'unresolved'

    # ------------------------------------------------------------------ #
    #  Port Scanning                                                       #
    # ------------------------------------------------------------------ #

    def scan_ports(self, target):
        """Fast TCP port scan on common ports"""
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            return {'target': target, 'error': 'Could not resolve hostname', 'open_ports': []}

        results = {'target': target, 'ip': ip, 'open_ports': [], 'timestamp': datetime.now().isoformat()}

        def check_port(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                if s.connect_ex((ip, port)) == 0:
                    service = self._get_service_name(port)
                    return {'port': port, 'state': 'open', 'service': service}
                s.close()
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=50) as ex:
            futures = {ex.submit(check_port, p): p for p in self.COMMON_PORTS}
            for f in as_completed(futures):
                r = f.result()
                if r:
                    results['open_ports'].append(r)

        results['open_ports'].sort(key=lambda x: x['port'])
        results['total_open'] = len(results['open_ports'])
        return results

    def _get_service_name(self, port):
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
            6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            8888: 'HTTP-Alt', 9200: 'Elasticsearch', 27017: 'MongoDB'
        }
        return services.get(port, 'unknown')

    # ------------------------------------------------------------------ #
    #  Sensitive Endpoint Discovery                                        #
    # ------------------------------------------------------------------ #

    def discover_endpoints(self, domain):
        """Check for exposed sensitive endpoints"""
        base_url = f"https://{domain}" if not domain.startswith('http') else domain
        results = {'target': domain, 'exposed': [], 'timestamp': datetime.now().isoformat()}

        def check_endpoint(path):
            try:
                url = base_url + path
                r = self.session.get(url, timeout=5, verify=False, allow_redirects=False)
                if r.status_code in [200, 301, 302, 403]:
                    risk = 'CRITICAL' if r.status_code == 200 else 'MEDIUM'
                    return {
                        'path': path,
                        'url': url,
                        'status_code': r.status_code,
                        'risk': risk,
                        'content_length': len(r.content)
                    }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = {ex.submit(check_endpoint, p): p for p in self.SENSITIVE_ENDPOINTS}
            for f in as_completed(futures):
                r = f.result()
                if r:
                    results['exposed'].append(r)

        results['total_exposed'] = len(results['exposed'])
        results['critical_count'] = sum(1 for e in results['exposed'] if e['risk'] == 'CRITICAL')
        return results

    # ------------------------------------------------------------------ #
    #  Breach Check                                                        #
    # ------------------------------------------------------------------ #

    def check_breach(self, email_or_username):
        """Check for data breaches using public APIs"""
        results = {
            'target': email_or_username,
            'breaches': [],
            'paste_count': 0,
            'timestamp': datetime.now().isoformat()
        }

        # DeHashed public search (no key needed for basic)
        try:
            resp = self.session.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email_or_username}",
                headers={**HEADERS, 'hibp-api-key': 'public'},
                timeout=8, verify=False
            )
            if resp.status_code == 200:
                for breach in resp.json():
                    results['breaches'].append({
                        'name': breach.get('Name'),
                        'domain': breach.get('Domain'),
                        'breach_date': breach.get('BreachDate'),
                        'data_classes': breach.get('DataClasses', []),
                        'is_verified': breach.get('IsVerified', False)
                    })
            elif resp.status_code == 404:
                results['status'] = 'No breaches found'
            elif resp.status_code == 401:
                results['status'] = 'API key required for HIBP - checking alternative sources'
        except Exception as e:
            logger.warning(f"HIBP check failed: {e}")

        # Fallback: check via leakcheck.io public endpoint
        try:
            resp = self.session.get(
                f"https://leakcheck.io/api/public?check={email_or_username}",
                timeout=8, verify=False
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get('found'):
                    results['leakcheck_found'] = True
                    results['leakcheck_sources'] = data.get('sources', [])
        except Exception as e:
            logger.warning(f"LeakCheck failed: {e}")

        results['total_breaches'] = len(results['breaches'])
        results['risk_level'] = (
            'CRITICAL' if results['total_breaches'] > 5 else
            'HIGH' if results['total_breaches'] > 2 else
            'MEDIUM' if results['total_breaches'] > 0 else
            'LOW'
        )
        return results

    # ------------------------------------------------------------------ #
    #  Full Bug Bounty Scan                                                #
    # ------------------------------------------------------------------ #

    def full_scan(self, target):
        """Run complete bug bounty recon on a target domain"""
        is_domain = bool(re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target))
        is_email = bool(re.match(r'^[^@]+@[^@]+\.[^@]+$', target))

        report = {
            'target': target,
            'scan_type': 'domain' if is_domain else 'email',
            'timestamp': datetime.now().isoformat()
        }

        if is_domain:
            report['subdomains'] = self.enumerate_subdomains(target)
            report['ports'] = self.scan_ports(target)
            report['endpoints'] = self.discover_endpoints(target)

        if is_email or not is_domain:
            report['breach'] = self.check_breach(target)

        # Risk summary
        critical_issues = []
        if report.get('endpoints', {}).get('critical_count', 0) > 0:
            critical_issues.append(f"{report['endpoints']['critical_count']} exposed sensitive endpoints")
        if report.get('ports', {}).get('open_ports'):
            risky = [p for p in report['ports']['open_ports'] if p['port'] in [23, 3389, 5900, 6379, 27017, 9200]]
            if risky:
                critical_issues.append(f"{len(risky)} high-risk open ports")
        if report.get('breach', {}).get('total_breaches', 0) > 0:
            critical_issues.append(f"{report['breach']['total_breaches']} data breaches found")

        report['critical_issues'] = critical_issues
        report['overall_risk'] = 'CRITICAL' if critical_issues else 'LOW'
        return report
