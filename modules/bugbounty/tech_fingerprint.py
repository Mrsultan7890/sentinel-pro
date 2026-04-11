"""
Tech Stack Fingerprinting (Deep)
Detects server, framework, CMS, CDN, analytics, JS libs, WAF via:
  - HTTP response headers
  - HTML meta tags / generator tags
  - Script src patterns
  - Favicon MD5 hash (Shodan-style)
  - Error page fingerprints
  - robots.txt / sitemap hints
"""

import re
import hashlib
import logging
import requests
from modules.utils import rate_limited_get

logger = logging.getLogger(__name__)

# ── Signature database ────────────────────────────────────────────────────────

HEADER_SIGS = {
    'Server': [
        (r'nginx/([\d.]+)',          'Nginx',       'Web Server'),
        (r'Apache/([\d.]+)',         'Apache',      'Web Server'),
        (r'Microsoft-IIS/([\d.]+)',  'IIS',         'Web Server'),
        (r'LiteSpeed',               'LiteSpeed',   'Web Server'),
        (r'cloudflare',              'Cloudflare',  'CDN/WAF'),
        (r'openresty',               'OpenResty',   'Web Server'),
        (r'gunicorn/([\d.]+)',        'Gunicorn',    'App Server'),
        (r'Kestrel',                 'Kestrel',     'App Server'),
    ],
    'X-Powered-By': [
        (r'PHP/([\d.]+)',            'PHP',         'Language'),
        (r'ASP\.NET',                'ASP.NET',     'Framework'),
        (r'Express',                 'Express.js',  'Framework'),
        (r'Next\.js',                'Next.js',     'Framework'),
        (r'Servlet/([\d.]+)',        'Java Servlet','Framework'),
    ],
    'X-Generator':    [(r'(.+)',     None,          'CMS')],
    'X-Drupal-Cache': [(r'',        'Drupal',      'CMS')],
    'X-Joomla':       [(r'',        'Joomla',      'CMS')],
    'CF-Ray':         [(r'',        'Cloudflare',  'CDN/WAF')],
    'X-Varnish':      [(r'',        'Varnish',     'Cache')],
    'X-Cache':        [(r'HIT|MISS','CDN Cache',   'Cache')],
    'Via':            [(r'varnish',  'Varnish',     'Cache'),
                       (r'squid',   'Squid',       'Proxy')],
    'X-Shopify-Stage':[(r'',        'Shopify',     'E-Commerce')],
    'X-WP-Nonce':     [(r'',        'WordPress',   'CMS')],
    'X-Magento':      [(r'',        'Magento',     'E-Commerce')],
}

HTML_SIGS = [
    (r'<meta[^>]+generator[^>]+WordPress ([\d.]+)',  'WordPress',    'CMS'),
    (r'<meta[^>]+generator[^>]+Joomla',              'Joomla',       'CMS'),
    (r'<meta[^>]+generator[^>]+Drupal',              'Drupal',       'CMS'),
    (r'<meta[^>]+generator[^>]+Wix',                 'Wix',          'Website Builder'),
    (r'<meta[^>]+generator[^>]+Squarespace',         'Squarespace',  'Website Builder'),
    (r'wp-content/themes/',                          'WordPress',    'CMS'),
    (r'wp-includes/',                                'WordPress',    'CMS'),
    (r'/sites/default/files/',                       'Drupal',       'CMS'),
    (r'Joomla!',                                     'Joomla',       'CMS'),
    (r'__NEXT_DATA__',                               'Next.js',      'Framework'),
    (r'__nuxt',                                      'Nuxt.js',      'Framework'),
    (r'ng-version=',                                 'Angular',      'JS Framework'),
    (r'data-reactroot',                              'React',        'JS Framework'),
    (r'data-v-[a-f0-9]+',                            'Vue.js',       'JS Framework'),
    (r'Shopify\.theme',                              'Shopify',      'E-Commerce'),
    (r'Magento',                                     'Magento',      'E-Commerce'),
    (r'PrestaShop',                                  'PrestaShop',   'E-Commerce'),
    (r'laravel_session',                             'Laravel',      'Framework'),
    (r'XSRF-TOKEN',                                  'Laravel/Rails','Framework'),
    (r'csrfmiddlewaretoken',                         'Django',       'Framework'),
    (r'__RequestVerificationToken',                  'ASP.NET MVC',  'Framework'),
    (r'gtag\(',                                      'Google Analytics','Analytics'),
    (r'ga\(',                                        'Google Analytics','Analytics'),
    (r'fbq\(',                                       'Facebook Pixel','Analytics'),
    (r'hotjar',                                      'Hotjar',       'Analytics'),
    (r'cdn\.jsdelivr\.net',                          'jsDelivr CDN', 'CDN'),
    (r'cdnjs\.cloudflare\.com',                      'Cloudflare CDN','CDN'),
    (r'ajax\.googleapis\.com',                       'Google CDN',   'CDN'),
    (r'bootstrap(?:\.min)?\.js',                     'Bootstrap',    'CSS Framework'),
    (r'tailwind',                                    'Tailwind CSS', 'CSS Framework'),
    (r'jquery(?:\.min)?\.js',                        'jQuery',       'JS Library'),
    (r'react(?:\.min)?\.js|react-dom',               'React',        'JS Framework'),
    (r'vue(?:\.min)?\.js',                           'Vue.js',       'JS Framework'),
    (r'angular(?:\.min)?\.js',                       'Angular',      'JS Framework'),
    (r'ember(?:\.min)?\.js',                         'Ember.js',     'JS Framework'),
    (r'backbone(?:\.min)?\.js',                      'Backbone.js',  'JS Framework'),
    (r'socket\.io',                                  'Socket.IO',    'Real-time'),
    (r'graphql',                                     'GraphQL',      'API'),
    (r'swagger-ui',                                  'Swagger UI',   'API Docs'),
    (r'redoc',                                       'ReDoc',        'API Docs'),
]

FAVICON_HASHES = {
    '1708400538':  ('Fortinet FortiGate', 'Network Device'),
    '-247388890':  ('Cisco',              'Network Device'),
    '116323821':   ('Citrix',             'Remote Access'),
    '-1424875092': ('VMware',             'Virtualization'),
    '708578229':   ('Jenkins',            'CI/CD'),
    '-1438083376': ('GitLab',             'DevOps'),
    '1278323681':  ('Grafana',            'Monitoring'),
    '-1427174862': ('Kibana',             'Monitoring'),
    '1278323681':  ('Prometheus',         'Monitoring'),
    '116323821':   ('Jira',               'Project Mgmt'),
    '-1424875092': ('Confluence',         'Wiki'),
    '708578229':   ('WordPress',          'CMS'),
    '1278323681':  ('phpMyAdmin',         'DB Admin'),
    '-1427174862': ('Roundcube',          'Webmail'),
}

ERROR_SIGS = [
    (r'Whitelabel Error Page',           'Spring Boot',  'Framework'),
    (r'Tomcat.*Apache',                  'Apache Tomcat','App Server'),
    (r'Servlet Exception',               'Java Servlet', 'Framework'),
    (r'Django.*Debug',                   'Django',       'Framework'),
    (r'Laravel.*Whoops',                 'Laravel',      'Framework'),
    (r'Ruby on Rails',                   'Ruby on Rails','Framework'),
    (r'Sinatra doesn',                   'Sinatra',      'Framework'),
    (r'Express.*Cannot GET',             'Express.js',   'Framework'),
    (r'ASP\.NET.*error',                 'ASP.NET',      'Framework'),
    (r'PHP.*Fatal error',                'PHP',          'Language'),
    (r'Microsoft OLE DB',                'MSSQL',        'Database'),
    (r'ORA-\d{5}',                       'Oracle DB',    'Database'),
    (r'MySQL.*error',                    'MySQL',        'Database'),
    (r'PostgreSQL.*ERROR',               'PostgreSQL',   'Database'),
    (r'MongoDB.*error',                  'MongoDB',      'Database'),
]


class TechFingerprint:

    def run(self, domain: str) -> dict:
        result = {
            'domain': domain,
            'stack': {},          # category -> {name, version, confidence, source}
            'all_findings': [],
            'total': 0,
            'cve_hints': [],      # tech names for CVE lookup
            'risk_level': 'INFO',
            'error': None,
        }

        seen = {}  # name -> entry (deduplicate)

        def add(name, category, version, confidence, source):
            if name and name not in seen:
                entry = {'name': name, 'category': category,
                         'version': version or '', 'confidence': confidence, 'source': source}
                seen[name] = entry
                result['all_findings'].append(entry)
                result['stack'][category] = result['stack'].get(category, [])
                result['stack'][category].append(entry)

        # ── Fetch main page ───────────────────────────────────────────────────
        for scheme in ('https', 'http'):
            try:
                resp = requests.get(f"{scheme}://{domain}", timeout=10,
                                    headers={'User-Agent': 'Mozilla/5.0'}, verify=False,
                                    allow_redirects=True)
                html = resp.text[:80000]

                # Header signatures
                for header, sigs in HEADER_SIGS.items():
                    val = resp.headers.get(header, '')
                    if not val:
                        continue
                    for pattern, tech_name, category in sigs:
                        m = re.search(pattern, val, re.IGNORECASE)
                        if m:
                            name    = tech_name or m.group(1)
                            version = m.group(1) if m.lastindex and tech_name else ''
                            add(name, category, version, 'HIGH', f'Header:{header}')

                # HTML signatures
                for pattern, tech_name, category in HTML_SIGS:
                    m = re.search(pattern, html, re.IGNORECASE)
                    if m:
                        version = m.group(1) if m.lastindex else ''
                        add(tech_name, category, version, 'MEDIUM', 'HTML')

                break  # success — no need to try http
            except Exception as e:
                logger.debug(f"TechFingerprint {scheme}://{domain}: {e}")

        # ── Favicon hash ─────────────────────────────────────────────────────
        try:
            fav = requests.get(f"https://{domain}/favicon.ico", timeout=6,
                               headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
            if fav.status_code == 200 and fav.content:
                try:
                    import mmh3, base64
                    fav_hash = str(mmh3.hash(base64.encodebytes(fav.content)))
                    if fav_hash in FAVICON_HASHES:
                        name, cat = FAVICON_HASHES[fav_hash]
                        add(name, cat, '', 'HIGH', f'Favicon hash:{fav_hash}')
                except ImportError:
                    logger.debug('mmh3 not installed — favicon hash fingerprinting skipped. Run: pip install mmh3')
        except Exception:
            pass

        # ── Error page fingerprint ────────────────────────────────────────────
        try:
            err_resp = requests.get(f"https://{domain}/this_path_does_not_exist_sentinel",
                                    timeout=8, headers={'User-Agent': 'Mozilla/5.0'},
                                    verify=False, allow_redirects=False)
            err_html = err_resp.text[:10000]
            for pattern, tech_name, category in ERROR_SIGS:
                if re.search(pattern, err_html, re.IGNORECASE):
                    add(tech_name, category, '', 'MEDIUM', 'Error page')
        except Exception:
            pass

        # ── robots.txt hints ─────────────────────────────────────────────────
        try:
            robots = requests.get(f"https://{domain}/robots.txt", timeout=6,
                                  headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
            if robots.status_code == 200:
                rb = robots.text
                if 'wp-admin' in rb:
                    add('WordPress', 'CMS', '', 'MEDIUM', 'robots.txt')
                if '/administrator' in rb:
                    add('Joomla', 'CMS', '', 'MEDIUM', 'robots.txt')
                if '/sites/default' in rb:
                    add('Drupal', 'CMS', '', 'MEDIUM', 'robots.txt')
        except Exception:
            pass

        result['total']     = len(result['all_findings'])
        result['cve_hints'] = [e['name'] for e in result['all_findings']
                                if e['category'] in ('Web Server', 'Framework', 'CMS', 'Language', 'App Server')]

        if result['total'] > 0:
            result['risk_level'] = 'INFO'  # findings are informational; CVE lookup uses cve_hints

        return result
