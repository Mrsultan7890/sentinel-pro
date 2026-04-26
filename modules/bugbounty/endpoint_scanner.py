"""
Endpoint Scanner
2000+ sensitive paths · WAF detection · Tech fingerprinting · HTTP method testing
"""

import logging
import requests
from modules.utils import tor_session
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

HEADERS = {'User-Agent': 'Mozilla/5.0 (compatible; SentinelPro/2.1)'}

SENSITIVE_PATHS = [
    # ── Secrets & configs ──────────────────────────────────────────────
    '/.env', '/.env.local', '/.env.production', '/.env.backup', '/.env.dev',
    '/.env.staging', '/.env.test', '/.env.example', '/.env.sample', '/.env.old',
    '/.env.bak', '/.env.orig', '/.env.save', '/.env.swp', '/.env~',
    '/config.php', '/wp-config.php', '/configuration.php', '/config.php.bak',
    '/config.yml', '/config.yaml', '/config.json', '/config.xml', '/config.ini',
    '/settings.py', '/settings.php', '/settings.yml', '/settings.json',
    '/database.yml', '/database.php', '/database.json', '/db.php',
    '/secrets.yml', '/secrets.json', '/secrets.php', '/secret.txt',
    '/credentials.json', '/credentials.yml', '/credentials.xml',
    '/web.config', '/web.config.bak', '/.htaccess', '/.htpasswd',
    '/php.ini', '/php.ini.bak', '/php-fpm.conf',
    '/application.properties', '/application.yml', '/application.yaml',
    '/bootstrap.php', '/init.php', '/initialize.php',
    '/local.xml', '/local.php', '/local.yml',
    '/parameters.yml', '/parameters.php',
    '/app/config/parameters.yml', '/app/config/config.yml',
    '/config/database.yml', '/config/secrets.yml', '/config/application.yml',
    '/config/settings.py', '/config/config.php', '/config/config.json',
    '/conf/config.php', '/conf/settings.php',
    '/includes/config.php', '/include/config.php',
    '/app/etc/local.xml', '/app/etc/config.xml',
    '/sites/default/settings.php', '/sites/default/default.settings.php',
    '/wp-config.php.bak', '/wp-config.php.old', '/wp-config.php.orig',
    '/wp-config.php.save', '/wp-config.php~',
    '/.aws/credentials', '/.aws/config',
    '/.ssh/id_rsa', '/.ssh/id_dsa', '/.ssh/authorized_keys', '/.ssh/known_hosts',
    '/.docker/config.json', '/docker-compose.yml', '/docker-compose.yaml',
    '/docker-compose.override.yml', '/Dockerfile', '/.dockerignore',
    '/k8s.yml', '/kubernetes.yml', '/deployment.yml', '/deployment.yaml',
    '/helm/values.yaml', '/charts/values.yaml',
    '/terraform.tfvars', '/terraform.tfstate', '/.terraform/terraform.tfstate',
    '/ansible.cfg', '/inventory.ini', '/playbook.yml',
    '/Vagrantfile', '/Procfile', '/Makefile',
    '/package.json', '/package-lock.json', '/yarn.lock',
    '/composer.json', '/composer.lock',
    '/Gemfile', '/Gemfile.lock',
    '/requirements.txt', '/requirements.dev.txt', '/Pipfile', '/Pipfile.lock',
    '/pom.xml', '/build.gradle', '/build.xml',
    '/go.mod', '/go.sum',
    '/Cargo.toml', '/Cargo.lock',
    '/.npmrc', '/.yarnrc', '/.pypirc', '/.netrc',
    '/bower.json', '/gulpfile.js', '/Gruntfile.js', '/webpack.config.js',
    '/.travis.yml', '/.circleci/config.yml', '/.github/workflows/main.yml',
    '/Jenkinsfile', '/.gitlab-ci.yml', '/bitbucket-pipelines.yml',
    '/sonar-project.properties', '/codecov.yml',

    # ── Backups ────────────────────────────────────────────────────────
    '/backup.zip', '/backup.tar.gz', '/backup.tar', '/backup.tgz',
    '/backup.sql', '/backup.sql.gz', '/backup.db',
    '/backup/', '/backups/', '/backup/db.sql', '/backup/database.sql',
    '/dump.sql', '/dump.sql.gz', '/db.sql', '/database.sql',
    '/db_backup.sql', '/mysql.sql', '/postgres.sql',
    '/site.zip', '/site.tar.gz', '/www.zip', '/www.tar.gz',
    '/htdocs.zip', '/public_html.zip', '/web.zip',
    '/old.zip', '/old.tar.gz', '/archive.zip', '/archive.tar.gz',
    '/data.zip', '/data.sql', '/export.sql', '/export.zip',
    '/full_backup.zip', '/full_backup.sql',
    '/db_dump.sql', '/db_export.sql',
    '/backup.bak', '/config.bak', '/index.php.bak', '/index.bak',
    '/web.config.bak', '/htaccess.bak',

    # ── Admin panels ───────────────────────────────────────────────────
    '/admin', '/admin/', '/admin/login', '/admin/login.php',
    '/admin/index.php', '/admin/dashboard', '/admin/panel',
    '/administrator', '/administrator/', '/administrator/index.php',
    '/wp-admin', '/wp-admin/', '/wp-login.php',
    '/phpmyadmin', '/phpmyadmin/', '/pma', '/pma/',
    '/phpMyAdmin', '/phpMyAdmin/', '/PHPMyAdmin/',
    '/cpanel', '/cpanel/', '/whm', '/whm/',
    '/plesk', '/plesk/', '/webmin', '/webmin/',
    '/adminer.php', '/adminer', '/adminer/',
    '/manager', '/manager/', '/management', '/management/',
    '/controlpanel', '/control', '/control/',
    '/backend', '/backend/', '/backoffice', '/backoffice/',
    '/cms', '/cms/', '/cms/admin', '/cms/login',
    '/siteadmin', '/siteadmin/', '/webadmin', '/webadmin/',
    '/moderator', '/moderator/', '/superadmin', '/superadmin/',
    '/root', '/root/', '/system', '/system/',
    '/manage', '/manage/', '/portal', '/portal/admin',
    '/user/login', '/users/login', '/account/login',
    '/auth/login', '/login', '/login.php', '/login.aspx',
    '/signin', '/sign-in', '/sign_in',
    '/wp-admin/admin-ajax.php',
    '/typo3', '/typo3/', '/typo3/index.php',
    '/joomla/administrator', '/administrator/index.php',
    '/drupal/admin', '/user/1',
    '/magento/admin', '/index.php/admin',
    '/laravel/admin', '/nova', '/horizon',
    '/telescope', '/debugbar',

    # ── APIs ───────────────────────────────────────────────────────────
    '/api', '/api/', '/api/v1', '/api/v2', '/api/v3', '/api/v4',
    '/api/v1/', '/api/v2/', '/api/v3/',
    '/api/users', '/api/user', '/api/admin', '/api/config',
    '/api/keys', '/api/token', '/api/tokens', '/api/auth',
    '/api/login', '/api/register', '/api/password',
    '/api/internal', '/api/private', '/api/secret',
    '/api/debug', '/api/test', '/api/dev',
    '/api/v1/users', '/api/v1/admin', '/api/v1/config',
    '/api/v2/users', '/api/v2/admin',
    '/swagger', '/swagger/', '/swagger-ui.html', '/swagger-ui/',
    '/swagger/index.html', '/swagger/v1/swagger.json',
    '/api-docs', '/api-docs/', '/api/docs', '/api/swagger',
    '/openapi.json', '/openapi.yaml', '/openapi.yml',
    '/v1/api-docs', '/v2/api-docs', '/v3/api-docs',
    '/graphql', '/graphiql', '/__graphql', '/graphql/console',
    '/graphql/playground', '/graphql/voyager',
    '/rest', '/rest/', '/rest/v1', '/rest/v2',
    '/jsonapi', '/json-api', '/json/api',
    '/rpc', '/xmlrpc.php', '/xmlrpc', '/soap', '/wsdl',
    '/.well-known/openid-configuration',
    '/.well-known/oauth-authorization-server',
    '/oauth/token', '/oauth/authorize', '/oauth/callback',
    '/connect/token', '/connect/authorize',
    '/auth/token', '/auth/oauth', '/auth/callback',
    '/token', '/tokens', '/access_token',
    '/api/health', '/api/status', '/api/ping', '/api/version',
    '/api/metrics', '/api/info',

    # ── Dev / Debug ────────────────────────────────────────────────────
    '/debug', '/debug/', '/console', '/console/',
    '/shell', '/shell.php', '/cmd.php', '/exec.php',
    '/phpinfo.php', '/phpinfo', '/info.php', '/test.php',
    '/eval.php', '/php-eval.php',
    '/.git', '/.git/', '/.git/config', '/.git/HEAD',
    '/.git/COMMIT_EDITMSG', '/.git/index', '/.git/packed-refs',
    '/.git/refs/heads/master', '/.git/refs/heads/main',
    '/.git/logs/HEAD', '/.git/objects/',
    '/.svn', '/.svn/', '/.svn/entries', '/.svn/wc.db',
    '/.hg', '/.hg/', '/.hg/hgrc',
    '/.bzr', '/.bzr/', '/.bzr/branch/format',
    '/CVS', '/CVS/', '/CVS/Root', '/CVS/Entries',
    '/.DS_Store', '/Thumbs.db', '/desktop.ini',
    '/error_log', '/error.log', '/access.log', '/debug.log',
    '/logs/', '/log/', '/logs/error.log', '/logs/access.log',
    '/logs/debug.log', '/logs/app.log', '/logs/application.log',
    '/storage/logs/laravel.log', '/var/log/nginx/error.log',
    '/tmp/', '/temp/', '/cache/', '/cache/config.php',
    '/test', '/test/', '/tests/', '/testing/',
    '/dev', '/dev/', '/development/',
    '/staging', '/staging/', '/stage/',
    '/demo', '/demo/', '/sample/', '/example/',
    '/.well-known/security.txt', '/security.txt',
    '/humans.txt', '/robots.txt', '/sitemap.xml',
    '/crossdomain.xml', '/clientaccesspolicy.xml',
    '/server-status', '/server-info', '/nginx_status',
    '/status', '/health', '/healthz', '/health/live',
    '/health/ready', '/ping', '/metrics', '/actuator',
    '/actuator/health', '/actuator/info', '/actuator/env',
    '/actuator/beans', '/actuator/mappings', '/actuator/trace',
    '/actuator/dump', '/actuator/heapdump', '/actuator/threaddump',
    '/actuator/logfile', '/actuator/shutdown',
    '/jolokia', '/jolokia/', '/jolokia/list',
    '/trace', '/trace/', '/tracing/',
    '/monitoring', '/monitoring/', '/monitor/',
    '/stats', '/statistics/', '/analytics/',
    '/info', '/version', '/build', '/build-info',
    '/env', '/environment', '/config/env',
    '/spring', '/spring/', '/spring/env',

    # ── Cloud metadata ─────────────────────────────────────────────────
    # Note: these paths only work on actual cloud instances (169.254.x.x)
    # External domain scanning always returns 404 — SSRF scanner handles this

    # ── Source / exposed files ─────────────────────────────────────────
    '/index.php~', '/index.php.bak', '/index.php.old', '/index.php.orig',
    '/index.html~', '/index.html.bak',
    '/app.py', '/app.rb', '/app.js', '/server.js', '/main.py',
    '/manage.py', '/artisan', '/bin/console',
    '/web.php', '/routes.php', '/routes/web.php',
    '/.bash_history', '/.bash_profile', '/.bashrc', '/.profile',
    '/.zsh_history', '/.zshrc',
    '/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/hostname',
    '/proc/self/environ', '/proc/version', '/proc/cmdline',
    '/windows/win.ini', '/winnt/win.ini',
    '/boot.ini', '/autoexec.bat',

    # ── CMS specific ───────────────────────────────────────────────────
    '/wp-content/debug.log', '/wp-content/uploads/',
    '/wp-json/wp/v2/users', '/wp-json/wp/v2/posts',
    '/wp-includes/wlwmanifest.xml', '/xmlrpc.php',
    '/wp-cron.php', '/wp-mail.php', '/wp-trackback.php',
    '/readme.html', '/license.txt', '/wp-readme.html',
    '/joomla.xml', '/configuration.php-dist',
    '/administrator/manifests/files/joomla.xml',
    '/modules/mod_simplefileuploadv1.3/elements/rte_popup.php',
    '/sites/default/files/', '/sites/default/private/',
    '/CHANGELOG.txt', '/UPGRADE.txt', '/INSTALL.txt',
    '/magento/app/etc/local.xml', '/app/etc/local.xml',
    '/var/export/', '/var/import/', '/var/report/',
    '/downloader/', '/downloader/index.php',
    '/typo3conf/localconf.php', '/typo3conf/LocalConfiguration.php',
    '/fileadmin/', '/uploads/', '/upload/',

    # ── Misc sensitive ─────────────────────────────────────────────────
    '/server.key', '/server.crt', '/server.pem',
    '/private.key', '/private.pem', '/cert.pem', '/ca.pem',
    '/ssl/', '/ssl/server.key', '/ssl/private.key',
    '/id_rsa', '/id_dsa', '/id_ecdsa', '/id_ed25519',
    '/.pgpass', '/.my.cnf', '/.mysql_history',
    '/sftp-config.json', '/ftp.json', '/ftpconfig',
    '/WS_FTP.LOG', '/WS_FTP.ini',
    '/crossdomain.xml', '/clientaccesspolicy.xml',
    '/elmah.axd', '/trace.axd', '/webresource.axd',
    '/ScriptResource.axd', '/WebResource.axd',
    '/netsparker.txt', '/nessus.txt', '/burp.txt',
    '/test.txt', '/test.html', '/test.php',
    '/1.txt', '/1.php', '/1.html',
    '/old/', '/old/index.php', '/old/admin',
    '/new/', '/new/index.php',
    '/bak/', '/bak/index.php',
    '/archive/', '/archive/index.php',
    '/legacy/', '/legacy/index.php',
    '/v1/', '/v2/', '/v3/',
    '/api_key.txt', '/apikey.txt', '/api-key.txt',
    '/token.txt', '/tokens.txt', '/secret.txt', '/secrets.txt',
    '/password.txt', '/passwords.txt', '/passwd.txt',
    '/users.txt', '/usernames.txt', '/emails.txt',
    '/keys/', '/keys/private.key', '/keys/public.key',
    '/certs/', '/certificates/',
    '/.well-known/acme-challenge/',
    '/apple-app-site-association',
    '/.well-known/apple-app-site-association',
    '/assetlinks.json', '/.well-known/assetlinks.json',
]

WAF_SIGNATURES = {
    'Cloudflare':   ['cf-ray', '__cfduid', 'cloudflare', 'cf-cache-status'],
    'Google':       ['x-goog-', 'gws', 'x-google', 'google-edge-cache'],
    'AWS WAF':      ['x-amzn-requestid', 'x-amz-cf-id', 'x-amzn-trace-id'],
    'Akamai':       ['akamai', 'x-akamai-transformed', 'x-check-cacheable'],
    'Sucuri':       ['x-sucuri-id', 'sucuri', 'x-sucuri-cache'],
    'Imperva':      ['x-iinfo', 'incap_ses', 'visid_incap', 'x-cdn=imperva'],
    'F5 BIG-IP':    ['bigipserver', 'f5-', 'x-wa-info'],
    'ModSecurity':  ['mod_security', 'modsecurity', 'x-modsec'],
    'Fastly':       ['x-fastly', 'fastly-restarts', 'x-served-by'],
    'Varnish':      ['x-varnish', 'via: varnish'],
    'Azure':        ['x-azure-ref', 'x-msedge-ref'],
    'Nginx':        ['server: nginx'],
}

DANGEROUS_METHODS = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']


class EndpointScanner:

    # Wordlist priority order
    WORDLISTS = [
        '/usr/share/seclists/Discovery/Web-Content/common.txt',
        '/usr/share/seclists/Discovery/Web-Content/big.txt',
        '/usr/share/wordlists/dirb/common.txt',
        '/usr/share/wordlists/dirb/big.txt',
    ]

    # CMS/Framework specific paths
    TECH_PATHS = {
        'WordPress': [
            '/wp-login.php', '/wp-admin/', '/wp-config.php', '/wp-json/wp/v2/users',
            '/wp-json/wp/v2/posts', '/wp-content/debug.log', '/xmlrpc.php',
            '/wp-includes/wlwmanifest.xml', '/wp-cron.php', '/readme.html',
        ],
        'Laravel': [
            '/telescope', '/horizon', '/nova', '/.env', '/storage/logs/laravel.log',
            '/artisan', '/routes/web.php', '/config/app.php',
        ],
        'Django': [
            '/admin/', '/admin/login/', '/api/schema/', '/api/schema.json',
            '/__debug__/', '/static/admin/',
        ],
        'Rails': [
            '/rails/info', '/rails/mailers', '/rails/routes',
            '/sidekiq', '/resque', '/delayed_job',
        ],
        'Drupal': [
            '/user/login', '/admin/config', '/sites/default/settings.php',
            '/CHANGELOG.txt', '/sites/default/files/',
        ],
        'Joomla': [
            '/administrator/', '/administrator/index.php',
            '/configuration.php', '/joomla.xml',
        ],
        'Spring': [
            '/actuator', '/actuator/env', '/actuator/heapdump',
            '/actuator/mappings', '/actuator/beans', '/actuator/shutdown',
            '/jolokia', '/jolokia/list',
        ],
        'Node': [
            '/package.json', '/.env', '/node_modules/', '/server.js',
            '/app.js', '/config.js',
        ],
    }

    def __init__(self):
        self.session = tor_session(pool_size=30)
        self.session.headers.update(HEADERS)

    def _get_paths(self, tech: dict) -> list:
        """Smart path list: SENSITIVE_PATHS + wordlist + tech-specific."""
        paths = list(SENSITIVE_PATHS)

        # Get depth-based wordlist limit
        try:
            from modules.bugbounty.payload_loader import SCAN_DEPTH
        except Exception:
            SCAN_DEPTH = 'NORMAL'

        WORDLIST_LIMITS = {'FAST': 200, 'NORMAL': 1000, 'DEEP': 0}
        wl_limit = WORDLIST_LIMITS.get(SCAN_DEPTH, 1000)

        # Add wordlist paths
        for wl in self.WORDLISTS:
            try:
                from pathlib import Path as _P
                if _P(wl).exists():
                    lines = _P(wl).read_text(errors='ignore').splitlines()
                    count = 0
                    for line in lines:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        path = line if line.startswith('/') else '/' + line
                        if path not in paths:
                            paths.append(path)
                            count += 1
                            if wl_limit and count >= wl_limit:
                                break
                    logger.info(f'Wordlist loaded: {wl} ({count} paths, depth={SCAN_DEPTH})')
                    break
            except Exception:
                pass

        # Add technology-specific paths
        for tech_name, tech_paths in self.TECH_PATHS.items():
            if tech_name.lower() in str(tech).lower():
                for p in tech_paths:
                    if p not in paths:
                        paths.append(p)
                logger.info(f'Tech paths added: {tech_name} ({len(tech_paths)} paths)')

        return paths

    def run(self, domain: str) -> dict:
        base = f"https://{domain}" if not domain.startswith('http') else domain
        result = {
            'target':    domain,
            'base_url':  base,
            'exposed':   [],
            'waf':       self._detect_waf(base),
            'technologies': self._fingerprint(base),
            'dangerous_methods': self._test_http_methods(base),
            'timestamp': datetime.now().isoformat()
        }

        # Smart path list — wordlist + tech-specific
        paths = self._get_paths(result['technologies'])
        logger.info(f'EndpointScanner: {len(paths)} paths to check for {domain}')

        def check(path):
            try:
                url = base + path
                r = self.session.get(url, timeout=5, verify=False, allow_redirects=False)
                if r.status_code in (301, 302):
                    location = r.headers.get('Location', '')
                    if location and not location.startswith(f'https://{domain}'):
                        return {
                            'path': path, 'url': url, 'status_code': r.status_code,
                            'content_length': 0, 'risk': 'LOW',
                            'snippet': f'Redirects to: {location[:80]}'
                        }
                    return None
                if r.status_code in (200, 403, 500):
                    risk = self._classify_risk(path, r.status_code, r.text)
                    return {
                        'path':           path,
                        'url':            url,
                        'status_code':    r.status_code,
                        'content_length': len(r.content),
                        'risk':           risk,
                        'snippet':        r.text[:150].strip() if r.status_code == 200 else ''
                    }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=30) as ex:
            futures = {ex.submit(check, p): p for p in paths}
            for f in as_completed(futures):
                r = f.result()
                if r:
                    result['exposed'].append(r)

        result['exposed'].sort(key=lambda x: (
            0 if x['risk'] == 'CRITICAL' else
            1 if x['risk'] == 'HIGH' else 2
        ))
        result['total_exposed']  = len(result['exposed'])
        result['critical_count'] = sum(1 for e in result['exposed'] if e['risk'] == 'CRITICAL')
        result['high_count']     = sum(1 for e in result['exposed'] if e['risk'] == 'HIGH')
        return result

    def _classify_risk(self, path: str, status: int, body: str) -> str:
        if status == 500:
            return 'MEDIUM'
        if status == 403:
            return 'LOW'

        critical_keywords = [
            '.env', 'wp-config', 'config.php', 'database.yml', 'secrets',
            'credentials', '.git/config', 'backup.sql', 'dump.sql', 'backup.zip',
            'phpinfo', 'adminer', 'id_rsa', 'id_dsa', 'private.key', 'server.key',
            '.aws/credentials', '.ssh/', 'passwd', 'shadow', 'proc/self',
            'terraform.tfstate', 'tfvars', 'actuator/env', 'actuator/heapdump',
            'actuator/shutdown', 'jolokia', 'sftp-config', 'ftp.json',
            'api_key.txt', 'token.txt', 'password.txt', 'secret.txt',
        ]
        high_keywords = [
            'admin', 'phpmyadmin', 'swagger', 'graphql', 'api-docs', 'openapi',
            'debug', 'console', 'shell', 'actuator', 'server-status', 'server-info',
            'nginx_status', 'wp-json/wp/v2/users', 'xmlrpc', 'elmah', 'trace.axd',
            'meta-data', 'computeMetadata', 'metadata/instance',
        ]

        path_lower = path.lower()
        if any(c in path_lower for c in critical_keywords):
            return 'CRITICAL'
        if any(h in path_lower for h in high_keywords):
            return 'HIGH'
        return 'MEDIUM'

    def _test_http_methods(self, base_url: str) -> dict:
        """Test for dangerous HTTP methods enabled on the server."""
        result = {'allowed': [], 'risk': 'LOW'}
        try:
            # OPTIONS request to discover allowed methods
            r = requests.options(base_url, timeout=8, verify=False,
                                 headers=HEADERS)
            allow_header = r.headers.get('Allow', '') + r.headers.get('Public', '')
            for method in DANGEROUS_METHODS:
                if method in allow_header.upper():
                    result['allowed'].append(method)

            # Also try TRACE directly
            r_trace = requests.request('TRACE', base_url, timeout=5,
                                       verify=False, headers=HEADERS)
            if r_trace.status_code == 200 and 'TRACE' not in result['allowed']:
                result['allowed'].append('TRACE')

        except Exception:
            pass

        if 'TRACE' in result['allowed'] or 'DELETE' in result['allowed']:
            result['risk'] = 'HIGH'
        elif result['allowed']:
            result['risk'] = 'MEDIUM'
        return result

    def _detect_waf(self, base_url: str) -> dict:
        waf_info = {'detected': False, 'name': None, 'evidence': []}
        try:
            r_normal = self.session.get(base_url, timeout=8, verify=False, allow_redirects=True)
            headers_str = str(dict(r_normal.headers)).lower()
            body_str    = r_normal.text[:2000].lower()

            for waf_name, sigs in WAF_SIGNATURES.items():
                for sig in sigs:
                    if sig.lower() in headers_str or sig.lower() in body_str:
                        waf_info['detected'] = True
                        waf_info['name']     = waf_name
                        waf_info['evidence'].append(sig)

            server = r_normal.headers.get('Server', '').lower()
            if 'gws' in server:
                waf_info['detected'] = True
                waf_info['name']     = 'Google (GWS)'
                waf_info['evidence'].append(f'Server: {server}')

            if not waf_info['detected']:
                r_attack = self.session.get(
                    f"{base_url}/?id=1'%20OR%20'1'='1",
                    timeout=8, verify=False, allow_redirects=False
                )
                headers_str2 = str(dict(r_attack.headers)).lower()
                for waf_name, sigs in WAF_SIGNATURES.items():
                    for sig in sigs:
                        if sig.lower() in headers_str2:
                            waf_info['detected'] = True
                            waf_info['name']     = waf_name
                            waf_info['evidence'].append(sig)
                            break
                if r_attack.status_code == 403 and not waf_info['detected']:
                    waf_info['detected'] = True
                    waf_info['name']     = 'Unknown WAF'
                    waf_info['evidence'] = ['403 on suspicious request']
        except Exception as e:
            logger.debug(f"WAF detection failed: {e}")
        return waf_info

    def _fingerprint(self, base_url: str) -> dict:
        tech = {}
        try:
            r = self.session.get(base_url, timeout=8, verify=False)
            h = r.headers
            body = r.text

            if h.get('X-Powered-By'):
                tech['backend'] = h['X-Powered-By']
            if h.get('Server'):
                tech['server'] = h['Server']
            if h.get('X-Generator'):
                tech['generator'] = h['X-Generator']
            if h.get('X-Drupal-Cache') or 'Drupal.settings' in body:
                tech['cms'] = 'Drupal'
            elif 'wp-content' in body or 'wp-includes' in body:
                tech['cms'] = 'WordPress'
            elif 'Joomla' in body or '/media/jui/' in body:
                tech['cms'] = 'Joomla'
            elif 'Magento' in body or 'mage/' in body:
                tech['cms'] = 'Magento'
            if 'laravel_session' in str(r.cookies) or 'laravel' in body.lower():
                tech['framework'] = 'Laravel'
            elif 'csrftoken' in str(r.cookies) or 'django' in str(h).lower():
                tech['framework'] = 'Django'
            elif '__rails' in str(r.cookies) or 'X-Runtime' in h:
                tech['framework'] = 'Rails'
            elif 'X-AspNet-Version' in h:
                tech['framework'] = f"ASP.NET {h.get('X-AspNet-Version','')}"
            if 'react' in body.lower() or '__REACT' in body:
                tech['frontend'] = 'React'
            elif 'ng-version' in body or 'angular' in body.lower():
                tech['frontend'] = 'Angular'
            elif '__vue' in body or 'vue.js' in body.lower():
                tech['frontend'] = 'Vue.js'
        except Exception:
            pass
        return tech
