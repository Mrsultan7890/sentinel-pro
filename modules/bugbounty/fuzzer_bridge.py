"""
Rust Parallel Fuzzer Bridge
Sends path/param fuzzing job to the Rust binary (rayon-powered).
"""

import json
import subprocess
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

import config as _config
BASE_DIR   = _config.get_base_dir()
FUZZER_BIN = BASE_DIR / 'fuzzer' / 'target' / 'release' / 'fuzzer'

# Default wordlist — common sensitive paths
DEFAULT_WORDLIST = [
    # Config / secrets
    ".env", ".env.local", ".env.production", ".env.backup",
    "config.php", "wp-config.php", "configuration.php", "config.yml",
    "database.yml", "secrets.yml", "application.properties", "appsettings.json",
    "web.config", ".htpasswd", ".htaccess",
    # Backup / dumps
    "backup.sql", "dump.sql", "db.sql", "backup.zip", "backup.tar.gz",
    "site.zip", "www.zip", "html.zip",
    # Git / VCS
    ".git/config", ".git/HEAD", ".svn/entries", ".hg/hgrc",
    # Keys / certs
    "id_rsa", "id_rsa.pub", "private.key", "server.key", "server.pem",
    ".aws/credentials", ".ssh/id_rsa",
    # Admin panels
    "admin", "admin/", "administrator", "wp-admin", "wp-admin/",
    "phpmyadmin", "adminer.php", "adminer", "cpanel", "webmail",
    "manager", "console", "dashboard", "panel",
    # API / debug
    "api", "api/v1", "api/v2", "graphql", "swagger", "swagger-ui",
    "swagger.json", "openapi.json", "api-docs",
    "actuator", "actuator/health", "actuator/env", "actuator/mappings",
    "metrics", "health", "debug", "trace", "status",
    # PHP info
    "phpinfo.php", "info.php", "test.php", "php.php",
    # Logs
    "logs", "log", "error.log", "access.log", "debug.log",
    # Common dirs
    "tmp", "temp", "cache", "old", "bak", "backup",
    "upload", "uploads", "files", "static", "assets",
    # Robots / sitemap
    "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    # Server status
    "server-status", "server-info", "nginx_status",
]


class RustFuzzerBridge:

    def run(self, domain: str, mode: str = 'path',
            wordlist: list = None, params: list = None,
            payloads: list = None) -> dict:

        result = {
            'domain': domain,
            'mode': mode,
            'total_requests': 0,
            'total_findings': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'risk_level': 'LOW',
            'findings': [],
            'error': None,
        }

        if not FUZZER_BIN.exists():
            result['error'] = f"Fuzzer binary not found: {FUZZER_BIN} — run setup.sh"
            logger.warning(result['error'])
            return result

        payload = {
            'target':   domain,
            'mode':     mode,
            'wordlist': wordlist or DEFAULT_WORDLIST,
            'threads':  40,
            'timeout_ms': 8000,
        }
        if params:
            payload['params'] = params
        if payloads:
            payload['payloads'] = payloads

        try:
            proc = subprocess.run(
                [str(FUZZER_BIN)],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode != 0:
                result['error'] = f"Fuzzer exited {proc.returncode}: {proc.stderr[:200]}"
                logger.warning(result['error'])
                return result

            out = json.loads(proc.stdout)
            result.update({
                'total_requests': out.get('total_requests', 0),
                'total_findings': out.get('total_findings', 0),
                'critical':       out.get('critical', 0),
                'high':           out.get('high', 0),
                'medium':         out.get('medium', 0),
                'risk_level':     out.get('risk_level', 'LOW'),
                'findings':       out.get('findings', []),
            })

        except subprocess.TimeoutExpired:
            result['error'] = 'Fuzzer timed out after 120s'
            logger.warning(result['error'])
        except json.JSONDecodeError as e:
            result['error'] = f"Invalid JSON from fuzzer: {e}"
            logger.warning(result['error'])
        except Exception as e:
            result['error'] = str(e)
            logger.warning(f"RustFuzzerBridge error: {e}")

        return result
