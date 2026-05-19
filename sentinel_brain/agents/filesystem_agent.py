"""
File System Agent — Evidence & File Management
===============================================
- Evidence automatically collect & organize karo
- Sensitive files dhundo
- File integrity monitor karo
- Reports organize karo
- Scan outputs save karo

Author: @who_is_the_black_hat
"""

import hashlib
import json
import logging
import os
import re
import shutil
import time
from datetime import datetime
from pathlib import Path

import config

logger = logging.getLogger(__name__)

EVIDENCE_DIR = config.EVIDENCE_DIR
REPORTS_DIR  = config.REPORTS_DIR


class FileSystemAgent:
    NAME = 'filesystem_agent'

    def __init__(self):
        self._integrity_db = {}   # path → hash
        self._watch_paths  = []

    # ── Evidence Collection ───────────────────────────────────────────────────

    def collect_evidence(self, target: str, scan_results: dict) -> dict:
        """Scan results se evidence collect karke organize karo."""
        ts       = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe     = re.sub(r'[^a-zA-Z0-9_.-]', '_', target)
        ev_dir   = EVIDENCE_DIR / f"{safe}_{ts}"
        ev_dir.mkdir(parents=True, exist_ok=True)

        collected = []

        # JSON save karo
        json_path = ev_dir / 'scan_results.json'
        json_path.write_text(
            json.dumps(scan_results, indent=2, default=str),
            encoding='utf-8'
        )
        collected.append(str(json_path))

        # Screenshots copy karo
        screenshots = self._find_screenshots(target)
        for ss in screenshots:
            dst = ev_dir / Path(ss).name
            try:
                shutil.copy2(ss, dst)
                collected.append(str(dst))
            except Exception as e:
                logger.debug(f"[FileSystemAgent] Screenshot copy failed for {ss}: {e}")

        # Reports copy karo
        reports = self._find_reports(target)
        for rpt in reports:
            dst = ev_dir / Path(rpt).name
            try:
                shutil.copy2(rpt, dst)
                collected.append(str(dst))
            except Exception as e:
                logger.debug(f"[FileSystemAgent] Report copy failed for {rpt}: {e}")

        # Hash manifest banao
        manifest = self._create_manifest(ev_dir, collected)
        manifest_path = ev_dir / 'manifest.json'
        manifest_path.write_text(json.dumps(manifest, indent=2))

        logger.info(f"[FileSystemAgent] Evidence collected: {ev_dir} ({len(collected)} files)")
        return {
            'directory':  str(ev_dir),
            'files':      collected,
            'manifest':   str(manifest_path),
            'total':      len(collected),
        }

    def _find_screenshots(self, target: str) -> list:
        safe = target.replace('.', '.').replace('/', '_')
        return [
            str(p) for p in config.BASE_DIR.glob(f'screenshots/{safe}*')
            if p.is_file()
        ]

    def _find_reports(self, target: str) -> list:
        safe = re.sub(r'[^a-zA-Z0-9]', '_', target)
        return [
            str(p) for p in REPORTS_DIR.glob(f'*{safe}*')
            if p.is_file() and p.suffix in ('.json', '.html', '.pdf', '.txt')
        ]

    def _create_manifest(self, directory: Path, files: list) -> dict:
        manifest = {
            'created':   datetime.now().isoformat(),
            'directory': str(directory),
            'files':     [],
            'tool':      'The Sentinel Pro v3.0',
            'standards': ['ISO 27037', 'NIST SP 800-86'],
        }
        for f in files:
            p = Path(f)
            if p.exists():
                manifest['files'].append({
                    'name':    p.name,
                    'size':    p.stat().st_size,
                    'sha256':  self._hash_file(p),
                    'created': datetime.fromtimestamp(p.stat().st_ctime).isoformat(),
                })
        return manifest

    def _hash_file(self, path: Path) -> str:
        try:
            h = hashlib.sha256()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ''

    # ── Sensitive File Search ─────────────────────────────────────────────────

    def find_sensitive_files(self, directory: str = '/home') -> list:
        """Sensitive files dhundo — credentials, keys, configs."""
        PATTERNS = [
            '*.pem', '*.key', '*.p12', '*.pfx',
            '*.env', '.env*', '*.conf', '*.config',
            'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
            '*.sql', '*.db', '*.sqlite',
            'credentials*', 'secret*', 'password*', 'passwd*',
            '*.bak', '*.backup', '*.old',
            'wp-config.php', 'config.php', 'settings.py',
            '.htpasswd', '.htaccess',
        ]
        found = []
        for pattern in PATTERNS:
            try:
                r = os.popen(
                    f'find {directory} -name "{pattern}" -not -path "*/\\.git/*" '
                    f'-not -path "*/node_modules/*" 2>/dev/null | head -5'
                ).read()
                for line in r.splitlines():
                    line = line.strip()
                    if line and Path(line).exists():
                        found.append({
                            'path':    line,
                            'pattern': pattern,
                            'size':    Path(line).stat().st_size,
                        })
            except Exception as e:
                logger.debug(f"[FileSystemAgent] Sensitive file search failed for {pattern}: {e}")
        return found[:50]

    def search_credentials_in_files(self, directory: str = '/home/kali/osints') -> list:
        """Files mein hardcoded credentials dhundo."""
        PATTERNS = [
            r'password\s*=\s*["\']([^"\']{4,})["\']',
            r'api_key\s*=\s*["\']([^"\']{8,})["\']',
            r'secret\s*=\s*["\']([^"\']{8,})["\']',
            r'token\s*=\s*["\']([^"\']{8,})["\']',
            r'AWS_SECRET_ACCESS_KEY\s*=\s*([^\s]+)',
        ]
        findings = []
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in
                       ('.git', '__pycache__', 'node_modules', 'venv', '.venv')]
            for fname in files:
                if not fname.endswith(('.py', '.js', '.env', '.conf', '.yml', '.yaml')):
                    continue
                fpath = Path(root) / fname
                try:
                    content = fpath.read_text(errors='ignore')
                    for pattern in PATTERNS:
                        for m in re.finditer(pattern, content, re.I):
                            findings.append({
                                'file':    str(fpath),
                                'pattern': pattern[:30],
                                'match':   m.group(0)[:80],
                                'line':    content[:m.start()].count('\n') + 1,
                            })
                except Exception as e:
                    logger.debug(f"[FileSystemAgent] Credential search failed in {fpath}: {e}")
        return findings[:20]

    # ── File Integrity ────────────────────────────────────────────────────────

    def baseline(self, paths: list) -> dict:
        """Files ka baseline hash banao."""
        baseline = {}
        for path in paths:
            p = Path(path)
            if p.is_file():
                baseline[str(p)] = {
                    'hash':     self._hash_file(p),
                    'size':     p.stat().st_size,
                    'modified': p.stat().st_mtime,
                }
            elif p.is_dir():
                for f in p.rglob('*'):
                    if f.is_file():
                        baseline[str(f)] = {
                            'hash':     self._hash_file(f),
                            'size':     f.stat().st_size,
                            'modified': f.stat().st_mtime,
                        }
        self._integrity_db.update(baseline)
        logger.info(f"[FileSystemAgent] Baseline: {len(baseline)} files")
        return baseline

    def check_integrity(self) -> list:
        """Baseline se compare karo — changed files dhundo."""
        changes = []
        for path, info in self._integrity_db.items():
            p = Path(path)
            if not p.exists():
                changes.append({'path': path, 'change': 'DELETED'})
                continue
            current_hash = self._hash_file(p)
            if current_hash != info['hash']:
                changes.append({
                    'path':     path,
                    'change':   'MODIFIED',
                    'old_hash': info['hash'][:16],
                    'new_hash': current_hash[:16],
                })
        return changes

    # ── Reports Organization ──────────────────────────────────────────────────

    def organize_reports(self, target: str = None) -> dict:
        """Reports ko target ke hisaab se organize karo."""
        organized = {}
        pattern = f'*{re.sub(r"[^a-zA-Z0-9]", "_", target)}*' if target else '*'

        for f in REPORTS_DIR.glob(pattern):
            if not f.is_file():
                continue
            # Type detect karo
            name = f.name
            if 'bugbounty' in name:
                rtype = 'bugbounty'
            elif 'recon' in name:
                rtype = 'recon'
            elif 'breach' in name:
                rtype = 'breach'
            elif 'brain' in name:
                rtype = 'brain'
            else:
                rtype = 'other'

            organized.setdefault(rtype, []).append({
                'name':    name,
                'path':    str(f),
                'size':    f.stat().st_size,
                'created': datetime.fromtimestamp(f.stat().st_ctime).strftime('%Y-%m-%d %H:%M'),
            })

        total = sum(len(v) for v in organized.values())
        logger.info(f"[FileSystemAgent] Reports organized: {total} files")
        return organized

    def cleanup_old_reports(self, days: int = 30) -> int:
        """Purane reports delete karo."""
        cutoff  = time.time() - (days * 86400)
        deleted = 0
        for f in REPORTS_DIR.glob('*'):
            if f.is_file() and f.stat().st_mtime < cutoff:
                try:
                    f.unlink()
                    deleted += 1
                except Exception as e:
                    logger.debug(f"[FileSystemAgent] Cleanup failed for {f}: {e}")
        logger.info(f"[FileSystemAgent] Cleaned {deleted} old reports (>{days} days)")
        return deleted

    def disk_usage_report(self) -> dict:
        """Project directories ka disk usage."""
        dirs = {
            'reports':      REPORTS_DIR,
            'evidence':     EVIDENCE_DIR,
            'screenshots':  config.BASE_DIR / 'screenshots',
            'models':       config.MODELS_DIR,
            'logs':         config.LOGS_DIR,
            'data':         config.BASE_DIR / 'data',
        }
        usage = {}
        for name, path in dirs.items():
            if path.exists():
                total = sum(
                    f.stat().st_size for f in path.rglob('*') if f.is_file()
                )
                usage[name] = {
                    'path':   str(path),
                    'size_mb': round(total / 1e6, 1),
                    'files':  sum(1 for f in path.rglob('*') if f.is_file()),
                }
        return usage
