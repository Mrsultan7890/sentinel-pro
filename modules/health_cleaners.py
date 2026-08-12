"""
Sentinel Health Cleaners v1.0
All cleanup/optimization functions used by the health daemon.
Author: @who_is_the_black_hat
"""

import json
import logging
import os
import shutil
import signal
import sqlite3
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import config

# File-only logger — no terminal output
logger = logging.getLogger('sentinel.health.cleaners')
logger.propagate = False
if not logger.handlers:
    _h = logging.FileHandler(config.LOG_FILE, encoding='utf-8')
    _h.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(_h)
    logger.setLevel(logging.INFO)

BASE_DIR    = config.BASE_DIR
REPORTS_DIR = config.REPORTS_DIR
LOGS_DIR    = config.LOGS_DIR
MODELS_DIR  = config.MODELS_DIR
DATA_DIR    = BASE_DIR / 'data'
TMP_SOCKET  = Path('/tmp/sentinel_proxy_v2.sock')

DB_FILES = [
    DATA_DIR / 'sentinel.db',
    DATA_DIR / 'sentinel_memory.db',
    DATA_DIR / 'sentinel_proxy.db',
    DATA_DIR / 'behavioral_data.db',
    DATA_DIR / 'behavioral_feedback.db',
    DATA_DIR / 'cve_monitor.db',
    DATA_DIR / 'incidents.db',
    DATA_DIR / 'sandbox_forensics.db',
    DATA_DIR / 'threat_trends.db',
]

RL_QTABLE   = MODELS_DIR / 'ml_engine' / 'rl_qtable.json'
RL_BACKUP   = MODELS_DIR / 'ml_engine' / 'rl_qtable.backup.json'


# ── Result container ──────────────────────────────────────────────────────────

class CleanResult:
    def __init__(self, name: str):
        self.name      = name
        self.freed_mb  = 0.0
        self.fixed     = 0
        self.errors    = []
        self.details   = []

    def add(self, detail: str):
        self.details.append(detail)

    def err(self, e: str):
        self.errors.append(e)

    def summary(self) -> str:
        parts = [f"[{self.name}]"]
        if self.freed_mb > 0:
            parts.append(f"freed {self.freed_mb:.1f}MB")
        if self.fixed > 0:
            parts.append(f"fixed {self.fixed} issues")
        if self.errors:
            parts.append(f"{len(self.errors)} errors")
        return ' — '.join(parts) if len(parts) > 1 else parts[0] + ' — nothing to do'


def _size_mb(path: Path) -> float:
    try:
        if path.is_file():
            return path.stat().st_size / 1024 / 1024
        if path.is_dir():
            return sum(f.stat().st_size for f in path.rglob('*') if f.is_file()) / 1024 / 1024
    except Exception:
        pass
    return 0.0


# ── 1. Cache Cleaner ──────────────────────────────────────────────────────────

def clean_cache() -> CleanResult:
    """Remove stale __pycache__, .pyc files, and .so vs .py conflicts."""
    r = CleanResult('cache')

    # __pycache__ dirs
    for cache_dir in BASE_DIR.rglob('__pycache__'):
        try:
            mb = _size_mb(cache_dir)
            shutil.rmtree(cache_dir)
            r.freed_mb += mb
            r.fixed += 1
            r.add(f"removed {cache_dir.relative_to(BASE_DIR)}")
        except Exception as e:
            r.err(str(e))

    # Stale .pyc / .pyo
    for pyc in BASE_DIR.rglob('*.pyc'):
        try:
            mb = _size_mb(pyc)
            pyc.unlink()
            r.freed_mb += mb
            r.fixed += 1
        except Exception as e:
            r.err(str(e))

    for pyo in BASE_DIR.rglob('*.pyo'):
        try:
            mb = _size_mb(pyo)
            pyo.unlink()
            r.freed_mb += mb
            r.fixed += 1
        except Exception as e:
            r.err(str(e))

    # .so vs .py conflicts — .so overrides .py silently
    for so_file in BASE_DIR.rglob('*.so'):
        py_file = so_file.parent / (so_file.name.split('.')[0] + '.py')
        if py_file.exists():
            try:
                mb = _size_mb(so_file)
                so_file.unlink()
                r.freed_mb += mb
                r.fixed += 1
                r.add(f"removed conflicting .so: {so_file.relative_to(BASE_DIR)}")
            except Exception as e:
                r.err(str(e))

    logger.info(r.summary())
    return r


# ── 2. Reports Rotator ────────────────────────────────────────────────────────

def rotate_reports(max_age_days: int = 30, max_size_mb: int = 500) -> CleanResult:
    """Delete reports older than max_age_days or when folder exceeds max_size_mb."""
    r      = CleanResult('reports')
    cutoff = datetime.now() - timedelta(days=max_age_days)

    if not REPORTS_DIR.exists():
        return r

    # Age-based rotation
    for f in REPORTS_DIR.iterdir():
        if not f.is_file():
            continue
        try:
            mtime = datetime.fromtimestamp(f.stat().st_mtime)
            if mtime < cutoff:
                mb = _size_mb(f)
                f.unlink()
                r.freed_mb += mb
                r.fixed += 1
        except Exception as e:
            r.err(str(e))

    # Size-based rotation — delete oldest first if still over limit
    total_mb = _size_mb(REPORTS_DIR)
    if total_mb > max_size_mb:
        files = sorted(
            [f for f in REPORTS_DIR.iterdir() if f.is_file()],
            key=lambda f: f.stat().st_mtime
        )
        for f in files:
            if _size_mb(REPORTS_DIR) <= max_size_mb * 0.8:
                break
            try:
                mb = _size_mb(f)
                f.unlink()
                r.freed_mb += mb
                r.fixed += 1
            except Exception as e:
                r.err(str(e))

    logger.info(r.summary())
    return r


# ── 3. Log Rotator ────────────────────────────────────────────────────────────

def rotate_logs(max_age_days: int = 7) -> CleanResult:
    """Delete log files older than max_age_days."""
    r      = CleanResult('logs')
    cutoff = datetime.now() - timedelta(days=max_age_days)

    if not LOGS_DIR.exists():
        return r

    for f in LOGS_DIR.rglob('*.log'):
        try:
            mtime = datetime.fromtimestamp(f.stat().st_mtime)
            if mtime < cutoff:
                mb = _size_mb(f)
                f.unlink()
                r.freed_mb += mb
                r.fixed += 1
        except Exception as e:
            r.err(str(e))

    # Truncate active log files over 50MB
    for f in LOGS_DIR.rglob('*.log'):
        try:
            if _size_mb(f) > 50:
                with open(f, 'w') as fh:
                    fh.write(f"[truncated by health daemon at {datetime.now()}]\n")
                r.fixed += 1
                r.add(f"truncated large log: {f.name}")
        except Exception as e:
            r.err(str(e))

    logger.info(r.summary())
    return r


# ── 4. Database Optimizer ─────────────────────────────────────────────────────

def optimize_databases(max_db_mb: int = 200) -> CleanResult:
    """VACUUM all SQLite DBs, remove orphaned findings, rotate old RL episodes."""
    r = CleanResult('database')

    for db_path in DB_FILES:
        if not db_path.exists():
            continue
        try:
            size_before = _size_mb(db_path)
            conn = sqlite3.connect(str(db_path), timeout=10)

            # Integrity check first
            result = conn.execute('PRAGMA integrity_check').fetchone()
            if result and result[0] != 'ok':
                r.err(f"{db_path.name}: integrity check failed — {result[0]}")
                conn.close()
                continue

            # Clean old RL episodes (keep last 1000)
            if db_path.name == 'sentinel.db':
                try:
                    count = conn.execute('SELECT COUNT(*) FROM rl_episodes').fetchone()[0]
                    if count > 1000:
                        conn.execute(
                            'DELETE FROM rl_episodes WHERE id NOT IN '
                            '(SELECT id FROM rl_episodes ORDER BY id DESC LIMIT 1000)'
                        )
                        r.add(f"pruned {count - 1000} old RL episodes")
                        r.fixed += 1
                except Exception:
                    pass

                # Remove duplicate findings (same target + vuln_type + severity)
                try:
                    conn.execute('''
                        DELETE FROM findings WHERE id NOT IN (
                            SELECT MIN(id) FROM findings
                            GROUP BY target, vuln_type, severity
                        )
                    ''')
                    r.fixed += conn.execute('SELECT changes()').fetchone()[0]
                except Exception:
                    pass

            # VACUUM
            conn.execute('VACUUM')
            conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            conn.close()

            size_after = _size_mb(db_path)
            freed = size_before - size_after
            if freed > 0:
                r.freed_mb += freed
                r.add(f"{db_path.name}: {freed:.1f}MB freed")

        except Exception as e:
            r.err(f"{db_path.name}: {e}")

    logger.info(r.summary())
    return r


# ── 5. Process Cleaner ────────────────────────────────────────────────────────

def clean_processes() -> CleanResult:
    """Clean stale sockets, zombie processes, and stuck ports."""
    r = CleanResult('processes')

    # Stale proxy socket
    if TMP_SOCKET.exists():
        try:
            TMP_SOCKET.unlink()
            r.fixed += 1
            r.add("removed stale proxy socket")
        except Exception as e:
            r.err(str(e))

    # Stale .sock.events file
    sock_events = Path(str(TMP_SOCKET) + '.events')
    if sock_events.exists():
        try:
            sock_events.unlink()
            r.fixed += 1
        except Exception:
            pass

    # Zombie sentinel child processes
    try:
        result = subprocess.run(
            ['pgrep', '-f', 'sentinel'],
            capture_output=True, text=True, timeout=5
        )
        pids = [int(p) for p in result.stdout.strip().split() if p.isdigit()]
        current_pid = os.getpid()
        for pid in pids:
            if pid == current_pid:
                continue
            try:
                # Check if zombie
                with open(f'/proc/{pid}/status') as f:
                    status = f.read()
                if 'zombie' in status.lower() or 'Z' in status:
                    os.kill(pid, signal.SIGKILL)
                    r.fixed += 1
                    r.add(f"killed zombie process {pid}")
            except Exception:
                pass
    except Exception as e:
        r.err(str(e))

    # Clean /tmp/sentinel_* temp files older than 1 hour
    try:
        cutoff = time.time() - 3600
        for f in Path('/tmp').glob('sentinel_*'):
            try:
                if f.stat().st_mtime < cutoff and f != TMP_SOCKET:
                    mb = _size_mb(f)
                    if f.is_file():
                        f.unlink()
                    elif f.is_dir():
                        shutil.rmtree(f)
                    r.freed_mb += mb
                    r.fixed += 1
            except Exception:
                pass
    except Exception as e:
        r.err(str(e))

    logger.info(r.summary())
    return r


# ── 6. Model Guardian ─────────────────────────────────────────────────────────

def guard_models() -> CleanResult:
    """Backup RL qtable, check for corruption, clean old checkpoints."""
    r = CleanResult('models')

    # Backup RL qtable
    if RL_QTABLE.exists():
        try:
            # Validate JSON first
            with open(RL_QTABLE) as f:
                data = json.load(f)
            # Valid — backup
            shutil.copy2(RL_QTABLE, RL_BACKUP)
            r.add("rl_qtable backed up")
        except json.JSONDecodeError:
            # Corrupted — restore from backup
            if RL_BACKUP.exists():
                shutil.copy2(RL_BACKUP, RL_QTABLE)
                r.fixed += 1
                r.add("rl_qtable restored from backup (was corrupted)")
            else:
                r.err("rl_qtable corrupted and no backup available")

    # Clean old model checkpoints
    checkpoints_dir = MODELS_DIR / 'ml_engine' / 'checkpoints'
    if checkpoints_dir.exists():
        checkpoints = sorted(checkpoints_dir.glob('*.pt'), key=lambda f: f.stat().st_mtime)
        # Keep last 3 checkpoints
        for old in checkpoints[:-3]:
            try:
                mb = _size_mb(old)
                old.unlink()
                r.freed_mb += mb
                r.fixed += 1
                r.add(f"removed old checkpoint: {old.name}")
            except Exception as e:
                r.err(str(e))

    logger.info(r.summary())
    return r


# ── 7. Stale Registry Cleaner ────────────────────────────────────────────────────────────────────

def clean_stale_registry() -> CleanResult:
    """Remove file_registry.json entries whose files no longer exist on disk."""
    r = CleanResult('registry')
    registry_path = DATA_DIR / 'file_registry.json'

    if not registry_path.exists():
        return r

    try:
        with open(registry_path) as f:
            registry = json.load(f)
    except Exception as e:
        r.err(f"Failed to load registry: {e}")
        return r

    files = registry.get('files', {})
    stale_ids = [
        fid for fid, info in files.items()
        if not Path(info.get('path', '')).exists()
    ]

    if not stale_ids:
        r.add("registry clean — no stale entries")
        logger.info(r.summary())
        return r

    for fid in stale_ids:
        path = files[fid].get('path', 'unknown')
        del files[fid]
        r.fixed += 1
        r.add(f"removed stale: {Path(path).name}")

    registry['files'] = files

    try:
        with open(registry_path, 'w') as f:
            json.dump(registry, f, indent=2)
        logger.info(f"Registry cleaned — {len(stale_ids)} stale entries removed")
    except Exception as e:
        r.err(f"Failed to save registry: {e}")

    logger.info(r.summary())
    return r


# ── Full Run ────────────────────────────────────────────────────────────────────

def run_all(cfg: dict) -> dict:
    """Run all cleaners based on config. Returns summary dict."""
    results = {}

    results['cache']     = clean_cache()
    results['processes'] = clean_processes()
    results['models']    = guard_models()
    results['registry']  = clean_stale_registry()
    results['reports']   = rotate_reports(
        max_age_days = cfg.get('reports_max_age_days', 30),
        max_size_mb  = cfg.get('max_reports_size_mb', 500)
    )
    results['logs']      =  rotate_logs(
        max_age_days = cfg.get('logs_max_age_days', 7)
    )
    results['database']  = optimize_databases(
        max_db_mb = cfg.get('max_db_size_mb', 200)
    )

    total_freed = sum(r.freed_mb for r in results.values())
    total_fixed = sum(r.fixed for r in results.values())
    total_errors = sum(len(r.errors) for r in results.values())

    return {
        'timestamp':   datetime.now().isoformat(),
        'total_freed_mb': round(total_freed, 2),
        'total_fixed':    total_fixed,
        'total_errors':   total_errors,
        'details':        {k: {'freed_mb': round(v.freed_mb, 2), 'fixed': v.fixed, 'errors': v.errors, 'details': v.details} for k, v in results.items()},
    }
