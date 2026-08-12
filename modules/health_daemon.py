"""
Sentinel Health Daemon v1.0
Background daemon that keeps the tool clean and optimized.
Author: @who_is_the_black_hat
"""

import json
import logging
import threading
import time
from datetime import datetime
from pathlib import Path

import config
from modules.health_cleaners import run_all

# Dedicated file-only logger — never writes to terminal
logger = logging.getLogger('sentinel.health')
logger.propagate = False  # Don't bubble up to root logger (which has StreamHandler)
if not logger.handlers:
    _h = logging.FileHandler(config.LOG_FILE, encoding='utf-8')
    _h.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(_h)
    logger.setLevel(logging.INFO)

CONFIG_PATH = Path.home() / '.sentinel_pro' / 'health.json'
LOG_PATH    = Path.home() / '.sentinel_pro' / 'health_log.json'

DEFAULT_CONFIG = {
    'enabled':               True,
    'reports_max_age_days':  30,
    'logs_max_age_days':     7,
    'max_reports_size_mb':   500,
    'max_db_size_mb':        200,
    'auto_fix_so_conflicts': True,
    'cache_interval_hours':  6,
    'db_interval_hours':     24,
    'process_interval_hours': 1,
}

MAX_LOG_ENTRIES = 50


# ── Config Manager ────────────────────────────────────────────────────────────

class HealthConfig:

    def __init__(self):
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        self._cfg = self._load()

    def _load(self) -> dict:
        if CONFIG_PATH.exists():
            try:
                with open(CONFIG_PATH) as f:
                    data = json.load(f)
                # Merge with defaults for any missing keys
                merged = dict(DEFAULT_CONFIG)
                merged.update(data)
                return merged
            except Exception:
                pass
        return dict(DEFAULT_CONFIG)

    def save(self):
        with open(CONFIG_PATH, 'w') as f:
            json.dump(self._cfg, f, indent=2)

    def get(self, key: str, default=None):
        return self._cfg.get(key, default)

    def set(self, key: str, value):
        if key not in DEFAULT_CONFIG:
            raise KeyError(f"Unknown setting: {key}")
        # Type coerce
        expected = type(DEFAULT_CONFIG[key])
        self._cfg[key] = expected(value)
        self.save()

    def all(self) -> dict:
        return dict(self._cfg)

    def reset(self):
        self._cfg = dict(DEFAULT_CONFIG)
        self.save()


# ── Log Manager ───────────────────────────────────────────────────────────────

class HealthLog:

    def __init__(self):
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        self._entries = self._load()

    def _load(self) -> list:
        if LOG_PATH.exists():
            try:
                with open(LOG_PATH) as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def append(self, result: dict):
        self._entries.append(result)
        # Keep only last MAX_LOG_ENTRIES
        if len(self._entries) > MAX_LOG_ENTRIES:
            self._entries = self._entries[-MAX_LOG_ENTRIES:]
        try:
            with open(LOG_PATH, 'w') as f:
                json.dump(self._entries, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Health log write failed: {e}")

    def last(self, n: int = 5) -> list:
        return self._entries[-n:]

    def last_run(self) -> dict | None:
        return self._entries[-1] if self._entries else None


# ── Daemon ────────────────────────────────────────────────────────────────────

class HealthDaemon:

    def __init__(self):
        self.cfg         = HealthConfig()
        self.log         = HealthLog()
        self._thread     = None
        self._stop_event = threading.Event()
        self._last_cache_run   = 0.0
        self._last_db_run      = 0.0
        self._last_process_run = 0.0

    def start(self):
        if not self.cfg.get('enabled', True):
            logger.info("[HealthDaemon] disabled in config")
            return
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name='sentinel-health',
            daemon=True
        )
        self._thread.start()
        logger.info("[HealthDaemon] started")

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("[HealthDaemon] stopped")

    def run_now(self) -> dict:
        """Manually trigger full cleanup. Returns result dict."""
        result = run_all(self.cfg.all())
        self.log.append(result)
        self._last_cache_run   = time.time()
        self._last_db_run      = time.time()
        self._last_process_run = time.time()
        return result

    def status(self) -> dict:
        last = self.log.last_run()
        now  = time.time()

        cache_interval   = self.cfg.get('cache_interval_hours', 6) * 3600
        db_interval      = self.cfg.get('db_interval_hours', 24) * 3600
        process_interval = self.cfg.get('process_interval_hours', 1) * 3600

        return {
            'enabled':       self.cfg.get('enabled', True),
            'running':       self._thread is not None and self._thread.is_alive(),
            'last_run':      last.get('timestamp', 'Never') if last else 'Never',
            'last_freed_mb': last.get('total_freed_mb', 0) if last else 0,
            'last_fixed':    last.get('total_fixed', 0) if last else 0,
            'last_errors':   last.get('total_errors', 0) if last else 0,
            'next_cache_in':   max(0, int((self._last_cache_run + cache_interval - now) / 60)),
            'next_db_in':      max(0, int((self._last_db_run + db_interval - now) / 60)),
            'next_process_in': max(0, int((self._last_process_run + process_interval - now) / 60)),
            'config':        self.cfg.all(),
        }

    def _loop(self):
        # Run once on startup after 30 sec delay
        time.sleep(30)
        self._run_startup()

        while not self._stop_event.is_set():
            now = time.time()

            cache_interval   = self.cfg.get('cache_interval_hours', 6) * 3600
            db_interval      = self.cfg.get('db_interval_hours', 24) * 3600
            process_interval = self.cfg.get('process_interval_hours', 1) * 3600

            ran_something = False

            if now - self._last_process_run >= process_interval:
                self._run_partial(['processes'])
                self._last_process_run = now
                ran_something = True

            if now - self._last_cache_run >= cache_interval:
                self._run_partial(['cache', 'models'])
                self._last_cache_run = now
                ran_something = True

            if now - self._last_db_run >= db_interval:
                self._run_partial(['database', 'reports', 'logs'])
                self._last_db_run = now
                ran_something = True

            # Sleep 60 sec between checks
            self._stop_event.wait(60)

    def _run_startup(self):
        """On startup: fix .so conflicts, check DB integrity, clean stale sockets."""
        from modules.health_cleaners import clean_cache, clean_processes, guard_models
        try:
            r1 = clean_cache()
            r2 = clean_processes()
            r3 = guard_models()
            total_freed = r1.freed_mb + r2.freed_mb + r3.freed_mb
            total_fixed = r1.fixed + r2.fixed + r3.fixed
            if total_fixed > 0 or total_freed > 0:
                logger.info(f"[HealthDaemon] startup clean: {total_fixed} fixed, {total_freed:.1f}MB freed")
        except Exception as e:
            logger.error(f"[HealthDaemon] startup clean error: {e}")

    def _run_partial(self, keys: list):
        """Run only specific cleaners."""
        from modules import health_cleaners as hc
        cleaner_map = {
            'cache':     hc.clean_cache,
            'processes': hc.clean_processes,
            'models':    hc.guard_models,
            'reports':   lambda: hc.rotate_reports(
                self.cfg.get('reports_max_age_days', 30),
                self.cfg.get('max_reports_size_mb', 500)
            ),
            'logs':      lambda: hc.rotate_logs(self.cfg.get('logs_max_age_days', 7)),
            'database':  lambda: hc.optimize_databases(self.cfg.get('max_db_size_mb', 200)),
        }
        results = {}
        for key in keys:
            if key in cleaner_map:
                try:
                    results[key] = cleaner_map[key]()
                except Exception as e:
                    logger.error(f"[HealthDaemon] {key} cleaner error: {e}")

        total_freed = sum(r.freed_mb for r in results.values())
        total_fixed = sum(r.fixed for r in results.values())
        if total_fixed > 0 or total_freed > 0:
            entry = {
                'timestamp':      datetime.now().isoformat(),
                'total_freed_mb': round(total_freed, 2),
                'total_fixed':    total_fixed,
                'total_errors':   sum(len(r.errors) for r in results.values()),
                'details':        {k: {'freed_mb': round(v.freed_mb, 2), 'fixed': v.fixed, 'errors': v.errors, 'details': v.details} for k, v in results.items()},
            }
            self.log.append(entry)


# ── Singleton ─────────────────────────────────────────────────────────────────

_daemon: HealthDaemon | None = None


def get_daemon() -> HealthDaemon:
    global _daemon
    if _daemon is None:
        _daemon = HealthDaemon()
    return _daemon
