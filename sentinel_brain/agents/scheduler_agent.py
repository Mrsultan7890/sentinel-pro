"""
Scheduler Agent — Automated Scan Scheduling
============================================
- Cron-like scheduled scans
- "Har roz raat 2 baje scan karo"
- One-time delayed scans
- Recurring interval scans
- Schedule save/restore karo

Author: @who_is_the_black_hat
"""

import json
import logging
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

import config

logger = logging.getLogger(__name__)

SCHEDULE_FILE = config.BASE_DIR / 'data' / 'schedules.json'


class SchedulerAgent:
    NAME = 'scheduler_agent'

    def __init__(self, brain=None):
        self._brain     = brain
        self._schedules = {}
        self._running   = False
        self._thread    = None
        self._lock      = threading.Lock()
        self._load_schedules()

    def set_brain(self, brain):
        self._brain = brain

    # ── Schedule Management ───────────────────────────────────────────────────

    def add(self, name: str, target: str, mode: str = 'full',
            schedule_type: str = 'interval', **kwargs) -> dict:
        """
        Schedule add karo.

        schedule_type:
          'interval' — har N seconds (kwargs: seconds=3600)
          'daily'    — har roz specific time (kwargs: hour=2, minute=0)
          'once'     — ek baar delay ke baad (kwargs: delay_seconds=3600)
          'cron'     — cron expression (kwargs: cron='0 2 * * *')
        """
        schedule = {
            'name':          name,
            'target':        target,
            'mode':          mode,
            'type':          schedule_type,
            'enabled':       True,
            'created':       datetime.now().isoformat(),
            'last_run':      None,
            'next_run':      None,
            'run_count':     0,
            'last_result':   None,
        }

        if schedule_type == 'interval':
            schedule['seconds']  = kwargs.get('seconds', 3600)
            schedule['next_run'] = (datetime.now() + timedelta(
                seconds=schedule['seconds']
            )).isoformat()

        elif schedule_type == 'daily':
            schedule['hour']   = kwargs.get('hour', 2)
            schedule['minute'] = kwargs.get('minute', 0)
            schedule['next_run'] = self._next_daily(
                schedule['hour'], schedule['minute']
            ).isoformat()

        elif schedule_type == 'once':
            delay = kwargs.get('delay_seconds', 3600)
            schedule['delay_seconds'] = delay
            schedule['next_run'] = (
                datetime.now() + timedelta(seconds=delay)
            ).isoformat()

        elif schedule_type == 'cron':
            schedule['cron'] = kwargs.get('cron', '0 2 * * *')
            schedule['next_run'] = self._next_cron(schedule['cron']).isoformat()

        with self._lock:
            self._schedules[name] = schedule
        self._save_schedules()

        if not self._running:
            self.start()

        logger.info(f"[Scheduler] Added: {name} → {target} ({schedule_type})")
        return {'success': True, 'schedule': schedule}

    def remove(self, name: str) -> bool:
        with self._lock:
            if name in self._schedules:
                del self._schedules[name]
                self._save_schedules()
                return True
        return False

    def enable(self, name: str) -> bool:
        with self._lock:
            if name in self._schedules:
                self._schedules[name]['enabled'] = True
                self._save_schedules()
                return True
        return False

    def disable(self, name: str) -> bool:
        with self._lock:
            if name in self._schedules:
                self._schedules[name]['enabled'] = False
                self._save_schedules()
                return True
        return False

    def list_schedules(self) -> list:
        with self._lock:
            return list(self._schedules.values())

    # ── Scheduler Loop ────────────────────────────────────────────────────────

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread  = threading.Thread(
            target=self._loop, daemon=True, name='sentinel-scheduler'
        )
        self._thread.start()
        logger.info("[Scheduler] Started")

    def stop(self):
        self._running = False
        logger.info("[Scheduler] Stopped")

    def is_running(self) -> bool:
        return self._running and self._thread and self._thread.is_alive()

    def _loop(self):
        while self._running:
            now = datetime.now()
            with self._lock:
                schedules = dict(self._schedules)

            for name, sched in schedules.items():
                if not sched.get('enabled'):
                    continue
                next_run = sched.get('next_run')
                if not next_run:
                    continue
                try:
                    next_dt = datetime.fromisoformat(next_run)
                except Exception:
                    continue

                if now >= next_dt:
                    threading.Thread(
                        target=self._execute_schedule,
                        args=(name, sched),
                        daemon=True,
                        name=f'sentinel-sched-{name}'
                    ).start()

            time.sleep(30)  # 30s check interval

    def _execute_schedule(self, name: str, sched: dict):
        target = sched['target']
        mode   = sched['mode']
        logger.info(f"[Scheduler] Running: {name} → {target} ({mode})")

        result = {'success': False, 'error': 'brain not set'}
        if self._brain:
            try:
                result = self._brain.run(f"{mode} {target}")
                result['success'] = True
            except Exception as e:
                result = {'success': False, 'error': str(e)}
                logger.error(f"[Scheduler] {name} failed: {e}")

        # Update schedule
        with self._lock:
            if name in self._schedules:
                s = self._schedules[name]
                s['last_run']    = datetime.now().isoformat()
                s['run_count']   = s.get('run_count', 0) + 1
                s['last_result'] = 'success' if result.get('success') else 'failed'

                # Next run calculate karo
                stype = s.get('type', 'interval')
                if stype == 'interval':
                    s['next_run'] = (
                        datetime.now() + timedelta(seconds=s.get('seconds', 3600))
                    ).isoformat()
                elif stype == 'daily':
                    s['next_run'] = self._next_daily(
                        s.get('hour', 2), s.get('minute', 0)
                    ).isoformat()
                elif stype == 'once':
                    s['enabled'] = False  # One-time — disable karo
                    s['next_run'] = None
                elif stype == 'cron':
                    s['next_run'] = self._next_cron(s.get('cron', '0 2 * * *')).isoformat()

        self._save_schedules()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _next_daily(self, hour: int, minute: int) -> datetime:
        now  = datetime.now()
        next = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if next <= now:
            next += timedelta(days=1)
        return next

    def _next_cron(self, cron: str) -> datetime:
        """Simple cron parser — minute hour * * *"""
        try:
            parts = cron.strip().split()
            if len(parts) >= 2:
                minute = int(parts[0]) if parts[0] != '*' else 0
                hour   = int(parts[1]) if parts[1] != '*' else 0
                return self._next_daily(hour, minute)
        except Exception:
            pass
        return datetime.now() + timedelta(hours=1)

    def _save_schedules(self):
        try:
            SCHEDULE_FILE.parent.mkdir(parents=True, exist_ok=True)
            data = {k: {kk: vv for kk, vv in v.items() if kk != 'proc'}
                    for k, v in self._schedules.items()}
            SCHEDULE_FILE.write_text(json.dumps(data, indent=2))
        except Exception as e:
            logger.debug(f"[Scheduler] save error: {e}")

    def _load_schedules(self):
        if SCHEDULE_FILE.exists():
            try:
                self._schedules = json.loads(SCHEDULE_FILE.read_text())
                enabled = sum(1 for s in self._schedules.values() if s.get('enabled'))
                if enabled:
                    self.start()
                logger.info(f"[Scheduler] Loaded {len(self._schedules)} schedules ({enabled} enabled)")
            except Exception:
                pass

    def status(self) -> dict:
        with self._lock:
            schedules = list(self._schedules.values())
        return {
            'running':  self.is_running(),
            'total':    len(schedules),
            'enabled':  sum(1 for s in schedules if s.get('enabled')),
            'schedules': schedules,
        }
