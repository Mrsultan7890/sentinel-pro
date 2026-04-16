"""
Sentinel Monitor — 24/7 Autonomous Monitoring
Target ko continuously watch karo — naya finding → Telegram alert
Author: @who_is_the_black_hat
"""

import time
import logging
import threading
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class SentinelMonitor:
    """
    24/7 monitoring — background mein chalta rehta hai.
    Har interval pe target scan karta hai, naya finding mile to Telegram alert.
    """

    def __init__(self, brain, interval: int = 3600):
        self.brain    = brain
        self.interval = interval  # seconds (default 1 hour)
        self.targets  = []
        self._running = False
        self._thread  = None
        self._seen    = {}  # target → set of finding titles

    def add_target(self, target: str, mode: str = 'full'):
        for t in self.targets:
            if t['target'] == target:
                return
        self.targets.append({'target': target, 'mode': mode})
        self._seen[target] = set()
        logger.info(f"[Monitor] Added: {target} mode={mode}")

    def remove_target(self, target: str):
        self.targets = [t for t in self.targets if t['target'] != target]

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True, name='sentinel-monitor')
        self._thread.start()
        logger.info(f"[Monitor] Started — {len(self.targets)} targets, interval={self.interval}s")

    def stop(self):
        self._running = False
        logger.info("[Monitor] Stopped")

    def is_running(self) -> bool:
        return self._running and self._thread and self._thread.is_alive()

    def status(self) -> dict:
        return {
            'running':  self.is_running(),
            'targets':  [t['target'] for t in self.targets],
            'interval': self.interval,
        }

    def _loop(self):
        # Pehla scan turant karo
        for entry in list(self.targets):
            if not self._running:
                return
            try:
                self._scan_target(entry['target'], entry['mode'])
            except Exception as e:
                logger.error(f"[Monitor] Error on {entry['target']}: {e}")

        while self._running:
            for _ in range(self.interval):
                if not self._running:
                    return
                time.sleep(1)
            for entry in list(self.targets):
                if not self._running:
                    break
                try:
                    self._scan_target(entry['target'], entry['mode'])
                except Exception as e:
                    logger.error(f"[Monitor] Error on {entry['target']}: {e}")

    def _scan_target(self, target: str, mode: str):
        logger.info(f"[Monitor] Scanning {target} in separate terminal...")
        import subprocess, tempfile, os
        # Alag terminal window mein chalao
        script = f"""
import sys
sys.path.insert(0, '/home/kali/osints')
from sentinel_brain.brain import SentinelBrain
brain = SentinelBrain()
result = brain.run('investigate {target}')
"""
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.py',
                                          prefix='sentinel_monitor_', delete=False)
        tmp.write(script)
        tmp.flush()
        tmp.close()

        # xterm mein chalao — alag window
        cmd = f"xterm -title 'Sentinel Monitor — {target}' -e python3 {tmp.name}"
        proc = subprocess.Popen(cmd, shell=True, start_new_session=True)
        logger.info(f"[Monitor] xterm PID {proc.pid} — {target}")

        # Result wait karo
        proc.wait()

        # Findings check karo — main brain ki memory se
        try:
            from sentinel_brain.memory import Memory
            mem = Memory()
            findings = mem.recall_findings(target)
            new = []
            for f in findings:
                key = f"{f['severity']}:{f['title']}"
                if key not in self._seen.get(target, set()):
                    new.append(f)
                    self._seen.setdefault(target, set()).add(key)
            if new:
                logger.info(f"[Monitor] {target}: {len(new)} NEW findings")
                self._alert(target, new)
            else:
                logger.info(f"[Monitor] {target}: no new findings")
        except Exception as e:
            logger.error(f"[Monitor] findings check error: {e}")

        # Cleanup
        try:
            os.unlink(tmp.name)
        except Exception:
            pass

    def _alert(self, target: str, findings: list):
        try:
            import config
            from modules.notifications import TelegramNotifier
            notifier = TelegramNotifier(config.TELEGRAM_BOT_TOKEN, config.TELEGRAM_CHAT_ID)
            if not notifier.enabled:
                return

            _sev = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            top  = sorted(findings, key=lambda x: _sev.get(x['severity'], 4))[:6]

            lines = [
                f"🔔 MONITOR ALERT",
                f"Target : {target}",
                f"Time   : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                f"New    : {len(findings)} finding(s)",
                "",
                "NEW FINDINGS:",
            ]
            for f in top:
                icon = '🔴' if f['severity'] == 'CRITICAL' else '🟠' if f['severity'] == 'HIGH' else '🟡'
                lines.append(f"{icon} {f['title']} — {f['detail'][:60]}")
            lines.append("")
            lines.append("Sentinel Pro — @who_is_the_black_hat")
            notifier.send('\n'.join(lines))
        except Exception as e:
            logger.error(f"[Monitor] Alert failed: {e}")
