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
        
    def _validate_target(self, target: str) -> bool:
        """Validate target to prevent injection attacks."""
        import re
        if not target or len(target) > 200:
            return False
        
        # Allow: emails, usernames, domains, IP addresses
        valid_patterns = [
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',  # Email
            r'^@?[a-zA-Z0-9_]{1,50}$',  # Username/handle
            r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',  # Domain
            r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'  # IP address
        ]
        
        return any(re.match(pattern, target) for pattern in valid_patterns)

    def add_target(self, target: str, mode: str = 'full'):
        # Validate target before adding
        if not self._validate_target(target):
            logger.error(f"[Monitor] Invalid target format: {target}")
            return False
            
        # Check if target already exists
        for t in self.targets:
            if t['target'] == target:
                logger.info(f"[Monitor] Target {target} already exists")
                return False
                
        # Validate mode
        valid_modes = ['full', 'recon', 'bugbounty', 'breach']
        if mode not in valid_modes:
            logger.error(f"[Monitor] Invalid mode: {mode}. Valid modes: {valid_modes}")
            return False
            
        self.targets.append({'target': target, 'mode': mode})
        self._seen[target] = set()
        logger.info(f"[Monitor] Added: {target} mode={mode}")
        return True

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
        import config
        tor_status = config.is_tor_active()
        return {
            'running':  self.is_running(),
            'targets':  [t['target'] for t in self.targets],
            'interval': self.interval,
            'tor_enabled': tor_status,
            'tor_proxy': config.TOR_PROXY if tor_status else None,
        }

    def _loop(self):
        import time
        
        # Pehla scan turant karo
        for entry in list(self.targets):
            if not self._running:
                return
            try:
                self._scan_target(entry['target'], entry['mode'])
            except Exception as e:
                logger.error(f"[Monitor] Error on {entry['target']}: {e}")

        # Improved interval handling with proper sleep
        while self._running:
            # Sleep in smaller chunks to allow responsive shutdown
            remaining = self.interval
            while remaining > 0 and self._running:
                sleep_time = min(10, remaining)  # Sleep max 10 seconds at a time
                time.sleep(sleep_time)
                remaining -= sleep_time
                
            if not self._running:
                break
                
            # Scan all targets
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
        
        # Validate target to prevent injection
        if not self._validate_target(target):
            logger.error(f"[Monitor] Invalid target format: {target}")
            return
            
        # Check Tor status and prepare environment
        import config
        tor_status = config.is_tor_active()
        tor_proxy = config.TOR_PROXY if tor_status else ''
        
        # Create secure script content with Tor integration
        script = f"""
import sys
sys.path.insert(0, '/home/kali/osints')
import config

# Inherit Tor settings from parent process
if {tor_status}:
    config.tor_on()
    print(f"[Monitor-Child] Tor ENABLED - Proxy: {tor_proxy}")
else:
    config.tor_off()
    print(f"[Monitor-Child] Tor DISABLED - Direct connection")

from sentinel_brain.brain import SentinelBrain
brain = SentinelBrain()
result = brain.run('investigate {target}')
print(f"[Monitor-Child] Scan complete for {target}")
"""
        
        # Use context manager for proper resource management
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py',
                                           prefix='sentinel_monitor_', delete=False) as tmp:
                tmp.write(script)
                tmp.flush()
                tmp_path = tmp.name

            # Use secure subprocess call without shell=True
            cmd = ['xterm', '-title', f'Sentinel Monitor — {target} {"[TOR]" if tor_status else "[DIRECT]"}', 
                   '-e', 'python3', tmp_path]
            
            # Set environment variables for child process
            env = os.environ.copy()
            if tor_status:
                env['TOR_ENABLED'] = 'true'
                env['HTTP_PROXY'] = tor_proxy
                env['HTTPS_PROXY'] = tor_proxy
                logger.info(f"[Monitor] Starting scan with Tor proxy: {tor_proxy}")
            else:
                env['TOR_ENABLED'] = 'false'
                logger.info(f"[Monitor] Starting scan with direct connection")
                
            proc = subprocess.Popen(cmd, start_new_session=True, env=env,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.info(f"[Monitor] xterm PID {proc.pid} — {target} {'[TOR]' if tor_status else '[DIRECT]'}")

            # Result wait karo with timeout
            try:
                proc.wait(timeout=1800)  # 30 minute timeout
            except subprocess.TimeoutExpired:
                logger.warning(f"[Monitor] Scan timeout for {target}, terminating...")
                proc.terminate()
                proc.wait(timeout=10)
                if proc.poll() is None:
                    proc.kill()

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
                
        except (OSError, subprocess.SubprocessError) as e:
            logger.error(f"[Monitor] Scan execution error for {target}: {e}")
        except Exception as e:
            logger.error(f"[Monitor] Unexpected error scanning {target}: {e}")
        finally:
            # Cleanup temporary file
            try:
                if 'tmp_path' in locals():
                    os.unlink(tmp_path)
            except OSError as e:
                logger.warning(f"[Monitor] Failed to cleanup temp file: {e}")

    def _alert(self, target: str, findings: list):
        try:
            import config
            from modules.notifications import TelegramNotifier
            notifier = TelegramNotifier(config.TELEGRAM_BOT_TOKEN, config.TELEGRAM_CHAT_ID)
            if not notifier.enabled:
                return

            _sev = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            sorted_findings = sorted(findings, key=lambda x: _sev.get(x['severity'], 4))

            lines = [
                f"🔔 MONITOR ALERT",
                f"Target : {target}",
                f"Time   : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                f"New    : {len(findings)} finding(s)",
                "",
                "ALL NEW FINDINGS:",
            ]
            for f in sorted_findings:
                icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(f['severity'], '⚪')
                lines.append(f"{icon} {f['title']} — {f['detail'][:80]}")
            lines.append("")
            lines.append("Sentinel Pro — @who_is_the_black_hat")
            notifier.send('\n'.join(lines))
        except Exception as e:
            logger.error(f"[Monitor] Alert failed: {e}")
