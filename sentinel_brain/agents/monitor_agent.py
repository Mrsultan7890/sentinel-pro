"""
Monitor Agent — 24/7 Autonomous Monitoring Bridge
==================================================
SentinelMonitor ko Brain ke ReAct loop se connect karta hai.
- Target add/remove karo
- Interval set karo
- New findings → auto Telegram alert

Author: @who_is_the_black_hat
"""

import logging
from sentinel_brain.memory import Memory

logger = logging.getLogger(__name__)


class MonitorAgent:
    NAME = 'monitor_agent'

    def __init__(self, memory: Memory, sentinel=None):
        self.memory   = memory
        self.sentinel = sentinel
        self._monitor = None
        self._groq    = self._load_groq()
        self._init_monitor()
        
    def _load_groq(self):
        try:
            from modules.ml_engine.groq_llm import GroqLLM
            if GroqLLM.is_available():
                g = GroqLLM()
                return g if g.is_ready else None
        except Exception:
            pass
        return None

    def _init_monitor(self):
        try:
            from sentinel_brain.monitor import SentinelMonitor
            # Brain instance lazily set hoga
            self._monitor_class = SentinelMonitor
        except Exception as e:
            logger.error(f"[MonitorAgent] init error: {e}")
            self._monitor_class = None

    def _get_monitor(self, brain=None):
        """Lazy init — brain instance chahiye."""
        if self._monitor is None and self._monitor_class and brain:
            self._monitor = self._monitor_class(brain)
        return self._monitor

    # ── Public API ────────────────────────────────────────────────────────────

    def add_target(self, target: str, brain=None, mode: str = 'full') -> dict:
        # Validate target input
        import re
        if not target or not isinstance(target, str):
            return {'success': False, 'error': 'Invalid target: must be non-empty string'}
        
        # Basic target validation patterns
        valid_patterns = [
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',  # Email
            r'^@?[a-zA-Z0-9_]{1,50}$',  # Username
            r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'  # Domain
        ]
        if not any(re.match(pattern, target.strip()) for pattern in valid_patterns):
            return {'success': False, 'error': f'Invalid target format: {target}'}
        
        target = target.strip()
        
        try:
            mon = self._get_monitor(brain)
            if not mon:
                return {'success': False, 'error': 'Monitor not initialized'}
            
            mon.add_target(target, mode)
            if not mon.is_running():
                mon.start()
            
            summary = f"Monitoring started: {target} mode={mode} interval={mon.interval}s"
            self.memory.remember_decision(target, self.NAME, 'monitor_add', 'Monitor', summary)
            logger.info(f"[MonitorAgent] {summary}")
            
            return {'success': True, 'target': target, 'mode': mode,
                    'interval': mon.interval, '_agent_summary': summary}
        except Exception as e:
            logger.error(f"[MonitorAgent] add_target failed: {e}")
            return {'success': False, 'error': str(e)}

    def remove_target(self, target: str) -> dict:
        if self._monitor:
            self._monitor.remove_target(target)
        return {'success': True, 'target': target}

    def set_interval(self, seconds: int) -> dict:
        if self._monitor:
            self._monitor.interval = seconds
        return {'success': True, 'interval': seconds}

    def start(self, brain=None) -> dict:
        mon = self._get_monitor(brain)
        if not mon:
            return {'success': False, 'error': 'No targets added yet'}
        mon.start()
        return {'success': True, 'running': mon.is_running()}

    def stop(self) -> dict:
        if self._monitor:
            self._monitor.stop()
        return {'success': True}

    def status(self) -> dict:
        if not self._monitor:
            return {'running': False, 'targets': [], 'interval': 3600}
        return self._monitor.status()

    def run(self, target: str, brain=None) -> dict:
        """Brain ke ReAct loop se call hota hai — target add + start."""
        return self.add_target(target, brain=brain)
