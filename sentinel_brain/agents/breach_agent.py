"""
Breach Agent — Credential Leak + Infostealer Detection
HIBP, HudsonRock, LeakCheck, IntelX, Dehashed, Paste Monitor

Author: @who_is_the_black_hat
"""

import logging
from sentinel_brain.terminal import Terminal
from sentinel_brain.memory import Memory

logger = logging.getLogger(__name__)


class BreachAgent:
    NAME = 'breach_agent'

    def __init__(self, terminal: Terminal, memory: Memory, sentinel=None):
        self.terminal = terminal
        self.memory   = memory
        self.sentinel = sentinel

    def run(self, target: str) -> dict:
        logger.info(f"[BreachAgent] Checking {target}")

        result = {}

        if self.sentinel:
            try:
                self.sentinel._handle_breach(f'breach {target}')
                result = self.sentinel.session_data.get('breach', {})
            except Exception as e:
                logger.error(f"[BreachAgent] Sentinel breach failed: {e}")
                result = {'error': str(e), 'risk_level': 'LOW'}
        else:
            result = {'error': 'No sentinel instance', 'risk_level': 'LOW'}

        # Memory save
        risk    = result.get('risk_level', 'LOW')
        breaches = result.get('total_breaches', 0)
        logs     = result.get('total_stealer_logs', 0)
        summary  = f"Breach check: {breaches} breaches, {logs} stealer logs, risk={risk}"

        self.memory.remember_scan(target, 'breach', risk, summary, result)
        self.memory.remember_decision(target, self.NAME, 'breach',
                                      'Credential leak check', summary)

        if risk in ('CRITICAL', 'HIGH'):
            self.memory.remember_finding(
                target, self.NAME, risk,
                'Credentials Compromised',
                summary,
                'Rotate all passwords, enable 2FA, check for active sessions'
            )
            if logs > 0:
                self.memory.learn_pattern(
                    f'infostealer {target}',
                    'escalate_and_notify'
                )

        result['_agent_summary'] = summary
        result['_risk'] = risk
        return result
