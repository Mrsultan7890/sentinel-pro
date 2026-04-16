"""
Autonomous Decision Engine — Sentinel Intelligence Core
=======================================================
Yeh model ka "brain" hai jo:
1. Scan results analyze karta hai
2. Khud decide karta hai next action
3. Tool ko commands deta hai (armor use karta hai)
4. Results se seekhta rehta hai
5. Threat chains build karta hai

Architecture:
    Intelligence (Model) → Decision → Action (Tool) → Result → Learn → Repeat
"""

import json
import logging
import threading
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

STATE_FILE = Path(__file__).resolve().parents[2] / 'models' / 'ml_engine' / 'training_data' / 'autonomous_decisions.jsonl'


class DecisionEngine:
    """
    Model ka brain — scan results padhta hai aur next actions decide karta hai.

    Flow:
        scan_result aata hai
            ↓
        analyze() — model se threat assess karo
            ↓
        decide() — kya karna chahiye?
            ↓
        actions list return karo
            ↓
        caller (main.py) actions execute karta hai
            ↓
        feedback() — result wapas feed karo
    """

    # Confidence threshold — kitne sure hone par action lo
    ACTION_THRESHOLD = 0.65

    # Max auto-actions per scan — infinite loop se bachao
    MAX_ACTIONS = 5

    def __init__(self):
        self._neural = None
        self._lock   = threading.Lock()
        self._load_model()

    def _load_model(self):
        try:
            from modules.ml_engine.sentinel_net import NeuralTrainer
            nt = NeuralTrainer()
            if nt.load():
                self._neural = nt
                logger.info("DecisionEngine: SentinelThreatNet loaded")
        except Exception as e:
            logger.debug(f"DecisionEngine model load failed: {e}")

    # ── Main API ──────────────────────────────────────────────────────────────

    def analyze(self, text: str) -> dict:
        """Text ka threat level assess karo — neural model use karo"""
        if self._neural:
            try:
                return self._neural.predict(text)
            except Exception:
                pass
        # Fallback — keyword based
        return self._keyword_assess(text)

    def decide(self, scan_type: str, scan_result: dict, target: str) -> list:
        """
        Scan result dekh ke next actions decide karo.

        Returns: list of actions
        [
            {'action': 'breach',    'target': 'user@example.com', 'reason': '...', 'priority': 'HIGH'},
            {'action': 'recon',     'target': 'example.com',      'reason': '...', 'priority': 'MEDIUM'},
            {'action': 'bugbounty', 'target': 'example.com',      'reason': '...', 'priority': 'HIGH'},
        ]
        """
        actions = []

        try:
            if scan_type == 'recon':
                actions = self._decide_from_recon(scan_result, target)
            elif scan_type == 'bugbounty':
                actions = self._decide_from_bugbounty(scan_result, target)
            elif scan_type == 'breach':
                actions = self._decide_from_breach(scan_result, target)
            elif scan_type == 'person':
                actions = self._decide_from_person(scan_result, target)
            elif scan_type == 'email':
                actions = self._decide_from_email(scan_result, target)

            # Max actions limit
            actions = actions[:self.MAX_ACTIONS]

            # Log decisions
            self._log_decision(scan_type, target, actions)

        except Exception as e:
            logger.debug(f"DecisionEngine.decide error: {e}")

        return actions

    def feedback(self, action: dict, result: dict) -> None:
        """Action ka result wapas feed karo — continuous learning"""
        try:
            from modules.ml_engine.trainer import ModelTrainer
            scan_type = action.get('action', '')
            if scan_type and result:
                ModelTrainer.scan_result_to_training_data(scan_type, result)
        except Exception as e:
            logger.debug(f"DecisionEngine.feedback error: {e}")

    # ── Decision Logic ────────────────────────────────────────────────────────

    def _decide_from_recon(self, result: dict, target: str) -> list:
        actions = []

        # GitHub secrets mile → bugbounty scan karo
        ghd = result.get('github_dorks', {})
        if ghd.get('total_secrets', 0) > 0:
            actions.append({
                'action':   'bugbounty',
                'target':   target,
                'reason':   f"GitHub mein {ghd['total_secrets']} secrets exposed — full vuln scan karo",
                'priority': 'CRITICAL',
                'auto':     True,
            })

        # Cloud assets exposed → breach check karo
        ca = result.get('cloud_assets', {})
        if ca.get('total', 0) > 0:
            actions.append({
                'action':   'bugbounty',
                'target':   target,
                'reason':   f"{ca['total']} exposed cloud assets found",
                'priority': 'HIGH',
                'auto':     True,
            })

        # Subdomains mile → takeover check (bugbounty mein)
        subs = result.get('subdomains', {})
        if subs.get('total_found', 0) > 10:
            actions.append({
                'action':   'bugbounty',
                'target':   target,
                'reason':   f"{subs['total_found']} subdomains found — takeover check karo",
                'priority': 'MEDIUM',
                'auto':     False,  # user confirm karo
            })

        # Emails found in go_scraper → email OSINT
        go = result.get('go_scraper', {})
        for email in go.get('emails', [])[:2]:
            actions.append({
                'action':   'email',
                'target':   email,
                'reason':   f"Email {email} found in web scraping",
                'priority': 'MEDIUM',
                'auto':     False,
            })

        return actions

    def _decide_from_bugbounty(self, result: dict, target: str) -> list:
        actions = []

        # CRITICAL vulns → Telegram alert + breach check
        vulns = result.get('vulns', {})
        if vulns.get('risk_level') in ('CRITICAL', 'HIGH'):
            actions.append({
                'action':   'alert',
                'target':   target,
                'reason':   f"CRITICAL vulnerability found: {vulns.get('risk_level')}",
                'priority': 'CRITICAL',
                'auto':     True,
                'data':     {'type': 'bugbounty_critical', 'result': result},
            })

        # JS secrets → breach check
        js = result.get('js', {})
        if js.get('secrets'):
            for secret in js['secrets'][:2]:
                if '@' in secret.get('value', ''):
                    actions.append({
                        'action':   'breach',
                        'target':   secret['value'],
                        'reason':   f"Email found in JS: {secret.get('type')}",
                        'priority': 'HIGH',
                        'auto':     False,
                    })

        # Subdomain takeover → recon deeper
        tkover = result.get('takeover', {})
        if tkover.get('vulnerable'):
            actions.append({
                'action':   'alert',
                'target':   target,
                'reason':   f"{len(tkover['vulnerable'])} subdomains vulnerable to takeover",
                'priority': 'CRITICAL',
                'auto':     True,
                'data':     {'type': 'takeover', 'vulnerable': tkover['vulnerable']},
            })

        return actions

    def _decide_from_breach(self, result: dict, target: str) -> list:
        actions = []

        risk = result.get('risk_level', 'LOW')

        # Stealer logs mile → person OSINT karo
        if result.get('total_stealer_logs', 0) > 0:
            actions.append({
                'action':   'person',
                'target':   target,
                'reason':   f"Infostealer logs found — identity investigation karo",
                'priority': 'CRITICAL',
                'auto':     False,
            })

        # CRITICAL breach → NLP analysis
        if risk == 'CRITICAL':
            actions.append({
                'action':   'nlp',
                'target':   target,
                'reason':   f"CRITICAL breach risk — deep profile analysis karo",
                'priority': 'HIGH',
                'auto':     False,
            })

        # Plaintext passwords → alert
        dh = result.get('dehashed', {})
        if dh.get('total', 0) > 0:
            plain = sum(1 for e in dh.get('entries', []) if e.get('has_plaintext'))
            if plain > 0:
                actions.append({
                    'action':   'alert',
                    'target':   target,
                    'reason':   f"{plain} plaintext passwords found in Dehashed",
                    'priority': 'CRITICAL',
                    'auto':     True,
                    'data':     {'type': 'plaintext_passwords', 'count': plain},
                })

        return actions

    def _decide_from_person(self, result: dict, target: str) -> list:
        actions = []

        # Multiple platforms → breach check karo
        profiles = result.get('social_profiles', [])
        if len(profiles) >= 3:
            # Email dhundho profiles mein
            emails = result.get('emails_found', [])
            for email in emails[:2]:
                actions.append({
                    'action':   'breach',
                    'target':   email,
                    'reason':   f"Email {email} found across {len(profiles)} platforms",
                    'priority': 'HIGH',
                    'auto':     False,
                })

        # High fake score → fakecheck
        fake_avg = result.get('ml_fake_avg', 0)
        if fake_avg >= 0.6:
            actions.append({
                'action':   'fakecheck',
                'target':   target,
                'reason':   f"High fake probability ({fake_avg:.0%}) — deep fake analysis karo",
                'priority': 'HIGH',
                'auto':     False,
            })

        return actions

    def _decide_from_email(self, result: dict, target: str) -> list:
        actions = []

        risk = result.get('risk_level', 'LOW')

        if risk in ('HIGH', 'CRITICAL'):
            actions.append({
                'action':   'breach',
                'target':   target,
                'reason':   f"High risk email — full breach check karo",
                'priority': 'HIGH',
                'auto':     False,
            })

        # Domain se recon
        domain = result.get('domain', '')
        if domain and risk != 'LOW':
            actions.append({
                'action':   'recon',
                'target':   domain,
                'reason':   f"Email domain {domain} — recon karo",
                'priority': 'MEDIUM',
                'auto':     False,
            })

        return actions

    # ── Keyword Fallback ──────────────────────────────────────────────────────

    def _keyword_assess(self, text: str) -> dict:
        text_lower = text.lower()
        if any(k in text_lower for k in ['ransomware', 'exploit', 'backdoor', 'critical', 'rce']):
            return {'label': 'CRITICAL', 'confidence': 0.7, 'source': 'keyword'}
        elif any(k in text_lower for k in ['vulnerability', 'injection', 'phishing', 'malware']):
            return {'label': 'HIGH', 'confidence': 0.65, 'source': 'keyword'}
        elif any(k in text_lower for k in ['misconfiguration', 'exposure', 'weak']):
            return {'label': 'MEDIUM', 'confidence': 0.6, 'source': 'keyword'}
        return {'label': 'LOW', 'confidence': 0.55, 'source': 'keyword'}

    # ── Logging ───────────────────────────────────────────────────────────────

    def _log_decision(self, scan_type: str, target: str, actions: list) -> None:
        try:
            STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(STATE_FILE, 'a') as f:
                f.write(json.dumps({
                    'timestamp':  time.strftime('%Y-%m-%d %H:%M:%S'),
                    'scan_type':  scan_type,
                    'target':     target,
                    'actions':    actions,
                }) + '\n')
        except Exception:
            pass

    def decision_history(self, limit: int = 20) -> list:
        """Recent decisions return karo"""
        if not STATE_FILE.exists():
            return []
        history = []
        with open(STATE_FILE) as f:
            for line in f:
                try: history.append(json.loads(line))
                except: pass
        return history[-limit:]
