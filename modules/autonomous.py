# ============================================================================
# Sentinel Pro v3.0 — Professional OSINT & Bug Bounty Platform
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
#
# Unauthorized copying, distribution, or modification of this software,
# via any medium, is strictly prohibited without written permission.
#
# Licensed users may use this software under the terms of their license.
# For licensing: https://github.com/Mrsultan7890/osints
# ============================================================================

"""
Sentinel Autonomous Core
========================
Model → Decision → Tool (existing handlers) → Result → DB → Learn → Repeat

TheSentinelPro instance inject hota hai — sab existing scanners use hote hain.
Naye modules banana zaroorat nahi.
"""

import json
import logging
import re
import time
from datetime import datetime
from pathlib import Path

from modules.database import SentinelDB as DB

logger = logging.getLogger(__name__)

# ── Smart Request Helper ──────────────────────────────────────────────────────

def smart_request(url: str, method: str = 'get', retries: int = 3, **kwargs):
    """
    Request karo — fail hone par automatically Tor on karo aur retry karo.
    """
    import requests as _requests
    import config as _config
    from modules.utils import tor_session
    import subprocess

    kwargs.setdefault('timeout', 15)
    kwargs.setdefault('verify', False)
    last_err = None

    for attempt in range(1, retries + 1):
        try:
            if _config.is_tor_active():
                sess = tor_session()
            else:
                sess = _requests.Session()
            resp = getattr(sess, method)(url, **kwargs)
            return resp
        except Exception as e:
            last_err = e
            logger.warning(f"Request failed (attempt {attempt}): {url} — {e}")

            if attempt == 1:
                # Tor start karo
                logger.info("Auto-enabling Tor...")
                try:
                    from modules.privilege_manager import privilege_manager
                    privilege_manager.execute_privileged(['systemctl', 'start', 'tor'], 'systemctl', timeout=15)
                    import time; time.sleep(3)
                    _config.tor_on()
                    logger.info("Tor enabled — retrying via Tor")
                except Exception as te:
                    logger.warning(f"Tor start failed: {te}")

    raise last_err

PRIORITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

# Heuristic rules — (result se condition check karo, action, priority, reason)
from modules.safe_data import has_findings, safe_get_count

RULES = [
    (lambda r: has_findings(r, 'github_dorks', 'total_secrets'),
     'bugbounty', 'CRITICAL', 'GitHub secrets exposed'),

    (lambda r: has_findings(r, 'cloud_assets', 'total'),
     'bugbounty', 'HIGH', 'Exposed cloud assets found'),

    (lambda r: safe_get_count(r, 'subdomains', 'total_found') > 15,
     'bugbounty', 'HIGH', 'Large attack surface — subdomain takeover risk'),

    (lambda r: bool(r.get('dns', {}).get('zone_transfer')),
     'bugbounty', 'CRITICAL', 'DNS zone transfer allowed'),

    (lambda r: r.get('risk_level') in ('CRITICAL', 'HIGH') and safe_get_count(r, 'total_stealer_logs') > 0,
     'alert', 'CRITICAL', 'Infostealer logs found'),

    (lambda r: r.get('risk_level') == 'CRITICAL',
     'person', 'HIGH', 'Critical risk — identity investigation'),
]


class AutonomousAgent:
    """
    Sentinel ka autonomous brain.
    TheSentinelPro inject karo — existing scanners use hote hain.

    Usage (main.py se):
        agent = AutonomousAgent(target, sentinel=self, auto=auto)
        agent.run()
    """

    MAX_STEPS      = 8
    MIN_CONFIDENCE = 0.55

    def __init__(self, target: str, sentinel=None, auto: bool = False, console=None):
        # https:// strip karo
        self.target   = re.sub(r'^https?://', '', target).rstrip('/')
        self.sentinel = sentinel   # TheSentinelPro instance
        self.auto     = auto
        self._print   = console or print
        self._model   = self._load_model()
        self._queue   = []
        self._done    = set()
        self._results = {}
        self._findings= []

    def _load_model(self):
        try:
            from modules.ml_engine.sentinel_net import NeuralTrainer
            nt = NeuralTrainer()
            if nt.load():
                return nt
        except Exception:
            pass
        return None

    # ── Main Loop ─────────────────────────────────────────────────────────────

    def run(self) -> dict:
        self._print(f"\n{'='*55}")
        self._print(f"  SENTINEL AUTONOMOUS — {self.target}")
        self._print(f"  Auto: {self.auto} | Model: {'V4.0' if self._model else 'heuristic'}")
        self._print(f"{'='*55}\n")

        # DB se history check karo
        history = DB.get_target_history(self.target)
        if history:
            self._print(f"[DB] {len(history)} previous scan(s) found:")
            for h in history[:3]:
                self._print(f"     {h['date']} | {h['type']:<12} | risk={h['risk']}")
            self._print()

        # Hamesha recon se shuru
        self._enqueue('recon', self.target, 'MEDIUM', 'Initial reconnaissance')

        step = 0
        while self._queue and step < self.MAX_STEPS:
            step += 1
            task = self._queue.pop(0)
            key  = f"{task['type']}:{task['target']}"

            if key in self._done:
                continue
            self._done.add(key)

            self._print(f"[Step {step}] {task['type'].upper()} → {task['target']}")
            self._print(f"  Reason   : {task['reason']}")
            self._print(f"  Priority : {task['priority']}")

            # Confirm — sirf non-CRITICAL pe (agar auto=False)
            if not self.auto and task['priority'] != 'CRITICAL':
                self._print(f"  [?] Execute? [Y/n]: ", end='')
                try:
                    if input().strip().lower() == 'n':
                        self._print("  Skipped.\n")
                        continue
                except EOFError:
                    # EOF or Ctrl+D pressed - assume yes and proceed
                    logger.debug("Input EOF - proceeding with task")
                except KeyboardInterrupt:
                    # Ctrl+C - re-raise to let user stop
                    raise
                except Exception as e:
                    logger.warning(f"Input error: {e} - proceeding with task")

            # Execute via existing handlers
            t0     = time.time()
            result = self._execute(task['type'], task['target'])
            elapsed= round(time.time() - t0, 1)
            self._results[key] = result

            # DB save
            risk = result.get('risk_level', 'LOW')
            DB.save_scan(task['target'], task['type'], risk,
                         {'elapsed': elapsed, 'risk': risk})

            # Model analyze
            model_risk = self._analyze(task['type'], result)
            self._print(f"  Model    : {model_risk} | Time: {elapsed}s")

            # Next actions decide karo
            next_actions = self._decide(task['type'], result, task['target'], model_risk)
            for a in next_actions:
                akey = f"{a['type']}:{a['target']}"
                if akey not in self._done:
                    self._queue.append(a)
                    self._print(f"  → Queue  : {a['type']} {a['target']} [{a['priority']}]")

            # Training data feed
            self._feed_training(task['type'], result, model_risk)
            self._print()

        return self._final_report()

    # ── Execute — existing handlers use karo ──────────────────────────────────

    def _execute(self, action: str, target: str) -> dict:
        if not self.sentinel:
            return {'error': 'No sentinel instance', 'risk_level': 'LOW'}
        try:
            if action == 'recon':
                self.sentinel._handle_recon(f'recon {target}')
                result = self.sentinel.session_data.get('recon', {})
                self._check_and_tor_retry(result, 'recon', target)
                # IOCs save karo
                for sub in result.get('subdomains', {}).get('subdomains', []):
                    DB.save_ioc(sub, 'domain', 'subdomain', 0.5, 'recon')
                for email in result.get('go_scraper', {}).get('emails', []):
                    DB.save_ioc(email, 'email', 'exposed_email', 0.6, 'recon')
                return result

            elif action == 'bugbounty':
                self.sentinel._handle_bugbounty(f'bugbounty {target}')
                result = self.sentinel.session_data.get('bugbounty', {})
                # Findings extract karo
                for check, data in result.items():
                    if not isinstance(data, dict): continue
                    sev = data.get('risk_level') or data.get('severity', '')
                    if sev in ('CRITICAL', 'HIGH', 'MEDIUM'):
                        # Clean detail — dict nahi, readable string
                        detail = data.get('summary', '')
                        if not detail:
                            # Key findings extract karo
                            if 'findings' in data:
                                findings = data['findings']
                                if isinstance(findings, list) and findings:
                                    detail = '; '.join(str(f.get('type','') or f.get('detail',''))[:60] for f in findings[:2])
                            if not detail:
                                detail = f'{check} {sev} risk detected'
                        detail = detail[:300]
                        fix = self._get_fix(check)
                        DB.save_finding(target, check, sev, detail, fix)
                        self._findings.append({'type': check, 'severity': sev,
                                               'detail': detail, 'fix': fix})
                return result

            elif action == 'breach':
                self.sentinel._handle_breach(f'breach {target}')
                return self.sentinel.session_data.get('breach', {})

            elif action == 'email':
                self.sentinel._handle_email(f'email {target}')
                return self.sentinel.session_data.get('email', {})

            elif action == 'person':
                self.sentinel._handle_person(f'person {target}')
                return self.sentinel.session_data.get('person', {})

            elif action == 'alert':
                try:
                    from modules.notifications import TelegramNotifier
                    TelegramNotifier().send(
                        f"🚨 AUTONOMOUS ALERT\nTarget: {target}\n"
                        f"Findings: {len(self._findings)}\n"
                        f"Sentinel Pro — @who_is_the_black_hat"
                    )
                except Exception:
                    pass
                return {'alerted': True}

        except Exception as e:
            logger.exception(f"Execute {action} {target}")
            return {'error': str(e), 'risk_level': 'LOW'}

        return {}

    # ── Model Analysis ────────────────────────────────────────────────────────

    def _analyze(self, scan_type: str, result: dict) -> str:
        if self._model:
            try:
                text = self._to_text(scan_type, result)
                pred = self._model.predict(text)
                if pred['confidence'] >= self.MIN_CONFIDENCE:
                    # Log enriched intel from new multi-head outputs
                    self._print(f"  ThreatType : {pred.get('threat_type', '?')}")
                    self._print(f"  ActionHint : {pred.get('action_hint', '?')}")
                    self._print(f"  Reasoning  : {pred.get('reasoning', '')}")
                    return pred['label']
            except Exception:
                pass
        return self._heuristic_risk(result)

    def _to_text(self, scan_type: str, result: dict) -> str:
        from modules.safe_data import get_github_secrets_count, get_cloud_assets_count, get_subdomain_count
        
        parts = [f'{scan_type}']
        if scan_type == 'recon':
            s = get_github_secrets_count(result)
            c = get_cloud_assets_count(result)
            n = get_subdomain_count(result)
            if s: parts.append(f'{s} github secrets exposed credentials leaked')
            if c: parts.append(f'{c} cloud assets exposed misconfiguration')
            if n > 20: parts.append(f'{n} subdomains large attack surface')
        elif scan_type == 'bugbounty':
            for k, v in result.items():
                if isinstance(v, dict) and v.get('risk_level') in ('CRITICAL','HIGH'):
                    parts.append(f'{k} vulnerability {v["risk_level"]}')
        elif scan_type == 'breach':
            r = result.get('risk_level', '')
            l = result.get('total_stealer_logs', 0)
            if r: parts.append(f'breach {r}')
            if l: parts.append(f'{l} infostealer logs credentials stolen')
        return ' '.join(parts)

    # ── Decision Engine ───────────────────────────────────────────────────────

    def _decide(self, scan_type: str, result: dict, target: str, model_risk: str) -> list:
        actions = []

        # Heuristic rules
        for condition, action, priority, reason in RULES:
            try:
                if condition(result):
                    actions.append({'type': action, 'target': target,
                                    'priority': priority, 'reason': reason})
            except Exception:
                pass

        # Model decisions — use action_hint from predict() if available
        model_pred = {}
        if self._model:
            try:
                model_pred = self._model.predict(self._to_text(scan_type, result))
            except Exception:
                pass

        action_hint = model_pred.get('action_hint', '')

        if model_risk == 'CRITICAL' and scan_type == 'recon':
            actions.append({'type': 'bugbounty', 'target': target,
                            'priority': 'CRITICAL',
                            'reason': model_pred.get('reasoning', 'Model CRITICAL risk in recon')})

        if model_risk == 'HIGH' and scan_type == 'recon':
            actions.append({'type': 'bugbounty', 'target': target,
                            'priority': 'HIGH',
                            'reason': model_pred.get('reasoning', 'Model HIGH risk in recon')})

        if model_risk == 'MEDIUM' and scan_type == 'recon':
            actions.append({'type': 'bugbounty', 'target': target,
                            'priority': 'MEDIUM',
                            'reason': model_pred.get('reasoning', 'Model MEDIUM risk — vuln scan recommended')})

        if model_risk in ('CRITICAL', 'HIGH') and scan_type == 'bugbounty':
            actions.append({'type': 'alert', 'target': target,
                            'priority': 'CRITICAL',
                            'reason': model_pred.get('reasoning', f'Model {model_risk} vulns confirmed')})

        # action_hint → extra queue item
        if action_hint == 'collect_evidence':
            actions.append({'type': 'alert', 'target': target,
                            'priority': 'HIGH', 'reason': 'Model: collect evidence recommended'})
        elif action_hint == 'escalate' and model_risk in ('CRITICAL', 'HIGH'):
            actions.append({'type': 'alert', 'target': target,
                            'priority': 'CRITICAL', 'reason': 'Model: escalate to SOC'})

        # Emails found → breach
        for email in result.get('go_scraper', {}).get('emails', [])[:2]:
            actions.append({'type': 'breach', 'target': email,
                            'priority': 'MEDIUM', 'reason': f'Email found: {email}'})

        # Deduplicate + sort
        seen, unique = set(), []
        for a in actions:
            k = f"{a['type']}:{a['target']}"
            if k not in seen:
                seen.add(k)
                unique.append(a)
        unique.sort(key=lambda x: PRIORITY_ORDER.get(x['priority'], 4))

        # DB save
        for a in unique:
            DB.save_decision(a['target'], 'AutonomousAgent', a['type'], a['reason'], a['priority'])

        return unique[:4]

    # ── Training Feed ─────────────────────────────────────────────────────────

    def _feed_training(self, scan_type: str, result: dict, risk: str):
        """Real scan result → training data mein add karo"""
        try:
            from modules.ml_engine.trainer import ModelTrainer
            ModelTrainer.scan_result_to_training_data(scan_type, result)
        except Exception:
            pass

    # ── Final Report ──────────────────────────────────────────────────────────

    def _final_report(self) -> dict:
        sev_order = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}
        risk = 'LOW'
        for f in self._findings:
            if sev_order.get(f['severity'],4) < sev_order.get(risk,4):
                risk = f['severity']

        self._print(f"\n{'='*55}")
        self._print(f"  AUTONOMOUS COMPLETE — {self.target}")
        self._print(f"{'='*55}")
        self._print(f"  Overall Risk  : {risk}")
        self._print(f"  Steps done    : {len(self._done)}")
        self._print(f"  Findings      : {len(self._findings)}")
        crit = sum(1 for f in self._findings if f['severity']=='CRITICAL')
        high = sum(1 for f in self._findings if f['severity']=='HIGH')
        self._print(f"  CRITICAL/HIGH : {crit}/{high}")
        stats = DB.stats()
        self._print(f"  DB Scans      : {stats['scans']}")
        self._print(f"  DB IOCs       : {stats['iocs']}")
        self._print(f"  DB Findings   : {stats['findings']}")
        self._print(f"{'='*55}")

        if self._findings:
            self._print("\n  TOP FINDINGS:")
            shown = sorted(self._findings, key=lambda x: sev_order.get(x['severity'],4))
            for f in shown[:5]:
                self._print(f"  [{f['severity']}] {f['type']}: {f['detail'][:65]}")
            self._print("\n  FIXES:")
            seen = set()
            for f in shown:
                if f['type'] not in seen and f.get('fix'):
                    seen.add(f['type'])
                    self._print(f"  → {f['fix'][:80]}")

        return {'target': self.target, 'risk': risk,
                'findings': self._findings, 'steps': len(self._done)}

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _enqueue(self, action, target, priority, reason):
        self._queue.append({'type': action, 'target': target,
                            'priority': priority, 'reason': reason})

    def _check_and_tor_retry(self, result: dict, action: str, target: str):
        """
        Timeouts detect karo — Tor on karo taaki agle scans Tor se chalein.
        Recon repeat NAHI hoga — sirf Tor enable hoga.
        """
        import config as _config

        result_str = json.dumps(result).lower()
        timeout_keywords = ['timeout', 'connection error', 'unreachable',
                            'network error', 'request failed']
        timeout_count = sum(1 for kw in timeout_keywords if kw in result_str)

        if timeout_count >= 2 and not _config.is_tor_active():
            self._print(f"  [!] {timeout_count} timeouts detected — enabling Tor for next scans...")
            if self._tor_enable():
                self._print(f"  [\u2713] Tor enabled — next scans will use Tor")
            else:
                self._print(f"  [!] Tor start failed — continuing without Tor")

    def _tor_enable(self) -> bool:
        """Tor service start karo aur config mein enable karo"""
        import subprocess
        import time
        import config as _config
        try:
            # Tor service start
            from modules.privilege_manager import privilege_manager
            result = privilege_manager.execute_privileged(
                ['systemctl', 'start', 'tor'],
                'systemctl',
                timeout=20
            )
            time.sleep(4)  # Tor boot hone do

            # Test karo
            from modules.utils import tor_session
            sess = tor_session()
            r = sess.get('https://httpbin.org/ip', timeout=15)
            exit_ip = r.json().get('origin', '?')
            _config.tor_on()
            self._print(f"  [✓] Tor active — Exit IP: {exit_ip}")
            return True
        except Exception as e:
            logger.warning(f"Tor enable failed: {e}")
            return False

    def _heuristic_risk(self, result: dict) -> str:
        from modules.safe_data import has_findings
        
        r = result.get('risk_level', '')
        if r in ('CRITICAL','HIGH','MEDIUM','LOW'): return r
        if has_findings(result, 'github_dorks', 'total_secrets'): return 'CRITICAL'
        if has_findings(result, 'cloud_assets', 'total'): return 'HIGH'
        return 'MEDIUM'

    def _get_fix(self, vuln: str) -> str:
        fixes = {
            'sqli':         'Use parameterized queries — never concatenate user input in SQL',
            'xss':          'Encode output, implement CSP, validate all inputs',
            'ssrf':         'Whitelist allowed URLs, block internal IP ranges',
            'cors':         'Set specific trusted origins only, never wildcard with credentials',
            'headers':      'Add HSTS, X-Frame-Options: DENY, CSP, X-Content-Type-Options',
            'ssl':          'Update to TLS 1.3, disable SSLv3/TLS1.0/1.1, strong ciphers only',
            'jwt':          'Use RS256, validate exp/iss/aud claims, reject alg:none',
            'lfi':          'Validate file paths, use whitelist, disable allow_url_include',
            'xxe':          'Disable external entity processing in XML parser',
            'ssti':         'CRITICAL: Use sandboxed templates, NEVER pass user input to render()',
            'takeover':     'Remove dangling DNS records pointing to deprovisioned services',
            'open_redirect':'Validate redirect URLs against whitelist',
            'zone_transfer':'CRITICAL: Disable AXFR on all NS servers — restrict zone transfer to authorized IPs only',
            'smuggling':    'Add Content-Length validation, disable HTTP/1.1 keep-alive or use HTTP/2',
            'clickjacking': 'Add X-Frame-Options: DENY and CSP frame-ancestors \'none\'',
            'fuzzer':       'Restrict access to sensitive endpoints — add authentication/IP whitelist',
            'vulns':        'Fix URL override: reject X-Original-URL and X-Rewrite-URL headers',
        }
        for k, v in fixes.items():
            if k in vuln.lower(): return v
        return f'Review and remediate {vuln} — follow OWASP guidelines'
