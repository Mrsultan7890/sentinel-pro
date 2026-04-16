"""
Sentinel Brain v2.0 — Real ReAct Autonomous Orchestrator
=========================================================
Real ReAct loop: Reason → Act → Observe → Reason again
- KaliController directly use karta hai
- Adaptive — findings ke hisaab se next step decide karta hai
- Retry logic — agent fail ho to retry ya alternate tool
- Full Kali Linux control

Author: @who_is_the_black_hat
"""

import json
import logging
import re
import time
from datetime import datetime
from pathlib import Path

from sentinel_brain.kali_controller import KaliController
from sentinel_brain.memory import Memory
from sentinel_brain.agents.recon_agent import ReconAgent
from sentinel_brain.agents.exploit_agent import ExploitAgent
from sentinel_brain.agents.osint_agent import OsintAgent
from sentinel_brain.agents.breach_agent import BreachAgent
from sentinel_brain.agents.report_agent import ReportAgent
from sentinel_brain.advanced_ml import AdvancedMLEngine

logger = logging.getLogger(__name__)

_SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

MAX_REACT_STEPS = 20
RETRY_LIMIT     = 2


def parse_task(task: str) -> dict:
    task_lower = task.lower()
    target = ''

    m = re.search(r'[\w.+-]+@[\w-]+\.[a-z]{2,}', task)
    if m:
        target = m.group(0)
    if not target:
        m = re.search(r'\+?\d{10,15}', task.replace(' ', ''))
        if m:
            target = m.group(0)
    if not target:
        m = re.search(r'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,})', task)
        if m:
            target = m.group(1)
    if not target:
        m = re.search(r'["\']([^"\']+)["\']', task)
        if m:
            target = m.group(1)
    if not target:
        words = task.split()
        target = words[-1] if words else task

    if any(w in task_lower for w in ['breach', 'leak', 'password', 'credential']):
        mode = 'breach'
    elif any(w in task_lower for w in ['recon', 'subdomain', 'dns', 'whois']):
        mode = 'recon'
    elif any(w in task_lower for w in ['bug', 'vuln', 'exploit', 'scan', 'pentest', 'hack']):
        mode = 'bugbounty'
    elif any(w in task_lower for w in ['person', 'osint', 'profile', 'social', 'email', 'phone']):
        mode = 'osint'
    elif any(w in task_lower for w in ['nmap', 'nikto', 'sqlmap', 'nuclei', 'gobuster']):
        mode = 'tool'
        # Direct tool command extract karo
        return {'target': target, 'mode': 'tool', 'raw': task, 'tool_cmd': task}
    else:
        mode = 'full'

    return {'target': target, 'mode': mode, 'raw': task}


class SentinelBrain:
    """
    Master autonomous brain v2.0
    Real ReAct loop — khud sochta hai, khud karta hai.

    Usage:
        brain = SentinelBrain(sentinel=sentinel_instance)
        brain.run("investigate neurodev.netlify.app")
        brain.run("nmap -sV example.com")
        brain.run("full hack example.com")
    """

    VERSION = '2.0'

    def __init__(self, sentinel=None, console=None, auto: bool = True):
        self._print   = console or print
        self.auto     = auto
        self.sentinel = sentinel

        self.kali   = KaliController(timeout=120)
        self.memory = Memory()
        self.adv_ml = AdvancedMLEngine()

        self.recon_agent   = ReconAgent(self.kali, self.memory, sentinel)
        self.exploit_agent = ExploitAgent(self.kali, self.memory, sentinel)
        self.osint_agent   = OsintAgent(self.kali, self.memory, sentinel)
        self.breach_agent  = BreachAgent(self.kali, self.memory, sentinel)
        self.report_agent  = ReportAgent(self.memory, sentinel)

        self._model = self._load_model()

        self._print(f"\n{'='*60}")
        self._print(f"  SENTINEL BRAIN v{self.VERSION} — ReAct Autonomous")
        self._print(f"  Model  : {'SentinelNet v4.0' if self._model else 'heuristic'}")
        self._print(f"  Kali   : {self.kali.get_local_ip()}")
        mem = self.memory.stats()
        self._print(f"  Memory : {mem['scans']} scans, {mem['findings']} findings")
        self._print(f"{'='*60}\n")

    def _load_model(self):
        try:
            from modules.ml_engine.sentinel_net import NeuralTrainer
            nt = NeuralTrainer()
            if nt.load():
                return nt
        except Exception:
            pass
        return None

    # ── Main Entry ────────────────────────────────────────────────────────────

    def run(self, task: str) -> dict:
        parsed = parse_task(task)
        target = parsed['target']
        mode   = parsed['mode']

        self._print(f"[Brain] Task   : {task}")
        self._print(f"[Brain] Target : {target}")
        self._print(f"[Brain] Mode   : {mode}\n")

        ctx = self.memory.get_context(target)
        if 'Previous scans' in ctx:
            self._print(f"[Memory] {ctx[:200]}\n")

        t0 = time.time()

        # Direct tool command
        if mode == 'tool':
            return self._run_direct_tool(parsed.get('tool_cmd', task), target)

        # ReAct loop
        all_results = self._react_loop(target, mode)

        # Report
        self._print("\n[Brain] → ReportAgent")
        report = self.report_agent.run(target, all_results)
        all_results['report'] = report

        elapsed  = round(time.time() - t0, 1)
        risk     = report.get('risk', 'LOW')
        findings = report.get('findings', [])

        self._print(f"\n{'='*60}")
        self._print(f"  BRAIN COMPLETE — {target}")
        self._print(f"  Time     : {elapsed}s")
        self._print(f"  Risk     : {risk}")
        self._print(f"  Findings : {len(findings)}")
        self._print(f"  Telegram : {'✓' if report.get('telegram') else '✗'}")
        if findings:
            self._print(f"\n  TOP FINDINGS:")
            for f in sorted(findings, key=lambda x: _SEV_ORDER.get(x['severity'], 4))[:5]:
                icon = '🔴' if f['severity'] == 'CRITICAL' else '🟠'
                self._print(f"  {icon} [{f['severity']}] {f['title']}: {f['detail'][:60]}")
        self._print(f"{'='*60}\n")

        return {'target': target, 'mode': mode, 'risk': risk,
                'findings': findings, 'elapsed': elapsed, 'results': all_results}

    # ── ReAct Loop ────────────────────────────────────────────────────────────

    def _react_loop(self, target: str, mode: str) -> dict:
        """
        Real ReAct: Reason → Act → Observe → Reason again
        Findings ke hisaab se next step khud decide karta hai
        """
        results  = {}
        step     = 0
        done     = False
        retries  = {}

        # Initial plan
        plan = self._make_plan(target, mode)
        self._print(f"[ReAct] Plan: {' → '.join(plan)}\n")

        while not done and step < MAX_REACT_STEPS:
            step += 1

            # ── REASON ────────────────────────────────────────────────────────
            next_action = self._reason(target, plan, results, step)
            if not next_action or next_action == 'done':
                self._print(f"[ReAct] Step {step}: Done\n")
                break

            self._print(f"[ReAct] Step {step}: {next_action}")

            # ── ACT ───────────────────────────────────────────────────────────
            action_result = self._act(target, next_action, results)

            # ── OBSERVE ───────────────────────────────────────────────────────
            success = action_result.get('success', True)
            summary = action_result.get('_agent_summary', action_result.get('stdout', '')[:100])
            self._print(f"[ReAct] Observe: {'✓' if success else '✗'} {summary[:80]}\n")

            if not success:
                retries[next_action] = retries.get(next_action, 0) + 1
                if retries[next_action] >= RETRY_LIMIT:
                    self._print(f"[ReAct] {next_action} failed {RETRY_LIMIT}x — skip\n")
                    plan = [p for p in plan if p != next_action]
                    continue

            results[next_action] = action_result

            # ── ADAPT PLAN ────────────────────────────────────────────────────
            plan = self._adapt_plan(target, plan, next_action, action_result, results)

        return results

    def _make_plan(self, target: str, mode: str) -> list:
        """Genetic algorithm se optimal tool order lo"""
        base_plans = {
            'recon':     ['recon', 'kali_recon'],
            'bugbounty': ['recon', 'kali_recon', 'bugbounty', 'kali_exploit'],
            'osint':     ['osint'],
            'breach':    ['breach'],
        }
        if mode in base_plans:
            return base_plans[mode]
        # Full mode — genetic algorithm se order lo
        optimal = self.adv_ml.get_optimal_scan_order()
        self._print(f"  [Genetic] Optimal order: {' → '.join(optimal[:4])}")
        return ['recon', 'kali_recon', 'bugbounty', 'kali_exploit', 'osint', 'breach']

    def _reason(self, target: str, plan: list, results: dict, step: int) -> str:
        """Model dekhta hai kya hua, khud decide karta hai next step"""
        remaining = [p for p in plan if p not in results]
        if not remaining:
            return 'done'

        # Abhi tak kya mila — model ko context do
        context_parts = [f"target={target}"]
        for action, result in results.items():
            summary = result.get('_agent_summary', '')
            if summary:
                context_parts.append(summary)

        context = ' '.join(context_parts)[:400]

        if not self._model:
            return remaining[0]

        try:
            pred = self._model.predict(context)
            label       = pred.get('label', 'LOW')
            action_hint = pred.get('action_hint', '')
            threat_type = pred.get('threat_type', '')
            conf        = pred.get('confidence', 0)

            self._print(f"  [ML] {label} | {threat_type} | {action_hint} | conf={conf:.0%}")

            # Model ke action_hint se next step map karo
            hint_map = {
                'patch_now':        'bugbounty',
                'escalate':         'breach',
                'investigate':      'osint',
                'block_ip':         'kali_exploit',
                'collect_evidence': 'kali_recon',
                'notify_team':      'bugbounty',
                'monitor':          remaining[0],
            }

            # CRITICAL/HIGH mila → exploit skip karke seedha bugbounty
            if label == 'CRITICAL' and 'bugbounty' in remaining:
                return 'bugbounty'
            if label == 'CRITICAL' and 'kali_exploit' in remaining:
                return 'kali_exploit'

            # action_hint se decide karo
            suggested = hint_map.get(action_hint, '')
            if suggested and suggested in remaining:
                return suggested

            # threat_type se decide karo
            if threat_type == 'breach' and 'breach' in remaining:
                return 'breach'
            if threat_type in ('web_vuln', 'exploit') and 'bugbounty' in remaining:
                return 'bugbounty'
            if threat_type == 'recon' and 'kali_recon' in remaining:
                return 'kali_recon'

        except Exception as e:
            logger.debug(f"_reason model error: {e}")

        return remaining[0]

    def _act(self, target: str, action: str, results: dict) -> dict:
        """Action execute karo"""
        try:
            if action == 'recon':
                return self.recon_agent.run(target)

            elif action == 'kali_recon':
                # Direct KaliController chain
                self._print(f"  [Kali] Running recon chain on {target}")
                chain = self.kali.chain_recon(target)
                # Memory mein save karo
                ports = chain.get('nmap', {}).get('total', 0)
                subs  = chain.get('subfinder', {}).get('total', 0)
                self.memory.remember_scan(target, 'kali_recon', 'MEDIUM',
                    f'{ports} ports, {subs} subdomains', chain)
                return {'success': True, '_agent_summary': f'{ports} ports, {subs} subdomains', **chain}

            elif action == 'bugbounty':
                return self.exploit_agent.run(target, results.get('recon'))

            elif action == 'kali_exploit':
                # Direct KaliController exploit chain
                self._print(f"  [Kali] Running exploit chain on {target}")
                recon = results.get('kali_recon', {})
                chain = self.kali.chain_exploit(target, recon)
                nikto_count = chain.get('nikto', {}).get('total', 0)
                dirs_count  = chain.get('gobuster', {}).get('total', 0)
                self.memory.remember_scan(target, 'kali_exploit', 'HIGH',
                    f'nikto={nikto_count} dirs={dirs_count}', chain)
                return {'success': True, '_agent_summary': f'nikto={nikto_count} dirs={dirs_count}', **chain}

            elif action == 'osint':
                return self.osint_agent.run(target)

            elif action == 'breach':
                return self.breach_agent.run(target)

            elif action.startswith('kali_cmd:'):
                # Direct kali command
                cmd = action.replace('kali_cmd:', '').strip()
                r   = self.kali.run(cmd, timeout=120)
                return {'success': r['success'], '_agent_summary': r['stdout'][:100], **r}

            else:
                return {'success': False, '_agent_summary': f'Unknown action: {action}'}

        except Exception as e:
            logger.exception(f"Act error: {action}")
            return {'success': False, '_agent_summary': str(e)}

    def _adapt_plan(self, target: str, plan: list, last_action: str,
                    last_result: dict, all_results: dict) -> list:
        new_steps = []

        # DecisionEngine se actions lo
        try:
            from modules.ml_engine.decision_engine import DecisionEngine
            if not hasattr(self, '_decision_engine'):
                self._decision_engine = DecisionEngine()
            de_actions = self._decision_engine.decide(last_action, last_result, target)
            for a in de_actions:
                action = a.get('action', '')
                reason = a.get('reason', '')
                if action in ('bugbounty', 'recon', 'osint', 'breach') and action not in plan:
                    new_steps.append(action)
                    self._print(f"  [Decision] +{action} — {reason}")
                elif action == 'alert' and a.get('auto'):
                    # Turant Telegram alert
                    try:
                        import config
                        from modules.notifications import TelegramNotifier
                        n = TelegramNotifier(config.TELEGRAM_BOT_TOKEN, config.TELEGRAM_CHAT_ID)
                        n.send(f"🚨 AUTO ALERT\nTarget: {target}\n{reason}\n\nSentinel Pro — @who_is_the_black_hat")
                        self._print(f"  [Alert] Telegram sent: {reason}")
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"DecisionEngine error: {e}")

        # Nmap mein DB ports mile → sqlmap
        nmap = last_result.get('nmap', {})
        for p in nmap.get('open_ports', []):
            port = p.get('port')
            svc  = p.get('service', '')
            if port in (3306, 1433, 5432):
                cmd = f'kali_cmd:sqlmap -u "http://{target}" --batch --dbs 2>/dev/null | tail -20'
                if cmd not in plan:
                    new_steps.append(cmd)
                    self._print(f"  [Adapt] DB port {port} open → sqlmap")
            if port == 445:
                cmd = f'kali_cmd:enum4linux -a {target} 2>/dev/null | tail -30'
                if cmd not in plan:
                    new_steps.append(cmd)
                    self._print(f"  [Adapt] SMB port open → enum4linux")

        # SSTI/LFI mila → commix
        ssti = last_result.get('ssti', {}).get('total', 0)
        lfi  = last_result.get('lfi', {}).get('total', 0)
        if ssti > 0 or lfi > 0:
            cmd = f'kali_cmd:commix --url="http://{target}" --batch 2>/dev/null | tail -20'
            if cmd not in plan:
                new_steps.append(cmd)
                self._print(f"  [Adapt] SSTI/LFI found → commix")

        # GitHub secrets → breach
        if last_result.get('github_dorks', {}).get('total_secrets', 0) > 0:
            if 'breach' not in plan:
                new_steps.append('breach')
                self._print(f"  [Adapt] GitHub secrets → breach check")

        for step in new_steps:
            if step not in plan:
                plan.append(step)

        return plan

    # ── Direct Tool Execution ─────────────────────────────────────────────────

    def _run_direct_tool(self, command: str, target: str) -> dict:
        """Direct kali command chalao — brain bypass"""
        self._print(f"[Brain] Direct tool: {command}\n")
        r = self.kali.run(command, timeout=180)

        # Clean output — fingerprint/SF lines hatao
        clean_lines = []
        for line in (r['stdout'] or '').splitlines():
            if line.startswith('SF-') or line.startswith('=='):
                continue
            clean_lines.append(line)
        clean_output = '\n'.join(clean_lines)
        self._print(clean_output[:3000] if clean_output else '[no output]')

        parsed = r.get('parsed', {})

        # Parsed summary print karo
        if parsed.get('tool') == 'nmap' and parsed.get('open_ports'):
            self._print(f"\n[Brain] Parsed — {parsed['total']} open ports:")
            for p in parsed['open_ports']:
                self._print(f"  {p['port']}/{p['proto']}  {p['service']}  {p['version']}")
            if parsed.get('os'):
                self._print(f"  OS: {parsed['os']}")
            # ML assessment
            if self._model:
                text = f"nmap scan {' '.join(str(p['port']) for p in parsed['open_ports'])} {' '.join(p['service'] for p in parsed['open_ports'])}"
                pred = self._model.predict(text)
                self._print(f"\n[ML] label={pred['label']} type={pred['threat_type']} action={pred['action_hint']} conf={pred['confidence']:.0%}")

        elif parsed.get('tool') == 'nuclei' and parsed.get('findings'):
            self._print(f"\n[Brain] Nuclei — {parsed['total']} findings:")
            for f in parsed['findings'][:10]:
                self._print(f"  [{f['severity']}] {f['template']} — {f['url']}")

        elif parsed.get('tool') == 'nikto' and parsed.get('findings'):
            self._print(f"\n[Brain] Nikto — {parsed['total']} findings:")
            for f in parsed['findings'][:10]:
                self._print(f"  {f}")

        elif parsed.get('tool') == 'dirbust' and parsed.get('found'):
            self._print(f"\n[Brain] DirBust — {parsed['total']} paths found:")
            for f in parsed['found'][:10]:
                self._print(f"  [{f['status']}] {f['url']}")

        elif parsed.get('tool') == 'sqlmap':
            if parsed.get('vulnerable'):
                self._print(f"\n[Brain] SQLMap — VULNERABLE!")
                for v in parsed.get('vulns', [])[:5]:
                    self._print(f"  {v}")
            else:
                self._print("\n[Brain] SQLMap — not vulnerable")

        self.memory.remember_scan(target, 'direct_tool', 'MEDIUM',
            f"cmd={command[:50]}", r)

        return {'target': target, 'mode': 'tool', 'command': command,
                'output': r['stdout'], 'parsed': parsed, 'success': r['success']}

    # ── Shell passthrough ─────────────────────────────────────────────────────

    def shell(self, command: str, timeout: int = 120) -> dict:
        """Direct terminal — agent ya user dono use kar sakte hain"""
        self._print(f"[Terminal] $ {command}")
        r = self.kali.run(command, timeout=timeout)
        if r['stdout']:
            self._print(r['stdout'][:2000])
        return r

    def memory_stats(self) -> dict:
        return self.memory.stats()
