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
from sentinel_brain.agents.threat_intel_agent import ThreatIntelAgent
from sentinel_brain.agents.network_agent import NetworkAgent
from sentinel_brain.agents.attack_chain_agent import AttackChainAgent
from sentinel_brain.agents.monitor_agent import MonitorAgent
from sentinel_brain.agents.darkweb_agent import DarkWebAgent
from sentinel_brain.agents.browser_agent import BrowserAgent
from sentinel_brain.agents.terminal_agent import TerminalAgent
from sentinel_brain.agents.system_monitor_agent import SystemMonitorAgent
from sentinel_brain.agents.filesystem_agent import FileSystemAgent
from sentinel_brain.agents.notification_agent import NotificationAgent
from sentinel_brain.agents.credential_agent import CredentialAgent
from sentinel_brain.agents.correlation_agent import CorrelationAgent
from sentinel_brain.agents.scheduler_agent import SchedulerAgent
from sentinel_brain.advanced_ml import AdvancedMLEngine
from sentinel_brain.rl_agent import RLAgent, ScanState

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

        self.recon_agent        = ReconAgent(self.kali, self.memory, sentinel)
        self.exploit_agent      = ExploitAgent(self.kali, self.memory, sentinel)
        self.osint_agent        = OsintAgent(self.kali, self.memory, sentinel)
        self.breach_agent       = BreachAgent(self.kali, self.memory, sentinel)
        self.report_agent       = ReportAgent(self.memory, sentinel)
        self.threat_intel_agent  = ThreatIntelAgent(self.kali, self.memory, sentinel)
        self.network_agent       = NetworkAgent(self.kali, self.memory, sentinel)
        self.attack_chain_agent  = AttackChainAgent(self.kali, self.memory, sentinel)
        self.monitor_agent       = MonitorAgent(self.memory, sentinel)
        self.darkweb_agent       = DarkWebAgent(self.memory, sentinel)
        self.browser_agent       = BrowserAgent()
        self.terminal_agent      = TerminalAgent()
        self.system_monitor      = SystemMonitorAgent()
        self.filesystem_agent    = FileSystemAgent()
        self.notifier            = NotificationAgent()
        self.credential_agent    = CredentialAgent()
        self.scheduler_agent     = SchedulerAgent(brain=self)
        self.correlation_agent   = CorrelationAgent(self.memory, sentinel)

        self._rl      = self._load_rl()
        self._model   = self._load_model()
        self._seq2seq = self._load_seq2seq()
        self._groq    = self._load_groq()

        self._print(f"\n{'='*60}")
        self._print(f"  SENTINEL BRAIN v{self.VERSION} — ReAct Autonomous")
        self._print(f"  Classifier : {'SentinelNet v4.0' if self._model else 'heuristic'}")
        self._print(f"  Seq2Seq    : {'SentinelSeq2Seq v2.0' if self._seq2seq else 'not loaded'}")
        self._print(f"  Groq LLM   : {'Llama-3.3-70B ✓' if self._groq and self._groq.is_ready else 'not configured'}")
        rl_states = len(self._rl.q_table) if self._rl else 0
        rl_eps    = round(self._rl.epsilon, 3) if self._rl else 0
        self._print(f"  RL Agent   : {rl_states} states | epsilon={rl_eps}")
        self._print(f"  Agents     : recon, exploit, osint, breach, threat_intel, network, attack_chain, monitor, darkweb, browser, terminal, sysmon, filesystem, notification, credential, scheduler")
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
        except (ImportError, AttributeError, FileNotFoundError) as e:
            logger.debug(f"Model load error: {e}")
        except Exception as e:
            logger.error(f"Unexpected model load error: {e}")
        return None

    def _load_seq2seq(self):
        try:
            from modules.ml_engine.sentinel_net import Seq2SeqInference
            if Seq2SeqInference.is_available():
                s2s = Seq2SeqInference()
                s2s.load()
                return s2s
        except (ImportError, AttributeError, FileNotFoundError) as e:
            logger.debug(f"Seq2Seq load error: {e}")
        except Exception as e:
            logger.error(f"Unexpected Seq2Seq load error: {e}")
        return None

    def _load_rl(self):
        try:
            rl = RLAgent()
            logger.info(f"[Brain] RL Agent: {len(rl.q_table)} states, epsilon={rl.epsilon:.3f}")
            return rl
        except Exception as e:
            logger.debug(f"RL load error: {e}")
            return None

    def _load_groq(self):
        try:
            from modules.ml_engine.groq_llm import GroqLLM
            if GroqLLM.is_available():
                g = GroqLLM()
                return g if g.is_ready else None
        except (ImportError, AttributeError) as e:
            logger.debug(f"Groq load error: {e}")
        except Exception as e:
            logger.error(f"Unexpected Groq load error: {e}")
        return None

    # ── Main Entry ────────────────────────────────────────────────────────────

    def run(self, task: str) -> dict:
        if not task or not isinstance(task, str):
            logger.error("Invalid task: must be non-empty string")
            return {'error': 'Invalid task', 'success': False}
        
        try:
            parsed = parse_task(task)
        except Exception as e:
            logger.error(f"Task parsing failed: {e}")
            return {'error': f'Task parsing failed: {e}', 'success': False}
        
        target = parsed.get('target', '')
        mode   = parsed.get('mode', 'full')
        
        if not target:
            logger.error("No target extracted from task")
            return {'error': 'No target found', 'success': False}

        self._print(f"[Brain] Task   : {task}")
        self._print(f"[Brain] Target : {target}")
        self._print(f"[Brain] Mode   : {mode}\n")

        ctx = self.memory.get_context(target)
        if 'Previous scans' in ctx:
            self._print(f"[Memory] {ctx[:200]}\n")

        # ── Physical agents: scan shuru ───────────────────────────────────────
        self.notifier.scan_started(target, mode)
        self.system_monitor.start_monitoring(interval=30)

        t0 = time.time()

        # Direct tool command
        if mode == 'tool':
            result = self._run_direct_tool(parsed.get('tool_cmd', task), target)
            self.system_monitor.stop_monitoring()
            return result

        # ReAct loop
        all_results = self._react_loop(target, mode)

        # Screenshot — web target ka
        if mode in ('full', 'bugbounty', 'recon'):
            try:
                ss = self.browser_agent.screenshot_domain(target)
                if ss and isinstance(ss, dict) and ss.get('path'):
                    all_results['screenshot'] = ss['path']
                    self._print(f"[Browser] Screenshot: {ss['path']}")
            except (OSError, TimeoutError) as e:
                logger.debug(f"Screenshot failed: {e}")
            except Exception as e:
                logger.error(f"Unexpected screenshot error: {e}")

        # Report
        self._print("\n[Brain] → ReportAgent (generating report...)")
        try:
            report = self.report_agent.run(target, all_results)
            all_results['report'] = report
            self._print("[Brain] Report generated successfully")
        except Exception as e:
            logger.error(f"[Brain] Report generation failed: {e}")
            # Fallback minimal report
            report = {
                'risk': 'MEDIUM',
                'findings': self.memory.recall_findings(target),
                'paths': {},
                'telegram': False,
                '_agent_summary': f'Report generation failed: {e}',
            }
            all_results['report'] = report
            self._print(f"[Brain] Report fallback used due to error: {e}")
        
        # Create evidence chain for legal compliance
        try:
            if hasattr(self.sentinel, 'secure_files'):
                evidence_files = []
                if report.get('paths', {}).get('json'):
                    evidence_files.append(report['paths']['json'])
                if report.get('paths', {}).get('html'):
                    evidence_files.append(report['paths']['html'])
                    
                if evidence_files:
                    chain_id = self.sentinel.secure_files.create_evidence_chain(
                        target, mode, evidence_files
                    )
                    if chain_id:
                        self._print(f"[Brain] Evidence Chain: {chain_id}")
                        all_results['evidence_chain'] = chain_id
        except Exception as e:
            logger.debug(f"Evidence chain creation failed: {e}")

        elapsed  = round(time.time() - t0, 1)
        risk     = report.get('risk', 'LOW')
        findings = report.get('findings', [])

        # ── Physical agents: scan complete ────────────────────────────────────
        # Evidence collect karo
        try:
            ev = self.filesystem_agent.collect_evidence(target, all_results)
            self._print(f"[FileSystem] Evidence: {ev['directory']} ({ev['total']} files)")
        except Exception:
            pass

        # Final notification
        self.notifier.scan_complete(target, risk, len(findings))

        # System monitor stop
        self.system_monitor.stop_monitoring()
        sys_stats = self.system_monitor.get_stats()

        self._print(f"\n{'='*60}")
        self._print(f"  BRAIN COMPLETE — {target}")
        self._print(f"  Time     : {elapsed}s")
        self._print(f"  Risk     : {risk}")
        self._print(f"  Findings : {len(findings)}")
        self._print(f"  Telegram : {'✓' if report.get('telegram') else '✗'}")
        if sys_stats:
            self._print(f"  CPU peak : {sys_stats.get('cpu',{}).get('percent',0)}%")
            self._print(f"  RAM peak : {sys_stats.get('memory',{}).get('percent',0)}%")
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

        # RL state init
        rl_state = ScanState(target) if self._rl else None

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
            
            # Check if action signals completion
            if action_result.get('_done'):
                self._print(f"[ReAct] Scan complete signal received\n")
                break

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

            # ── Save findings to DB (deduplicate) ────────────────────────────
            existing_keys = {
                f"{f['severity']}:{f['title']}"
                for f in self.memory.recall_findings(target)
            }
            for f in action_result.get('_findings', []):
                key = f"{f.get('severity','')}:{f.get('title','')}"
                if key not in existing_keys:
                    try:
                        self.memory.remember_finding(
                            target, next_action,
                            f.get('severity', 'MEDIUM'),
                            f.get('title', ''),
                            f.get('detail', ''),
                            f.get('fix', '')
                        )
                        existing_keys.add(key)
                    except Exception:
                        pass

            # ── RL: state update + reward ─────────────────────────────────────
            if self._rl and rl_state:
                state_before_vec = rl_state.to_vector()
                from sentinel_brain.rl_agent import ACTIONS
                tool_name = next_action
                for a in ACTIONS:
                    if a in next_action.lower():
                        tool_name = a
                        break
                prev_findings  = list(rl_state.findings)
                prev_ports     = list(rl_state.ports_found)
                prev_subs      = list(rl_state.subdomains)
                rl_state.update(tool_name, action_result)
                class _Prev:
                    findings    = prev_findings
                    ports_found = prev_ports
                    subdomains  = prev_subs
                # _findings se direct reward calculate karo
                direct_reward = 0.0
                for f in action_result.get('_findings', []):
                    sev = f.get('severity', 'LOW')
                    if sev == 'CRITICAL':   direct_reward += 20
                    elif sev == 'HIGH':     direct_reward += 10
                    elif sev == 'MEDIUM':   direct_reward += 5
                # agent summary se bhi check karo
                summary = action_result.get('_agent_summary', '')
                if 'port' in summary.lower() or 'subdomain' in summary.lower():
                    direct_reward += 2
                if direct_reward == 0:
                    direct_reward = -1  # nothing found
                reward = direct_reward
                self._rl.update_q(state_before_vec, tool_name, reward, rl_state.to_vector())
                self._rl.episode_rewards.append(reward)
                self._print(f"  [RL] tool={tool_name} reward={reward:+.1f} | states={len(self._rl.q_table)}")

            # ── CRITICAL finding → turant notification ────────────────────────
            for f in action_result.get('_findings', []):
                if f.get('severity') == 'CRITICAL':
                    try:
                        self.notifier.critical_finding(
                            target, f.get('title',''), f.get('detail','')
                        )
                    except Exception:
                        pass
                    break

            # ── ADAPT PLAN ────────────────────────────────────────────────────
            plan = self._adapt_plan(target, plan, next_action, action_result, results)

        # RL save karo
        if self._rl:
            try:
                self._rl._save_q_table()
                from modules.database import SentinelDB
                if rl_state:
                    SentinelDB.save_rl_episode(
                        target=target, episode=len(self._rl.episode_rewards)+1,
                        tools_used=list(rl_state.tools_used),
                        total_reward=sum(self._rl.episode_rewards[-1:] or [0]),
                        findings=len(rl_state.findings),
                        risk=rl_state.risk_level,
                        epsilon=self._rl.epsilon
                    )
            except (OSError, IOError) as e:
                logger.error(f"RL save I/O error: {e}")
            except Exception as e:
                logger.error(f"RL save error: {e}")

        return results

    def _make_plan(self, target: str, mode: str) -> list:
        """Genetic algorithm se optimal tool order lo"""
        base_plans = {
            'recon':     ['kali_recon', 'recon'],
            'bugbounty': ['kali_recon', 'bugbounty', 'kali_exploit'],
            'osint':     ['osint'],
            'breach':    ['breach'],
        }
        if mode in base_plans:
            return base_plans[mode]
        # Full mode — kali_recon pehle, phir baaki
        optimal = self.adv_ml.get_optimal_scan_order()
        self._print(f"  [Genetic] Optimal order: {' → '.join(optimal[:4])}")
        return ['kali_recon', 'network', 'recon', 'threat_intel', 'bugbounty', 'kali_exploit', 'osint', 'breach', 'darkweb']

    def _reason(self, target: str, plan: list, results: dict, step: int) -> str:
        """Model dekhta hai kya hua, khud decide karta hai next step"""
        remaining = [p for p in plan if p not in results]
        if not remaining:
            return 'done'

        # Abhi tak kya mila — model ko ACCURATE context do (no hallucination)
        context_parts = [f"target={target}"]
        for action, result in results.items():
            summary = result.get('_agent_summary', '')
            if summary:
                # Clean summary - actual numbers only
                context_parts.append(f"{action}: {summary}")

        context = ' '.join(context_parts)[:400]

        if not self._model and not self._seq2seq:
            return remaining[0]

        try:
            # ── Groq LLM: best reasoning ──────────────────────────────────
            if self._groq and self._groq.is_ready and results:
                last_action = list(results.keys())[-1]
                last_result = results[last_action]
                summary     = last_result.get('_agent_summary', '')
                
                # Validate summary has actual findings before asking Groq
                has_findings = any([
                    'found' in summary.lower(),
                    'detected' in summary.lower(),
                    'vulnerable' in summary.lower(),
                    any(str(num) in summary for num in range(1, 100) if f'{num} ' in summary or f'={num}' in summary)
                ])
                
                # Only use Groq if there are actual findings to reason about
                if has_findings:
                    next_tool = self._groq.chain_gen(last_action, summary)
                    if next_tool:
                        tool_to_action = {
                            'nmap': 'kali_recon', 'subfinder': 'kali_recon',
                            'amass': 'kali_recon', 'theHarvester': 'kali_recon',
                            'nikto': 'kali_exploit', 'nuclei': 'kali_exploit',
                            'gobuster': 'kali_exploit', 'ffuf': 'kali_exploit',
                            'sqlmap': 'bugbounty', 'commix': 'bugbounty',
                            'wpscan': 'bugbounty', 'hydra': 'kali_exploit',
                        }
                        mapped = tool_to_action.get(next_tool, '')
                        if mapped and mapped in remaining:
                            self._print(f"  [Groq] next_tool={next_tool} → {mapped}")
                            return mapped

            # ── Seq2Seq: fallback ─────────────────────────────────────────
            elif self._seq2seq and results:
                last_action = list(results.keys())[-1]
                last_result = results[last_action]
                summary     = last_result.get('_agent_summary', '')
                next_tool   = self._seq2seq.chain_gen(
                    f'[CURRENT_TOOL] {last_action} [FINDING] {summary} [STATE] scan in progress'
                )
                if next_tool:
                    tool_to_action = {
                        'nmap': 'kali_recon', 'subfinder': 'kali_recon',
                        'amass': 'kali_recon', 'theHarvester': 'kali_recon',
                        'nikto': 'kali_exploit', 'nuclei': 'kali_exploit',
                        'gobuster': 'kali_exploit', 'ffuf': 'kali_exploit',
                        'sqlmap': 'bugbounty', 'commix': 'bugbounty',
                        'wpscan': 'bugbounty', 'hydra': 'kali_exploit',
                    }
                    mapped = tool_to_action.get(next_tool, '')
                    if mapped and mapped in remaining:
                        self._print(f"  [Seq2Seq] next_tool={next_tool} → {mapped}")
                        return mapped

            # ── Classifier: label + action_hint + threat_type se decide ──────
            if self._model:
                pred        = self._model.predict(context)
                label       = pred.get('label', 'LOW')
                action_hint = pred.get('action_hint', '')
                threat_type = pred.get('threat_type', '')
                conf        = pred.get('confidence', 0)
                self._print(f"  [ML] {label} | {threat_type} | {action_hint} | conf={conf:.0%}")

                hint_map = {
                    'patch_now':        'bugbounty',
                    'escalate':         'breach',
                    'investigate':      'osint',
                    'block_ip':         'kali_exploit',
                    'collect_evidence': 'kali_recon',
                    'notify_team':      'bugbounty',
                    'monitor':          remaining[0],
                }
                if label == 'CRITICAL' and 'bugbounty' in remaining:
                    return 'bugbounty'
                if label == 'CRITICAL' and 'kali_exploit' in remaining:
                    return 'kali_exploit'
                suggested = hint_map.get(action_hint, '')
                if suggested and suggested in remaining:
                    return suggested
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
        if not target or not isinstance(target, str):
            return {'success': False, '_agent_summary': 'Invalid target'}
        if not action or not isinstance(action, str):
            return {'success': False, '_agent_summary': 'Invalid action'}
        if not isinstance(results, dict):
            results = {}
        
        # Handle done/report/finish signals
        if action in ('done', 'generate_report', 'finish', 'report', 'complete'):
            return {'success': True, '_agent_summary': 'Scan complete - ready for report',
                    '_done': True}
        
        try:
            if action == 'recon':
                # kali_recon already nmap run kar chuka hai — skip nmap
                kali_done = any(r.get('_nmap_done') for r in results.values() if isinstance(r, dict))
                return self.recon_agent.run(target, skip_nmap=kali_done)

            elif action == 'kali_recon':
                self._print(f"  [Kali] Running recon chain on {target}")
                chain = self.kali.chain_recon(target)
                ports = chain.get('nmap', {}).get('total', 0)
                subs  = chain.get('subfinder', {}).get('total', 0)
                self.memory.remember_scan(target, 'kali_recon', 'MEDIUM',
                    f'{ports} ports, {subs} subdomains', chain)
                return {'success': True, '_agent_summary': f'{ports} ports, {subs} subdomains',
                        '_nmap_done': True, **chain}

            elif action == 'threat_intel':
                recon = results.get('recon', results.get('kali_recon', {}))
                tech_stack = recon.get('tech_stack', recon.get('technologies', {}))
                return self.threat_intel_agent.run(target, tech_stack=tech_stack)

            elif action == 'network':
                return self.network_agent.run(target)

            elif action == 'attack_chain':
                recon = results.get('recon', results.get('kali_recon', {}))
                intel = results.get('threat_intel', {})
                return self.attack_chain_agent.run(target, recon_data=recon,
                                                   threat_intel=intel, auto=True)

            elif action == 'monitor':
                return self.monitor_agent.run(target, brain=self)

            elif action == 'darkweb':
                return self.darkweb_agent.run(target)

            elif action == 'correlate':
                return self.correlation_agent.run(target)

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
        from modules.safe_data import has_findings
        if has_findings(last_result, 'github_dorks', 'total_secrets'):
            if 'breach' not in plan:
                new_steps.append('breach')
                self._print(f"  [Adapt] GitHub secrets → breach check")

        for step in new_steps:
            if step not in plan:
                plan.append(step)

        return plan

    # ── Direct Tool Execution ─────────────────────────────────────────────────

    def generate_command(self, context: str, threat_level: str = 'HIGH',
                         threat_type: str = 'web_vuln') -> str:
        """Groq ya Seq2Seq se exact kali command generate karo."""
        # Groq first — better quality
        if self._groq and self._groq.is_ready:
            cmd = self._groq.cmd_gen(context, threat_level, threat_type)
            if cmd:
                return cmd
        # Seq2Seq fallback
        if self._seq2seq:
            cmd = self._seq2seq.cmd_gen(
                f'[SCAN_CONTEXT] {context} [THREAT] {threat_level} [TYPE] {threat_type}'
            )
            if cmd:
                return cmd
        return ''

    def ask(self, prompt: str) -> str:
        """Natural language prompt — Groq se answer lo."""
        if self._groq and self._groq.is_ready:
            return self._groq.ask(prompt)
        return 'Groq API not configured. Add GROQ_API_KEY to .env'

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
        if not command or not isinstance(command, str):
            logger.error("Invalid shell command")
            return {'success': False, 'error': 'Invalid command'}
        if timeout <= 0 or timeout > 3600:
            timeout = 120
        
        # Command injection check
        dangerous = ['rm -rf /', 'mkfs', 'dd if=', ':(){:|:&};:', 'fork()']
        if any(d in command for d in dangerous):
            logger.error(f"Dangerous command blocked: {command}")
            return {'success': False, 'error': 'Dangerous command blocked'}
        
        try:
            self._print(f"[Terminal] $ {command}")
            r = self.kali.run(command, timeout=timeout)
            if r and isinstance(r, dict) and r.get('stdout'):
                self._print(r['stdout'][:2000])
            return r
        except Exception as e:
            logger.error(f"Shell execution error: {e}")
            return {'success': False, 'error': str(e)}

    def memory_stats(self) -> dict:
        return self.memory.stats()
