"""
SentinelNet Agent Core — ReAct Loop
=====================================
Reason → Act → Observe → Reason → ...

SentinelNet (v4.0) decides which tool to call next.
ToolRegistry executes the tool on the real system.
Agent loops until task complete or max_steps reached.

Author: @who_is_the_black_hat
"""

import json
import logging
import re
import time
from datetime import datetime
from pathlib import Path

from modules.tool_registry import ToolRegistry, ToolResult
from modules.database import SentinelDB as DB

logger = logging.getLogger(__name__)

# ── Prompt Templates ──────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are SentinelNet Agent — an autonomous cybersecurity AI running on Kali Linux.

Your job: complete the user's task by reasoning step-by-step and calling tools.

Available tools:
{tool_list}

Rules:
- Think before acting. Write your reasoning as THOUGHT.
- Then pick ONE tool as ACTION with JSON args.
- After observing the result, think again.
- When task is complete, write FINAL ANSWER.
- Never repeat the same tool+args twice.
- For shell commands: be specific, use real Linux commands.

Format STRICTLY:
THOUGHT: <your reasoning>
ACTION: <tool_name>
ARGS: {{"key": "value"}}

Or when done:
THOUGHT: <reasoning>
FINAL ANSWER: <summary of what was done and findings>
"""

# ── ReAct Agent ───────────────────────────────────────────────────────────────

class SentinelAgent:
    """
    ReAct (Reason + Act) autonomous agent.

    Flow:
        task → think → pick tool → execute → observe → think → ...
        → FINAL ANSWER

    SentinelNet v4.0 provides threat context at each step.
    ToolRegistry executes tools on the real system.
    """

    MAX_STEPS   = 12
    MIN_CONF    = 0.50

    def __init__(self, sentinel=None, console=None, auto: bool = False):
        self._sentinel = sentinel
        self._print    = console or print
        self.auto      = auto
        self.tools     = ToolRegistry(sentinel=sentinel, console=console)
        self._model    = self._load_model()
        self._history  = []   # (thought, action, args, observation)
        self._step     = 0

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
        """
        Run the agent on a task string.
        Returns final report dict.
        """
        self._print(f"\n{'='*60}")
        self._print(f"  SENTINEL AGENT")
        self._print(f"  Task   : {task}")
        self._print(f"  Model  : {'SentinelNet v4.0' if self._model else 'heuristic'}")
        self._print(f"  Auto   : {self.auto}")
        self._print(f"{'='*60}\n")

        context = self._build_context(task)
        self._step = 0

        while self._step < self.MAX_STEPS:
            self._step += 1
            self._print(f"[Step {self._step}/{self.MAX_STEPS}]")

            # ── THINK ──
            thought, action, args, is_final, final_answer = self._think(context, task)

            self._print(f"  THOUGHT : {thought}")

            if is_final:
                self._print(f"\n  FINAL ANSWER: {final_answer}")
                return self._build_report(task, final_answer)

            self._print(f"  ACTION  : {action}")
            self._print(f"  ARGS    : {json.dumps(args)}")

            # ── CONFIRM (if not auto) ──
            if not self.auto:
                self._print(f"  [?] Execute {action}? [Y/n]: ", end='')
                try:
                    ans = input().strip().lower()
                    if ans == 'n':
                        self._print("  Skipped.\n")
                        # Add skip to history so agent knows
                        self._history.append({
                            'step': self._step, 'thought': thought,
                            'action': action, 'args': args,
                            'observation': 'SKIPPED by user'
                        })
                        context = self._update_context(context, thought, action, args,
                                                       'SKIPPED by user')
                        continue
                except EOFError:
                    # EOF or Ctrl+D pressed - assume yes and proceed
                    logger.debug("Input EOF - proceeding with action")
                except KeyboardInterrupt:
                    # Ctrl+C - re-raise to let user stop
                    raise
                except Exception as e:
                    logger.warning(f"Input error: {e} - proceeding with action")

            # ── ACT ──
            t0     = time.time()
            result = self.tools.execute(action, args)
            elapsed= round(time.time() - t0, 1)

            observation = str(result)
            self._print(f"  OBSERVE : {observation[:200]}")
            self._print(f"  Time    : {elapsed}s\n")

            # ── ML threat assessment on observation ──
            threat_ctx = self._assess_threat(observation, result.data)
            if threat_ctx:
                self._print(f"  [ML] {threat_ctx}\n")

            # ── Save to DB ──
            DB.save_decision(
                target=args.get('target', task[:50]),
                agent='SentinelAgent',
                action=action,
                reason=thought[:200],
                priority=self._priority_from_threat(threat_ctx)
            )

            # ── Update context ──
            self._history.append({
                'step': self._step, 'thought': thought,
                'action': action, 'args': args,
                'observation': observation, 'threat': threat_ctx,
                'data': result.data if hasattr(result, 'data') and isinstance(result.data, dict) else {}
            })
            context = self._update_context(context, thought, action, args,
                                           observation, threat_ctx)

        # Max steps reached
        self._print(f"\n[!] Max steps ({self.MAX_STEPS}) reached.")
        return self._build_report(task, f"Max steps reached. Completed {self._step} steps.")

    # ── Thinking Engine ───────────────────────────────────────────────────────

    def _think(self, context: str, task: str) -> tuple:
        """
        Decide next action using SentinelNet + heuristic rules.
        Returns: (thought, action, args, is_final, final_answer)
        """
        # Build observation summary for model
        obs_text = self._history_to_text()

        # SentinelNet predict on current context
        model_pred = {}
        if self._model:
            try:
                model_pred = self._model.predict(f"{task} {obs_text}")
            except Exception:
                pass

        label       = model_pred.get('label', 'MEDIUM')
        threat_type = model_pred.get('threat_type', 'unknown')
        action_hint = model_pred.get('action_hint', 'investigate')
        reasoning   = model_pred.get('reasoning', '')
        confidence  = model_pred.get('confidence', 0.0)

        # Decide next tool based on history + model
        action, args, thought = self._decide_next(
            task, label, threat_type, action_hint, reasoning, confidence
        )

        # Check if we should finish
        if action == 'DONE':
            summary = self._build_summary()
            return (thought, None, {}, True, summary)

        return (thought, action, args, False, None)

    def _decide_next(self, task: str, label: str, threat_type: str,
                     action_hint: str, reasoning: str, confidence: float) -> tuple:
        """
        Rule-based + model-guided decision for next tool.
        Returns: (action, args, thought)
        """
        done_actions = {f"{h['action']}:{json.dumps(h['args'], sort_keys=True)}"
                        for h in self._history if h.get('action')}

        # Extract target from task
        target = self._extract_target(task)

        # ── Step 0: Always start with DB check ──
        if self._step == 1:
            key = f"db_query:{json.dumps({'target': target}, sort_keys=True)}"
            if key not in done_actions:
                return ('db_query', {'target': target},
                        f"First check DB history for {target}")

        # ── Step 1: Recon if not done ──
        recon_key = f"recon:{json.dumps({'target': target}, sort_keys=True)}"
        if recon_key not in done_actions and self._is_domain(target):
            return ('recon', {'target': target},
                    f"Start with passive recon on {target}")

        # ── Model-guided decisions ──
        last_obs = self._history[-1]['observation'] if self._history else ''
        last_action = self._history[-1].get('action', '') if self._history else ''

        # After recon — check what was found
        if last_action == 'recon' and self._history:
            from modules.safe_data import has_findings, get_github_secrets_count, get_cloud_assets_count
            
            last_data = self._history[-1].get('data', {})
            
            # GitHub secrets → bugbounty (safe check)
            if has_findings(last_data, 'github_dorks', 'total_secrets'):
                github_secrets = get_github_secrets_count(last_data)
                bb_key = f"bugbounty:{json.dumps({'target': target}, sort_keys=True)}"
                if bb_key not in done_actions:
                    return ('bugbounty', {'target': target},
                            f"GitHub secrets found ({github_secrets}) — run full vuln scan. {reasoning}")
            
            # Cloud assets → bugbounty (safe check)
            if has_findings(last_data, 'cloud_assets', 'total'):
                cloud_count = get_cloud_assets_count(last_data)
                bb_key = f"bugbounty:{json.dumps({'target': target}, sort_keys=True)}"
                if bb_key not in done_actions:
                    return ('bugbounty', {'target': target},
                            f"Cloud assets exposed ({cloud_count}) — check for misconfigs. {reasoning}")
            
            # Model says HIGH/CRITICAL → bugbounty
            if label in ('HIGH', 'CRITICAL'):
                bb_key = f"bugbounty:{json.dumps({'target': target}, sort_keys=True)}"
                if bb_key not in done_actions:
                    return ('bugbounty', {'target': target},
                            f"{reasoning}")

        # After bugbounty — check vulns
        if last_action == 'bugbounty' and self._history:
            data = self._history[-1].get('observation', '')
            if 'risk=critical' in data.lower() or 'risk=high' in data.lower():
                # Notify
                notify_key = f"notify:{json.dumps({'message': f'CRITICAL vuln on {target}'}, sort_keys=True)}"
                if notify_key not in done_actions:
                    return ('notify',
                            {'message': f'🚨 CRITICAL vulnerability found on {target}\n'
                                        f'SentinelNet Agent — @who_is_the_black_hat'},
                            f"CRITICAL vulns confirmed — send Telegram alert")
                # Save evidence
                ev_key = f"save_evidence:{json.dumps({'label': 'bugbounty_critical'}, sort_keys=True)}"
                if ev_key not in done_actions:
                    return ('save_evidence',
                            {'label': 'bugbounty_critical',
                             'data': {'target': target, 'risk': label}},
                            "Save critical findings to evidence vault")

        # action_hint from model
        if action_hint == 'patch_now' and label in ('CRITICAL', 'HIGH'):
            report_key = f"generate_report:{json.dumps({}, sort_keys=True)}"
            if report_key not in done_actions:
                return ('generate_report', {},
                        f"Model says patch_now — generate report for remediation")

        if action_hint == 'collect_evidence':
            ev_key = f"save_evidence:{json.dumps({'label': 'agent_evidence'}, sort_keys=True)}"
            if ev_key not in done_actions:
                return ('save_evidence',
                        {'label': 'agent_evidence', 'data': {'target': target, 'label': label}},
                        f"Model says collect_evidence — saving to vault")

        # Shell tool — for custom tasks
        if 'shell' in task.lower() or 'run' in task.lower() or 'execute' in task.lower():
            cmd = self._extract_shell_cmd(task)
            if cmd:
                shell_key = f"shell:{json.dumps({'command': cmd}, sort_keys=True)}"
                if shell_key not in done_actions:
                    return ('shell', {'command': cmd},
                            f"Task requires shell execution: {cmd}")

        # Breach check for emails found
        for h in self._history:
            obs = h.get('observation', '')
            emails = re.findall(r'[\w.+-]+@[\w-]+\.[a-z]{2,}', obs)
            for email in emails[:2]:
                breach_key = f"breach:{json.dumps({'target': email}, sort_keys=True)}"
                if breach_key not in done_actions:
                    return ('breach', {'target': email},
                            f"Email {email} found — check breach databases")

        # Generate report if we have scan data
        if len(self._history) >= 3:
            report_key = f"generate_report:{json.dumps({}, sort_keys=True)}"
            if report_key not in done_actions:
                return ('generate_report', {},
                        "Sufficient data collected — generate final report")

        # Nothing more to do
        return ('DONE', {}, f"Task complete. {len(self._history)} steps executed.")

    # ── Context Management ────────────────────────────────────────────────────

    def _build_context(self, task: str) -> str:
        tool_list = self.tools.tool_descriptions()
        return SYSTEM_PROMPT.format(tool_list=tool_list) + f"\n\nTASK: {task}\n"

    def _update_context(self, context: str, thought: str, action: str,
                        args: dict, observation: str, threat: str = '') -> str:
        entry = (f"\nSTEP {self._step}:\n"
                 f"THOUGHT: {thought}\n"
                 f"ACTION: {action}\n"
                 f"ARGS: {json.dumps(args)}\n"
                 f"OBSERVATION: {observation[:400]}\n")
        if threat:
            entry += f"ML ASSESSMENT: {threat}\n"
        return context + entry

    def _history_to_text(self) -> str:
        parts = []
        for h in self._history[-5:]:   # last 5 steps only
            parts.append(f"{h.get('action','')}({h.get('args',{})}) → {h.get('observation','')[:100]}")
        return ' | '.join(parts)

    # ── ML Threat Assessment ──────────────────────────────────────────────────

    def _assess_threat(self, observation: str, data: dict) -> str:
        if not self._model:
            return ''
        try:
            pred = self._model.predict(observation[:500])
            if pred['confidence'] >= self.MIN_CONF:
                return (f"label={pred['label']} type={pred['threat_type']} "
                        f"action={pred['action_hint']} conf={pred['confidence']:.0%} "
                        f"— {pred['reasoning']}")
        except Exception:
            pass
        return ''

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _extract_target(self, task: str) -> str:
        # Domain
        m = re.search(r'(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', task)
        if m:
            return m.group(1)
        # Email
        m = re.search(r'[\w.+-]+@[\w-]+\.[a-z]{2,}', task)
        if m:
            return m.group(0)
        # Phone
        m = re.search(r'\+?\d{10,15}', task)
        if m:
            return m.group(0)
        # Fallback — first word after common verbs
        m = re.search(r'(?:scan|investigate|check|recon|hack|test)\s+(\S+)', task, re.I)
        if m:
            return m.group(1)
        return task.split()[-1] if task.split() else task

    def _extract_shell_cmd(self, task: str) -> str:
        # Extract quoted command
        m = re.search(r'["`\'](.*?)["`\']', task)
        if m:
            return m.group(1)
        # After 'run' or 'execute'
        m = re.search(r'(?:run|execute|shell)\s+(.+)', task, re.I)
        if m:
            return m.group(1).strip()
        return ''

    def _is_domain(self, target: str) -> bool:
        return bool(re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target))

    def _priority_from_threat(self, threat_ctx: str) -> str:
        if not threat_ctx:
            return 'MEDIUM'
        if 'CRITICAL' in threat_ctx:
            return 'CRITICAL'
        if 'HIGH' in threat_ctx:
            return 'HIGH'
        if 'MEDIUM' in threat_ctx:
            return 'MEDIUM'
        return 'LOW'

    def _build_summary(self) -> str:
        actions = [h['action'] for h in self._history if h.get('action')]
        # Risk from actual scan data, not just observation text
        risk = 'LOW'
        for h in self._history:
            data = h.get('data', {})
            if isinstance(data, dict):
                r = data.get('_risk', data.get('risk_level', ''))
                if r in ('CRITICAL', 'HIGH', 'MEDIUM'):
                    if {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}.get(r, 3) < {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(risk, 3):
                        risk = r
            # Also check observation for explicit risk markers
            obs = h.get('observation', '')
            for level in ('CRITICAL', 'HIGH', 'MEDIUM'):
                if f'risk={level.lower()}' in obs.lower() or f'risk: {level}' in obs:
                    if {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}.get(level, 3) < {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(risk, 3):
                        risk = level
        return (f"Completed {len(self._history)} steps: {', '.join(actions)}. "
                f"Overall risk: {risk}.")

    def _build_report(self, task: str, final_answer: str) -> dict:
        stats = DB.stats()
        return {
            'task':         task,
            'steps':        self._step,
            'final_answer': final_answer,
            'history':      self._history,
            'db_stats':     stats,
            'timestamp':    datetime.now().isoformat(),
        }
