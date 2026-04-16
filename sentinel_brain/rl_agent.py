"""
Sentinel RL Agent — Reinforcement Learning for Autonomous Tool Selection
========================================================================
Q-Learning based agent jo khud seekhta hai ki kaunsa tool kab chalana hai.

State  : scan results abhi tak (ports, findings, risk)
Action : next tool choose karo
Reward : finding mili = +10, new info = +5, nothing = -1, error = -2

Author: @who_is_the_black_hat
"""

import json
import logging
import random
import time
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)

Q_TABLE_PATH = Path('/home/kali/osints/models/ml_engine/rl_qtable.json')

# ── Actions ───────────────────────────────────────────────────────────────────
ACTIONS = [
    'nmap',         # port scan + service detection
    'nikto',        # web vuln scan
    'nuclei',       # template scan
    'gobuster',     # directory brute
    'ffuf',         # web fuzzer
    'sqlmap',       # sql injection (forms pe)
    'amass',        # subdomain enum
    'whatweb',      # tech fingerprint
    'wafw00f',      # WAF detection
    'sslscan',      # ssl check
    'theHarvester', # email/domain osint
    'searchsploit', # exploit search
    'breach',       # breach check
    'report',       # stop
]

# ── Rewards ───────────────────────────────────────────────────────────────────
REWARDS = {
    'critical_finding': +20,
    'high_finding':     +10,
    'medium_finding':   +5,
    'new_subdomain':    +3,
    'new_endpoint':     +2,
    'nothing_found':    -1,
    'tool_error':       -2,
    'duplicate':        -3,
    'report':           +5,   # episode end
}


class ScanState:
    """
    Abhi tak kya hua — RL agent ka state
    """
    def __init__(self, target: str):
        self.target        = target
        self.tools_used    = set()
        self.findings      = []        # {severity, title, tool}
        self.ports_found   = []
        self.subdomains    = []
        self.endpoints     = []
        self.risk_level    = 'LOW'
        self.step          = 0

    def to_vector(self) -> tuple:
        """State ko tuple mein convert karo — Q-table key"""
        return (
            len(self.tools_used),
            len(self.findings),
            len(self.ports_found),
            len(self.subdomains),
            len(self.endpoints),
            self.risk_level,
            # Kaunse tools use ho chuke
            int('nmap'      in self.tools_used),
            int('nikto'     in self.tools_used),
            int('sqlmap'    in self.tools_used),
            int('gobuster'  in self.tools_used),
            int('nuclei'    in self.tools_used),
            int('subfinder' in self.tools_used),
            int('breach'    in self.tools_used),
        )

    def update(self, tool: str, result: dict):
        self.tools_used.add(tool)
        self.step += 1

        # result string bhi ho sakta hai — dict ensure karo
        if not isinstance(result, dict):
            return

        parsed = result.get('parsed', {})
        if not isinstance(parsed, dict):
            parsed = {}

        # Ports
        new_ports = parsed.get('open_ports', [])
        self.ports_found.extend(new_ports)

        # Subdomains
        new_subs = parsed.get('subdomains', [])
        self.subdomains.extend(new_subs)

        # Findings — dict ya string dono handle karo
        SKIP_PREFIXES = ('target ip', 'target hostname', 'target port',
                         'start time', 'end time', '+ end time', 'server:')
        for f in parsed.get('findings', []):
            if isinstance(f, dict):
                self.findings.append({
                    'severity': f.get('severity', 'MEDIUM'),
                    'title':    f.get('template', f.get('title', tool)),
                    'tool':     tool,
                })
            elif isinstance(f, str) and len(f) > 10:
                # Skip non-vulnerability lines
                fl = f.lower()
                if any(fl.startswith(p) for p in SKIP_PREFIXES):
                    continue
                sev = 'HIGH' if any(k in fl for k in
                      ['xss', 'inject', 'vuln', 'critical', 'rce',
                       'exec', 'traversal', 'disclosure', 'exposed']) else 'MEDIUM'
                self.findings.append({'severity': sev, 'title': f[:80], 'tool': tool})

        # Risk update
        if self.findings:
            sevs = [f['severity'] for f in self.findings]
            if 'CRITICAL' in sevs:   self.risk_level = 'CRITICAL'
            elif 'HIGH' in sevs:     self.risk_level = 'HIGH'
            elif 'MEDIUM' in sevs:   self.risk_level = 'MEDIUM'


class RLAgent:
    """
    Q-Learning agent — khud seekhta hai kaunsa tool kab chalana hai.

    Usage:
        agent = RLAgent()
        agent.train(targets=['neurodev.netlify.app'], episodes=50)
        agent.run('neurodev.netlify.app', kali_controller)
    """

    def __init__(self, alpha=0.1, gamma=0.9, epsilon=0.3):
        self.alpha   = alpha    # learning rate
        self.gamma   = gamma    # future reward discount
        self.epsilon = epsilon  # exploration rate

        self.q_table  = {}      # state → {action: q_value}
        self.episode_rewards = []
        self._load_q_table()

    # ── Q-Table ───────────────────────────────────────────────────────────────

    def _get_q(self, state: tuple, action: str) -> float:
        return self.q_table.get(str(state), {}).get(action, 0.0)

    def _set_q(self, state: tuple, action: str, value: float):
        key = str(state)
        if key not in self.q_table:
            self.q_table[key] = {}
        self.q_table[key][action] = round(value, 4)

    def _best_action(self, state: tuple, available: list) -> str:
        q_vals = {a: self._get_q(state, a) for a in available}
        return max(q_vals, key=q_vals.get)

    # ── Action Selection ──────────────────────────────────────────────────────

    def choose_action(self, state: ScanState) -> str:
        """Epsilon-greedy: explore ya exploit"""
        available = [a for a in ACTIONS if a not in state.tools_used]
        if not available:
            return 'report'

        # Explore
        if random.random() < self.epsilon:
            return random.choice(available)

        # Exploit — best Q value
        return self._best_action(state.to_vector(), available)

    # ── Reward Calculation ────────────────────────────────────────────────────

    def calculate_reward(self, tool: str, result: dict,
                         state_before: ScanState, state_after: ScanState) -> float:
        reward = 0.0

        if not isinstance(result, dict) or not result.get('success', True):
            return REWARDS['tool_error']

        # New findings
        new_findings = len(state_after.findings) - len(state_before.findings)
        for f in state_after.findings[len(state_before.findings):]:
            sev = f.get('severity', 'MEDIUM')
            if sev == 'CRITICAL':   reward += REWARDS['critical_finding']
            elif sev == 'HIGH':     reward += REWARDS['high_finding']
            else:                   reward += REWARDS['medium_finding']

        # New subdomains
        new_subs = len(state_after.subdomains) - len(state_before.subdomains)
        reward += new_subs * REWARDS['new_subdomain']

        # New ports
        new_ports = len(state_after.ports_found) - len(state_before.ports_found)
        reward += new_ports * REWARDS['new_endpoint']

        # Nothing found
        if new_findings == 0 and new_subs == 0 and new_ports == 0:
            reward += REWARDS['nothing_found']

        # Report action
        if tool == 'report':
            reward += REWARDS['report']

        return reward

    # ── Q-Learning Update ─────────────────────────────────────────────────────

    def update_q(self, state: tuple, action: str, reward: float, next_state: tuple):
        """Q(s,a) = Q(s,a) + alpha * (reward + gamma * max_Q(s') - Q(s,a))"""
        available_next = [a for a in ACTIONS]
        max_next_q = max(self._get_q(next_state, a) for a in available_next)

        current_q = self._get_q(state, action)
        new_q     = current_q + self.alpha * (reward + self.gamma * max_next_q - current_q)
        self._set_q(state, action, new_q)

    # ── Training ──────────────────────────────────────────────────────────────

    def train(self, targets: list, kali, episodes: int = 100,
              print_fn=None):
        """
        Real targets pe train karo.
        kali = KaliController instance
        """
        _print = print_fn or print
        _print(f"\n[RL] Training shuru — {episodes} episodes on {targets}")
        _print(f"[RL] alpha={self.alpha} gamma={self.gamma} epsilon={self.epsilon}\n")

        for ep in range(1, episodes + 1):
            target       = random.choice(targets)
            state        = ScanState(target)
            total_reward = 0.0
            done         = False

            _print(f"[RL] Episode {ep}/{episodes} — {target}")

            while not done and state.step < 8:
                state_vec = state.to_vector()
                action    = self.choose_action(state)

                if action == 'report':
                    total_reward += REWARDS['report']
                    done = True
                    break

                # Tool chalao
                result = self._execute_tool(action, target, state, kali)

                # State update
                state_before = ScanState(target)
                state_before.findings   = list(state.findings)
                state_before.ports_found = list(state.ports_found)
                state_before.subdomains  = list(state.subdomains)

                state.update(action, result)

                # Reward calculate karo
                reward = self.calculate_reward(action, result, state_before, state)
                total_reward += reward

                # Q update
                self.update_q(state_vec, action, reward, state.to_vector())

                _print(f"  {action:12s} → reward={reward:+.1f} | findings={len(state.findings)} ports={len(state.ports_found)}")

            self.episode_rewards.append(total_reward)
            _print(f"  Episode {ep} total reward: {total_reward:+.1f} | risk={state.risk_level}\n")

            # DB mein save karo
            try:
                from modules.database import SentinelDB
                SentinelDB.save_rl_episode(
                    target=target, episode=ep,
                    tools_used=list(state.tools_used),
                    total_reward=total_reward,
                    findings=len(state.findings),
                    risk=state.risk_level,
                    epsilon=self.epsilon
                )
                # Tool stats update
                for tool in state.tools_used:
                    found = any(f['tool'] == tool for f in state.findings)
                    SentinelDB.update_tool_stat(tool, found, 0)
            except Exception:
                pass

            # Epsilon decay — kam explore karo jaise seekhte hain
            self.epsilon = max(0.05, self.epsilon * 0.97)

            # Save every 10 episodes
            if ep % 10 == 0:
                self._save_q_table()
                avg = np.mean(self.episode_rewards[-10:])
                _print(f"[RL] Saved | Last 10 avg reward: {avg:.1f} | epsilon={self.epsilon:.3f}\n")

        self._save_q_table()
        _print(f"\n[RL] Training complete!")
        _print(f"[RL] Q-table: {len(self.q_table)} states learned")
        _print(f"[RL] Best episode reward: {max(self.episode_rewards):.1f}")

    def _execute_tool(self, action: str, target: str,
                      state: ScanState, kali) -> dict:
        try:
            from sentinel_brain.advanced_ml import SentinelGeneticOptimizer
            if not hasattr(self, '_genetic'):
                self._genetic = SentinelGeneticOptimizer()
        except Exception:
            pass

        start  = time.time()
        result = self._run_tool(action, target, kali)
        elapsed = time.time() - start

        # Always ensure dict
        if not isinstance(result, dict):
            result = {'success': False, 'stdout': str(result), 'parsed': {}}
        if not isinstance(result.get('parsed'), dict):
            result['parsed'] = {}

        found = bool(
            result['parsed'].get('findings') or
            result['parsed'].get('open_ports') or
            result['parsed'].get('subdomains')
        )
        if hasattr(self, '_genetic'):
            self._genetic.update_fitness(action, found, elapsed)

        return result

    def _run_tool(self, action: str, target: str, kali) -> dict:
        try:
            wl = '/usr/share/wordlists/dirb/common.txt'
            if action == 'nmap':
                return kali.run(f'nmap -sV -sC -T4 --open {target} 2>/dev/null', timeout=90)
            elif action == 'masscan':
                return kali.run(f'masscan {target} -p1-10000 --rate=1000 2>/dev/null | head -20', timeout=60)
            elif action == 'nikto':
                return kali.run(f'nikto -h https://{target} -maxtime 30 -nointeractive 2>/dev/null', timeout=45)
            elif action == 'sqlmap':
                return kali.run(f'sqlmap -u "https://{target}" --batch --level=1 --risk=1 --forms 2>/dev/null | tail -10', timeout=90)
            elif action == 'gobuster':
                return kali.run(f'gobuster dir -u https://{target} -w {wl} -q -t 20 2>/dev/null | head -20', timeout=60)
            elif action == 'ffuf':
                return kali.run(f'ffuf -u https://{target}/FUZZ -w {wl} -mc 200,301,302,403 -s 2>/dev/null | head -20', timeout=60)
            elif action == 'wfuzz':
                return kali.run(f'wfuzz -c -z file,{wl} --hc 404 https://{target}/FUZZ 2>/dev/null | head -20', timeout=60)
            elif action == 'nuclei':
                return kali.run(f'nuclei -u https://{target} -severity critical,high,medium -silent 2>/dev/null | head -30', timeout=120)
            elif action == 'amass':
                return kali.run(f'amass enum -passive -d {target} -timeout 2 2>/dev/null | head -30', timeout=60)
            elif action == 'whatweb':
                return kali.run(f'whatweb https://{target} --color=never 2>/dev/null', timeout=20)
            elif action == 'wafw00f':
                return kali.run(f'wafw00f https://{target} 2>/dev/null', timeout=20)
            elif action == 'wpscan':
                return kali.run(f'wpscan --url https://{target} --no-update --disable-tls-checks 2>/dev/null | tail -20', timeout=60)
            elif action == 'commix':
                return kali.run(f'commix --url="https://{target}" --batch --level=1 2>/dev/null | tail -10', timeout=60)
            elif action == 'hydra':
                return kali.run(f'hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt {target} http-get / -t 4 2>/dev/null | tail -5', timeout=30)
            elif action == 'searchsploit':
                # whatweb results se tech dhundho
                r = kali.run(f'whatweb https://{target} --color=never 2>/dev/null', timeout=15)
                tech = r.get('stdout', '')[:100]
                return kali.run(f'searchsploit {tech[:30]} 2>/dev/null | head -10', timeout=15)
            elif action == 'sslscan':
                return kali.run(f'sslscan --no-colour {target} 2>/dev/null | tail -20', timeout=30)
            elif action == 'theHarvester':
                return kali.run(f'theHarvester -d {target} -b bing,google -l 30 2>/dev/null | tail -20', timeout=60)
            elif action == 'breach':
                return kali.run(f'curl -s "https://breachdirectory.p.rapidapi.com/?func=auto&term={target}" 2>/dev/null | head -5', timeout=15)
        except Exception as e:
            return {'success': False, 'stdout': '', 'parsed': {}, 'error': str(e)}
        return {'success': False, 'stdout': '', 'parsed': {}}

    # ── Inference ─────────────────────────────────────────────────────────────

    def run(self, target: str, kali, print_fn=None) -> dict:
        _print    = print_fn or print
        state     = ScanState(target)
        old_eps   = self.epsilon
        self.epsilon = 0.0

        _print(f"\n[RL] Autonomous scan: {target}")

        # Pehla action hamesha nmap — baseline info chahiye
        _print(f"  [RL] Step 1: nmap (baseline)")
        result = self._execute_tool('nmap', target, state, kali)
        state.update('nmap', result)
        _print(f"  ports={len(state.ports_found)} risk={state.risk_level}")

        # Baaki steps Q-table se
        while not state.step >= 7:
            action = self.choose_action(state)
            if action == 'report':
                break

            _print(f"  [RL] Step {state.step+1}: {action}")
            result = self._execute_tool(action, target, state, kali)
            state.update(action, result)
            _print(f"  findings={len(state.findings)} ports={len(state.ports_found)} risk={state.risk_level}")

        self.epsilon = old_eps

        # DB mein save karo
        try:
            from modules.database import SentinelDB
            SentinelDB.save_scan(target, 'rl_scan', state.risk_level,
                {'tools': list(state.tools_used), 'findings': len(state.findings)}, source='rl')
            for f in state.findings:
                SentinelDB.save_finding(target, f['title'], f['severity'], f['title'], tool=f['tool'])
        except Exception:
            pass

        return {
            'target':     target,
            'findings':   state.findings,
            'ports':      state.ports_found,
            'risk':       state.risk_level,
            'tools_used': list(state.tools_used),
            'steps':      state.step,
        }

    # ── Save / Load ───────────────────────────────────────────────────────────

    def _save_q_table(self):
        Q_TABLE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(Q_TABLE_PATH, 'w') as f:
            json.dump({
                'q_table':        self.q_table,
                'epsilon':        self.epsilon,
                'episodes_done':  len(self.episode_rewards),
                'avg_reward':     float(np.mean(self.episode_rewards)) if self.episode_rewards else 0,
                'saved_at':       time.strftime('%Y-%m-%d %H:%M:%S'),
            }, f, indent=2)

    def _load_q_table(self):
        if Q_TABLE_PATH.exists():
            try:
                data = json.loads(Q_TABLE_PATH.read_text())
                self.q_table        = data.get('q_table', {})
                self.epsilon        = data.get('epsilon', self.epsilon)
                episodes_done       = data.get('episodes_done', 0)
                avg_reward          = data.get('avg_reward', 0)
                # episode_rewards reconstruct karo
                if episodes_done > 0 and not self.episode_rewards:
                    self.episode_rewards = [avg_reward] * episodes_done
                logger.info(f"[RL] Q-table loaded: {len(self.q_table)} states, epsilon={self.epsilon:.3f}")
            except Exception:
                pass

    def stats(self) -> dict:
        return {
            'states_learned': len(self.q_table),
            'episodes_done':  len(self.episode_rewards),
            'epsilon':        round(self.epsilon, 3),
            'avg_reward':     round(float(np.mean(self.episode_rewards)), 2) if self.episode_rewards else 0,
            'q_table_path':   str(Q_TABLE_PATH),
        }
