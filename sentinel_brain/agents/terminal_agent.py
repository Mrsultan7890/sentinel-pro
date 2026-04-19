"""
Terminal Agent — Multi-Terminal & Session Management
=====================================================
- Multiple xterm/tmux windows open karo
- Parallel scans chalao
- Background processes manage karo
- Real-time output stream karo
- Session save/restore karo

Author: @who_is_the_black_hat
"""

import logging
import os
import subprocess
import tempfile
import time
import threading
from pathlib import Path

import config

logger = logging.getLogger(__name__)

LOGS_DIR = config.LOGS_DIR


class TerminalAgent:
    NAME = 'terminal_agent'

    def __init__(self):
        self._sessions  = {}   # name → {proc, log, cmd, pid}
        self._lock      = threading.Lock()
        self._tmux_avail = self._check_tmux()
        self._xterm_avail = self._check_xterm()

    def _check_tmux(self) -> bool:
        return bool(subprocess.run(['which', 'tmux'],
                                   capture_output=True).returncode == 0)

    def _check_xterm(self) -> bool:
        return bool(subprocess.run(['which', 'xterm'],
                                   capture_output=True).returncode == 0)

    # ── Background Process ────────────────────────────────────────────────────

    def run_bg(self, command: str, name: str = None, log: bool = True) -> dict:
        """Command ko background mein chalao."""
        log_file = str(LOGS_DIR / f"bg_{name or int(time.time())}.log")
        try:
            with open(log_file, 'w') as lf:
                proc = subprocess.Popen(
                    command, shell=True,
                    stdout=lf, stderr=lf,
                    cwd=str(config.BASE_DIR),
                    start_new_session=True,
                    env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'},
                )
            key = name or f'bg_{proc.pid}'
            with self._lock:
                self._sessions[key] = {
                    'proc': proc, 'log': log_file,
                    'cmd': command, 'pid': proc.pid,
                    'started': time.time(), 'type': 'bg',
                }
            logger.info(f"[TerminalAgent] BG started: {key} PID={proc.pid}")
            return {'success': True, 'name': key, 'pid': proc.pid, 'log': log_file}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def run_parallel(self, commands: list) -> dict:
        """Multiple commands parallel chalao."""
        results = {}
        threads = []

        def _run(name, cmd):
            r = self.run_bg(cmd, name=name)
            results[name] = r

        for i, cmd in enumerate(commands):
            name = f'parallel_{i}_{int(time.time())}'
            t = threading.Thread(target=_run, args=(name, cmd), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=1)

        return results

    # ── xterm Window ──────────────────────────────────────────────────────────

    def open_xterm(self, command: str = None, title: str = 'Sentinel',
                   geometry: str = '120x35') -> dict:
        """Naya xterm window kholo."""
        if not self._xterm_avail:
            return {'success': False, 'error': 'xterm not available'}

        cmd_str = command or 'bash'
        xterm_cmd = (
            f"xterm -title '{title}' -geometry {geometry} "
            f"-bg '#1a1a2e' -fg '#e0e0e0' -fa 'Monospace' -fs 11 "
            f"-e {cmd_str}"
        )
        try:
            proc = subprocess.Popen(
                xterm_cmd, shell=True, start_new_session=True
            )
            key = f'xterm_{proc.pid}'
            with self._lock:
                self._sessions[key] = {
                    'proc': proc, 'pid': proc.pid,
                    'cmd': cmd_str, 'type': 'xterm',
                    'started': time.time(),
                }
            logger.info(f"[TerminalAgent] xterm opened: PID={proc.pid} title={title}")
            return {'success': True, 'pid': proc.pid, 'name': key}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def open_scan_terminal(self, target: str, scan_type: str = 'recon') -> dict:
        """Scan ke liye dedicated xterm window kholo."""
        script = f"""#!/bin/bash
cd {config.BASE_DIR}
source venv/bin/activate 2>/dev/null || true
echo "=== Sentinel Pro — {scan_type.upper()} ==="
echo "Target: {target}"
echo "Started: $(date)"
echo "================================"
python3 -c "
import sys
sys.path.insert(0, '{config.BASE_DIR}')
from sentinel_brain.brain import SentinelBrain
b = SentinelBrain()
b.run('{scan_type} {target}')
"
echo ""
echo "=== SCAN COMPLETE ==="
read -p "Press Enter to close..."
"""
        tmp = tempfile.NamedTemporaryFile(
            mode='w', suffix='.sh', prefix='sentinel_scan_', delete=False
        )
        tmp.write(script)
        tmp.flush()
        tmp.close()
        os.chmod(tmp.name, 0o755)

        return self.open_xterm(
            command=f'bash {tmp.name}',
            title=f'Sentinel — {scan_type} — {target}',
            geometry='140x40'
        )

    # ── tmux Sessions ─────────────────────────────────────────────────────────

    def tmux_new_session(self, name: str, command: str = None) -> dict:
        """Naya tmux session banao."""
        if not self._tmux_avail:
            return {'success': False, 'error': 'tmux not available'}
        cmd = f"tmux new-session -d -s '{name}'"
        if command:
            cmd += f" '{command}'"
        r = subprocess.run(cmd, shell=True, capture_output=True)
        return {'success': r.returncode == 0, 'session': name}

    def tmux_send(self, session: str, command: str) -> dict:
        """tmux session mein command bhejo."""
        if not self._tmux_avail:
            return {'success': False, 'error': 'tmux not available'}
        cmd = f"tmux send-keys -t '{session}' '{command}' Enter"
        r = subprocess.run(cmd, shell=True, capture_output=True)
        return {'success': r.returncode == 0}

    def tmux_capture(self, session: str) -> str:
        """tmux session ka output capture karo."""
        if not self._tmux_avail:
            return ''
        r = subprocess.run(
            f"tmux capture-pane -t '{session}' -p",
            shell=True, capture_output=True, text=True
        )
        return r.stdout

    def tmux_list(self) -> list:
        """Active tmux sessions list karo."""
        if not self._tmux_avail:
            return []
        r = subprocess.run(
            'tmux list-sessions 2>/dev/null',
            shell=True, capture_output=True, text=True
        )
        return [l.strip() for l in r.stdout.splitlines() if l.strip()]

    # ── Session Management ────────────────────────────────────────────────────

    def get_output(self, name: str, tail: int = 50) -> str:
        """Background process ka output lo."""
        with self._lock:
            entry = self._sessions.get(name, {})
        log_file = entry.get('log', '')
        if log_file and Path(log_file).exists():
            lines = Path(log_file).read_text(errors='replace').splitlines()
            return '\n'.join(lines[-tail:])
        return ''

    def is_running(self, name: str) -> bool:
        with self._lock:
            entry = self._sessions.get(name, {})
        proc = entry.get('proc')
        return proc is not None and proc.poll() is None

    def kill(self, name: str) -> bool:
        with self._lock:
            entry = self._sessions.get(name, {})
        proc = entry.get('proc')
        if proc:
            try:
                proc.terminate()
                return True
            except Exception:
                pass
        return False

    def kill_all(self):
        with self._lock:
            names = list(self._sessions.keys())
        for name in names:
            self.kill(name)

    def status(self) -> dict:
        with self._lock:
            sessions = dict(self._sessions)
        result = {}
        for name, entry in sessions.items():
            proc = entry.get('proc')
            result[name] = {
                'type':    entry.get('type', 'bg'),
                'pid':     entry.get('pid'),
                'running': proc.poll() is None if proc else False,
                'cmd':     entry.get('cmd', '')[:60],
                'started': entry.get('started'),
            }
        return result

    def cleanup_finished(self):
        """Finished processes ko sessions se hata do."""
        with self._lock:
            to_remove = [
                name for name, entry in self._sessions.items()
                if entry.get('proc') and entry['proc'].poll() is not None
            ]
            for name in to_remove:
                del self._sessions[name]
        return len(to_remove)
