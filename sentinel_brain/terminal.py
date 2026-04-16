"""
Sentinel Terminal — Real PTY terminal control
Agent is terminal khol ke real commands chala sakta hai,
output dekh sakta hai, aur next step decide kar sakta hai.

Author: @who_is_the_black_hat
"""

import os
import pty
import select
import subprocess
import threading
import time
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_BLOCKED = [
    'rm -rf /', 'mkfs', ':(){:|:&};:', 'dd if=/dev/zero of=/dev/',
    'chmod -R 777 /', '> /dev/sda', 'shred /dev/',
]


class Terminal:
    """
    Real PTY terminal — agent commands execute karta hai aur output capture karta hai.
    Interactive tools (nmap, sqlmap, nikto) bhi chalte hain.
    """

    def __init__(self, cwd: str = None, timeout: int = 60):
        self.cwd     = cwd or str(Path.home())
        self.timeout = timeout
        self._history: list[dict] = []

    def run(self, command: str, timeout: int = None) -> dict:
        """
        Command execute karo — PTY se real output milta hai.
        Returns: {success, stdout, stderr, returncode, command}
        """
        timeout = timeout or self.timeout

        # Safety check
        for blocked in _BLOCKED:
            if blocked in command:
                return self._result(command, False, '', f'BLOCKED: {blocked}', -1)

        logger.info(f"Terminal: {command}")

        try:
            master_fd, slave_fd = pty.openpty()
            proc = subprocess.Popen(
                command, shell=True,
                stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
                cwd=self.cwd, close_fds=True,
                env={**os.environ, 'TERM': 'xterm', 'COLUMNS': '200'}
            )
            os.close(slave_fd)

            output_chunks = []
            deadline = time.time() + timeout

            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    proc.kill()
                    break
                ready, _, _ = select.select([master_fd], [], [], min(remaining, 0.5))
                if ready:
                    try:
                        chunk = os.read(master_fd, 4096).decode('utf-8', errors='replace')
                        output_chunks.append(chunk)
                    except OSError:
                        break
                elif proc.poll() is not None:
                    # Drain remaining output
                    try:
                        while True:
                            ready2, _, _ = select.select([master_fd], [], [], 0.1)
                            if not ready2: break
                            chunk = os.read(master_fd, 4096).decode('utf-8', errors='replace')
                            output_chunks.append(chunk)
                    except OSError:
                        pass
                    break

            os.close(master_fd)
            proc.wait(timeout=5)

            output = ''.join(output_chunks).strip()
            # ANSI escape codes clean karo
            import re
            output = re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', output)
            output = re.sub(r'\x1b\[\?[0-9;]*[hl]', '', output)

            result = self._result(command, proc.returncode == 0,
                                  output[:8000], '', proc.returncode)
            self._history.append(result)
            return result

        except Exception as e:
            logger.exception(f"Terminal error: {command}")
            return self._result(command, False, '', str(e), -1)

    def run_bg(self, command: str, log_file: str = None) -> subprocess.Popen:
        """Background mein command chalao — PID return karo"""
        for blocked in _BLOCKED:
            if blocked in command:
                raise ValueError(f'Blocked: {blocked}')
        log_path = log_file or f'/tmp/sentinel_bg_{int(time.time())}.log'
        with open(log_path, 'w') as lf:
            proc = subprocess.Popen(
                command, shell=True, stdout=lf, stderr=lf,
                cwd=self.cwd, start_new_session=True
            )
        logger.info(f"Background PID {proc.pid}: {command} → {log_path}")
        return proc

    def read_bg_output(self, log_file: str, tail: int = 50) -> str:
        """Background process ka output padhna"""
        try:
            lines = Path(log_file).read_text(errors='replace').splitlines()
            return '\n'.join(lines[-tail:])
        except Exception:
            return ''

    def get_history(self, last: int = 10) -> list:
        return self._history[-last:]

    @staticmethod
    def _result(cmd, success, stdout, stderr, rc) -> dict:
        return {
            'command':    cmd,
            'success':    success,
            'stdout':     stdout,
            'stderr':     stderr,
            'returncode': rc,
            'timestamp':  time.time(),
        }
