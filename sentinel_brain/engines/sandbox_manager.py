"""
Sandbox Manager - Multi-layer isolation engine (ASE Layer 1-4)

Layer 1: Language safety (safe env, restricted PATH)
Layer 2: Syscall filtering (resource limits via setrlimit)
Layer 3: Process isolation (Linux namespaces via unshare)
Layer 4: Escape detection (EscapeDetector — real-time process monitoring)
Layer 5: Container isolation (Docker/Podman — when available)
"""
import os
import resource
import shutil
import signal
import subprocess
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import psutil

from .risk_assessor import RiskAssessor, RiskLevel
from .escape_detector import EscapeDetector, SandboxForensicsDB

logger = logging.getLogger(__name__)


def _apply_resource_limits(limits: dict):
    """Called in child process (preexec_fn) to apply hard resource limits."""
    try:
        mem_bytes = limits['memory_mb'] * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS,   (mem_bytes, mem_bytes))
        resource.setrlimit(resource.RLIMIT_DATA,  (mem_bytes, mem_bytes))

        # Max open files
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))

        # Max processes (anti fork-bomb)
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))

        # Max file size written (disk_mb)
        disk_bytes = limits['disk_mb'] * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (disk_bytes, disk_bytes))

        # CPU time (seconds)
        cpu_sec = limits['timeout_sec']
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_sec, cpu_sec))

    except Exception as e:
        # Non-fatal — log but don't crash child
        import sys
        print(f"[sandbox] resource limit warning: {e}", file=sys.stderr)


class SandboxManager:
    def __init__(self, sandbox_dir: str = "/tmp/sentinel_sandbox"):
        self.sandbox_dir = Path(sandbox_dir)
        self.sandbox_dir.mkdir(parents=True, exist_ok=True)
        self.risk_assessor = RiskAssessor()
        self.active_sandboxes: dict = {}
        self.forensics_db = SandboxForensicsDB()
        self.escape_detector = EscapeDetector(self.forensics_db)

    # ── Public API ────────────────────────────────────────────────────────────

    def execute(self, command: str, risk_level: RiskLevel = None,
                timeout: int = None) -> tuple:
        """
        Execute command in sandbox with appropriate isolation.
        Returns: (success: bool, output: str, error: str)
        """
        if risk_level is None:
            risk_level = self.risk_assessor.assess_command(command)

        limits = self.risk_assessor.get_resource_limits(risk_level)
        if timeout is None:
            timeout = limits['timeout_sec']

        sandbox_id = self._create_sandbox_env(command, risk_level)
        logger.info(f"Sandbox execute: [{risk_level.name}] {command[:80]}")

        try:
            if risk_level == RiskLevel.CRITICAL:
                result = self._execute_container(command, sandbox_id, timeout, limits)
            elif risk_level == RiskLevel.HIGH:
                result = self._execute_process_monitored(command, sandbox_id, timeout, limits)
            elif risk_level == RiskLevel.MEDIUM:
                result = self._execute_process_monitored(command, sandbox_id, timeout, limits)
            else:
                result = self._execute_filtered(command, sandbox_id, timeout, limits)

            exit_code = 0 if result[0] else 1
            escape = self._had_escape(sandbox_id)
            self.forensics_db.close_run(sandbox_id, exit_code, escape)
            return result

        finally:
            self._cleanup_sandbox(sandbox_id)

    def get_forensics(self, sandbox_id: str) -> list:
        """Get forensics events for a sandbox run."""
        return self.forensics_db.get_events(sandbox_id)

    def get_recent_runs(self, limit: int = 20) -> list:
        """Get recent sandbox run history."""
        return self.forensics_db.get_recent_runs(limit)

    def get_status(self) -> dict:
        return {
            'active_sandboxes': len(self.active_sandboxes),
            'sandbox_dir': str(self.sandbox_dir),
            'container_runtime': self._get_container_runtime(),
            'sandboxes': list(self.active_sandboxes.keys()),
        }

    # ── Execution layers ──────────────────────────────────────────────────────

    def _execute_filtered(self, command: str, sandbox_id: str,
                          timeout: int, limits: dict) -> tuple:
        """Layer 1-2: Safe env + resource limits via setrlimit."""
        work_dir = Path(self.active_sandboxes[sandbox_id]['path']) / "work"
        try:
            proc = subprocess.Popen(
                command, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=str(work_dir),
                env=self._get_safe_env(),
                preexec_fn=lambda: _apply_resource_limits(limits),
            )
            stdout, stderr = proc.communicate(timeout=timeout)
            return (proc.returncode == 0,
                    stdout.decode('utf-8', errors='ignore'),
                    stderr.decode('utf-8', errors='ignore'))

        except subprocess.TimeoutExpired:
            proc.kill()
            return False, "", f"Timeout after {timeout}s"
        except Exception as e:
            return False, "", str(e)

    def _execute_process_monitored(self, command: str, sandbox_id: str,
                                   timeout: int, limits: dict) -> tuple:
        """
        Layer 1-4: namespaces + resource limits + EscapeDetector monitoring.
        Falls back to filtered if unshare unavailable.
        """
        work_dir = Path(self.active_sandboxes[sandbox_id]['path']) / "work"
        allowed_uids = {os.getuid()}

        isolated_cmd = [
            'unshare',
            '--pid', '--net', '--mount', '--uts', '--ipc',
            '--fork', '--',
            'sh', '-c', command
        ]

        try:
            proc = subprocess.Popen(
                isolated_cmd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=str(work_dir),
                env=self._get_safe_env(),
                preexec_fn=lambda: _apply_resource_limits(limits),
            )

            # Start escape detector in background
            monitor_thread = self.escape_detector.monitor(
                root_pid=proc.pid,
                sandbox_id=sandbox_id,
                sandbox_dir=str(work_dir),
                allowed_uids=allowed_uids,
                kill_callback=self._kill_process_tree,
                timeout=float(timeout),
            )

            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                self._kill_process_tree(proc.pid)
                return False, "", f"Timeout after {timeout}s"
            finally:
                monitor_thread.join(timeout=1.0)

            # Check if escape was detected
            if self._had_escape(sandbox_id):
                return False, "", "ESCAPE DETECTED — process killed"

            return (proc.returncode == 0,
                    stdout.decode('utf-8', errors='ignore'),
                    stderr.decode('utf-8', errors='ignore'))

        except FileNotFoundError:
            logger.warning("unshare not available, falling back to filtered")
            return self._execute_filtered(command, sandbox_id, timeout, limits)
        except Exception as e:
            return False, "", str(e)

    def _execute_container(self, command: str, sandbox_id: str,
                           timeout: int, limits: dict) -> tuple:
        """Layer 5: Container isolation (Docker/Podman) with escape monitoring."""
        runtime = self._get_container_runtime()
        if not runtime:
            logger.warning("No container runtime — falling back to process+monitor")
            return self._execute_process_monitored(command, sandbox_id, timeout, limits)

        work_dir = Path(self.active_sandboxes[sandbox_id]['path']) / "work"

        container_cmd = [
            runtime, 'run', '--rm',
            '--name', sandbox_id,
            '--network', 'none',
            '--memory', f"{limits['memory_mb']}m",
            '--memory-swap', f"{limits['memory_mb']}m",
            '--cpus', str(limits['cpu_percent'] / 100.0),
            '--pids-limit', '64',
            '--read-only',
            '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
            '-v', f"{work_dir}:/work:rw",
            '-w', '/work',
            '--security-opt', 'no-new-privileges',
            '--security-opt', 'seccomp=unconfined',
            '--cap-drop', 'ALL',
            'alpine:latest',
            'sh', '-c', command
        ]

        try:
            proc = subprocess.Popen(
                container_cmd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )

            # Monitor the container host-side process too
            monitor_thread = self.escape_detector.monitor(
                root_pid=proc.pid,
                sandbox_id=sandbox_id,
                sandbox_dir=str(work_dir),
                allowed_uids={os.getuid()},
                kill_callback=lambda pid: self._kill_container(runtime, sandbox_id, pid),
                timeout=float(timeout),
            )

            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                self._kill_container(runtime, sandbox_id, proc.pid)
                return False, "", f"Timeout after {timeout}s"
            finally:
                monitor_thread.join(timeout=1.0)

            return (proc.returncode == 0,
                    stdout.decode('utf-8', errors='ignore'),
                    stderr.decode('utf-8', errors='ignore'))

        except Exception as e:
            return False, "", str(e)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _create_sandbox_env(self, command: str, risk_level: RiskLevel) -> str:
        sandbox_id = f"sb_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
        sandbox_path = self.sandbox_dir / sandbox_id
        sandbox_path.mkdir(parents=True, exist_ok=True)
        (sandbox_path / "work").mkdir()
        (sandbox_path / "tmp").mkdir()
        (sandbox_path / "logs").mkdir()

        self.active_sandboxes[sandbox_id] = {
            'path': str(sandbox_path),
            'created': datetime.now().isoformat(),
            'escape_detected': False,
        }
        self.forensics_db.log_run(sandbox_id, command, risk_level.name)
        return sandbox_id

    def _had_escape(self, sandbox_id: str) -> bool:
        events = self.forensics_db.get_events(sandbox_id)
        return any(e[1] == 'CRITICAL' for e in events)

    def _kill_process_tree(self, pid: int):
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                except psutil.NoSuchProcess:
                    pass
            parent.kill()
            logger.warning(f"[SANDBOX] Killed process tree rooted at pid={pid}")
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.debug(f"Kill tree error: {e}")

    def _kill_container(self, runtime: str, sandbox_id: str, pid: int):
        import subprocess as sp
        sp.run([runtime, 'kill', sandbox_id], stderr=sp.DEVNULL, timeout=5)
        self._kill_process_tree(pid)

    def _get_safe_env(self) -> dict:
        return {
            'PATH': '/usr/local/bin:/usr/bin:/bin',
            'HOME': '/tmp',
            'LANG': 'C.UTF-8',
            'LC_ALL': 'C.UTF-8',
        }

    def _get_container_runtime(self) -> Optional[str]:
        for rt in ['podman', 'docker']:
            if shutil.which(rt):
                return rt
        return None

    def _cleanup_sandbox(self, sandbox_id: str):
        if sandbox_id in self.active_sandboxes:
            sandbox_path = Path(self.active_sandboxes[sandbox_id]['path'])
            try:
                shutil.rmtree(sandbox_path)
            except Exception as e:
                logger.warning(f"Cleanup failed for {sandbox_id}: {e}")
            del self.active_sandboxes[sandbox_id]
