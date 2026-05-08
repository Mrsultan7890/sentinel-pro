"""
Escape Detector - ASE Layer 4
Monitors sandboxed processes for escape attempts in real-time.

Detects:
  - Privilege escalation (UID/GID changes, setuid binaries)
  - Network exfiltration (unexpected outbound connections)
  - Filesystem escape (access outside sandbox dir)
  - Process tree explosion (fork bombs)
  - Suspicious binary execution (shells, interpreters spawned)
  - Resource limit violations
"""
import os
import threading
import logging
import sqlite3
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import psutil

logger = logging.getLogger(__name__)

# ─── Forensics DB ─────────────────────────────────────────────────────────────

class SandboxForensicsDB:
    def __init__(self, db_path: str = "data/sandbox_forensics.db"):
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        self._init()

    def _init(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS sandbox_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                sandbox_id  TEXT NOT NULL,
                timestamp   TEXT NOT NULL,
                event_type  TEXT NOT NULL,
                severity    TEXT NOT NULL,
                pid         INTEGER,
                details     TEXT,
                auto_killed INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sandbox_runs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                sandbox_id  TEXT UNIQUE NOT NULL,
                command     TEXT,
                risk_level  TEXT,
                started_at  TEXT,
                ended_at    TEXT,
                exit_code   INTEGER,
                escape_detected INTEGER DEFAULT 0,
                event_count INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_events_sandbox
                ON sandbox_events(sandbox_id);
        """)
        self.conn.commit()

    def log_run(self, sandbox_id: str, command: str, risk_level: str):
        with self._lock:
            self.conn.execute("""
                INSERT OR IGNORE INTO sandbox_runs
                (sandbox_id, command, risk_level, started_at)
                VALUES (?, ?, ?, ?)
            """, (sandbox_id, command[:500], risk_level, datetime.now().isoformat()))
            self.conn.commit()

    def close_run(self, sandbox_id: str, exit_code: int, escape_detected: bool):
        with self._lock:
            cursor = self.conn.execute(
                "SELECT COUNT(*) FROM sandbox_events WHERE sandbox_id=?", (sandbox_id,))
            count = cursor.fetchone()[0]
            self.conn.execute("""
                UPDATE sandbox_runs
                SET ended_at=?, exit_code=?, escape_detected=?, event_count=?
                WHERE sandbox_id=?
            """, (datetime.now().isoformat(), exit_code,
                  1 if escape_detected else 0, count, sandbox_id))
            self.conn.commit()

    def log_event(self, sandbox_id: str, event_type: str, severity: str,
                  pid: Optional[int], details: dict, auto_killed: bool = False):
        with self._lock:
            self.conn.execute("""
                INSERT INTO sandbox_events
                (sandbox_id, timestamp, event_type, severity, pid, details, auto_killed)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (sandbox_id, datetime.now().isoformat(), event_type, severity,
                  pid, json.dumps(details), 1 if auto_killed else 0))
            self.conn.commit()

    def get_events(self, sandbox_id: str) -> list:
        cursor = self.conn.execute("""
            SELECT event_type, severity, pid, details, auto_killed, timestamp
            FROM sandbox_events WHERE sandbox_id=? ORDER BY id
        """, (sandbox_id,))
        return cursor.fetchall()

    def get_recent_runs(self, limit: int = 20) -> list:
        cursor = self.conn.execute("""
            SELECT sandbox_id, command, risk_level, started_at, ended_at,
                   exit_code, escape_detected, event_count
            FROM sandbox_runs ORDER BY id DESC LIMIT ?
        """, (limit,))
        return cursor.fetchall()

    def close(self):
        self.conn.close()


# ─── Escape Detector ──────────────────────────────────────────────────────────

# Binaries that should never be spawned inside a sandbox
SUSPICIOUS_BINARIES = {
    'bash', 'sh', 'zsh', 'fish', 'dash', 'ksh',       # shells
    'python', 'python3', 'ruby', 'perl', 'php',         # interpreters
    'nc', 'netcat', 'ncat', 'socat',                    # network tools
    'curl', 'wget', 'fetch',                             # downloaders
    'ssh', 'scp', 'sftp', 'rsync',                      # remote access
    'sudo', 'su', 'pkexec', 'doas',                     # privilege escalation
    'nsenter', 'unshare', 'chroot',                     # namespace escape
    'mount', 'umount',                                   # filesystem escape
    'iptables', 'ip6tables', 'nft',                     # firewall manipulation
    'insmod', 'modprobe', 'rmmod',                      # kernel modules
    'dd', 'mkfs',                                        # disk operations
}

# Paths that sandboxed processes must NOT access
FORBIDDEN_PATH_PREFIXES = [
    '/etc/passwd', '/etc/shadow', '/etc/sudoers',
    '/root/', '/home/',
    '/proc/sysrq-trigger', '/proc/sys/',
    '/sys/kernel/', '/sys/module/',
    '/dev/sda', '/dev/nvme', '/dev/mem', '/dev/kmem',
    '/boot/',
]


class EscapeDetector:
    """
    Monitors a sandboxed process tree in a background thread.
    Calls kill_callback(pid) and logs forensics on escape detection.
    """

    def __init__(self, db: SandboxForensicsDB, poll_interval: float = 0.3):
        self.db = db
        self.poll_interval = poll_interval

    def monitor(self, root_pid: int, sandbox_id: str, sandbox_dir: str,
                allowed_uids: set, kill_callback, timeout: float = 300.0):
        """
        Start monitoring in a background thread.
        Returns the thread — caller can join() it.
        """
        t = threading.Thread(
            target=self._monitor_loop,
            args=(root_pid, sandbox_id, sandbox_dir,
                  allowed_uids, kill_callback, timeout),
            daemon=True,
            name=f"escape-detector-{sandbox_id[:12]}"
        )
        t.start()
        return t

    def _monitor_loop(self, root_pid: int, sandbox_id: str, sandbox_dir: str,
                      allowed_uids: set, kill_callback, timeout: float):
        deadline = time.monotonic() + timeout
        escape_detected = False
        seen_pids = set()

        while time.monotonic() < deadline:
            try:
                if not psutil.pid_exists(root_pid):
                    break

                # Collect entire process tree
                try:
                    root = psutil.Process(root_pid)
                    tree = [root] + root.children(recursive=True)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    break

                for proc in tree:
                    try:
                        pid = proc.pid
                        if pid in seen_pids:
                            continue
                        seen_pids.add(pid)

                        # 1. Privilege escalation check
                        escape = self._check_privilege_escalation(
                            proc, sandbox_id, allowed_uids)
                        if escape:
                            escape_detected = True
                            kill_callback(root_pid)
                            return

                        # 2. Suspicious binary check
                        escape = self._check_suspicious_binary(
                            proc, sandbox_id)
                        if escape:
                            escape_detected = True
                            kill_callback(root_pid)
                            return

                        # 3. Network exfiltration check
                        self._check_network_connections(proc, sandbox_id)

                        # 4. Fork bomb / process explosion
                        escape = self._check_process_explosion(
                            tree, sandbox_id, root_pid)
                        if escape:
                            escape_detected = True
                            kill_callback(root_pid)
                            return

                        # 5. Filesystem escape check
                        self._check_filesystem_access(
                            proc, sandbox_id, sandbox_dir)

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

            except Exception as e:
                logger.debug(f"EscapeDetector loop error: {e}")

            time.sleep(self.poll_interval)

        if escape_detected:
            logger.warning(f"[ESCAPE] sandbox={sandbox_id} — process tree killed")

    # ── Individual checks ────────────────────────────────────────────────────

    def _check_privilege_escalation(self, proc: psutil.Process,
                                    sandbox_id: str, allowed_uids: set) -> bool:
        try:
            uids = proc.uids()
            gids = proc.gids()
            # Root UID = 0 is never allowed inside sandbox
            if uids.effective == 0 or uids.real == 0:
                self.db.log_event(sandbox_id, 'PRIVILEGE_ESCALATION', 'CRITICAL',
                                  proc.pid, {
                                      'name': proc.name(),
                                      'real_uid': uids.real,
                                      'effective_uid': uids.effective,
                                      'cmdline': ' '.join(proc.cmdline()[:10]),
                                  }, auto_killed=True)
                logger.critical(f"[ESCAPE] Privilege escalation: pid={proc.pid} "
                                f"uid={uids.effective} sandbox={sandbox_id}")
                return True

            # UID changed outside allowed set
            if allowed_uids and uids.effective not in allowed_uids:
                self.db.log_event(sandbox_id, 'UID_CHANGE', 'HIGH', proc.pid, {
                    'name': proc.name(),
                    'effective_uid': uids.effective,
                    'allowed_uids': list(allowed_uids),
                }, auto_killed=False)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return False

    def _check_suspicious_binary(self, proc: psutil.Process,
                                  sandbox_id: str) -> bool:
        try:
            name = proc.name().lower()
            exe = proc.exe() if proc.exe() else ''

            if name in SUSPICIOUS_BINARIES:
                # Extra check: is it a setuid binary?
                is_setuid = False
                try:
                    stat = os.stat(exe)
                    is_setuid = bool(stat.st_mode & 0o4000)
                except Exception:
                    pass

                severity = 'CRITICAL' if is_setuid or name in {
                    'sudo', 'su', 'pkexec', 'nsenter', 'unshare', 'chroot'
                } else 'HIGH'

                self.db.log_event(sandbox_id, 'SUSPICIOUS_BINARY', severity,
                                  proc.pid, {
                                      'name': name,
                                      'exe': exe,
                                      'is_setuid': is_setuid,
                                      'cmdline': ' '.join(proc.cmdline()[:10]),
                                  }, auto_killed=(severity == 'CRITICAL'))

                if severity == 'CRITICAL':
                    logger.critical(f"[ESCAPE] Suspicious binary: {name} "
                                    f"pid={proc.pid} sandbox={sandbox_id}")
                    return True

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return False

    def _check_network_connections(self, proc: psutil.Process, sandbox_id: str):
        try:
            conns = proc.net_connections(kind='inet')
            for conn in conns:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    rip = conn.raddr.ip
                    rport = conn.raddr.port
                    # Any established outbound = suspicious in sandbox
                    self.db.log_event(sandbox_id, 'NETWORK_EXFILTRATION', 'HIGH',
                                      proc.pid, {
                                          'name': proc.name(),
                                          'remote_ip': rip,
                                          'remote_port': rport,
                                          'local_port': conn.laddr.port if conn.laddr else None,
                                      }, auto_killed=False)
                    logger.warning(f"[ESCAPE] Network connection: {rip}:{rport} "
                                   f"pid={proc.pid} sandbox={sandbox_id}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            pass

    def _check_process_explosion(self, tree: list, sandbox_id: str,
                                  root_pid: int) -> bool:
        count = len(tree)
        if count > 50:
            self.db.log_event(sandbox_id, 'FORK_BOMB', 'CRITICAL', root_pid, {
                'process_count': count,
                'threshold': 50,
            }, auto_killed=True)
            logger.critical(f"[ESCAPE] Fork bomb: {count} processes "
                            f"sandbox={sandbox_id}")
            return True
        return False

    def _check_filesystem_access(self, proc: psutil.Process,
                                  sandbox_id: str, sandbox_dir: str):
        try:
            open_files = proc.open_files()
            for f in open_files:
                path = f.path
                # Check forbidden paths
                for forbidden in FORBIDDEN_PATH_PREFIXES:
                    if path.startswith(forbidden):
                        self.db.log_event(sandbox_id, 'FILESYSTEM_ESCAPE', 'HIGH',
                                          proc.pid, {
                                              'name': proc.name(),
                                              'path': path,
                                              'forbidden_prefix': forbidden,
                                          }, auto_killed=False)
                        logger.warning(f"[ESCAPE] Filesystem access: {path} "
                                       f"pid={proc.pid} sandbox={sandbox_id}")
                        break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
