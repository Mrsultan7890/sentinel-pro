"""
Incident Responder - SHE Phase 3
Automated incident detection and response.

Capabilities:
  - Detect active exploitation (suspicious processes, network connections, file modifications)
  - Auto-isolate compromised components (kill processes, block IPs, quarantine files)
  - Restore from clean backups
  - Generate forensics timeline
  - Alert via Telegram/email
"""
import os
import signal
import subprocess
import logging
import json
import sqlite3
import hashlib
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Tuple

import psutil

logger = logging.getLogger(__name__)


class IncidentDB:
    """SQLite database for incident tracking and forensics."""
    
    def __init__(self, db_path: str = "data/incidents.db"):
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self._init()

    def _init(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS incidents (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT UNIQUE NOT NULL,
                detected_at TEXT NOT NULL,
                incident_type TEXT NOT NULL,
                severity    TEXT NOT NULL,
                status      TEXT DEFAULT 'active',
                resolved_at TEXT,
                description TEXT,
                indicators  TEXT,
                response_actions TEXT
            );
            CREATE TABLE IF NOT EXISTS incident_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                timestamp   TEXT NOT NULL,
                event_type  TEXT NOT NULL,
                details     TEXT,
                FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
            );
            CREATE TABLE IF NOT EXISTS quarantine (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                file_path   TEXT NOT NULL,
                file_hash   TEXT,
                quarantined_at TEXT NOT NULL,
                original_location TEXT,
                FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
            );
        """)
        self.conn.commit()

    def create_incident(self, incident_id: str, incident_type: str, 
                       severity: str, description: str, indicators: dict) -> int:
        cursor = self.conn.execute("""
            INSERT INTO incidents 
            (incident_id, detected_at, incident_type, severity, description, indicators)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (incident_id, datetime.now().isoformat(), incident_type, 
              severity, description, json.dumps(indicators)))
        self.conn.commit()
        return cursor.lastrowid

    def log_event(self, incident_id: str, event_type: str, details: dict):
        self.conn.execute("""
            INSERT INTO incident_events (incident_id, timestamp, event_type, details)
            VALUES (?, ?, ?, ?)
        """, (incident_id, datetime.now().isoformat(), event_type, json.dumps(details)))
        self.conn.commit()

    def resolve_incident(self, incident_id: str, actions: list):
        self.conn.execute("""
            UPDATE incidents 
            SET status='resolved', resolved_at=?, response_actions=?
            WHERE incident_id=?
        """, (datetime.now().isoformat(), json.dumps(actions), incident_id))
        self.conn.commit()

    def quarantine_file(self, incident_id: str, file_path: str, 
                       file_hash: str, original_location: str):
        self.conn.execute("""
            INSERT INTO quarantine 
            (incident_id, file_path, file_hash, quarantined_at, original_location)
            VALUES (?, ?, ?, ?, ?)
        """, (incident_id, file_path, file_hash, datetime.now().isoformat(), original_location))
        self.conn.commit()

    def get_active_incidents(self) -> list:
        cursor = self.conn.execute("""
            SELECT incident_id, incident_type, severity, detected_at, description
            FROM incidents WHERE status='active' ORDER BY detected_at DESC
        """)
        return cursor.fetchall()

    def get_incident_timeline(self, incident_id: str) -> list:
        cursor = self.conn.execute("""
            SELECT timestamp, event_type, details
            FROM incident_events WHERE incident_id=? ORDER BY timestamp
        """, (incident_id,))
        return cursor.fetchall()

    def close(self):
        self.conn.close()


class IncidentResponder:
    """
    Automated incident detection and response engine.
    Monitors system for active exploitation and responds automatically.
    """

    def __init__(self):
        self.db = IncidentDB()
        self.quarantine_dir = Path("data/quarantine")
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir = Path("data/incident_backups")
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    # ── Detection ─────────────────────────────────────────────────────────────

    def detect_suspicious_processes(self) -> List[dict]:
        """Detect processes with suspicious characteristics."""
        suspicious = []
        
        # Known malicious process names
        malicious_names = {
            'cryptominer', 'xmrig', 'minerd', 'cgminer',
            'backdoor', 'rootkit', 'keylogger',
            'mimikatz', 'meterpreter', 'cobalt',
        }

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                info = proc.info
                name = (info['name'] or '').lower()
                exe = info['exe'] or ''
                cmdline = ' '.join(info['cmdline'] or []).lower()

                # Check 1: Known malicious names
                if any(mal in name or mal in cmdline for mal in malicious_names):
                    suspicious.append({
                        'pid': info['pid'],
                        'name': info['name'],
                        'exe': exe,
                        'cmdline': cmdline[:200],
                        'reason': 'malicious_name',
                    })
                    continue

                # Check 2: Hidden process (name starts with space or dot)
                if name.startswith(('.', ' ')):
                    suspicious.append({
                        'pid': info['pid'],
                        'name': info['name'],
                        'exe': exe,
                        'reason': 'hidden_process',
                    })
                    continue

                # Check 3: Suspicious network connections (C2 patterns)
                try:
                    conns = proc.net_connections(kind='inet')
                    for conn in conns:
                        if conn.status == 'ESTABLISHED' and conn.raddr:
                            # Non-standard ports often used by C2
                            if conn.raddr.port in {4444, 5555, 6666, 7777, 8888, 9999, 31337}:
                                suspicious.append({
                                    'pid': info['pid'],
                                    'name': info['name'],
                                    'remote_ip': conn.raddr.ip,
                                    'remote_port': conn.raddr.port,
                                    'reason': 'suspicious_c2_port',
                                })
                                break
                except (psutil.AccessDenied, AttributeError):
                    pass

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return suspicious

    def detect_file_modifications(self, watch_paths: List[str] = None) -> List[dict]:
        """Detect unauthorized modifications to critical files."""
        if watch_paths is None:
            watch_paths = [
                '/etc/passwd', '/etc/shadow', '/etc/sudoers',
                '/etc/ssh/sshd_config',
            ]

        modifications = []
        for path in watch_paths:
            p = Path(path)
            try:
                if not p.exists():
                    continue

                stat = p.stat()
                # Check if modified in last 5 minutes
                mtime = datetime.fromtimestamp(stat.st_mtime)
                age_seconds = (datetime.now() - mtime).total_seconds()
                
                if age_seconds < 300:  # 5 minutes
                    modifications.append({
                        'path': str(p),
                        'mtime': mtime.isoformat(),
                        'age_seconds': age_seconds,
                        'size': stat.st_size,
                    })
            except (PermissionError, FileNotFoundError, OSError) as e:
                logger.debug(f"File check error for {path}: {e}")

        return modifications

    def detect_network_anomalies(self) -> List[dict]:
        """Detect unusual network activity."""
        anomalies = []
        
        # Count connections per remote IP
        conn_counts = {}
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                ip = conn.raddr.ip
                conn_counts[ip] = conn_counts.get(ip, 0) + 1

        # Flag IPs with excessive connections (potential DDoS or scanning)
        for ip, count in conn_counts.items():
            if count > 20:
                anomalies.append({
                    'type': 'excessive_connections',
                    'remote_ip': ip,
                    'connection_count': count,
                })

        return anomalies

    def scan_for_incidents(self) -> List[dict]:
        """Run all detection checks and return incidents."""
        incidents = []

        # Check 1: Suspicious processes
        sus_procs = self.detect_suspicious_processes()
        if sus_procs:
            incidents.append({
                'type': 'suspicious_process',
                'severity': 'HIGH',
                'indicators': sus_procs,
                'description': f'{len(sus_procs)} suspicious processes detected',
            })

        # Check 2: File modifications
        file_mods = self.detect_file_modifications()
        if file_mods:
            incidents.append({
                'type': 'unauthorized_file_modification',
                'severity': 'CRITICAL',
                'indicators': file_mods,
                'description': f'{len(file_mods)} critical files modified recently',
            })

        # Check 3: Network anomalies
        net_anom = self.detect_network_anomalies()
        if net_anom:
            incidents.append({
                'type': 'network_anomaly',
                'severity': 'MEDIUM',
                'indicators': net_anom,
                'description': f'{len(net_anom)} network anomalies detected',
            })

        return incidents

    # ── Response ──────────────────────────────────────────────────────────────

    def respond_to_incident(self, incident: dict, auto_respond: bool = False) -> dict:
        """
        Respond to detected incident.
        Returns dict with actions taken.
        """
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        # Log incident
        self.db.create_incident(
            incident_id=incident_id,
            incident_type=incident['type'],
            severity=incident['severity'],
            description=incident['description'],
            indicators=incident['indicators']
        )

        actions = []

        if not auto_respond:
            actions.append({'action': 'logged', 'status': 'manual_review_required'})
            return {'incident_id': incident_id, 'actions': actions}

        # Auto-response based on incident type
        if incident['type'] == 'suspicious_process':
            for proc_info in incident['indicators']:
                ok, msg = self._kill_process(proc_info['pid'])
                actions.append({
                    'action': 'kill_process',
                    'pid': proc_info['pid'],
                    'name': proc_info.get('name'),
                    'status': 'success' if ok else 'failed',
                    'message': msg,
                })
                self.db.log_event(incident_id, 'kill_process', proc_info)

        elif incident['type'] == 'unauthorized_file_modification':
            for file_info in incident['indicators']:
                ok, msg = self._quarantine_file(incident_id, file_info['path'])
                actions.append({
                    'action': 'quarantine_file',
                    'path': file_info['path'],
                    'status': 'success' if ok else 'failed',
                    'message': msg,
                })
                self.db.log_event(incident_id, 'quarantine_file', file_info)

        elif incident['type'] == 'network_anomaly':
            for anom in incident['indicators']:
                if anom['type'] == 'excessive_connections':
                    ok, msg = self._block_ip(anom['remote_ip'])
                    actions.append({
                        'action': 'block_ip',
                        'ip': anom['remote_ip'],
                        'status': 'success' if ok else 'failed',
                        'message': msg,
                    })
                    self.db.log_event(incident_id, 'block_ip', anom)

        self.db.resolve_incident(incident_id, actions)
        logger.info(f"Incident {incident_id} responded: {len(actions)} actions")
        
        return {'incident_id': incident_id, 'actions': actions}

    def _kill_process(self, pid: int) -> Tuple[bool, str]:
        """Kill a process and its children."""
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            
            for child in children:
                try:
                    child.kill()
                except psutil.NoSuchProcess:
                    pass
            
            parent.kill()
            return True, f"Killed process {pid} and {len(children)} children"
        except psutil.NoSuchProcess:
            return False, "Process not found"
        except psutil.AccessDenied:
            return False, "Permission denied"
        except Exception as e:
            return False, str(e)

    def _quarantine_file(self, incident_id: str, file_path: str) -> Tuple[bool, str]:
        """Move file to quarantine directory."""
        try:
            src = Path(file_path)
            if not src.exists():
                return False, "File not found"

            # Calculate hash
            file_hash = hashlib.sha256(src.read_bytes()).hexdigest()

            # Move to quarantine
            dst = self.quarantine_dir / f"{incident_id}_{src.name}"
            shutil.move(str(src), str(dst))

            self.db.quarantine_file(incident_id, str(dst), file_hash, file_path)
            return True, f"Quarantined to {dst}"
        except Exception as e:
            return False, str(e)

    def _block_ip(self, ip: str) -> Tuple[bool, str]:
        """Block IP using iptables."""
        try:
            result = subprocess.run(
                ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                capture_output=True, timeout=10
            )
            if result.returncode == 0:
                return True, f"Blocked {ip} via iptables"
            return False, result.stderr.decode()
        except subprocess.TimeoutExpired:
            return False, "Timeout"
        except FileNotFoundError:
            return False, "iptables not found"
        except Exception as e:
            return False, str(e)

    # ── Backup & Restore ──────────────────────────────────────────────────────

    def create_backup(self, paths: List[str], backup_name: str = None) -> Tuple[bool, str]:
        """Create backup of specified paths."""
        if backup_name is None:
            backup_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        backup_path = self.backup_dir / backup_name
        backup_path.mkdir(parents=True, exist_ok=True)

        try:
            for path in paths:
                src = Path(path)
                if not src.exists():
                    continue
                
                if src.is_file():
                    dst = backup_path / src.name
                    shutil.copy2(src, dst)
                elif src.is_dir():
                    dst = backup_path / src.name
                    shutil.copytree(src, dst, dirs_exist_ok=True)

            return True, f"Backup created: {backup_path}"
        except Exception as e:
            return False, str(e)

    def restore_from_backup(self, backup_name: str) -> Tuple[bool, str]:
        """Restore files from backup."""
        backup_path = self.backup_dir / backup_name
        if not backup_path.exists():
            return False, "Backup not found"

        try:
            for item in backup_path.iterdir():
                # Restore to original location (root of filesystem)
                dst = Path("/") / item.name
                if item.is_file():
                    shutil.copy2(item, dst)
                elif item.is_dir():
                    shutil.copytree(item, dst, dirs_exist_ok=True)

            return True, f"Restored from {backup_path}"
        except Exception as e:
            return False, str(e)

    # ── Reporting ─────────────────────────────────────────────────────────────

    def get_incident_report(self, incident_id: str) -> str:
        """Generate forensics report for an incident."""
        cursor = self.db.conn.execute("""
            SELECT incident_type, severity, detected_at, resolved_at, 
                   description, indicators, response_actions, status
            FROM incidents WHERE incident_id=?
        """, (incident_id,))
        
        row = cursor.fetchone()
        if not row:
            return f"Incident {incident_id} not found"

        itype, sev, detected, resolved, desc, indicators, actions, status = row
        
        report = []
        report.append("=" * 60)
        report.append(f"Incident Report: {incident_id}")
        report.append("=" * 60)
        report.append(f"Type: {itype}")
        report.append(f"Severity: {sev}")
        report.append(f"Status: {status}")
        report.append(f"Detected: {detected}")
        if resolved:
            report.append(f"Resolved: {resolved}")
        report.append(f"\nDescription: {desc}")
        
        if indicators:
            report.append(f"\nIndicators:")
            inds = json.loads(indicators)
            for ind in inds[:10]:
                report.append(f"  {ind}")

        if actions:
            report.append(f"\nResponse Actions:")
            acts = json.loads(actions)
            for act in acts:
                report.append(f"  {act['action']}: {act.get('status', 'unknown')}")

        # Timeline
        timeline = self.db.get_incident_timeline(incident_id)
        if timeline:
            report.append(f"\nTimeline:")
            for ts, etype, details in timeline:
                report.append(f"  [{ts}] {etype}")

        return "\n".join(report)

    def get_active_incidents_summary(self) -> str:
        """Get summary of all active incidents."""
        incidents = self.db.get_active_incidents()
        if not incidents:
            return "No active incidents"

        report = []
        report.append(f"Active Incidents: {len(incidents)}")
        for inc_id, itype, sev, detected, desc in incidents:
            report.append(f"  [{sev}] {inc_id}: {desc} (detected: {detected})")

        return "\n".join(report)

    def close(self):
        self.db.close()
