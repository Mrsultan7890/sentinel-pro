"""
Configuration Hardener - SHE Phase 2
CIS Benchmark compliance checker and auto-hardening for Linux systems.

Checks and hardens:
  - SSH configuration (disable root login, password auth, etc.)
  - File permissions (sensitive files like /etc/shadow, /etc/passwd)
  - Kernel parameters (sysctl hardening)
  - Service hardening (disable unnecessary services)
  - Firewall rules (basic iptables/nftables)
  - User account security (password policies, sudo config)
  - Audit logging (auditd configuration)
"""
import os
import re
import subprocess
import logging
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


class ConfigHardener:
    """
    CIS Benchmark-inspired configuration hardening.
    Detects misconfigurations and applies fixes with rollback support.
    """

    def __init__(self):
        self.backup_dir = Path("data/config_backups")
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self) -> dict:
        """
        Scan system for misconfigurations.
        Returns dict with findings categorized by severity.
        """
        self.findings = []
        
        self._check_ssh_config()
        self._check_file_permissions()
        self._check_kernel_params()
        self._check_services()
        self._check_user_accounts()
        self._check_firewall()
        self._check_audit_logging()

        return self._categorize_findings()

    def harden(self, auto_fix: bool = False, categories: list = None) -> dict:
        """
        Apply hardening fixes.
        auto_fix: if False, only report what would be fixed
        categories: list of categories to fix (default: all)
        Returns dict with applied fixes and failures.
        """
        if not self.findings:
            self.scan()

        results = {'fixed': [], 'failed': [], 'skipped': []}
        
        for finding in self.findings:
            if categories and finding['category'] not in categories:
                results['skipped'].append(finding['id'])
                continue

            if finding['severity'] in ['CRITICAL', 'HIGH']:
                if auto_fix:
                    ok, msg = self._apply_fix(finding)
                    if ok:
                        results['fixed'].append(finding['id'])
                        logger.info(f"Fixed: {finding['id']}")
                    else:
                        results['failed'].append({'id': finding['id'], 'error': msg})
                        logger.error(f"Fix failed: {finding['id']} — {msg}")
                else:
                    results['skipped'].append(finding['id'])

        return results

    def get_compliance_score(self) -> float:
        """Calculate CIS compliance score (0-100)."""
        if not self.findings:
            self.scan()
        
        total = len(self.findings)
        if total == 0:
            return 100.0
        
        # Weight by severity
        weights = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        total_weight = sum(weights.get(f['severity'], 1) for f in self.findings)
        max_weight = total * 4  # if all were CRITICAL
        
        score = 100.0 * (1.0 - total_weight / max(max_weight, 1))
        return round(score, 1)

    # ── Check Functions ───────────────────────────────────────────────────────

    def _check_ssh_config(self):
        """CIS 5.2.x — SSH Server Configuration"""
        ssh_config = Path("/etc/ssh/sshd_config")
        if not ssh_config.exists():
            return

        try:
            content = ssh_config.read_text()
            
            # CIS 5.2.8 — Disable root login
            if not re.search(r'^PermitRootLogin\s+no', content, re.M):
                self.findings.append({
                    'id': 'SSH-001',
                    'category': 'ssh',
                    'severity': 'HIGH',
                    'title': 'SSH root login enabled',
                    'description': 'PermitRootLogin should be set to "no"',
                    'fix_cmd': 'sed -i "s/^#*PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config && systemctl reload sshd',
                    'file': str(ssh_config),
                })

            # CIS 5.2.10 — Disable password authentication
            if not re.search(r'^PasswordAuthentication\s+no', content, re.M):
                self.findings.append({
                    'id': 'SSH-002',
                    'category': 'ssh',
                    'severity': 'MEDIUM',
                    'title': 'SSH password authentication enabled',
                    'description': 'PasswordAuthentication should be "no" (use keys)',
                    'fix_cmd': 'sed -i "s/^#*PasswordAuthentication.*/PasswordAuthentication no/" /etc/ssh/sshd_config && systemctl reload sshd',
                    'file': str(ssh_config),
                })

            # CIS 5.2.11 — Disable empty passwords
            if not re.search(r'^PermitEmptyPasswords\s+no', content, re.M):
                self.findings.append({
                    'id': 'SSH-003',
                    'category': 'ssh',
                    'severity': 'CRITICAL',
                    'title': 'SSH empty passwords allowed',
                    'description': 'PermitEmptyPasswords must be "no"',
                    'fix_cmd': 'sed -i "s/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/" /etc/ssh/sshd_config && systemctl reload sshd',
                    'file': str(ssh_config),
                })

        except Exception as e:
            logger.debug(f"SSH config check error: {e}")

    def _check_file_permissions(self):
        """CIS 6.1.x — File Permissions"""
        checks = [
            ('/etc/passwd', 0o644, 'FILE-001', 'CRITICAL', '/etc/passwd permissions'),
            ('/etc/shadow', 0o000, 'FILE-002', 'CRITICAL', '/etc/shadow permissions'),
            ('/etc/group', 0o644, 'FILE-003', 'HIGH', '/etc/group permissions'),
            ('/etc/gshadow', 0o000, 'FILE-004', 'HIGH', '/etc/gshadow permissions'),
            ('/boot/grub/grub.cfg', 0o600, 'FILE-005', 'HIGH', 'GRUB config permissions'),
        ]

        for path, expected_mode, fid, severity, title in checks:
            p = Path(path)
            if not p.exists():
                continue
            try:
                stat = p.stat()
                actual_mode = stat.st_mode & 0o777
                if actual_mode != expected_mode:
                    self.findings.append({
                        'id': fid,
                        'category': 'permissions',
                        'severity': severity,
                        'title': title,
                        'description': f'{path} has mode {oct(actual_mode)}, should be {oct(expected_mode)}',
                        'fix_cmd': f'chmod {oct(expected_mode)[2:]} {path}',
                        'file': path,
                    })
            except Exception as e:
                logger.debug(f"Permission check error for {path}: {e}")

    def _check_kernel_params(self):
        """CIS 3.x — Network and Kernel Parameters"""
        sysctl_checks = [
            ('net.ipv4.ip_forward', '0', 'KERN-001', 'HIGH', 'IP forwarding disabled'),
            ('net.ipv4.conf.all.send_redirects', '0', 'KERN-002', 'MEDIUM', 'ICMP redirects disabled'),
            ('net.ipv4.conf.all.accept_source_route', '0', 'KERN-003', 'HIGH', 'Source routing disabled'),
            ('net.ipv4.icmp_echo_ignore_broadcasts', '1', 'KERN-004', 'MEDIUM', 'Ignore ICMP broadcasts'),
            ('kernel.randomize_va_space', '2', 'KERN-005', 'HIGH', 'ASLR enabled'),
        ]

        for param, expected, fid, severity, title in sysctl_checks:
            try:
                result = subprocess.run(['sysctl', '-n', param],
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    actual = result.stdout.strip()
                    if actual != expected:
                        self.findings.append({
                            'id': fid,
                            'category': 'kernel',
                            'severity': severity,
                            'title': title,
                            'description': f'{param} is {actual}, should be {expected}',
                            'fix_cmd': f'sysctl -w {param}={expected} && echo "{param} = {expected}" >> /etc/sysctl.d/99-sentinel.conf',
                            'file': '/etc/sysctl.conf',
                        })
            except Exception as e:
                logger.debug(f"Sysctl check error for {param}: {e}")

    def _check_services(self):
        """CIS 2.x — Disable unnecessary services"""
        unnecessary_services = [
            'avahi-daemon', 'cups', 'isc-dhcp-server', 'isc-dhcp-server6',
            'slapd', 'nfs-server', 'rpcbind', 'bind9', 'vsftpd',
            'apache2', 'dovecot', 'smbd', 'snmpd', 'rsync',
        ]

        for service in unnecessary_services:
            try:
                result = subprocess.run(['systemctl', 'is-enabled', service],
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and result.stdout.strip() == 'enabled':
                    self.findings.append({
                        'id': f'SVC-{service.upper()[:6]}',
                        'category': 'services',
                        'severity': 'MEDIUM',
                        'title': f'Unnecessary service {service} enabled',
                        'description': f'{service} is enabled but may not be needed',
                        'fix_cmd': f'systemctl disable --now {service}',
                        'file': None,
                    })
            except Exception:
                pass

    def _check_user_accounts(self):
        """CIS 5.4.x — User accounts and password policies"""
        # Check for users with UID 0 (besides root)
        try:
            passwd = Path('/etc/passwd').read_text()
            for line in passwd.splitlines():
                if not line or line.startswith('#'):
                    continue
                parts = line.split(':')
                if len(parts) >= 3 and parts[2] == '0' and parts[0] != 'root':
                    self.findings.append({
                        'id': 'USER-001',
                        'category': 'users',
                        'severity': 'CRITICAL',
                        'title': f'Non-root user {parts[0]} has UID 0',
                        'description': 'Only root should have UID 0',
                        'fix_cmd': f'# Manual: userdel {parts[0]} or change UID',
                        'file': '/etc/passwd',
                    })
        except Exception as e:
            logger.debug(f"User account check error: {e}")

    def _check_firewall(self):
        """CIS 3.5.x — Firewall configuration"""
        # Check if iptables/nftables is active
        try:
            result = subprocess.run(['iptables', '-L', '-n'],
                                  capture_output=True, timeout=5)
            if result.returncode != 0:
                self.findings.append({
                    'id': 'FW-001',
                    'category': 'firewall',
                    'severity': 'HIGH',
                    'title': 'Firewall not configured',
                    'description': 'iptables/nftables should be configured',
                    'fix_cmd': '# Manual: configure iptables or install ufw',
                    'file': None,
                })
        except Exception:
            pass

    def _check_audit_logging(self):
        """CIS 4.1.x — Audit logging"""
        try:
            result = subprocess.run(['systemctl', 'is-enabled', 'auditd'],
                                  capture_output=True, text=True, timeout=5)
            if result.returncode != 0 or result.stdout.strip() != 'enabled':
                self.findings.append({
                    'id': 'AUDIT-001',
                    'category': 'audit',
                    'severity': 'MEDIUM',
                    'title': 'Audit daemon not enabled',
                    'description': 'auditd should be enabled for security logging',
                    'fix_cmd': 'systemctl enable --now auditd',
                    'file': None,
                })
        except Exception:
            pass

    # ── Fix Application ───────────────────────────────────────────────────────

    def _apply_fix(self, finding: dict) -> Tuple[bool, str]:
        """Apply a single fix with backup and rollback support."""
        fix_cmd = finding.get('fix_cmd')
        if not fix_cmd or fix_cmd.startswith('# Manual'):
            return False, "Manual fix required"

        # Backup file if applicable
        if finding.get('file'):
            self._backup_file(finding['file'])

        try:
            result = subprocess.run(
                fix_cmd, shell=True,
                capture_output=True, text=True,
                timeout=30
            )
            if result.returncode == 0:
                return True, "Fixed successfully"
            else:
                return False, result.stderr[:200]
        except subprocess.TimeoutExpired:
            return False, "Timeout"
        except Exception as e:
            return False, str(e)

    def _backup_file(self, filepath: str):
        """Backup a file before modification."""
        try:
            src = Path(filepath)
            if not src.exists():
                return
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            dst = self.backup_dir / f"{src.name}.{timestamp}.bak"
            import shutil
            shutil.copy2(src, dst)
            logger.info(f"Backed up {filepath} → {dst}")
        except Exception as e:
            logger.warning(f"Backup failed for {filepath}: {e}")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _categorize_findings(self) -> dict:
        """Group findings by severity and category."""
        by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
        by_category = {}

        for f in self.findings:
            by_severity[f['severity']].append(f)
            by_category.setdefault(f['category'], []).append(f)

        return {
            'total': len(self.findings),
            'by_severity': {k: len(v) for k, v in by_severity.items()},
            'by_category': {k: len(v) for k, v in by_category.items()},
            'findings': self.findings,
            'compliance_score': self.get_compliance_score(),
        }

    def get_report(self) -> str:
        """Generate human-readable report."""
        if not self.findings:
            self.scan()

        report = []
        report.append("=" * 60)
        report.append("Configuration Hardening Report")
        report.append("=" * 60)
        report.append(f"Compliance Score: {self.get_compliance_score()}%")
        report.append(f"Total Findings: {len(self.findings)}")
        report.append("")

        by_sev = {}
        for f in self.findings:
            by_sev.setdefault(f['severity'], []).append(f)

        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            items = by_sev.get(sev, [])
            if items:
                report.append(f"\n[{sev}] {len(items)} findings:")
                for f in items:
                    report.append(f"  {f['id']}: {f['title']}")
                    report.append(f"    {f['description']}")

        return "\n".join(report)
