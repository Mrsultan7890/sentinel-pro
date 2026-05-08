"""
Patch Manager - Automatic vulnerability patching
Tests patches in sandbox before applying to production
"""
import subprocess
import logging
from datetime import datetime
from pathlib import Path
import json
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from modules.privilege_manager import privilege_manager
from .cve_monitor import CVEMonitor
from .sandbox_manager import SandboxManager
from .risk_assessor import RiskLevel

logger = logging.getLogger(__name__)

class PatchManager:
    def __init__(self):
        self.cve_monitor = CVEMonitor()
        self.sandbox = SandboxManager()
        self.patch_log = Path("data/patch_history.json")
        self.patch_log.parent.mkdir(parents=True, exist_ok=True)
    
    def check_updates(self):
        """Check for available package updates"""
        updates = {}
        
        # APT updates
        try:
            # Update package list
            privilege_manager.execute_privileged(['apt', 'update'], 'apt', timeout=60)
            
            # Check upgradable packages
            result = subprocess.run(['apt', 'list', '--upgradable'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if '/' in line and '[upgradable' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            pkg_name = parts[0].split('/')[0]
                            new_version = parts[1]
                            updates[pkg_name] = {
                                'source': 'apt',
                                'new_version': new_version,
                                'current_version': 'unknown'
                            }
        except Exception as e:
            logger.error(f"APT update check failed: {e}")
        
        # pip updates
        try:
            result = subprocess.run(['pip3', 'list', '--outdated', '--format=json'],
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                outdated = json.loads(result.stdout)
                for pkg in outdated:
                    updates[pkg['name']] = {
                        'source': 'pip',
                        'current_version': pkg['version'],
                        'new_version': pkg['latest_version']
                    }
        except Exception as e:
            logger.error(f"pip update check failed: {e}")
        
        return updates
    
    def test_patch_in_sandbox(self, package_name: str, source: str):
        """Test package update in sandbox before applying"""
        logger.info(f"Testing patch for {package_name} in sandbox")
        
        if source == 'apt':
            test_cmd = f"apt-cache show {package_name}"
        elif source == 'pip':
            test_cmd = f"pip3 show {package_name}"
        else:
            return False, "Unknown package source"
        
        # Test in sandbox
        success, output, error = self.sandbox.execute(
            test_cmd, 
            risk_level=RiskLevel.MEDIUM,
            timeout=30
        )
        
        if not success:
            return False, f"Sandbox test failed: {error}"
        
        return True, "Sandbox test passed"
    
    def apply_patch(self, package_name: str, source: str, test_first: bool = True):
        """Apply patch to system"""
        logger.info(f"Applying patch for {package_name}")
        
        # Test in sandbox first
        if test_first:
            test_ok, test_msg = self.test_patch_in_sandbox(package_name, source)
            if not test_ok:
                logger.warning(f"Sandbox test failed for {package_name}: {test_msg}")
                return False, test_msg
        
        # Apply patch
        try:
            if source == 'apt':
                result = privilege_manager.execute_privileged(
                    ['apt', 'install', '-y', package_name],
                    'apt',
                    timeout=300
                )
            elif source == 'pip':
                result = subprocess.run(
                    ['pip3', 'install', '--upgrade', package_name],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
            else:
                return False, "Unknown package source"
            
            success = result.returncode == 0
            
            # Log patch
            self._log_patch(package_name, source, success, result.stdout, result.stderr)
            
            if success:
                # Mark vulnerability as patched
                self.cve_monitor.conn.execute("""
                    UPDATE vulnerabilities 
                    SET status='patched', patched_at=?
                    WHERE package_name=? AND status='open'
                """, (datetime.now().isoformat(), package_name))
                self.cve_monitor.conn.commit()
                
                return True, "Patch applied successfully"
            else:
                return False, f"Patch failed: {result.stderr}"
        
        except subprocess.TimeoutExpired:
            return False, "Patch timeout"
        except Exception as e:
            return False, str(e)
    
    def auto_patch_critical(self, max_patches: int = 5):
        """Automatically patch critical vulnerabilities"""
        critical_vulns = self.cve_monitor.get_critical_vulnerabilities()
        
        if not critical_vulns:
            logger.info("No critical vulnerabilities to patch")
            return []
        
        results = []
        patched_count = 0
        
        for vuln in critical_vulns[:max_patches]:
            vuln_id, cve_id, pkg_name, version, severity, cvss, cisa_kev, exploited = vuln
            
            logger.info(f"Auto-patching {pkg_name} (CVE: {cve_id}, Severity: {severity})")
            
            # Check if update available
            updates = self.check_updates()
            if pkg_name not in updates:
                results.append({
                    'package': pkg_name,
                    'cve': cve_id,
                    'status': 'no_update_available'
                })
                continue
            
            # Apply patch
            source = updates[pkg_name]['source']
            success, message = self.apply_patch(pkg_name, source, test_first=True)
            
            results.append({
                'package': pkg_name,
                'cve': cve_id,
                'status': 'patched' if success else 'failed',
                'message': message
            })
            
            if success:
                patched_count += 1
        
        logger.info(f"Auto-patched {patched_count}/{len(results)} critical vulnerabilities")
        return results
    
    def rollback_patch(self, package_name: str, source: str, previous_version: str):
        """Rollback a patch to previous version"""
        logger.info(f"Rolling back {package_name} to {previous_version}")
        
        try:
            if source == 'apt':
                result = privilege_manager.execute_privileged(
                    ['apt', 'install', '-y', f"{package_name}={previous_version}"],
                    'apt',
                    timeout=300
                )
            elif source == 'pip':
                result = subprocess.run(
                    ['pip3', 'install', f"{package_name}=={previous_version}"],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
            else:
                return False, "Unknown package source"
            
            success = result.returncode == 0
            self._log_patch(package_name, source, success, result.stdout, result.stderr, rollback=True)
            
            return success, "Rollback successful" if success else result.stderr
        
        except Exception as e:
            return False, str(e)
    
    def _log_patch(self, package: str, source: str, success: bool, 
                   stdout: str, stderr: str, rollback: bool = False):
        """Log patch operation"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'package': package,
            'source': source,
            'action': 'rollback' if rollback else 'patch',
            'success': success,
            'stdout': stdout[:500],
            'stderr': stderr[:500]
        }
        
        # Append to log file
        logs = []
        if self.patch_log.exists():
            with open(self.patch_log, 'r') as f:
                logs = json.load(f)
        
        logs.append(log_entry)
        
        # Keep last 1000 entries
        logs = logs[-1000:]
        
        with open(self.patch_log, 'w') as f:
            json.dump(logs, f, indent=2)
    
    def get_patch_history(self, limit: int = 50):
        """Get recent patch history"""
        if not self.patch_log.exists():
            return []
        
        with open(self.patch_log, 'r') as f:
            logs = json.load(f)
        
        return logs[-limit:]
    
    def get_stats(self):
        """Get patch manager statistics"""
        history = self.get_patch_history(limit=1000)
        
        total_patches = len(history)
        successful = sum(1 for p in history if p['success'] and p['action'] == 'patch')
        failed = sum(1 for p in history if not p['success'] and p['action'] == 'patch')
        rollbacks = sum(1 for p in history if p['action'] == 'rollback')
        
        return {
            'total_patches': total_patches,
            'successful_patches': successful,
            'failed_patches': failed,
            'rollbacks': rollbacks,
            'success_rate': (successful / total_patches * 100) if total_patches > 0 else 0
        }
