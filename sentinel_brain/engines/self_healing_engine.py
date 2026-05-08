"""
Self-Healing Engine - Autonomous vulnerability management
Monitors, patches, and recovers from security issues
"""
import logging
import threading
import time
from datetime import datetime
from .cve_monitor import CVEMonitor
from .patch_manager import PatchManager
from .config_hardener import ConfigHardener
from .incident_responder import IncidentResponder

logger = logging.getLogger(__name__)

class SelfHealingEngine:
    def __init__(self):
        self.cve_monitor = CVEMonitor()
        self.patch_manager = PatchManager()
        self.config_hardener = ConfigHardener()
        self.incident_responder = IncidentResponder()
        self.running = False
        self.monitor_thread = None
        self.scan_interval = 3600  # 1 hour
    
    def start_monitoring(self, scan_interval: int = 3600):
        """Start continuous monitoring"""
        if self.running:
            logger.warning("Self-healing engine already running")
            return False
        
        self.scan_interval = scan_interval
        self.running = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name='self-healing-monitor'
        )
        self.monitor_thread.start()
        logger.info(f"Self-healing engine started (interval: {scan_interval}s)")
        return True
    
    def stop_monitoring(self):
        """Stop continuous monitoring"""
        if not self.running:
            return False
        
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Self-healing engine stopped")
        return True
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                logger.info("Running self-healing scan...")
                
                # 1. Scan system packages
                pkg_count = self.cve_monitor.scan_system_packages()
                logger.info(f"Scanned {pkg_count} packages")
                
                # 2. Fetch recent CVEs
                cve_count = self.cve_monitor.fetch_recent_cves(days=7)
                logger.info(f"Fetched {cve_count} recent CVEs")
                
                # 3. Fetch CISA KEV
                kev_count = self.cve_monitor.fetch_cisa_kev()
                logger.info(f"Fetched {kev_count} CISA KEV entries")
                
                # 4. Match vulnerabilities
                match_count = self.cve_monitor.match_vulnerabilities()
                logger.info(f"Matched {match_count} vulnerabilities")
                
                # 5. Auto-patch critical vulnerabilities
                results = self.patch_manager.auto_patch_critical(max_patches=3)
                patched = sum(1 for r in results if r['status'] == 'patched')
                logger.info(f"Auto-patched {patched}/{len(results)} critical vulnerabilities")
                
                # Sleep until next scan
                for _ in range(self.scan_interval):
                    if not self.running:
                        break
                    time.sleep(1)
            
            except Exception as e:
                logger.error(f"Self-healing scan error: {e}")
                time.sleep(60)  # Wait 1 minute on error
    
    def run_manual_scan(self):
        """Run manual scan (non-blocking)"""
        logger.info("Running manual self-healing scan...")
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'packages_scanned': 0,
            'cves_fetched': 0,
            'kev_fetched': 0,
            'vulnerabilities_matched': 0,
            'patches_applied': 0,
            'critical_remaining': 0
        }
        
        try:
            # Scan packages
            results['packages_scanned'] = self.cve_monitor.scan_system_packages()
            
            # Fetch CVEs
            results['cves_fetched'] = self.cve_monitor.fetch_recent_cves(days=7)
            
            # Fetch CISA KEV
            results['kev_fetched'] = self.cve_monitor.fetch_cisa_kev()
            
            # Match vulnerabilities
            results['vulnerabilities_matched'] = self.cve_monitor.match_vulnerabilities()
            
            # Auto-patch critical
            patch_results = self.patch_manager.auto_patch_critical(max_patches=5)
            results['patches_applied'] = sum(1 for r in patch_results if r['status'] == 'patched')
            
            # Get remaining critical
            critical_vulns = self.cve_monitor.get_critical_vulnerabilities()
            results['critical_remaining'] = len(critical_vulns)
            
            logger.info(f"Manual scan complete: {results}")
            return results
        
        except Exception as e:
            logger.error(f"Manual scan error: {e}")
            results['error'] = str(e)
            return results
    
    def get_critical_vulnerabilities(self):
        """Get list of critical vulnerabilities"""
        return self.cve_monitor.get_critical_vulnerabilities()
    
    def patch_vulnerability(self, package_name: str, source: str = 'apt'):
        """Manually patch a specific package"""
        return self.patch_manager.apply_patch(package_name, source, test_first=True)
    
    def rollback_patch(self, package_name: str, source: str, previous_version: str):
        """Rollback a patch"""
        return self.patch_manager.rollback_patch(package_name, source, previous_version)
    
    def get_status(self):
        """Get self-healing engine status"""
        cve_stats = self.cve_monitor.get_stats()
        patch_stats = self.patch_manager.get_stats()
        
        return {
            'monitoring': self.running,
            'scan_interval': self.scan_interval,
            'cve_stats': cve_stats,
            'patch_stats': patch_stats,
            'last_scan': datetime.now().isoformat() if self.running else 'Not running'
        }
    
    def get_patch_history(self, limit: int = 50):
        """Get recent patch history"""
        return self.patch_manager.get_patch_history(limit)
    
    def harden_config(self, auto_fix: bool = False, categories: list = None) -> dict:
        """Run configuration hardening scan and optionally apply fixes."""
        return self.config_hardener.harden(auto_fix=auto_fix, categories=categories)

    def get_compliance_score(self) -> float:
        """Get CIS compliance score."""
        return self.config_hardener.get_compliance_score()

    def get_hardening_report(self) -> str:
        """Get human-readable hardening report."""
        return self.config_hardener.get_report()

    def scan_incidents(self) -> list:
        """Scan for active security incidents."""
        return self.incident_responder.scan_for_incidents()

    def respond_to_incident(self, incident: dict, auto_respond: bool = False) -> dict:
        """Respond to a detected incident."""
        return self.incident_responder.respond_to_incident(incident, auto_respond)

    def get_active_incidents(self) -> str:
        """Get summary of active incidents."""
        return self.incident_responder.get_active_incidents_summary()

    def get_incident_report(self, incident_id: str) -> str:
        """Get detailed incident report."""
        return self.incident_responder.get_incident_report(incident_id)

    def close(self):
        """Cleanup resources"""
        self.stop_monitoring()
        self.cve_monitor.close()
