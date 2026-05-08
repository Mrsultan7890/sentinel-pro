"""
CVE Monitor - Real-time vulnerability tracking
Monitors NVD, CISA KEV, and system packages
"""
import requests
import json
import sqlite3
import subprocess
import re
from datetime import datetime, timedelta
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class CVEMonitor:
    def __init__(self, db_path="data/cve_monitor.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._init_db()
        
        # NVD API (no key needed for basic access)
        self.nvd_api = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cisa_kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    def _init_db(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                published_date TEXT,
                modified_date TEXT,
                cisa_kev INTEGER DEFAULT 0,
                exploited INTEGER DEFAULT 0,
                affected_packages TEXT,
                discovered_at TEXT
            )
        """)
        
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS system_packages (
                package_name TEXT PRIMARY KEY,
                version TEXT,
                source TEXT,
                last_checked TEXT
            )
        """)
        
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                package_name TEXT,
                installed_version TEXT,
                fixed_version TEXT,
                severity TEXT,
                status TEXT DEFAULT 'open',
                detected_at TEXT,
                patched_at TEXT,
                FOREIGN KEY(cve_id) REFERENCES cves(cve_id)
            )
        """)
        self.conn.commit()
    
    def scan_system_packages(self):
        """Scan installed packages on system"""
        packages = {}
        
        # Python packages
        try:
            result = subprocess.run(['pip3', 'list', '--format=json'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                pip_packages = json.loads(result.stdout)
                for pkg in pip_packages:
                    packages[pkg['name']] = {
                        'version': pkg['version'],
                        'source': 'pip'
                    }
        except Exception as e:
            logger.debug(f"pip scan error: {e}")
        
        # APT packages (Debian/Ubuntu/Kali)
        try:
            result = subprocess.run(['dpkg', '-l'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.startswith('ii'):
                        parts = line.split()
                        if len(parts) >= 3:
                            packages[parts[1]] = {
                                'version': parts[2],
                                'source': 'apt'
                            }
        except Exception as e:
            logger.debug(f"dpkg scan error: {e}")
        
        # Store in database
        now = datetime.now().isoformat()
        for name, info in packages.items():
            self.conn.execute("""
                INSERT OR REPLACE INTO system_packages 
                (package_name, version, source, last_checked)
                VALUES (?, ?, ?, ?)
            """, (name, info['version'], info['source'], now))
        
        self.conn.commit()
        return len(packages)
    
    def fetch_recent_cves(self, days=7):
        """Fetch recent CVEs from NVD"""
        start_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%dT00:00:00.000')
        
        try:
            params = {
                'pubStartDate': start_date,
                'resultsPerPage': 100
            }
            
            response = requests.get(self.nvd_api, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                cves = data.get('vulnerabilities', [])
                
                count = 0
                for item in cves:
                    cve_data = item.get('cve', {})
                    cve_id = cve_data.get('id', '')
                    
                    if not cve_id:
                        continue
                    
                    # Extract description
                    descriptions = cve_data.get('descriptions', [])
                    desc = descriptions[0].get('value', '') if descriptions else ''
                    
                    # Extract CVSS score
                    metrics = cve_data.get('metrics', {})
                    cvss_score = 0.0
                    severity = 'UNKNOWN'
                    
                    if 'cvssMetricV31' in metrics:
                        cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                        cvss_score = cvss_data.get('baseScore', 0.0)
                        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    elif 'cvssMetricV2' in metrics:
                        cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                        cvss_score = cvss_data.get('baseScore', 0.0)
                        severity = self._cvss2_to_severity(cvss_score)
                    
                    published = cve_data.get('published', '')
                    modified = cve_data.get('lastModified', '')
                    
                    self.conn.execute("""
                        INSERT OR REPLACE INTO cves 
                        (cve_id, description, severity, cvss_score, 
                         published_date, modified_date, discovered_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (cve_id, desc, severity, cvss_score, 
                          published, modified, datetime.now().isoformat()))
                    
                    count += 1
                
                self.conn.commit()
                logger.info(f"Fetched {count} CVEs from NVD")
                return count
        
        except Exception as e:
            logger.error(f"NVD fetch error: {e}")
            return 0
    
    def fetch_cisa_kev(self):
        """Fetch CISA Known Exploited Vulnerabilities"""
        try:
            response = requests.get(self.cisa_kev_url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                vulns = data.get('vulnerabilities', [])
                
                count = 0
                for vuln in vulns:
                    cve_id = vuln.get('cveID', '')
                    if not cve_id:
                        continue
                    
                    # Mark as CISA KEV and exploited
                    self.conn.execute("""
                        UPDATE cves SET cisa_kev=1, exploited=1 
                        WHERE cve_id=?
                    """, (cve_id,))
                    
                    # If not in DB, add it
                    cursor = self.conn.execute("SELECT cve_id FROM cves WHERE cve_id=?", (cve_id,))
                    if not cursor.fetchone():
                        self.conn.execute("""
                            INSERT INTO cves 
                            (cve_id, description, severity, cisa_kev, exploited, discovered_at)
                            VALUES (?, ?, ?, 1, 1, ?)
                        """, (cve_id, vuln.get('vulnerabilityName', ''), 
                              'CRITICAL', datetime.now().isoformat()))
                    
                    count += 1
                
                self.conn.commit()
                logger.info(f"Fetched {count} CISA KEV entries")
                return count
        
        except Exception as e:
            logger.error(f"CISA KEV fetch error: {e}")
            return 0
    
    def match_vulnerabilities(self):
        """Match CVEs to installed packages"""
        # Get all packages
        cursor = self.conn.execute("SELECT package_name, version FROM system_packages")
        packages = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Get all CVEs
        cursor = self.conn.execute("""
            SELECT cve_id, description, severity 
            FROM cves 
            WHERE severity IN ('CRITICAL', 'HIGH')
        """)
        cves = cursor.fetchall()
        
        matches = 0
        for cve_id, desc, severity in cves:
            # Simple keyword matching (production would use CPE matching)
            desc_lower = desc.lower()
            
            for pkg_name, version in packages.items():
                pkg_lower = pkg_name.lower()
                
                # Check if package name appears in CVE description
                if pkg_lower in desc_lower or pkg_name in desc_lower:
                    # Check if vulnerability already recorded
                    cursor = self.conn.execute("""
                        SELECT id FROM vulnerabilities 
                        WHERE cve_id=? AND package_name=? AND status='open'
                    """, (cve_id, pkg_name))
                    
                    if not cursor.fetchone():
                        self.conn.execute("""
                            INSERT INTO vulnerabilities 
                            (cve_id, package_name, installed_version, severity, detected_at)
                            VALUES (?, ?, ?, ?, ?)
                        """, (cve_id, pkg_name, version, severity, datetime.now().isoformat()))
                        matches += 1
        
        self.conn.commit()
        return matches
    
    def get_critical_vulnerabilities(self):
        """Get critical vulnerabilities that need immediate patching"""
        cursor = self.conn.execute("""
            SELECT v.id, v.cve_id, v.package_name, v.installed_version, 
                   v.severity, c.cvss_score, c.cisa_kev, c.exploited
            FROM vulnerabilities v
            JOIN cves c ON v.cve_id = c.cve_id
            WHERE v.status='open' 
            AND (v.severity='CRITICAL' OR c.cisa_kev=1)
            ORDER BY c.cvss_score DESC, c.cisa_kev DESC
        """)
        return cursor.fetchall()
    
    def get_stats(self):
        """Get monitoring statistics"""
        stats = {}
        
        cursor = self.conn.execute("SELECT COUNT(*) FROM cves")
        stats['total_cves'] = cursor.fetchone()[0]
        
        cursor = self.conn.execute("SELECT COUNT(*) FROM cves WHERE cisa_kev=1")
        stats['cisa_kev_count'] = cursor.fetchone()[0]
        
        cursor = self.conn.execute("SELECT COUNT(*) FROM system_packages")
        stats['total_packages'] = cursor.fetchone()[0]
        
        cursor = self.conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status='open'")
        stats['open_vulnerabilities'] = cursor.fetchone()[0]
        
        cursor = self.conn.execute("""
            SELECT COUNT(*) FROM vulnerabilities 
            WHERE status='open' AND severity='CRITICAL'
        """)
        stats['critical_vulnerabilities'] = cursor.fetchone()[0]
        
        return stats
    
    def _cvss2_to_severity(self, score):
        """Convert CVSS v2 score to severity"""
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def close(self):
        self.conn.close()
