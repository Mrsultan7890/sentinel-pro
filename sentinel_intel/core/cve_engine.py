"""
CVE Intelligence Engine - Vulnerability Analysis
NVD, MITRE, ExploitDB, GitHub Security, VulnDB + ML
"""
import sys
import os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
import config
import requests
from typing import Dict, List
import re

class CVEEngine:
    def __init__(self):
        self.free_apis = {
            'nvd': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'mitre': 'https://cveawg.mitre.org/api/cve',
            'circl': 'https://cve.circl.lu/api/cve',
            'vulners': 'https://vulners.com/api/v3/search/lucene',
            'github_advisory': 'https://api.github.com/advisories',
            'exploitdb': 'https://www.exploit-db.com/search',
            'vulndb': 'https://vuldb.com/api/v1',
            'cisa_kev': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
        }
        self.paid_apis = {
            'nvd_key': config.NVD_API_KEY or os.getenv('NVD_API_KEY', ''),
            'vulners_key': os.getenv('VULNERS_API_KEY', ''),
            'vulndb_key': os.getenv('VULNDB_API_KEY', '')
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def investigate(self, cve_id: str) -> Dict:
        """Deep CVE investigation - exploits, patches, affected products"""
        # Normalize CVE ID
        cve_id = cve_id.upper()
        if not cve_id.startswith('CVE-'):
            cve_id = f'CVE-{cve_id}'
        
        results = {
            'cve_id': cve_id,
            'sources': [],
            'description': None,
            'published': None,
            'modified': None,
            'cvss_v3': {},
            'cvss_v2': {},
            'severity': None,
            'exploitability': None,
            'impact': None,
            'cwe': [],
            'cpe': [],
            'affected_products': [],
            'vendors': [],
            'references': [],
            'exploits': [],
            'patches': [],
            'metasploit_modules': [],
            'poc_available': False,
            'exploit_available': False,
            'patch_available': False,
            'in_wild': False,
            'cisa_kev': False,
            'risk_score': 0.0,
            'tags': []
        }
        
        # === FREE APIs ===
        
        # 1. NVD (National Vulnerability Database)
        try:
            headers = {}
            if self.paid_apis['nvd_key']:
                headers['apiKey'] = self.paid_apis['nvd_key']
            
            r = self.session.get(self.free_apis['nvd'],
                                params={'cveId': cve_id},
                                headers=headers,
                                timeout=15)
            if r.status_code == 200:
                data = r.json()
                if data.get('vulnerabilities'):
                    vuln = data['vulnerabilities'][0]['cve']
                    
                    # Basic info
                    results['description'] = vuln.get('descriptions', [{}])[0].get('value')
                    results['published'] = vuln.get('published')
                    results['modified'] = vuln.get('lastModified')
                    
                    # CVSS v3
                    metrics = vuln.get('metrics', {})
                    if metrics.get('cvssMetricV31'):
                        cvss3 = metrics['cvssMetricV31'][0]['cvssData']
                        results['cvss_v3'] = {
                            'score': cvss3.get('baseScore'),
                            'severity': cvss3.get('baseSeverity'),
                            'vector': cvss3.get('vectorString'),
                            'exploitability': metrics['cvssMetricV31'][0].get('exploitabilityScore'),
                            'impact': metrics['cvssMetricV31'][0].get('impactScore')
                        }
                        results['severity'] = cvss3.get('baseSeverity')
                        results['exploitability'] = metrics['cvssMetricV31'][0].get('exploitabilityScore')
                        results['impact'] = metrics['cvssMetricV31'][0].get('impactScore')
                    
                    # CVSS v2
                    if metrics.get('cvssMetricV2'):
                        cvss2 = metrics['cvssMetricV2'][0]['cvssData']
                        results['cvss_v2'] = {
                            'score': cvss2.get('baseScore'),
                            'severity': metrics['cvssMetricV2'][0].get('baseSeverity'),
                            'vector': cvss2.get('vectorString')
                        }
                    
                    # CWE (weakness types)
                    for weakness in vuln.get('weaknesses', []):
                        for desc in weakness.get('description', []):
                            if desc.get('value'):
                                results['cwe'].append(desc['value'])
                    
                    # CPE (affected products)
                    for config in vuln.get('configurations', []):
                        for node in config.get('nodes', []):
                            for match in node.get('cpeMatch', []):
                                if match.get('criteria'):
                                    results['cpe'].append(match['criteria'])
                                    # Extract vendor and product
                                    cpe_parts = match['criteria'].split(':')
                                    if len(cpe_parts) >= 5:
                                        vendor = cpe_parts[3]
                                        product = cpe_parts[4]
                                        results['affected_products'].append(f"{vendor} {product}")
                                        results['vendors'].append(vendor)
                    
                    # References
                    for ref in vuln.get('references', [])[:20]:
                        results['references'].append({
                            'url': ref.get('url'),
                            'source': ref.get('source'),
                            'tags': ref.get('tags', [])
                        })
                    
                    results['sources'].append('nvd')
        except: pass
        
        # 2. CIRCL.lu - CVE database
        try:
            r = self.session.get(f"{self.free_apis['circl']}/{cve_id}", timeout=10)
            if r.status_code == 200:
                data = r.json()
                if not results['description']:
                    results['description'] = data.get('summary')
                
                # CAPEC (attack patterns)
                if data.get('capec'):
                    results['tags'].extend([f"CAPEC-{c['id']}" for c in data['capec'][:5]])
                
                results['sources'].append('circl')
        except: pass
        
        # 3. CISA KEV (Known Exploited Vulnerabilities)
        try:
            r = self.session.get(self.free_apis['cisa_kev'], timeout=10)
            if r.status_code == 200:
                data = r.json()
                for vuln in data.get('vulnerabilities', []):
                    if vuln.get('cveID') == cve_id:
                        results['cisa_kev'] = True
                        results['in_wild'] = True
                        results['tags'].append('CISA_KEV')
                        results['tags'].append('exploited_in_wild')
                        results['sources'].append('cisa_kev')
                        break
        except: pass
        
        # 4. ExploitDB - Exploit search
        try:
            r = self.session.get(self.free_apis['exploitdb'],
                                params={'cve': cve_id},
                                timeout=10)
            if r.status_code == 200:
                # Parse HTML for exploits
                exploit_matches = re.findall(r'<a href="/exploits/(\d+)"[^>]*>([^<]+)</a>', r.text)
                for exploit_id, title in exploit_matches[:10]:
                    results['exploits'].append({
                        'source': 'ExploitDB',
                        'id': exploit_id,
                        'title': title.strip(),
                        'url': f'https://www.exploit-db.com/exploits/{exploit_id}'
                    })
                    results['exploit_available'] = True
                    results['poc_available'] = True
                
                if results['exploits']:
                    results['sources'].append('exploitdb')
        except: pass
        
        # 5. GitHub Security Advisories
        try:
            r = self.session.get(self.free_apis['github_advisory'],
                                params={'cve_id': cve_id},
                                timeout=10)
            if r.status_code == 200:
                advisories = r.json()
                for advisory in advisories[:5]:
                    results['references'].append({
                        'url': advisory.get('html_url'),
                        'source': 'GitHub Advisory',
                        'severity': advisory.get('severity'),
                        'summary': advisory.get('summary')
                    })
                    
                    # Check for patches
                    if advisory.get('vulnerabilities'):
                        for vuln in advisory['vulnerabilities']:
                            if vuln.get('patched_versions'):
                                results['patch_available'] = True
                                results['patches'].append({
                                    'package': vuln.get('package', {}).get('name'),
                                    'patched_versions': vuln.get('patched_versions')
                                })
                
                if advisories:
                    results['sources'].append('github_advisory')
        except: pass
        
        # === PAID APIs ===
        
        # 6. Vulners - Exploit intelligence
        if self.paid_apis['vulners_key']:
            try:
                r = self.session.post('https://vulners.com/api/v3/search/id/',
                                     json={'id': cve_id, 'apiKey': self.paid_apis['vulners_key']},
                                     timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    if data.get('data', {}).get('documents'):
                        doc = data['data']['documents'][cve_id]
                        
                        # Exploit info
                        if doc.get('exploits'):
                            for exploit in doc['exploits'][:10]:
                                results['exploits'].append({
                                    'source': 'Vulners',
                                    'title': exploit.get('title'),
                                    'url': exploit.get('href')
                                })
                                results['exploit_available'] = True
                        
                        results['sources'].append('vulners')
            except: pass
        
        # === SENTINEL PRO MODULE INTEGRATION ===
        
        # 7. Metasploit module search
        try:
            from sentinel_brain.kali_controller import KaliController
            kali = KaliController()
            
            # Search for Metasploit modules
            msf_result = kali.execute_tool('searchsploit', [cve_id])
            if msf_result.get('success'):
                output = msf_result.get('output', '')
                # Parse searchsploit output
                for line in output.split('\n'):
                    if cve_id.lower() in line.lower():
                        results['metasploit_modules'].append(line.strip())
                        results['exploit_available'] = True
            
            results['sources'].append('sentinel_searchsploit')
        except: pass
        
        # 8. Nuclei template search
        try:
            import subprocess
            nuclei_path = '/usr/bin/nuclei'
            if os.path.exists(nuclei_path):
                result = subprocess.run(
                    [nuclei_path, '-t', f'cves/{cve_id.lower()}.yaml', '-list', '/dev/null'],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0 or 'loaded' in result.stderr.lower():
                    results['tags'].append('nuclei_template_available')
                    results['poc_available'] = True
                    results['sources'].append('nuclei')
        except: pass
        
        # === ML ANALYSIS ===
        
        # 9. ML Risk Scoring with SentinelNet
        try:
            from modules.ml_engine.trainer import ModelTrainer
            trainer = ModelTrainer()
            
            threat_text = f"""
            cve: {cve_id}
            severity: {results['severity']}
            cvss_score: {results['cvss_v3'].get('score', 0)}
            exploitability: {results['exploitability']}
            impact: {results['impact']}
            exploit_available: {results['exploit_available']}
            poc_available: {results['poc_available']}
            in_wild: {results['in_wild']}
            cisa_kev: {results['cisa_kev']}
            cwe: {', '.join(results['cwe'][:5])}
            affected_products: {len(results['affected_products'])}
            """
            
            ml_pred = trainer.predict_threat(threat_text)
            risk_map = {'LOW': 0.2, 'MEDIUM': 0.5, 'HIGH': 0.75, 'CRITICAL': 1.0}
            results['risk_score'] = risk_map.get(ml_pred.get('label', 'LOW'), 0.0)
            
            # Override risk based on CVSS and exploitation
            cvss_score = results['cvss_v3'].get('score', 0)
            if cvss_score >= 9.0:
                results['risk_score'] = max(results['risk_score'], 0.9)
            elif cvss_score >= 7.0:
                results['risk_score'] = max(results['risk_score'], 0.75)
            
            if results['in_wild'] or results['cisa_kev']:
                results['risk_score'] = max(results['risk_score'], 0.95)
            elif results['exploit_available']:
                results['risk_score'] = max(results['risk_score'], 0.8)
            
            results['ml_prediction'] = ml_pred
            results['sources'].append('sentinelnet_ml')
        except: pass
        
        # Deduplicate lists
        results['cwe'] = list(set(results['cwe']))
        results['vendors'] = list(set([v for v in results['vendors'] if v]))
        results['affected_products'] = list(set(results['affected_products']))[:20]
        results['tags'] = list(set(results['tags']))
        
        # Summary
        results['summary'] = {
            'severity': results['severity'] or 'UNKNOWN',
            'cvss_score': results['cvss_v3'].get('score') or results['cvss_v2'].get('score') or 'N/A',
            'exploit_available': results['exploit_available'],
            'poc_available': results['poc_available'],
            'patch_available': results['patch_available'],
            'in_wild': results['in_wild'],
            'cisa_kev': results['cisa_kev'],
            'total_sources': len(results['sources']),
            'exploits_found': len(results['exploits']),
            'affected_products': len(results['affected_products'])
        }
        
        return results
