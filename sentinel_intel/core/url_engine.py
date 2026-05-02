"""
URL Intelligence Engine - Malicious Link Detection + Redirect Analysis
VirusTotal, URLhaus, PhishTank, Google Safe Browsing + ML
"""
import sys
import os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
import config
import requests
from typing import Dict, List
from urllib.parse import urlparse, parse_qs
import re

class URLEngine:
    def __init__(self):
        self.free_apis = {
            'urlhaus': 'https://urlhaus-api.abuse.ch/v1/url/',
            'phishtank': 'https://checkurl.phishtank.com/checkurl/',
            'virustotal': 'https://www.virustotal.com/api/v3/urls',
            'urlscan': 'https://urlscan.io/api/v1/search',
            'safebrowsing': 'https://safebrowsing.googleapis.com/v4/threatMatches:find',
            'alienvault': 'https://otx.alienvault.com/api/v1/indicators/url',
            'hybrid_analysis': 'https://www.hybrid-analysis.com/api/v2/search/terms',
            'checkphish': 'https://developers.checkphish.ai/api/neo/scan'
        }
        self.paid_apis = {
            'virustotal_key': os.getenv('VIRUSTOTAL_API_KEY', ''),
            'urlscan_key': os.getenv('URLSCAN_API_KEY', ''),
            'safebrowsing_key': os.getenv('GOOGLE_SAFEBROWSING_KEY', ''),
            'phishtank_key': os.getenv('PHISHTANK_API_KEY', ''),
            'checkphish_key': os.getenv('CHECKPHISH_API_KEY', '')
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def investigate(self, url: str) -> Dict:
        """Deep URL investigation - malicious link detection"""
        results = {
            'url': url,
            'sources': [],
            'malicious': False,
            'phishing': False,
            'malware': False,
            'suspicious': False,
            'safe': False,
            'risk_score': 0.0,
            'detections': 0,
            'total_scans': 0,
            'categories': [],
            'tags': [],
            'redirects': [],
            'final_url': url,
            'domain': '',
            'ip': None,
            'country': None,
            'server': None,
            'status_code': None,
            'content_type': None,
            'title': None,
            'screenshot': None,
            'certificates': [],
            'technologies': [],
            'threat_names': [],
            'reports': []
        }
        
        # Parse URL
        parsed = urlparse(url)
        results['domain'] = parsed.netloc
        results['scheme'] = parsed.scheme
        results['path'] = parsed.path
        results['query'] = parse_qs(parsed.query)
        
        # === FREE APIs ===
        
        # 1. URLhaus - Malware URL database (abuse.ch)
        try:
            r = self.session.post(self.free_apis['urlhaus'], 
                                 data={'url': url}, timeout=10)
            if r.status_code == 200:
                data = r.json()
                if data.get('query_status') == 'ok':
                    results['malicious'] = True
                    results['malware'] = True
                    results['detections'] += 1
                    results['threat_names'].append(data.get('threat'))
                    results['tags'].extend(data.get('tags', []))
                    results['reports'].append({
                        'source': 'URLhaus',
                        'threat': data.get('threat'),
                        'date_added': data.get('date_added'),
                        'reporter': data.get('reporter'),
                        'larted': data.get('larted')
                    })
                    results['sources'].append('urlhaus')
                results['total_scans'] += 1
        except: pass
        
        # 2. PhishTank - Phishing URL database
        if self.paid_apis['phishtank_key']:
            try:
                r = self.session.post(self.free_apis['phishtank'],
                                     data={
                                         'url': url,
                                         'format': 'json',
                                         'app_key': self.paid_apis['phishtank_key']
                                     }, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    if data.get('results', {}).get('in_database'):
                        if data['results'].get('valid'):
                            results['malicious'] = True
                            results['phishing'] = True
                            results['detections'] += 1
                            results['reports'].append({
                                'source': 'PhishTank',
                                'verified': data['results'].get('verified'),
                                'submission_time': data['results'].get('submission_time')
                            })
                        results['sources'].append('phishtank')
                    results['total_scans'] += 1
            except: pass
        
        # 3. AlienVault OTX - Threat intelligence
        try:
            r = self.session.get(f"{self.free_apis['alienvault']}/{url}/general", timeout=10)
            if r.status_code == 200:
                data = r.json()
                pulse_count = data.get('pulse_info', {}).get('count', 0)
                if pulse_count > 0:
                    results['suspicious'] = True
                    results['detections'] += pulse_count
                    for pulse in data.get('pulse_info', {}).get('pulses', [])[:5]:
                        results['threat_names'].append(pulse.get('name'))
                        results['tags'].extend(pulse.get('tags', []))
                    results['sources'].append('alienvault')
                results['total_scans'] += 1
        except: pass
        
        # 4. Google Safe Browsing
        if self.paid_apis['safebrowsing_key']:
            try:
                payload = {
                    'client': {'clientId': 'sentinel-intel', 'clientVersion': '1.0'},
                    'threatInfo': {
                        'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                        'platformTypes': ['ANY_PLATFORM'],
                        'threatEntryTypes': ['URL'],
                        'threatEntries': [{'url': url}]
                    }
                }
                r = self.session.post(
                    f"{self.free_apis['safebrowsing']}?key={self.paid_apis['safebrowsing_key']}",
                    json=payload, timeout=10
                )
                if r.status_code == 200:
                    data = r.json()
                    if data.get('matches'):
                        results['malicious'] = True
                        results['detections'] += len(data['matches'])
                        for match in data['matches']:
                            threat_type = match.get('threatType')
                            results['threat_names'].append(threat_type)
                            if 'SOCIAL_ENGINEERING' in threat_type:
                                results['phishing'] = True
                            if 'MALWARE' in threat_type:
                                results['malware'] = True
                        results['sources'].append('google_safebrowsing')
                    else:
                        results['safe'] = True
                    results['total_scans'] += 1
            except: pass
        
        # === PAID APIs ===
        
        # 5. VirusTotal - Comprehensive URL scanning
        if self.paid_apis['virustotal_key']:
            try:
                import base64
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                headers = {'x-apikey': self.paid_apis['virustotal_key']}
                r = self.session.get(f"{self.free_apis['virustotal']}/{url_id}", 
                                    headers=headers, timeout=10)
                if r.status_code == 200:
                    data = r.json().get('data', {}).get('attributes', {})
                    
                    # Detection stats
                    last_analysis = data.get('last_analysis_stats', {})
                    results['detections'] += last_analysis.get('malicious', 0)
                    results['total_scans'] += sum(last_analysis.values())
                    
                    if last_analysis.get('malicious', 0) > 0:
                        results['malicious'] = True
                    if last_analysis.get('suspicious', 0) > 0:
                        results['suspicious'] = True
                    if last_analysis.get('malicious', 0) == 0 and last_analysis.get('suspicious', 0) == 0:
                        results['safe'] = True
                    
                    # Categories
                    results['categories'] = list(data.get('categories', {}).values())
                    
                    # Final URL after redirects
                    results['final_url'] = data.get('last_final_url', url)
                    
                    # Title
                    results['title'] = data.get('title')
                    
                    # Threat names
                    last_analysis_results = data.get('last_analysis_results', {})
                    for engine, result in last_analysis_results.items():
                        if result.get('category') in ['malicious', 'suspicious']:
                            threat = result.get('result')
                            if threat:
                                results['threat_names'].append(f"{engine}: {threat}")
                    
                    results['sources'].append('virustotal')
            except: pass
        
        # 6. URLScan.io - Website scanner
        if self.paid_apis['urlscan_key']:
            try:
                # Search for existing scans
                r = self.session.get(f"{self.free_apis['urlscan']}",
                                    params={'q': f'page.url:"{url}"'},
                                    headers={'API-Key': self.paid_apis['urlscan_key']},
                                    timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    if data.get('results'):
                        scan = data['results'][0]
                        results['screenshot'] = scan.get('screenshot')
                        results['final_url'] = scan.get('page', {}).get('url', url)
                        results['ip'] = scan.get('page', {}).get('ip')
                        results['country'] = scan.get('page', {}).get('country')
                        results['server'] = scan.get('page', {}).get('server')
                        results['title'] = scan.get('page', {}).get('title')
                        
                        # Verdicts
                        verdicts = scan.get('verdicts', {})
                        if verdicts.get('overall', {}).get('malicious'):
                            results['malicious'] = True
                            results['detections'] += 1
                        
                        results['sources'].append('urlscan')
                    results['total_scans'] += 1
            except: pass
        
        # === LIVE URL ANALYSIS ===
        
        # 7. Direct HTTP request - Follow redirects
        try:
            r = self.session.get(url, timeout=10, allow_redirects=True, verify=False)
            results['status_code'] = r.status_code
            results['content_type'] = r.headers.get('Content-Type')
            results['server'] = r.headers.get('Server')
            results['final_url'] = r.url
            
            # Track redirects
            if r.history:
                for resp in r.history:
                    results['redirects'].append({
                        'url': resp.url,
                        'status': resp.status_code
                    })
            
            # Extract title from HTML
            if 'text/html' in results['content_type']:
                title_match = re.search(r'<title[^>]*>(.*?)</title>', r.text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    results['title'] = title_match.group(1).strip()[:200]
            
            # Suspicious patterns in content
            suspicious_keywords = ['login', 'password', 'verify', 'account', 'suspended', 'update', 'confirm', 'secure']
            content_lower = r.text.lower()
            found_keywords = [kw for kw in suspicious_keywords if kw in content_lower]
            if len(found_keywords) >= 3:
                results['suspicious'] = True
                results['tags'].append('suspicious_content')
            
            results['sources'].append('http_analysis')
        except: pass
        
        # 8. DNS resolution
        try:
            import socket
            results['ip'] = socket.gethostbyname(results['domain'])
            results['sources'].append('dns_resolution')
        except: pass
        
        # === HEURISTIC ANALYSIS ===
        
        # 9. URL pattern analysis
        suspicious_patterns = [
            r'bit\.ly|tinyurl|goo\.gl',  # URL shorteners
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address in URL
            r'@',  # @ symbol (phishing trick)
            r'-{2,}',  # Multiple dashes
            r'\.tk|\.ml|\.ga|\.cf|\.gq',  # Free TLDs
            r'paypal|amazon|apple|microsoft|google',  # Brand impersonation
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                results['suspicious'] = True
                results['tags'].append(f'pattern_{pattern[:20]}')
        
        # Long URLs are suspicious
        if len(url) > 100:
            results['suspicious'] = True
            results['tags'].append('long_url')
        
        # === SENTINEL PRO MODULE INTEGRATION ===
        
        # 10. Use Sentinel Pro's domain scanner
        try:
            from modules.bugbounty.ssl_checker import SSLChecker
            ssl_checker = SSLChecker()
            ssl_data = ssl_checker.check(results['domain'])
            
            if ssl_data.get('valid'):
                results['certificates'].append({
                    'issuer': ssl_data.get('issuer'),
                    'valid_from': ssl_data.get('valid_from'),
                    'valid_to': ssl_data.get('valid_to'),
                    'expired': ssl_data.get('expired')
                })
            results['sources'].append('sentinel_ssl')
        except: pass
        
        # 11. Tech fingerprinting
        try:
            from modules.bugbounty.tech_fingerprint import TechFingerprinter
            tech = TechFingerprinter()
            tech_data = tech.detect(url)
            
            results['technologies'] = tech_data.get('technologies', [])
            results['sources'].append('sentinel_tech')
        except: pass
        
        # === ML ANALYSIS ===
        
        # 12. ML Risk Scoring with SentinelNet
        try:
            from modules.ml_engine.trainer import ModelTrainer
            trainer = ModelTrainer()
            
            threat_text = f"""
            url: {url}
            domain: {results['domain']}
            malicious: {results['malicious']}
            phishing: {results['phishing']}
            malware: {results['malware']}
            suspicious: {results['suspicious']}
            detections: {results['detections']}
            total_scans: {results['total_scans']}
            redirects: {len(results['redirects'])}
            threat_names: {len(results['threat_names'])}
            tags: {', '.join(results['tags'][:10])}
            """
            
            ml_pred = trainer.predict_threat(threat_text)
            risk_map = {'LOW': 0.2, 'MEDIUM': 0.5, 'HIGH': 0.75, 'CRITICAL': 1.0}
            results['risk_score'] = risk_map.get(ml_pred.get('label', 'LOW'), 0.0)
            
            # Override risk if malicious
            if results['malicious']:
                results['risk_score'] = max(results['risk_score'], 0.9)
            elif results['phishing']:
                results['risk_score'] = max(results['risk_score'], 0.85)
            elif results['suspicious']:
                results['risk_score'] = max(results['risk_score'], 0.6)
            
            results['ml_prediction'] = ml_pred
            results['sources'].append('sentinelnet_ml')
        except: pass
        
        # Deduplicate lists
        results['threat_names'] = list(set([t for t in results['threat_names'] if t]))[:20]
        results['tags'] = list(set(results['tags']))
        results['categories'] = list(set(results['categories']))
        
        # Summary
        results['summary'] = {
            'verdict': 'MALICIOUS' if results['malicious'] else 'SUSPICIOUS' if results['suspicious'] else 'SAFE' if results['safe'] else 'UNKNOWN',
            'detection_ratio': f"{results['detections']}/{results['total_scans']}" if results['total_scans'] > 0 else 'N/A',
            'total_sources': len(results['sources']),
            'has_redirects': len(results['redirects']) > 0,
            'final_destination': results['final_url'] != url
        }
        
        return results
