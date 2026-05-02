"""
Hash Intelligence Engine - Malware & File Hash Analysis
VirusTotal, MalwareBazaar, Hybrid Analysis, ThreatFox + ML
"""
import sys
import os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
import config
import requests
from typing import Dict

class HashEngine:
    def __init__(self):
        self.free_apis = {
            'virustotal': 'https://www.virustotal.com/api/v3/files',
            'malwarebazaar': 'https://mb-api.abuse.ch/api/v1',
            'threatfox': 'https://threatfox-api.abuse.ch/api/v1',
            'hybridanalysis': 'https://www.hybrid-analysis.com/api/v2/search/hash',
            'alienvault': 'https://otx.alienvault.com/api/v1/indicators/file',
            'metadefender': 'https://api.metadefender.com/v4/hash'
        }
        self.paid_apis = {
            'virustotal_key': os.getenv('VIRUSTOTAL_API_KEY', ''),
            'hybridanalysis_key': os.getenv('HYBRIDANALYSIS_API_KEY', '')
        }
    
    def investigate(self, hash_value: str) -> Dict:
        """Deep hash investigation - malware analysis"""
        results = {
            'hash': hash_value,
            'hash_type': self._detect_hash_type(hash_value),
            'sources': [],
            'malicious': False,
            'detections': 0,
            'total_engines': 0,
            'malware_families': [],
            'file_info': {},
            'signatures': [],
            'behavior': [],
            'network_activity': [],
            'dropped_files': [],
            'registry_keys': [],
            'threat_names': [],
            'risk_score': 0.0,
            'first_seen': None,
            'last_seen': None
        }
        
        # === FREE APIs ===
        
        # 1. MalwareBazaar - Free malware database
        try:
            r = requests.post(self.free_apis['malwarebazaar'],
                            data={'query': 'get_info', 'hash': hash_value}, timeout=10)
            if r.status_code == 200:
                data = r.json()
                if data.get('query_status') == 'ok':
                    info = data.get('data', [{}])[0]
                    results['malicious'] = True
                    results['file_info'] = {
                        'file_name': info.get('file_name'),
                        'file_type': info.get('file_type'),
                        'file_size': info.get('file_size'),
                        'mime_type': info.get('mime_type')
                    }
                    results['malware_families'].append(info.get('signature'))
                    results['first_seen'] = info.get('first_seen')
                    results['threat_names'].append(info.get('signature'))
                    results['sources'].append('malwarebazaar')
        except: pass
        
        # 2. ThreatFox - IOC database
        try:
            r = requests.post(self.free_apis['threatfox'],
                            json={'query': 'search_hash', 'hash': hash_value}, timeout=10)
            if r.status_code == 200:
                data = r.json()
                if data.get('query_status') == 'ok':
                    for ioc in data.get('data', []):
                        results['malicious'] = True
                        results['malware_families'].append(ioc.get('malware'))
                        results['threat_names'].append(ioc.get('threat_type'))
                    results['sources'].append('threatfox')
        except: pass
        
        # 3. AlienVault OTX - Threat intelligence
        try:
            r = requests.get(f"{self.free_apis['alienvault']}/{hash_value}/general", timeout=10)
            if r.status_code == 200:
                data = r.json()
                pulse_info = data.get('pulse_info', {})
                if pulse_info.get('count', 0) > 0:
                    results['malicious'] = True
                    for pulse in pulse_info.get('pulses', [])[:5]:
                        results['threat_names'].append(pulse.get('name'))
                        results['malware_families'].extend(pulse.get('tags', []))
                    results['sources'].append('alienvault')
        except: pass
        
        # === PAID APIs ===
        
        # 4. VirusTotal - Comprehensive malware analysis
        if self.paid_apis['virustotal_key']:
            try:
                headers = {'x-apikey': self.paid_apis['virustotal_key']}
                r = requests.get(f"{self.free_apis['virustotal']}/{hash_value}", headers=headers, timeout=10)
                if r.status_code == 200:
                    data = r.json().get('data', {}).get('attributes', {})
                    
                    # Detection stats
                    last_analysis = data.get('last_analysis_stats', {})
                    results['detections'] = last_analysis.get('malicious', 0)
                    results['total_engines'] = sum(last_analysis.values())
                    results['malicious'] = results['detections'] > 0
                    
                    # File info
                    results['file_info'] = {
                        'file_name': data.get('meaningful_name'),
                        'file_type': data.get('type_description'),
                        'file_size': data.get('size'),
                        'magic': data.get('magic'),
                        'md5': data.get('md5'),
                        'sha1': data.get('sha1'),
                        'sha256': data.get('sha256')
                    }
                    
                    # Signatures
                    results['signatures'] = data.get('signature_info', {}).get('verified', [])
                    
                    # Threat names
                    last_analysis_results = data.get('last_analysis_results', {})
                    for engine, result in last_analysis_results.items():
                        if result.get('category') == 'malicious':
                            threat_name = result.get('result')
                            if threat_name:
                                results['threat_names'].append(threat_name)
                    
                    # Timestamps
                    results['first_seen'] = data.get('first_submission_date')
                    results['last_seen'] = data.get('last_analysis_date')
                    
                    results['sources'].append('virustotal')
            except: pass
        
        # 5. Hybrid Analysis - Sandbox analysis
        if self.paid_apis['hybridanalysis_key']:
            try:
                headers = {
                    'api-key': self.paid_apis['hybridanalysis_key'],
                    'User-Agent': 'Falcon Sandbox'
                }
                r = requests.post(self.free_apis['hybridanalysis'],
                                data={'hash': hash_value}, headers=headers, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    if data:
                        report = data[0]
                        results['malicious'] = report.get('verdict') in ['malicious', 'suspicious']
                        results['threat_names'].append(report.get('threat_level'))
                        
                        # Behavior analysis
                        if report.get('processes'):
                            results['behavior'] = report['processes'][:10]
                        if report.get('network'):
                            results['network_activity'] = report['network'][:10]
                        if report.get('dropped_files'):
                            results['dropped_files'] = report['dropped_files'][:10]
                        
                        results['sources'].append('hybridanalysis')
            except: pass
        
        # === ML ANALYSIS ===
        
        # 6. ML Risk Scoring
        try:
            from modules.ml_engine.trainer import ModelTrainer
            trainer = ModelTrainer()
            
            threat_text = f"""
            hash: {hash_value}
            malicious: {results['malicious']}
            detections: {results['detections']}
            total_engines: {results['total_engines']}
            malware_families: {len(results['malware_families'])}
            threat_names: {len(results['threat_names'])}
            signatures: {len(results['signatures'])}
            behavior: {len(results['behavior'])}
            """
            
            ml_pred = trainer.predict_threat(threat_text)
            risk_map = {'LOW': 0.2, 'MEDIUM': 0.5, 'HIGH': 0.75, 'CRITICAL': 1.0}
            results['risk_score'] = risk_map.get(ml_pred.get('label', 'LOW'), 0.0)
            
            # Override risk if malicious
            if results['malicious']:
                results['risk_score'] = max(results['risk_score'], 0.75)
            
            results['ml_prediction'] = ml_pred
            results['sources'].append('sentinelnet_ml')
        except: pass
        
        # === GROQ MALWARE ANALYSIS ===
        
        try:
            from modules.ml_engine.groq_llm import get_groq
            import time
            groq = get_groq()
            
            if groq and groq.is_ready:
                families = ', '.join(results['malware_families'][:5]) if results['malware_families'] else 'None'
                threats = ', '.join(results['threat_names'][:5]) if results['threat_names'] else 'None'
                sigs = ', '.join(results['signatures'][:5]) if results['signatures'] else 'None'
                
                context = f"""
Hash Intelligence Summary:
- Hash: {hash_value}
- Type: {results.get('hash_type', 'Unknown')}
- Malicious: {results['malicious']}
- Detection Ratio: {results['detections']}/{results['total_engines']}
- Malware Families: {families}
- Threat Names: {threats}
- File Type: {results.get('file_type', 'Unknown')}
- File Size: {results.get('file_size', 'Unknown')}
- Signatures: {sigs}
- Behavior Indicators: {len(results['behavior'])}
- Network Activity: {len(results['network_activity'])}
- ML Risk Score: {results['risk_score']:.0%}
"""
                
                prompt = f"""Analyze this malware sample:

1. **Threat Severity Assessment**: How dangerous is this malware? (LOW/MEDIUM/HIGH/CRITICAL)
2. **Attack Vector Analysis**: How does this malware spread and infect?
3. **Potential Impact**: What damage can this malware cause?
4. **IOC Extraction**: Key indicators of compromise
5. **Mitigation Recommendations**: How to detect and remove this threat

{context}

Provide detailed professional malware analysis."""
                
                groq_response = groq.ask(prompt, max_tokens=500)
                
                results['groq_analysis'] = {
                    'assessment': groq_response,
                    'timestamp': time.time(),
                    'model': groq.MODEL
                }
                results['sources'].append('groq_llm')
        except Exception as e:
            pass
        
        # Deduplicate lists
        results['malware_families'] = list(set([f for f in results['malware_families'] if f]))[:20]
        results['threat_names'] = list(set([t for t in results['threat_names'] if t]))[:20]
        
        return results
    
    def _detect_hash_type(self, hash_value: str) -> str:
        """Detect hash type by length"""
        length = len(hash_value)
        if length == 32:
            return 'MD5'
        elif length == 40:
            return 'SHA1'
        elif length == 64:
            return 'SHA256'
        elif length == 128:
            return 'SHA512'
        else:
            return 'Unknown'
