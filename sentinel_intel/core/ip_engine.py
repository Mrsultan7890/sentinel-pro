"""
IP Intelligence Engine - 12+ Free APIs + Threat Intel
Shodan, Censys, GreyNoise, AbuseIPDB, VirusTotal + ML
"""
import sys
import os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
import config
import requests
from typing import Dict, List

class IPEngine:
    def __init__(self):
        self.free_apis = {
            'ipapi': 'http://ip-api.com/json',
            'ipinfo': 'https://ipinfo.io',
            'abuseipdb': 'https://api.abuseipdb.com/api/v2/check',
            'virustotal': 'https://www.virustotal.com/api/v3/ip_addresses',
            'ipqualityscore': 'https://ipqualityscore.com/api/json/ip',
            'greynoise': 'https://api.greynoise.io/v3/community',
            'alienvault': 'https://otx.alienvault.com/api/v1/indicators/IPv4',
            'threatcrowd': 'https://www.threatcrowd.org/searchApi/v2/ip/report',
            'censys': 'https://search.censys.io/api/v2/hosts',
            'ipgeolocation': 'https://api.ipgeolocation.io/ipgeo',
            'ipdata': 'https://api.ipdata.co'
        }
        self.paid_apis = {
            'shodan': config.SHODAN_API_KEY,
            'virustotal_key': os.getenv('VIRUSTOTAL_API_KEY', ''),
            'abuseipdb_key': os.getenv('ABUSEIPDB_API_KEY', ''),
            'greynoise_key': os.getenv('GREYNOISE_API_KEY', ''),
            'censys_id': os.getenv('CENSYS_API_ID', ''),
            'censys_secret': os.getenv('CENSYS_API_SECRET', '')
        }
    
    def investigate(self, ip: str) -> Dict:
        """Deep IP investigation - 12+ sources + ML"""
        results = {
            'ip': ip,
            'sources': [],
            'geolocation': {},
            'reputation': {},
            'ports': [],
            'services': [],
            'vulns': [],
            'cves': [],
            'domains': [],
            'hostnames': [],
            'asn': {},
            'threat_intel': [],
            'malware': [],
            'risk_score': 0.0,
            'tags': [],
            'historical_data': {}
        }
        
        # === FREE APIs (No Key Required) ===
        
        # 1. ip-api.com - Geolocation (100 req/min limit)
        try:
            r = requests.get(f"{self.free_apis['ipapi']}/{ip}?fields=66846719", timeout=10)
            if r.status_code == 200:
                data = r.json()
                if data.get('status') == 'success':
                    results['geolocation'] = {
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'zip': data.get('zip'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'as': data.get('as'),
                        'mobile': data.get('mobile', False),
                        'proxy': data.get('proxy', False),
                        'hosting': data.get('hosting', False)
                    }
                    results['asn'] = {
                        'number': data.get('as', '').split()[0] if data.get('as') else None,
                        'name': data.get('as')
                    }
                    results['sources'].append('ipapi')
        except: pass
        
        # 2. IPInfo.io - Additional geolocation (fallback)
        if not results['geolocation'].get('country'):  # Only if first API failed
            try:
                r = requests.get(f"{self.free_apis['ipinfo']}/{ip}/json", timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    loc = data.get('loc', '').split(',')
                    results['geolocation'] = {
                        'city': data.get('city'),
                        'region': data.get('region'),
                        'country': data.get('country'),
                        'lat': float(loc[0]) if len(loc) == 2 else None,
                        'lon': float(loc[1]) if len(loc) == 2 else None,
                        'org': data.get('org'),
                        'zip': data.get('postal'),
                        'timezone': data.get('timezone')
                    }
                    if data.get('hostname'):
                        results['hostnames'].append(data.get('hostname'))
                    results['sources'].append('ipinfo')
            except: pass
        
        # 3. ThreatCrowd - Threat intelligence
        try:
            r = requests.get(f"{self.free_apis['threatcrowd']}", params={'ip': ip}, timeout=10)
            if r.status_code == 200:
                data = r.json()
                if data.get('response_code') == '1':
                    results['domains'].extend(data.get('resolutions', []))
                    results['threat_intel'].append({
                        'source': 'threatcrowd',
                        'votes': data.get('votes', 0),
                        'references': data.get('references', [])
                    })
                    results['sources'].append('threatcrowd')
        except: pass
        
        # 4. AlienVault OTX - Threat intelligence
        try:
            r = requests.get(f"{self.free_apis['alienvault']}/{ip}/general", timeout=10)
            if r.status_code == 200:
                data = r.json()
                results['threat_intel'].append({
                    'source': 'alienvault_otx',
                    'pulse_count': data.get('pulse_info', {}).get('count', 0),
                    'tags': data.get('pulse_info', {}).get('pulses', [])[:5]
                })
                results['sources'].append('alienvault')
            
            # Get malware data
            r = requests.get(f"{self.free_apis['alienvault']}/{ip}/malware", timeout=10)
            if r.status_code == 200:
                data = r.json()
                results['malware'].extend(data.get('data', [])[:10])
        except: pass
        
        # === PAID APIs (If Keys Available) ===
        
        # 5. AbuseIPDB - Abuse reports
        if self.paid_apis['abuseipdb_key']:
            try:
                headers = {'Key': self.paid_apis['abuseipdb_key'], 'Accept': 'application/json'}
                r = requests.get(self.free_apis['abuseipdb'], headers=headers,
                               params={'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': ''}, timeout=10)
                if r.status_code == 200:
                    data = r.json().get('data', {})
                    results['reputation'] = {
                        'abuse_score': data.get('abuseConfidenceScore', 0),
                        'reports': data.get('totalReports', 0),
                        'distinct_users': data.get('numDistinctUsers', 0),
                        'last_reported': data.get('lastReportedAt'),
                        'is_whitelisted': data.get('isWhitelisted', False),
                        'usage_type': data.get('usageType'),
                        'isp': data.get('isp'),
                        'domain': data.get('domain')
                    }
                    results['sources'].append('abuseipdb')
            except: pass
        
        # 6. VirusTotal - Malware/threat detection
        if self.paid_apis['virustotal_key']:
            try:
                headers = {'x-apikey': self.paid_apis['virustotal_key']}
                r = requests.get(f"{self.free_apis['virustotal']}/{ip}", headers=headers, timeout=10)
                if r.status_code == 200:
                    data = r.json().get('data', {}).get('attributes', {})
                    last_analysis = data.get('last_analysis_stats', {})
                    results['reputation']['virustotal'] = {
                        'malicious': last_analysis.get('malicious', 0),
                        'suspicious': last_analysis.get('suspicious', 0),
                        'harmless': last_analysis.get('harmless', 0),
                        'undetected': last_analysis.get('undetected', 0)
                    }
                    results['tags'].extend(data.get('tags', []))
                    results['sources'].append('virustotal')
            except: pass
        
        # 7. GreyNoise - Internet scanner detection
        if self.paid_apis['greynoise_key']:
            try:
                headers = {'key': self.paid_apis['greynoise_key']}
                r = requests.get(f"{self.free_apis['greynoise']}/{ip}", headers=headers, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    results['threat_intel'].append({
                        'source': 'greynoise',
                        'noise': data.get('noise', False),
                        'riot': data.get('riot', False),
                        'classification': data.get('classification'),
                        'name': data.get('name'),
                        'last_seen': data.get('last_seen')
                    })
                    results['sources'].append('greynoise')
            except: pass
        
        # 8. Shodan - Port scanning & vulnerabilities
        if self.paid_apis['shodan']:
            try:
                import shodan
                api = shodan.Shodan(self.paid_apis['shodan'])
                host = api.host(ip)
                
                results['ports'] = host.get('ports', [])
                results['vulns'] = list(host.get('vulns', []))
                results['hostnames'].extend(host.get('hostnames', []))
                results['domains'].extend(host.get('domains', []))
                results['tags'].extend(host.get('tags', []))
                
                # Extract services
                for item in host.get('data', []):
                    results['services'].append({
                        'port': item.get('port'),
                        'transport': item.get('transport'),
                        'product': item.get('product'),
                        'version': item.get('version'),
                        'banner': item.get('data', '')[:200]
                    })
                
                # Extract CVEs
                for vuln in host.get('vulns', []):
                    results['cves'].append({
                        'cve': vuln,
                        'cvss': host.get('vulns', {}).get(vuln, {}).get('cvss')
                    })
                
                results['asn'] = {
                    'number': host.get('asn'),
                    'name': host.get('org')
                }
                
                results['sources'].append('shodan')
            except: pass
        
        # 9. Censys - Internet-wide scanning
        if self.paid_apis['censys_id'] and self.paid_apis['censys_secret']:
            try:
                auth = (self.paid_apis['censys_id'], self.paid_apis['censys_secret'])
                r = requests.get(f"{self.free_apis['censys']}/{ip}", auth=auth, timeout=10)
                if r.status_code == 200:
                    data = r.json().get('result', {})
                    
                    # Extract services
                    for service in data.get('services', []):
                        results['services'].append({
                            'port': service.get('port'),
                            'service_name': service.get('service_name'),
                            'transport_protocol': service.get('transport_protocol'),
                            'banner': service.get('banner', '')[:200]
                        })
                    
                    results['sources'].append('censys')
            except: pass
        
        # === SENTINEL PRO MODULE INTEGRATION ===
        
        # 10. Use Sentinel Pro's recon modules
        try:
            from modules.recon.asn_mapper import ASNMapper
            asn_mapper = ASNMapper()
            asn_data = asn_mapper.lookup_ip(ip)
            
            if asn_data:
                results['asn'].update(asn_data)
                results['sources'].append('sentinel_asn')
        except: pass
        
        # 11. Cloud asset detection
        try:
            from modules.recon.cloud_assets import CloudAssetDetector
            cloud = CloudAssetDetector()
            cloud_data = cloud.detect_ip(ip)
            
            if cloud_data.get('is_cloud'):
                results['cloud'] = cloud_data
                results['tags'].append(f"cloud_{cloud_data.get('provider', 'unknown')}")
                results['sources'].append('sentinel_cloud')
        except: pass
        
        # === ML ANALYSIS ===
        
        # 12. ML Risk Scoring with SentinelNet
        try:
            from modules.ml_engine.trainer import ModelTrainer
            trainer = ModelTrainer()
            
            # Build threat context
            threat_text = f"""
            ip: {ip}
            abuse_score: {results['reputation'].get('abuse_score', 0)}
            reports: {results['reputation'].get('reports', 0)}
            vulns: {len(results['vulns'])}
            cves: {len(results['cves'])}
            malware: {len(results['malware'])}
            threat_intel_sources: {len(results['threat_intel'])}
            open_ports: {len(results['ports'])}
            tags: {', '.join(results['tags'][:10])}
            """
            
            ml_pred = trainer.predict_threat(threat_text)
            risk_map = {'LOW': 0.2, 'MEDIUM': 0.5, 'HIGH': 0.75, 'CRITICAL': 1.0}
            results['risk_score'] = risk_map.get(ml_pred.get('label', 'LOW'), 0.0)
            results['ml_prediction'] = ml_pred
            results['sources'].append('sentinelnet_ml')
        except: pass
        
        # === GROQ IP THREAT ANALYSIS ===
        
        try:
            from modules.ml_engine.groq_llm import get_groq
            import time
            groq = get_groq()
            
            if groq and groq.is_ready:
                # Build context
                geo = results.get('geolocation', {})
                rep = results.get('reputation', {})
                
                ports_summary = ', '.join([str(p) for p in results['ports'][:10]])
                vulns_summary = [f"- {v.get('title', 'Unknown')} [{v.get('severity', 'N/A')}]" for v in results['vulns'][:3]]
                threat_summary = [f"- {t.get('source', 'Unknown')}: {t.get('description', 'N/A')[:80]}" for t in results['threat_intel'][:3]]
                
                context = f"""
IP Intelligence Summary:
- IP Address: {ip}
- Location: {geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}
- ISP: {geo.get('isp', 'Unknown')}
- ASN: {geo.get('asn', 'Unknown')}
- Organization: {geo.get('org', 'Unknown')}
- Abuse Score: {rep.get('abuse_score', 0)}%
- Abuse Reports: {rep.get('reports', 0)}
- Open Ports: {ports_summary or 'None detected'}
- Vulnerabilities: {len(results['vulns'])}
- CVEs: {len(results['cves'])}
- Malware Associations: {len(results['malware'])}
- Threat Intel Sources: {len(results['threat_intel'])}
- ML Risk Score: {results['risk_score']:.0%}

Top Vulnerabilities:
{chr(10).join(vulns_summary) if vulns_summary else 'None'}

Threat Intelligence:
{chr(10).join(threat_summary) if threat_summary else 'None'}
"""
                
                prompt = f"""Analyze this IP address intelligence:

1. **Threat Level Assessment**: Overall security threat (LOW/MEDIUM/HIGH/CRITICAL)
2. **Attack Surface Analysis**: Open ports and exposed services
3. **Reputation Score Interpretation**: What the abuse score means
4. **Vulnerability Assessment**: Critical security issues
5. **Recommended Security Actions**: Immediate steps to take

{context}

Provide detailed professional security analysis."""
                
                groq_response = groq.ask(prompt, max_tokens=500)
                
                results['groq_analysis'] = {
                    'assessment': groq_response,
                    'timestamp': time.time(),
                    'model': groq.MODEL
                }
                results['sources'].append('groq_llm')
        except Exception as e:
            results['errors'].append(f'Groq: {str(e)}')
        
        # Deduplicate lists
        results['domains'] = list(set([d for d in results['domains'] if d]))
        results['hostnames'] = list(set([h for h in results['hostnames'] if h]))
        results['tags'] = list(set(results['tags']))
        
        return results
