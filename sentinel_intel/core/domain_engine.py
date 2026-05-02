"""
Domain Intelligence Engine - 20+ Sources + Subdomain Enum
WHOIS, DNS, Subdomains, Tech Stack, Certificates, Wayback + ML
"""
import sys
import os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
import config
import requests
import socket
import dns.resolver
from typing import Dict, List

class DomainEngine:
    def __init__(self):
        self.free_apis = {
            'urlscan': 'https://urlscan.io/api/v1/search',
            'virustotal': 'https://www.virustotal.com/api/v3/domains',
            'whoxy': 'https://api.whoxy.com',
            'securitytrails': 'https://api.securitytrails.com/v1/domain',
            'crtsh': 'https://crt.sh',
            'wayback': 'https://web.archive.org/cdx/search/cdx',
            'hackertarget': 'https://api.hackertarget.com',
            'threatcrowd': 'https://www.threatcrowd.org/searchApi/v2/domain/report',
            'alienvault': 'https://otx.alienvault.com/api/v1/indicators/domain',
            'builtwith': 'https://api.builtwith.com/v20/api.json',
            'wappalyzer': 'internal'
        }
        self.paid_apis = {
            'shodan': config.SHODAN_API_KEY,
            'securitytrails_key': config.SECURITYTRAILS_API_KEY,
            'virustotal_key': os.getenv('VIRUSTOTAL_API_KEY', ''),
            'builtwith_key': os.getenv('BUILTWITH_API_KEY', '')
        }
    
    def investigate(self, domain: str) -> Dict:
        """Deep domain investigation - 20+ sources + ML"""
        results = {
            'domain': domain,
            'sources': [],
            'ips': [],
            'ipv6': [],
            'subdomains': [],
            'whois': {},
            'dns_records': {},
            'reputation': {},
            'certificates': [],
            'tech_stack': [],
            'cms': None,
            'frameworks': [],
            'analytics': [],
            'cdn': None,
            'hosting': None,
            'nameservers': [],
            'mx_records': [],
            'txt_records': [],
            'historical_ips': [],
            'wayback_urls': [],
            'related_domains': [],
            'threat_intel': [],
            'risk_score': 0.0,
            'age_days': None,
            'ssl_info': {}
        }
        
        # Clean domain
        clean_domain = domain.replace('http://', '').replace('https://', '').replace('www.', '').split('/')[0]
        
        # === FREE APIs (No Key Required) ===
        
        # 1. DNS Resolution
        try:
            # A records (IPv4)
            results['ips'] = [str(ip) for ip in socket.gethostbyname_ex(clean_domain)[2]]
            results['sources'].append('dns_a')
            
            # AAAA records (IPv6)
            try:
                resolver = dns.resolver.Resolver()
                answers = resolver.resolve(clean_domain, 'AAAA')
                results['ipv6'] = [str(rdata) for rdata in answers]
            except: pass
            
            # MX records
            try:
                answers = resolver.resolve(clean_domain, 'MX')
                results['mx_records'] = [{'priority': rdata.preference, 'server': str(rdata.exchange)} for rdata in answers]
            except: pass
            
            # TXT records
            try:
                answers = resolver.resolve(clean_domain, 'TXT')
                results['txt_records'] = [str(rdata) for rdata in answers]
            except: pass
            
            # NS records
            try:
                answers = resolver.resolve(clean_domain, 'NS')
                results['nameservers'] = [str(rdata) for rdata in answers]
            except: pass
            
            results['sources'].append('dns_full')
        except: pass
        
        # 2. URLScan.io - Reputation & screenshots
        try:
            r = requests.get(f"{self.free_apis['urlscan']}/?q=domain:{clean_domain}", timeout=10)
            if r.status_code == 200:
                data = r.json()
                scan_results = data.get('results', [])
                
                malicious_count = sum(1 for s in scan_results if s.get('verdicts', {}).get('overall', {}).get('malicious', False))
                results['reputation'] = {
                    'scans': len(scan_results),
                    'malicious': malicious_count,
                    'suspicious': sum(1 for s in scan_results if s.get('verdicts', {}).get('overall', {}).get('suspicious', False)),
                    'latest_scan': scan_results[0].get('task', {}).get('time') if scan_results else None
                }
                results['sources'].append('urlscan')
        except: pass
        
        # 3. crt.sh - Certificate Transparency (subdomain discovery)
        try:
            r = requests.get(f"{self.free_apis['crtsh']}", params={'q': f'%.{clean_domain}', 'output': 'json'}, timeout=15)
            if r.status_code == 200:
                data = r.json()
                for cert in data[:100]:
                    name = cert.get('name_value', '')
                    if name and name not in results['subdomains']:
                        results['subdomains'].append(name)
                    
                    results['certificates'].append({
                        'issuer': cert.get('issuer_name'),
                        'common_name': cert.get('common_name'),
                        'not_before': cert.get('not_before'),
                        'not_after': cert.get('not_after')
                    })
                
                results['sources'].append('crtsh')
        except: pass
        
        # 4. Wayback Machine - Historical URLs
        try:
            r = requests.get(f"{self.free_apis['wayback']}",
                           params={'url': f'*.{clean_domain}/*', 'output': 'json', 'limit': 100},
                           timeout=15)
            if r.status_code == 200:
                data = r.json()
                for entry in data[1:]:  # Skip header
                    if len(entry) > 2:
                        results['wayback_urls'].append({
                            'timestamp': entry[1],
                            'url': entry[2],
                            'status': entry[4] if len(entry) > 4 else None
                        })
                results['sources'].append('wayback')
        except: pass
        
        # 5. HackerTarget - Free DNS/subdomain tools
        try:
            # Reverse DNS
            r = requests.get(f"{self.free_apis['hackertarget']}/reversedns/?q={clean_domain}", timeout=10)
            if r.status_code == 200 and 'error' not in r.text.lower():
                results['related_domains'].extend(r.text.strip().split('\n'))
            
            # Zone transfer check
            r = requests.get(f"{self.free_apis['hackertarget']}/zonetransfer/?q={clean_domain}", timeout=10)
            if r.status_code == 200 and 'failed' not in r.text.lower():
                results['dns_records']['zone_transfer'] = r.text.strip()
            
            results['sources'].append('hackertarget')
        except: pass
        
        # 6. ThreatCrowd - Threat intelligence
        try:
            r = requests.get(f"{self.free_apis['threatcrowd']}", params={'domain': clean_domain}, timeout=10)
            if r.status_code == 200:
                data = r.json()
                if data.get('response_code') == '1':
                    results['subdomains'].extend(data.get('subdomains', []))
                    results['related_domains'].extend(data.get('resolutions', []))
                    results['threat_intel'].append({
                        'source': 'threatcrowd',
                        'votes': data.get('votes', 0),
                        'references': data.get('references', [])
                    })
                    results['sources'].append('threatcrowd')
        except: pass
        
        # 7. AlienVault OTX - Threat intelligence
        try:
            r = requests.get(f"{self.free_apis['alienvault']}/{clean_domain}/general", timeout=10)
            if r.status_code == 200:
                data = r.json()
                results['threat_intel'].append({
                    'source': 'alienvault_otx',
                    'pulse_count': data.get('pulse_info', {}).get('count', 0),
                    'tags': [p.get('name') for p in data.get('pulse_info', {}).get('pulses', [])[:5]]
                })
                results['sources'].append('alienvault')
        except: pass
        
        # === PAID APIs (If Keys Available) ===
        
        # 8. SecurityTrails - Subdomains & DNS history
        if self.paid_apis['securitytrails_key']:
            try:
                headers = {'APIKEY': self.paid_apis['securitytrails_key']}
                
                # Subdomains
                r = requests.get(f"{self.free_apis['securitytrails']}/{clean_domain}/subdomains", headers=headers, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    results['subdomains'].extend([f"{sub}.{clean_domain}" for sub in data.get('subdomains', [])])
                
                # DNS history
                r = requests.get(f"{self.free_apis['securitytrails']}/{clean_domain}/history/dns/a", headers=headers, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    for record in data.get('records', [])[:20]:
                        results['historical_ips'].extend(record.get('values', []))
                
                results['sources'].append('securitytrails')
            except: pass
        
        # 9. VirusTotal - Malware/threat detection
        if self.paid_apis['virustotal_key']:
            try:
                headers = {'x-apikey': self.paid_apis['virustotal_key']}
                r = requests.get(f"{self.free_apis['virustotal']}/{clean_domain}", headers=headers, timeout=10)
                if r.status_code == 200:
                    data = r.json().get('data', {}).get('attributes', {})
                    last_analysis = data.get('last_analysis_stats', {})
                    results['reputation']['virustotal'] = {
                        'malicious': last_analysis.get('malicious', 0),
                        'suspicious': last_analysis.get('suspicious', 0),
                        'harmless': last_analysis.get('harmless', 0),
                        'undetected': last_analysis.get('undetected', 0)
                    }
                    results['sources'].append('virustotal')
            except: pass
        
        # 10. Shodan - Domain info
        if self.paid_apis['shodan']:
            try:
                import shodan
                api = shodan.Shodan(self.paid_apis['shodan'])
                info = api.dns.domain_info(clean_domain)
                
                results['subdomains'].extend(info.get('subdomains', []))
                results['sources'].append('shodan')
            except: pass
        
        # === SENTINEL PRO MODULE INTEGRATION ===
        
        # 11. Use existing WHOIS module
        try:
            from modules.recon.whois_lookup import WHOISLookup
            whois = WHOISLookup()
            whois_data = whois.lookup(clean_domain)
            
            results['whois'] = whois_data
            if whois_data.get('creation_date'):
                from datetime import datetime
                try:
                    created = datetime.fromisoformat(str(whois_data['creation_date']))
                    results['age_days'] = (datetime.now() - created).days
                except: pass
            
            results['sources'].append('sentinel_whois')
        except: pass
        
        # 12. Use subdomain enumeration module
        try:
            from modules.recon.subdomain_enum import SubdomainEnumerator
            enum = SubdomainEnumerator()
            subdomain_data = enum.enumerate(clean_domain)
            
            if subdomain_data.get('subdomains'):
                results['subdomains'].extend(subdomain_data['subdomains'])
            
            results['sources'].append('sentinel_subdomain_enum')
        except: pass
        
        # 13. Technology fingerprinting
        try:
            from modules.bugbounty.tech_fingerprint import TechFingerprinter
            tech = TechFingerprinter()
            tech_data = tech.fingerprint(f"https://{clean_domain}")
            
            results['tech_stack'] = tech_data.get('technologies', [])
            results['cms'] = tech_data.get('cms')
            results['frameworks'] = tech_data.get('frameworks', [])
            results['analytics'] = tech_data.get('analytics', [])
            results['cdn'] = tech_data.get('cdn')
            results['hosting'] = tech_data.get('hosting')
            
            results['sources'].append('sentinel_tech_fingerprint')
        except: pass
        
        # 14. Certificate analysis
        try:
            from modules.recon.cert_transparency import CertTransparency
            cert = CertTransparency()
            cert_data = cert.search(clean_domain)
            
            if cert_data.get('certificates'):
                results['certificates'].extend(cert_data['certificates'])
            if cert_data.get('subdomains'):
                results['subdomains'].extend(cert_data['subdomains'])
            
            results['sources'].append('sentinel_cert_transparency')
        except: pass
        
        # 15. Wayback integration
        try:
            from modules.recon.wayback import WaybackMachine
            wayback = WaybackMachine()
            wayback_data = wayback.search(clean_domain)
            
            if wayback_data.get('urls'):
                results['wayback_urls'].extend(wayback_data['urls'][:100])
            
            results['sources'].append('sentinel_wayback')
        except: pass
        
        # === ML ANALYSIS ===
        
        # 16. ML Risk Scoring with SentinelNet
        try:
            from modules.ml_engine.trainer import ModelTrainer
            trainer = ModelTrainer()
            
            # Build threat context
            threat_text = f"""
            domain: {clean_domain}
            malicious_scans: {results['reputation'].get('malicious', 0)}
            suspicious_scans: {results['reputation'].get('suspicious', 0)}
            subdomains: {len(results['subdomains'])}
            threat_intel_sources: {len(results['threat_intel'])}
            age_days: {results['age_days']}
            ips: {len(results['ips'])}
            certificates: {len(results['certificates'])}
            """
            
            ml_pred = trainer.predict_threat(threat_text)
            risk_map = {'LOW': 0.2, 'MEDIUM': 0.5, 'HIGH': 0.75, 'CRITICAL': 1.0}
            results['risk_score'] = risk_map.get(ml_pred.get('label', 'LOW'), 0.0)
            results['ml_prediction'] = ml_pred
            results['sources'].append('sentinelnet_ml')
        except: pass
        
        # === GROQ DOMAIN SECURITY ANALYSIS ===
        
        try:
            from modules.ml_engine.groq_llm import get_groq
            import time
            groq = get_groq()
            
            if groq and groq.is_ready:
                # Build context
                whois_data = results.get('whois', {})
                rep = results.get('reputation', {})
                tech = results.get('tech_stack', {})
                
                tech_summary = ', '.join([f"{k}: {v}" for k, v in tech.items()][:5]) if tech else 'None detected'
                threat_summary = [f"- {t.get('source', 'Unknown')}: {t.get('description', 'N/A')[:60]}" for t in results['threat_intel'][:3]]
                
                context = f"""
Domain Intelligence Summary:
- Domain: {clean_domain}
- Registrar: {whois_data.get('registrar', 'Unknown')}
- Created: {whois_data.get('creation_date', 'Unknown')}
- Age: {results.get('age_days', 0)} days
- IPs: {', '.join(results['ips'][:3])}
- Subdomains: {len(results['subdomains'])}
- Tech Stack: {tech_summary}
- VirusTotal Malicious: {rep.get('malicious', 0)}
- VirusTotal Suspicious: {rep.get('suspicious', 0)}
- SSL Certificates: {len(results['certificates'])}
- Threat Intel Sources: {len(results['threat_intel'])}
- ML Risk Score: {results['risk_score']:.0%}

Threat Intelligence:
{chr(10).join(threat_summary) if threat_summary else 'None'}
"""
                
                prompt = f"""Analyze this domain security posture:

1. **Attack Surface Assessment**: What attack vectors are exposed?
2. **Technology Stack Vulnerabilities**: Security risks in detected technologies
3. **Subdomain Takeover Risks**: Potential subdomain vulnerabilities
4. **SSL/TLS Configuration Issues**: Certificate and encryption concerns
5. **Recommended Security Hardening**: Immediate security improvements

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
            if 'errors' not in results:
                results['errors'] = []
            results['errors'].append(f'Groq: {str(e)}')
        
        # Deduplicate lists
        results['ips'] = list(set(results['ips']))
        results['subdomains'] = list(set([s for s in results['subdomains'] if s and clean_domain in s]))[:100]
        results['related_domains'] = list(set(results['related_domains']))[:50]
        results['historical_ips'] = list(set(results['historical_ips']))
        
        return results
