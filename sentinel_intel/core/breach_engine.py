"""
Breach Intelligence Engine - Data Breach Analysis
HaveIBeenPwned, DeHashed, LeakCheck, IntelX, HudsonRock + ML
"""
import sys
import os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
import config
import requests
from typing import Dict, List
import re
from datetime import datetime

class BreachEngine:
    def __init__(self):
        self.free_apis = {
            'hibp_breaches': 'https://haveibeenpwned.com/api/v3/breaches',
            'hibp_account': 'https://haveibeenpwned.com/api/v3/breachedaccount',
            'hibp_pastes': 'https://haveibeenpwned.com/api/v3/pasteaccount',
            'leakcheck': 'https://leakcheck.io/api/public',
            'intelx': 'https://2.intelx.io/phonebook/search',
            'hudsonrock': 'https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-login',
            'snusbase': 'https://api.snusbase.com/data/search',
            'breachdirectory': 'https://breachdirectory.org/api/query'
        }
        self.paid_apis = {
            'hibp_key': config.HIBP_API_KEY or os.getenv('HIBP_API_KEY', ''),
            'dehashed_email': config.DEHASHED_EMAIL or os.getenv('DEHASHED_EMAIL', ''),
            'dehashed_key': config.DEHASHED_API_KEY or os.getenv('DEHASHED_API_KEY', ''),
            'leakcheck_key': os.getenv('LEAKCHECK_API_KEY', ''),
            'intelx_key': os.getenv('INTELX_API_KEY', ''),
            'snusbase_key': os.getenv('SNUSBASE_API_KEY', '')
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def investigate(self, identifier: str) -> Dict:
        """Deep breach investigation - email/username/phone"""
        results = {
            'identifier': identifier,
            'identifier_type': self._detect_type(identifier),
            'sources': [],
            'breaches': [],
            'pastes': [],
            'leaks': [],
            'passwords': [],
            'total_breaches': 0,
            'total_records': 0,
            'first_breach': None,
            'last_breach': None,
            'sensitive_breaches': [],
            'data_classes': [],
            'domains': [],
            'usernames': [],
            'emails': [],
            'phones': [],
            'names': [],
            'addresses': [],
            'risk_score': 0.0,
            'tags': []
        }
        
        # === FREE APIs ===
        
        # 1. HaveIBeenPwned - Breach database (requires API key but has free tier)
        if self.paid_apis['hibp_key']:
            try:
                headers = {'hibp-api-key': self.paid_apis['hibp_key']}
                
                # Get breached account
                r = self.session.get(f"{self.free_apis['hibp_account']}/{identifier}",
                                    headers=headers, timeout=10)
                if r.status_code == 200:
                    breaches = r.json()
                    for breach in breaches:
                        results['breaches'].append({
                            'name': breach.get('Name'),
                            'title': breach.get('Title'),
                            'domain': breach.get('Domain'),
                            'breach_date': breach.get('BreachDate'),
                            'added_date': breach.get('AddedDate'),
                            'modified_date': breach.get('ModifiedDate'),
                            'pwn_count': breach.get('PwnCount'),
                            'description': breach.get('Description'),
                            'data_classes': breach.get('DataClasses', []),
                            'is_verified': breach.get('IsVerified'),
                            'is_fabricated': breach.get('IsFabricated'),
                            'is_sensitive': breach.get('IsSensitive'),
                            'is_retired': breach.get('IsRetired'),
                            'is_spam_list': breach.get('IsSpamList'),
                            'logo_path': breach.get('LogoPath')
                        })
                        
                        # Collect data classes
                        results['data_classes'].extend(breach.get('DataClasses', []))
                        
                        # Track sensitive breaches
                        if breach.get('IsSensitive'):
                            results['sensitive_breaches'].append(breach.get('Name'))
                        
                        # Track domains
                        if breach.get('Domain'):
                            results['domains'].append(breach.get('Domain'))
                    
                    results['total_breaches'] = len(breaches)
                    results['sources'].append('haveibeenpwned')
                
                # Get pastes
                r = self.session.get(f"{self.free_apis['hibp_pastes']}/{identifier}",
                                    headers=headers, timeout=10)
                if r.status_code == 200:
                    pastes = r.json()
                    for paste in pastes[:20]:
                        results['pastes'].append({
                            'source': paste.get('Source'),
                            'id': paste.get('Id'),
                            'title': paste.get('Title'),
                            'date': paste.get('Date'),
                            'email_count': paste.get('EmailCount')
                        })
                    
                    results['sources'].append('hibp_pastes')
            except: pass
        
        # 2. BreachDirectory - Free breach search
        try:
            r = self.session.post(self.free_apis['breachdirectory'],
                                 json={'term': identifier},
                                 timeout=10)
            if r.status_code == 200:
                data = r.json()
                if data.get('success'):
                    for result in data.get('result', [])[:20]:
                        results['leaks'].append({
                            'source': 'BreachDirectory',
                            'email': result.get('email'),
                            'username': result.get('username'),
                            'password': result.get('password'),
                            'hash': result.get('hash'),
                            'database': result.get('sources', [])
                        })
                        
                        # Collect passwords (hashed)
                        if result.get('password'):
                            results['passwords'].append({
                                'password': result['password'][:50],  # Truncate
                                'type': 'plaintext' if len(result['password']) < 32 else 'hash'
                            })
                    
                    results['sources'].append('breachdirectory')
        except: pass
        
        # 3. HudsonRock - Stealer logs
        try:
            r = self.session.get(self.free_apis['hudsonrock'],
                                params={'login': identifier},
                                timeout=10)
            if r.status_code == 200:
                data = r.json()
                if data.get('stealers'):
                    for stealer in data['stealers'][:10]:
                        results['leaks'].append({
                            'source': 'HudsonRock Stealer',
                            'computer_name': stealer.get('computer_name'),
                            'operating_system': stealer.get('operating_system'),
                            'malware_path': stealer.get('malware_path'),
                            'date_compromised': stealer.get('date_compromised'),
                            'antiviruses': stealer.get('antiviruses', [])
                        })
                    
                    results['tags'].append('stealer_logs')
                    results['sources'].append('hudsonrock')
        except: pass
        
        # === PAID APIs ===
        
        # 4. DeHashed - Comprehensive breach database
        if self.paid_apis['dehashed_email'] and self.paid_apis['dehashed_key']:
            try:
                auth = (self.paid_apis['dehashed_email'], self.paid_apis['dehashed_key'])
                r = self.session.get('https://api.dehashed.com/search',
                                    params={'query': f'email:{identifier}'},
                                    auth=auth,
                                    timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    for entry in data.get('entries', [])[:50]:
                        results['leaks'].append({
                            'source': 'DeHashed',
                            'email': entry.get('email'),
                            'username': entry.get('username'),
                            'password': entry.get('password'),
                            'hashed_password': entry.get('hashed_password'),
                            'name': entry.get('name'),
                            'vin': entry.get('vin'),
                            'address': entry.get('address'),
                            'phone': entry.get('phone'),
                            'database_name': entry.get('database_name')
                        })
                        
                        # Collect related data
                        if entry.get('username'):
                            results['usernames'].append(entry['username'])
                        if entry.get('email') and entry['email'] != identifier:
                            results['emails'].append(entry['email'])
                        if entry.get('phone'):
                            results['phones'].append(entry['phone'])
                        if entry.get('name'):
                            results['names'].append(entry['name'])
                        if entry.get('address'):
                            results['addresses'].append(entry['address'])
                        
                        # Collect passwords
                        if entry.get('password'):
                            results['passwords'].append({
                                'password': entry['password'][:50],
                                'type': 'plaintext',
                                'database': entry.get('database_name')
                            })
                        elif entry.get('hashed_password'):
                            results['passwords'].append({
                                'password': entry['hashed_password'][:50],
                                'type': 'hash',
                                'database': entry.get('database_name')
                            })
                    
                    results['total_records'] = data.get('total', 0)
                    results['sources'].append('dehashed')
            except: pass
        
        # 5. LeakCheck - Leak database
        if self.paid_apis['leakcheck_key']:
            try:
                r = self.session.get(self.free_apis['leakcheck'],
                                    params={'key': self.paid_apis['leakcheck_key'], 'check': identifier},
                                    timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    if data.get('found'):
                        for source in data.get('sources', []):
                            results['leaks'].append({
                                'source': 'LeakCheck',
                                'database': source.get('name'),
                                'date': source.get('date')
                            })
                        
                        results['sources'].append('leakcheck')
            except: pass
        
        # 6. IntelX - Intelligence database
        if self.paid_apis['intelx_key']:
            try:
                headers = {'x-key': self.paid_apis['intelx_key']}
                r = self.session.get(self.free_apis['intelx'],
                                    params={'term': identifier},
                                    headers=headers,
                                    timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    for result in data.get('selectors', [])[:20]:
                        results['leaks'].append({
                            'source': 'IntelX',
                            'selector': result.get('selectorvalue'),
                            'type': result.get('selectortype'),
                            'date': result.get('date')
                        })
                    
                    results['sources'].append('intelx')
            except: pass
        
        # 7. Snusbase - Breach aggregator
        if self.paid_apis['snusbase_key']:
            try:
                headers = {'Auth': self.paid_apis['snusbase_key']}
                r = self.session.post(self.free_apis['snusbase'],
                                     json={'terms': [identifier], 'types': ['email', 'username']},
                                     headers=headers,
                                     timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    for db_name, entries in data.get('results', {}).items():
                        for entry in entries[:20]:
                            results['leaks'].append({
                                'source': 'Snusbase',
                                'database': db_name,
                                'email': entry.get('email'),
                                'username': entry.get('username'),
                                'password': entry.get('password'),
                                'hash': entry.get('hash')
                            })
                    
                    results['sources'].append('snusbase')
            except: pass
        
        # === SENTINEL PRO MODULE INTEGRATION ===
        
        # 8. Use Sentinel Pro's breach checker
        try:
            from modules.breach.breach_checker import BreachChecker
            checker = BreachChecker()
            breach_data = checker.check(identifier)
            
            if breach_data.get('breaches'):
                results['breaches'].extend(breach_data['breaches'])
                results['total_breaches'] += len(breach_data['breaches'])
            
            results['sources'].append('sentinel_breach')
        except: pass
        
        # === ANALYSIS ===
        
        # 9. Timeline analysis
        if results['breaches']:
            dates = [b.get('breach_date') for b in results['breaches'] if b.get('breach_date')]
            if dates:
                dates.sort()
                results['first_breach'] = dates[0]
                results['last_breach'] = dates[-1]
        
        # 10. Password analysis
        if results['passwords']:
            # Analyze password patterns
            plaintext_count = len([p for p in results['passwords'] if p.get('type') == 'plaintext'])
            hash_count = len([p for p in results['passwords'] if p.get('type') == 'hash'])
            
            results['password_analysis'] = {
                'total': len(results['passwords']),
                'plaintext': plaintext_count,
                'hashed': hash_count,
                'unique_databases': len(set([p.get('database') for p in results['passwords'] if p.get('database')]))
            }
        
        # === ML ANALYSIS ===
        
        # 11. ML Risk Scoring with SentinelNet
        try:
            from modules.ml_engine.trainer import ModelTrainer
            trainer = ModelTrainer()
            
            threat_text = f"""
            identifier: {identifier}
            type: {results['identifier_type']}
            total_breaches: {results['total_breaches']}
            total_records: {results['total_records']}
            sensitive_breaches: {len(results['sensitive_breaches'])}
            pastes: {len(results['pastes'])}
            leaks: {len(results['leaks'])}
            passwords_exposed: {len(results['passwords'])}
            data_classes: {len(results['data_classes'])}
            """
            
            ml_pred = trainer.predict_threat(threat_text)
            risk_map = {'LOW': 0.2, 'MEDIUM': 0.5, 'HIGH': 0.75, 'CRITICAL': 1.0}
            results['risk_score'] = risk_map.get(ml_pred.get('label', 'LOW'), 0.0)
            
            # Override risk based on breach count
            if results['total_breaches'] >= 10:
                results['risk_score'] = max(results['risk_score'], 0.9)
            elif results['total_breaches'] >= 5:
                results['risk_score'] = max(results['risk_score'], 0.75)
            elif results['total_breaches'] >= 1:
                results['risk_score'] = max(results['risk_score'], 0.6)
            
            # Increase risk if passwords exposed
            if len(results['passwords']) > 0:
                results['risk_score'] = max(results['risk_score'], 0.8)
            
            results['ml_prediction'] = ml_pred
            results['sources'].append('sentinelnet_ml')
        except: pass
        
        # Deduplicate lists
        results['data_classes'] = list(set(results['data_classes']))
        results['domains'] = list(set([d for d in results['domains'] if d]))
        results['usernames'] = list(set([u for u in results['usernames'] if u]))[:50]
        results['emails'] = list(set([e for e in results['emails'] if e]))[:50]
        results['phones'] = list(set([p for p in results['phones'] if p]))[:50]
        results['names'] = list(set([n for n in results['names'] if n]))[:20]
        results['tags'] = list(set(results['tags']))
        
        # Summary
        results['summary'] = {
            'total_sources': len(results['sources']),
            'total_breaches': results['total_breaches'],
            'total_leaks': len(results['leaks']),
            'total_pastes': len(results['pastes']),
            'passwords_exposed': len(results['passwords']),
            'sensitive_data': len(results['sensitive_breaches']) > 0,
            'data_types_exposed': len(results['data_classes']),
            'timeline_span': f"{results['first_breach']} to {results['last_breach']}" if results['first_breach'] else 'N/A'
        }
        
        return results
    
    def _detect_type(self, identifier: str) -> str:
        """Detect identifier type"""
        if '@' in identifier:
            return 'email'
        elif re.match(r'^\+?[0-9\s\-\(\)]{10,}$', identifier):
            return 'phone'
        else:
            return 'username'
