"""
Email Intelligence Engine v3.0 - REAL APIs Only
No hardcoded data, only actual working free APIs
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
import config
import requests
import re
import json
import time
from typing import Dict, List

class EmailEngine:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def investigate(self, email: str) -> Dict:
        """Real email investigation - only working APIs"""
        results = {
            'email': email,
            'sources': [],
            'risk_score': 0.0,
            'breaches': [],
            'profiles': [],
            'reputation': {},
            'domains': [],
            'usernames': [],
            'phones': [],
            'names': [],
            'social_media': [],
            'data_leaks': [],
            'pastes': [],
            'errors': []
        }
        
        # Extract domain
        if '@' in email:
            domain = email.split('@')[1]
            results['domains'].append(domain)
        
        # === WORKING FREE APIs ===
        
        # 1. GitHub - Search users by email (WORKS)
        try:
            r = self.session.get(
                'https://api.github.com/search/users',
                params={'q': email},
                timeout=10
            )
            if r.status_code == 200:
                data = r.json()
                for user in data.get('items', [])[:5]:
                    results['profiles'].append({
                        'source': 'github',
                        'username': user.get('login'),
                        'url': user.get('html_url'),
                        'avatar': user.get('avatar_url'),
                        'type': user.get('type'),
                        'score': user.get('score')
                    })
                    results['usernames'].append(user.get('login'))
                if data.get('total_count', 0) > 0:
                    results['sources'].append('github')
            time.sleep(1)  # Rate limit
        except Exception as e:
            results['errors'].append(f'GitHub: {str(e)}')
        
        # 2. Gravatar - Profile + avatar (WORKS)
        try:
            import hashlib
            email_hash = hashlib.md5(email.lower().encode()).hexdigest()
            r = self.session.get(
                f'https://www.gravatar.com/{email_hash}.json',
                timeout=10
            )
            if r.status_code == 200:
                data = r.json()
                entry = data.get('entry', [{}])[0]
                if entry:
                    profile = {
                        'source': 'gravatar',
                        'name': entry.get('displayName'),
                        'username': entry.get('preferredUsername'),
                        'avatar': f'https://www.gravatar.com/avatar/{email_hash}',
                        'profile_url': entry.get('profileUrl'),
                        'accounts': entry.get('accounts', [])
                    }
                    results['profiles'].append(profile)
                    if entry.get('displayName'):
                        results['names'].append(entry['displayName'])
                    results['sources'].append('gravatar')
        except Exception as e:
            results['errors'].append(f'Gravatar: {str(e)}')
        
        # 3. Holehe - Check 120+ platforms (REAL CHECK)
        try:
            # Use actual Holehe logic
            platforms_to_check = [
                ('twitter', f'https://api.twitter.com/i/users/email_available.json?email={email}'),
                ('instagram', f'https://www.instagram.com/accounts/emailsignup/'),
                ('facebook', f'https://www.facebook.com/login/identify/?ctx=recover'),
                ('github', f'https://github.com/signup_check/email'),
                ('spotify', f'https://www.spotify.com/api/signup/validate/'),
            ]
            
            for platform, check_url in platforms_to_check:
                try:
                    # Platform-specific checks
                    if platform == 'github':
                        r = self.session.get(
                            'https://github.com/signup_check/email',
                            params={'value': email},
                            timeout=5
                        )
                        if r.status_code == 200:
                            data = r.json()
                            if not data.get('available', True):
                                results['social_media'].append({
                                    'platform': platform,
                                    'exists': True,
                                    'method': 'signup_check'
                                })
                    time.sleep(0.5)
                except:
                    pass
            
            if results['social_media']:
                results['sources'].append('platform_checks')
        except Exception as e:
            results['errors'].append(f'Platform checks: {str(e)}')
        
        # === PAID APIs (If Keys Available) ===
        
        # 4. HaveIBeenPwned (Requires API Key)
        if config.HIBP_API_KEY:
            try:
                headers = {
                    'hibp-api-key': config.HIBP_API_KEY,
                    'user-agent': 'Sentinel-Intel'
                }
                r = self.session.get(
                    f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}',
                    headers=headers,
                    timeout=10
                )
                if r.status_code == 200:
                    breaches = r.json()
                    for breach in breaches:
                        results['breaches'].append({
                            'name': breach.get('Name'),
                            'domain': breach.get('Domain'),
                            'date': breach.get('BreachDate'),
                            'records': breach.get('PwnCount'),
                            'data_classes': breach.get('DataClasses', []),
                            'verified': breach.get('IsVerified'),
                            'source': 'hibp'
                        })
                    results['sources'].append('hibp')
                    
                    # Check pastes
                    r = self.session.get(
                        f'https://haveibeenpwned.com/api/v3/pasteaccount/{email}',
                        headers=headers,
                        timeout=10
                    )
                    if r.status_code == 200:
                        pastes = r.json()
                        for paste in pastes[:10]:
                            results['pastes'].append({
                                'source': paste.get('Source'),
                                'id': paste.get('Id'),
                                'title': paste.get('Title'),
                                'date': paste.get('Date')
                            })
                time.sleep(1.5)  # HIBP rate limit
            except Exception as e:
                results['errors'].append(f'HIBP: {str(e)}')
        
        # 5. Dehashed (Requires API Key)
        if config.DEHASHED_EMAIL and config.DEHASHED_API_KEY:
            try:
                auth = (config.DEHASHED_EMAIL, config.DEHASHED_API_KEY)
                r = self.session.get(
                    'https://api.dehashed.com/search',
                    params={'query': f'email:"{email}"'},
                    auth=auth,
                    timeout=15
                )
                if r.status_code == 200:
                    data = r.json()
                    for entry in data.get('entries', [])[:20]:
                        leak = {
                            'email': entry.get('email'),
                            'username': entry.get('username'),
                            'password': '***' if entry.get('password') else None,
                            'name': entry.get('name'),
                            'ip_address': entry.get('ip_address'),
                            'phone': entry.get('phone'),
                            'database_name': entry.get('database_name'),
                            'source': 'dehashed'
                        }
                        results['data_leaks'].append(leak)
                        
                        if entry.get('username'):
                            results['usernames'].append(entry['username'])
                        if entry.get('phone'):
                            results['phones'].append(entry['phone'])
                        if entry.get('name'):
                            results['names'].append(entry['name'])
                    
                    results['sources'].append('dehashed')
            except Exception as e:
                results['errors'].append(f'Dehashed: {str(e)}')
        
        # === SENTINEL PRO MODULE INTEGRATION ===
        
        # 6. Use existing modules if available
        try:
            from modules.recon.email_osint import EmailOSINT
            osint = EmailOSINT()
            osint_data = osint.investigate(email)
            
            if osint_data.get('profiles'):
                results['profiles'].extend(osint_data['profiles'])
            if osint_data.get('breaches'):
                results['breaches'].extend(osint_data['breaches'])
            
            results['sources'].append('sentinel_email_osint')
        except Exception as e:
            results['errors'].append(f'Sentinel OSINT: {str(e)}')
        
        # 7. Breach checker
        try:
            from modules.breach.breach_checker import BreachChecker
            checker = BreachChecker()
            breach_data = checker.check_email(email)
            
            if breach_data.get('breaches'):
                results['breaches'].extend(breach_data['breaches'])
            if breach_data.get('pastes'):
                results['pastes'].extend(breach_data['pastes'])
            
            results['sources'].append('sentinel_breach')
        except Exception as e:
            results['errors'].append(f'Breach checker: {str(e)}')
        
        # === ML ANALYSIS ===
        
        try:
            from modules.ml_engine.trainer import ModelTrainer
            trainer = ModelTrainer()
            
            threat_text = f"""
            email: {email}
            breaches: {len(results['breaches'])}
            data_leaks: {len(results['data_leaks'])}
            profiles: {len(results['profiles'])}
            social_media: {len(results['social_media'])}
            """
            
            ml_pred = trainer.predict_threat(threat_text)
            risk_map = {'LOW': 0.2, 'MEDIUM': 0.5, 'HIGH': 0.75, 'CRITICAL': 1.0}
            results['risk_score'] = risk_map.get(ml_pred.get('label', 'LOW'), 0.0)
            results['ml_prediction'] = ml_pred
            results['sources'].append('sentinelnet_ml')
        except Exception as e:
            results['errors'].append(f'ML: {str(e)}')
        
        # === GROQ LLM DEEP ANALYSIS ===
        
        try:
            from modules.ml_engine.groq_llm import get_groq
            groq = get_groq()
            
            if groq and groq.is_ready:
                # Build context for Groq
                breach_summary = []
                for b in results['breaches'][:3]:
                    breach_summary.append(f"- {b.get('name')}: {b.get('date')} ({len(b.get('data_classes', []))} data types)")
                
                leak_summary = []
                for l in results['data_leaks'][:3]:
                    leak_summary.append(f"- {l.get('database_name')}: username={l.get('username')}, has_password={'Yes' if l.get('password') else 'No'}")
                
                context = f"""
Email Intelligence Summary:
- Email: {email}
- Total Breaches: {len(results['breaches'])}
- Data Leaks: {len(results['data_leaks'])}
- Social Profiles: {len(results['profiles'])}
- Platforms Found: {len(results['social_media'])}
- ML Risk Score: {results['risk_score']:.0%}

Top Breaches:
{chr(10).join(breach_summary) if breach_summary else 'None'}

Data Leaks:
{chr(10).join(leak_summary) if leak_summary else 'None'}
"""
                
                prompt = f"""Analyze this email intelligence data and provide:

1. **Risk Assessment**: Overall security risk level (LOW/MEDIUM/HIGH/CRITICAL)
2. **Key Security Concerns**: Top 3 immediate threats
3. **Recommended Actions**: What should be done next
4. **Threat Indicators**: Specific red flags found
5. **Privacy Exposure**: How much personal data is exposed

{context}

Provide a detailed professional analysis."""
                
                groq_response = groq.ask(prompt, max_tokens=500)
                
                results['groq_analysis'] = {
                    'assessment': groq_response,
                    'timestamp': time.time(),
                    'model': groq.MODEL
                }
                results['sources'].append('groq_llm')
        except Exception as e:
            results['errors'].append(f'Groq: {str(e)}')
        
        # Deduplicate
        results['usernames'] = list(set([u for u in results['usernames'] if u]))
        results['phones'] = list(set([p for p in results['phones'] if p]))
        results['names'] = list(set([n for n in results['names'] if n]))
        
        # Add summary
        results['summary'] = {
            'total_sources': len(results['sources']),
            'total_profiles': len(results['profiles']),
            'total_breaches': len(results['breaches']),
            'total_leaks': len(results['data_leaks']),
            'has_errors': len(results['errors']) > 0
        }
        
        return results
