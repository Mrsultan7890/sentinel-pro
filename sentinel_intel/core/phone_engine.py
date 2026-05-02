"""
Phone Intelligence Engine v3.0 - REAL Data Only
Uses phonenumbers library + real messaging app checks
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
import config
import requests
import re
import time
from typing import Dict, List

class PhoneEngine:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def investigate(self, phone: str) -> Dict:
        """Real phone investigation - no fake data"""
        results = {
            'phone': phone,
            'sources': [],
            'valid': False,
            'carrier': None,
            'country': None,
            'country_code': None,
            'region': None,
            'line_type': None,
            'location': None,
            'timezone': None,
            'risk_score': 0.0,
            'messaging_apps': [],
            'profiles': [],
            'names': [],
            'emails': [],
            'errors': []
        }
        
        # Clean phone number
        clean_phone = re.sub(r'[^0-9+]', '', phone)
        
        # === OFFLINE VALIDATION (phonenumbers library) ===
        
        try:
            import phonenumbers
            from phonenumbers import geocoder, timezone
            
            # Parse number
            parsed = phonenumbers.parse(clean_phone, None)
            
            # Validation
            results['valid'] = phonenumbers.is_valid_number(parsed)
            
            if results['valid']:
                # Get country
                results['country'] = geocoder.description_for_number(parsed, "en")
                results['country_code'] = f"+{parsed.country_code}"
                
                # Get carrier (requires phonenumbers.carrier module)
                try:
                    from phonenumbers import carrier as pn_carrier
                    carrier_name = pn_carrier.name_for_number(parsed, "en")
                    if carrier_name:
                        results['carrier'] = carrier_name
                except ImportError:
                    pass  # carrier module not available
                
                # Get timezone
                timezones = timezone.time_zones_for_number(parsed)
                if timezones:
                    results['timezone'] = timezones[0]
                
                # Get number type
                number_type = phonenumbers.number_type(parsed)
                type_map = {
                    0: 'FIXED_LINE',
                    1: 'MOBILE',
                    2: 'FIXED_LINE_OR_MOBILE',
                    3: 'TOLL_FREE',
                    4: 'PREMIUM_RATE',
                    5: 'SHARED_COST',
                    6: 'VOIP',
                    7: 'PERSONAL_NUMBER',
                    8: 'PAGER',
                    9: 'UAN',
                    10: 'VOICEMAIL'
                }
                results['line_type'] = type_map.get(number_type, 'UNKNOWN')
                
                results['sources'].append('phonenumbers_lib')
        
        except ImportError:
            results['errors'].append('phonenumbers library not installed')
        except Exception as e:
            results['errors'].append(f'phonenumbers: {str(e)}')
        
        # === REAL MESSAGING APP CHECKS ===
        
        # NOTE: Most messaging apps don't provide public APIs to check number existence
        # wa.me and t.me links always return 200 even for non-existent numbers
        # So we mark them as 'possible' not 'exists'
        
        # 1. WhatsApp - Mark as possible only (no real verification)
        if results['valid'] and results.get('line_type') in ['MOBILE', 'FIXED_LINE_OR_MOBILE']:
            results['messaging_apps'].append({
                'app': 'WhatsApp',
                'platform': 'whatsapp',
                'exists': False,  # Cannot verify without official API
                'possible': True,  # Mobile numbers can have WhatsApp
                'url': f'https://wa.me/{clean_phone}',
                'method': 'inference',
                'note': 'Mobile number - WhatsApp possible but not verified'
            })
        
        # 2. Telegram - Mark as possible only
        if results['valid']:
            results['messaging_apps'].append({
                'app': 'Telegram',
                'platform': 'telegram',
                'exists': False,  # Cannot verify without official API
                'possible': True,
                'url': f'https://t.me/{clean_phone}',
                'method': 'inference',
                'note': 'Any number can have Telegram - not verified'
            })
        
        # 3. Signal - Mark as possible only
        if results['valid'] and results.get('line_type') in ['MOBILE', 'FIXED_LINE_OR_MOBILE']:
            results['messaging_apps'].append({
                'app': 'Signal',
                'platform': 'signal',
                'exists': False,  # Cannot verify without official API
                'possible': True,
                'method': 'inference',
                'note': 'Mobile number - Signal possible but not verified'
            })
        
        # 3. Signal (No public API - note only)
        results['messaging_apps'].append({
            'platform': 'signal',
            'note': 'Signal uses phone numbers but has no public API for verification',
            'possible': True
        })
        
        # === PAID APIs (If Keys Available) ===
        
        # 4. NumVerify
        if config.NUMVERIFY_API_KEY:
            try:
                r = self.session.get(
                    'http://apilayer.net/api/validate',
                    params={
                        'access_key': config.NUMVERIFY_API_KEY,
                        'number': clean_phone,
                        'format': 1
                    },
                    timeout=10
                )
                if r.status_code == 200:
                    data = r.json()
                    if data.get('valid'):
                        results['valid'] = True
                        results['carrier'] = data.get('carrier') or results['carrier']
                        results['line_type'] = data.get('line_type') or results['line_type']
                        results['country'] = data.get('country_name') or results['country']
                        results['country_code'] = data.get('country_prefix') or results['country_code']
                        results['location'] = data.get('location')
                        results['sources'].append('numverify')
            except Exception as e:
                results['errors'].append(f'NumVerify: {str(e)}')
        
        # 5. AbstractAPI
        if config.ABSTRACTAPI_PHONE_KEY:
            try:
                r = self.session.get(
                    'https://phonevalidation.abstractapi.com/v1',
                    params={
                        'api_key': config.ABSTRACTAPI_PHONE_KEY,
                        'phone': clean_phone
                    },
                    timeout=10
                )
                if r.status_code == 200:
                    data = r.json()
                    if data.get('valid'):
                        results['valid'] = True
                        results['carrier'] = data.get('carrier') or results['carrier']
                        results['line_type'] = data.get('type') or results['line_type']
                        results['country'] = data.get('country', {}).get('name') or results['country']
                        results['timezone'] = data.get('timezone', {}).get('name') or results['timezone']
                        results['sources'].append('abstractapi')
            except Exception as e:
                results['errors'].append(f'AbstractAPI: {str(e)}')
        
        # === SENTINEL PRO MODULE INTEGRATION ===
        
        try:
            from modules.recon.phone_osint import PhoneOSINT
            osint = PhoneOSINT()
            osint_data = osint.investigate(clean_phone)
            
            if osint_data.get('carrier'):
                results['carrier'] = osint_data['carrier']
            if osint_data.get('country'):
                results['country'] = osint_data['country']
            if osint_data.get('profiles'):
                results['profiles'].extend(osint_data['profiles'])
            
            results['sources'].append('sentinel_phone_osint')
        except Exception as e:
            results['errors'].append(f'Sentinel OSINT: {str(e)}')
        
        # === ML ANALYSIS ===
        
        try:
            from modules.ml_engine.trainer import ModelTrainer
            trainer = ModelTrainer()
            
            threat_text = f"""
            phone: {clean_phone}
            valid: {results['valid']}
            carrier: {results['carrier']}
            line_type: {results['line_type']}
            country: {results['country']}
            messaging_apps: {len(results['messaging_apps'])}
            """
            
            ml_pred = trainer.predict_threat(threat_text)
            risk_map = {'LOW': 0.2, 'MEDIUM': 0.5, 'HIGH': 0.75, 'CRITICAL': 1.0}
            results['risk_score'] = risk_map.get(ml_pred.get('label', 'LOW'), 0.0)
            results['ml_prediction'] = ml_pred
            results['sources'].append('sentinelnet_ml')
        except Exception as e:
            results['errors'].append(f'ML: {str(e)}')
        
        # === GROQ PHONE INTELLIGENCE ===
        
        try:
            from modules.ml_engine.groq_llm import get_groq
            groq = get_groq()
            
            if groq and groq.is_ready:
                # Build context
                messaging_found = [m['app'] for m in results['messaging_apps'] if m.get('exists')]
                
                context = f"""
Phone Intelligence Summary:
- Phone: {clean_phone}
- Valid: {results['valid']}
- Country: {results['country']} (+{results['country_code']})
- Carrier: {results['carrier'] or 'Unknown'}
- Line Type: {results['line_type'] or 'Unknown'}
- Timezone: {results['timezone'] or 'Unknown'}
- Messaging Apps: {', '.join(messaging_found) if messaging_found else 'None detected'}
- Social Profiles: {len(results['profiles'])}
- ML Risk Score: {results['risk_score']:.0%}
"""
                
                prompt = f"""Analyze this phone number intelligence:

1. **Number Classification**: Is this likely personal, business, or VoIP?
2. **Risk Indicators**: Any spam, scam, or fraud indicators?
3. **Privacy Exposure**: What information is publicly exposed?
4. **OSINT Recommendations**: Next investigation steps
5. **Security Concerns**: Potential threats or vulnerabilities

{context}

Provide detailed professional analysis."""
                
                groq_response = groq.ask(prompt, max_tokens=400)
                
                results['groq_analysis'] = {
                    'assessment': groq_response,
                    'timestamp': time.time(),
                    'model': groq.MODEL
                }
                results['sources'].append('groq_llm')
        except Exception as e:
            results['errors'].append(f'Groq: {str(e)}')
        
        # Deduplicate
        results['names'] = list(set([n for n in results['names'] if n]))
        results['emails'] = list(set([e for e in results['emails'] if e]))
        
        # Summary
        results['summary'] = {
            'total_sources': len(results['sources']),
            'is_valid': results['valid'],
            'has_carrier': results['carrier'] is not None,
            'messaging_apps_found': len([m for m in results['messaging_apps'] if m.get('exists')]),
            'has_errors': len(results['errors']) > 0
        }
        
        return results
