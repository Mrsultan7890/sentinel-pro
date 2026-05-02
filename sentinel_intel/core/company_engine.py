"""
Company Intelligence Engine - Corporate OSINT
Clearbit, Hunter.io, LinkedIn, Crunchbase + Free sources + ML
"""
import sys
import os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
import config
import requests
from typing import Dict, List
import re

class CompanyEngine:
    def __init__(self):
        self.free_apis = {
            'clearbit': 'https://company.clearbit.com/v2/companies/find',
            'hunter': 'https://api.hunter.io/v2/domain-search',
            'crunchbase': 'https://api.crunchbase.com/api/v4/entities/organizations',
            'linkedin': 'https://www.linkedin.com/company',
            'glassdoor': 'https://www.glassdoor.com/api-impl/employer',
            'opencorporates': 'https://api.opencorporates.com/v0.4/companies/search',
            'companies_house': 'https://api.company-information.service.gov.uk/search/companies'
        }
        self.paid_apis = {
            'clearbit_key': os.getenv('CLEARBIT_API_KEY', ''),
            'hunter_key': os.getenv('HUNTER_API_KEY', ''),
            'crunchbase_key': os.getenv('CRUNCHBASE_API_KEY', ''),
            'pipl_key': os.getenv('PIPL_API_KEY', ''),
            'companies_house_key': os.getenv('COMPANIES_HOUSE_API_KEY', '')
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def investigate(self, company_name: str) -> Dict:
        """Deep company investigation - employees, domains, social media"""
        results = {
            'company': company_name,
            'sources': [],
            'domain': None,
            'domains': [],
            'description': None,
            'industry': None,
            'founded': None,
            'size': None,
            'employees': [],
            'emails': [],
            'phones': [],
            'addresses': [],
            'social_media': {},
            'technologies': [],
            'funding': {},
            'acquisitions': [],
            'competitors': [],
            'news': [],
            'jobs': [],
            'risk_score': 0.0,
            'tags': [],
            'logo': None,
            'website': None
        }
        
        # === FREE APIs ===
        
        # 1. OpenCorporates - Free company registry
        try:
            r = self.session.get(self.free_apis['opencorporates'],
                                params={'q': company_name, 'format': 'json'},
                                timeout=10)
            if r.status_code == 200:
                data = r.json()
                companies = data.get('results', {}).get('companies', [])
                if companies:
                    company = companies[0].get('company', {})
                    results['domain'] = company.get('registry_url')
                    results['addresses'].append({
                        'type': 'registered',
                        'address': company.get('registered_address_in_full'),
                        'country': company.get('jurisdiction_code')
                    })
                    results['founded'] = company.get('incorporation_date')
                    results['tags'].append(company.get('company_type'))
                    results['sources'].append('opencorporates')
        except: pass
        
        # 2. Companies House UK (if UK company)
        if self.paid_apis['companies_house_key']:
            try:
                r = self.session.get(self.free_apis['companies_house'],
                                    params={'q': company_name},
                                    auth=(self.paid_apis['companies_house_key'], ''),
                                    timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    items = data.get('items', [])
                    if items:
                        company = items[0]
                        results['description'] = company.get('description')
                        results['addresses'].append({
                            'type': 'registered',
                            'address': company.get('address_snippet'),
                            'country': 'UK'
                        })
                        results['founded'] = company.get('date_of_creation')
                        results['tags'].append(company.get('company_status'))
                        results['sources'].append('companies_house_uk')
            except: pass
        
        # === PAID APIs ===
        
        # 3. Clearbit - Company enrichment
        if self.paid_apis['clearbit_key']:
            try:
                r = self.session.get(self.free_apis['clearbit'],
                                    params={'domain': results['domain'] or f"{company_name.lower().replace(' ', '')}.com"},
                                    headers={'Authorization': f"Bearer {self.paid_apis['clearbit_key']}"},
                                    timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    results['domain'] = data.get('domain')
                    results['description'] = data.get('description')
                    results['founded'] = data.get('foundedYear')
                    results['size'] = data.get('metrics', {}).get('employees')
                    results['industry'] = data.get('category', {}).get('industry')
                    results['logo'] = data.get('logo')
                    results['website'] = data.get('url')
                    results['tags'].extend(data.get('tags', []))
                    
                    # Social media
                    results['social_media'] = {
                        'twitter': data.get('twitter', {}).get('handle'),
                        'facebook': data.get('facebook', {}).get('handle'),
                        'linkedin': data.get('linkedin', {}).get('handle'),
                        'crunchbase': data.get('crunchbase', {}).get('handle')
                    }
                    
                    # Technologies
                    results['technologies'] = data.get('tech', [])
                    
                    # Location
                    if data.get('geo'):
                        results['addresses'].append({
                            'type': 'headquarters',
                            'city': data['geo'].get('city'),
                            'state': data['geo'].get('state'),
                            'country': data['geo'].get('country'),
                            'lat': data['geo'].get('lat'),
                            'lng': data['geo'].get('lng')
                        })
                    
                    results['sources'].append('clearbit')
            except: pass
        
        # 4. Hunter.io - Email finder
        if self.paid_apis['hunter_key']:
            try:
                domain = results['domain'] or f"{company_name.lower().replace(' ', '')}.com"
                r = self.session.get(self.free_apis['hunter'],
                                    params={'domain': domain, 'api_key': self.paid_apis['hunter_key']},
                                    timeout=10)
                if r.status_code == 200:
                    data = r.json().get('data', {})
                    
                    # Email pattern
                    pattern = data.get('pattern')
                    if pattern:
                        results['tags'].append(f'email_pattern:{pattern}')
                    
                    # Employees with emails
                    for email_data in data.get('emails', [])[:20]:
                        results['emails'].append(email_data.get('value'))
                        if email_data.get('first_name') and email_data.get('last_name'):
                            results['employees'].append({
                                'name': f"{email_data['first_name']} {email_data['last_name']}",
                                'email': email_data['value'],
                                'position': email_data.get('position'),
                                'department': email_data.get('department'),
                                'linkedin': email_data.get('linkedin')
                            })
                    
                    results['sources'].append('hunter')
            except: pass
        
        # 5. Crunchbase - Funding & acquisitions
        if self.paid_apis['crunchbase_key']:
            try:
                r = self.session.get(f"{self.free_apis['crunchbase']}/{company_name}",
                                    headers={'X-cb-user-key': self.paid_apis['crunchbase_key']},
                                    timeout=10)
                if r.status_code == 200:
                    data = r.json().get('properties', {})
                    
                    results['description'] = data.get('short_description')
                    results['founded'] = data.get('founded_on')
                    results['size'] = data.get('num_employees_enum')
                    
                    # Funding
                    results['funding'] = {
                        'total': data.get('total_funding_usd'),
                        'rounds': data.get('num_funding_rounds'),
                        'last_round': data.get('last_funding_type'),
                        'investors': data.get('num_investors')
                    }
                    
                    # Acquisitions
                    for acq in data.get('acquisitions', [])[:10]:
                        results['acquisitions'].append({
                            'company': acq.get('acquiree_name'),
                            'date': acq.get('announced_on'),
                            'price': acq.get('price_usd')
                        })
                    
                    results['sources'].append('crunchbase')
            except: pass
        
        # === FREE WEB SCRAPING ===
        
        # 6. LinkedIn company page
        try:
            linkedin_url = f"{self.free_apis['linkedin']}/{company_name.lower().replace(' ', '-')}"
            r = self.session.get(linkedin_url, timeout=10)
            if r.status_code == 200:
                # Extract employee count
                employee_match = re.search(r'(\d+[\d,]*)\s+employees', r.text, re.IGNORECASE)
                if employee_match:
                    results['size'] = employee_match.group(1).replace(',', '')
                
                # Extract industry
                industry_match = re.search(r'<dd[^>]*>([^<]+)</dd>', r.text)
                if industry_match:
                    results['industry'] = industry_match.group(1).strip()
                
                results['social_media']['linkedin'] = linkedin_url
                results['sources'].append('linkedin_scrape')
        except: pass
        
        # 7. Job boards - Indeed, Glassdoor
        try:
            # Indeed jobs
            r = self.session.get(f'https://www.indeed.com/jobs',
                                params={'q': f'company:"{company_name}"', 'limit': 10},
                                timeout=10)
            if r.status_code == 200:
                job_matches = re.findall(r'<h2[^>]*>([^<]+)</h2>', r.text)
                results['jobs'] = [{'title': job, 'source': 'indeed'} for job in job_matches[:10]]
                results['sources'].append('indeed_jobs')
        except: pass
        
        # 8. Google search for company info
        try:
            from modules.recon.google_dorker import GoogleDorker
            dorker = GoogleDorker()
            
            # Find company domain
            domain_results = dorker.search(f'"{company_name}" site:*.com OR site:*.io OR site:*.co')
            if domain_results:
                for result in domain_results[:3]:
                    domain = re.search(r'https?://([^/]+)', result.get('url', ''))
                    if domain:
                        results['domains'].append(domain.group(1))
            
            # Find employees on LinkedIn
            employee_results = dorker.search(f'site:linkedin.com/in "{company_name}"')
            for result in employee_results[:10]:
                results['employees'].append({
                    'linkedin': result.get('url'),
                    'name': result.get('title', '').split('-')[0].strip()
                })
            
            results['sources'].append('google_dorking')
        except: pass
        
        # === SENTINEL PRO MODULE INTEGRATION ===
        
        # 9. Domain WHOIS lookup
        if results['domain']:
            try:
                from modules.recon.whois_lookup import WHOISLookup
                whois = WHOISLookup()
                whois_data = whois.lookup(results['domain'])
                
                if whois_data.get('registrant'):
                    results['addresses'].append({
                        'type': 'registrant',
                        'address': whois_data['registrant'].get('address'),
                        'country': whois_data['registrant'].get('country')
                    })
                
                if whois_data.get('emails'):
                    results['emails'].extend(whois_data['emails'])
                
                results['sources'].append('sentinel_whois')
            except: pass
        
        # 10. Subdomain enumeration
        if results['domain']:
            try:
                from modules.recon.subdomain_enum import SubdomainEnumerator
                sub_enum = SubdomainEnumerator()
                subdomains = sub_enum.enumerate(results['domain'])
                
                results['domains'].extend(subdomains[:20])
                results['sources'].append('sentinel_subdomains')
            except: pass
        
        # 11. Tech stack detection
        if results['website'] or results['domain']:
            try:
                from modules.bugbounty.tech_fingerprint import TechFingerprinter
                tech = TechFingerprinter()
                tech_data = tech.detect(results['website'] or f"https://{results['domain']}")
                
                results['technologies'].extend(tech_data.get('technologies', []))
                results['sources'].append('sentinel_tech')
            except: pass
        
        # === ML ANALYSIS ===
        
        # 12. ML Risk Scoring with SentinelNet
        try:
            from modules.ml_engine.trainer import ModelTrainer
            trainer = ModelTrainer()
            
            threat_text = f"""
            company: {company_name}
            domain: {results['domain']}
            industry: {results['industry']}
            size: {results['size']}
            employees_found: {len(results['employees'])}
            emails_found: {len(results['emails'])}
            domains_found: {len(results['domains'])}
            social_media: {len([v for v in results['social_media'].values() if v])}
            technologies: {len(results['technologies'])}
            """
            
            ml_pred = trainer.predict_threat(threat_text)
            risk_map = {'LOW': 0.2, 'MEDIUM': 0.5, 'HIGH': 0.75, 'CRITICAL': 1.0}
            results['risk_score'] = risk_map.get(ml_pred.get('label', 'LOW'), 0.0)
            results['ml_prediction'] = ml_pred
            results['sources'].append('sentinelnet_ml')
        except: pass
        
        # Deduplicate lists
        results['emails'] = list(set([e for e in results['emails'] if e]))[:50]
        results['domains'] = list(set([d for d in results['domains'] if d]))[:50]
        results['tags'] = list(set(results['tags']))
        
        # Summary
        results['summary'] = {
            'total_sources': len(results['sources']),
            'has_domain': results['domain'] is not None,
            'employees_found': len(results['employees']),
            'emails_found': len(results['emails']),
            'domains_found': len(results['domains']),
            'has_funding_data': bool(results['funding']),
            'social_media_profiles': len([v for v in results['social_media'].values() if v])
        }
        
        return results
