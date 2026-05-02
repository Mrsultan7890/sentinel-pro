"""
Person Intelligence Engine - 40+ Platforms + Deep ML
Username enumeration, face recognition, identity scoring, writing fingerprinting
"""
import sys
import os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
import config
import requests
from typing import Dict, List

class PersonEngine:
    def __init__(self):
        self.free_apis = {
            'pipl': 'https://api.pipl.com/search',
            'fullcontact': 'https://api.fullcontact.com/v3/person.enrich',
            'clearbit': 'https://person.clearbit.com/v2/combined/find',
            'social_searcher': 'https://api.social-searcher.com/v2/search',
            'hunter': 'https://api.hunter.io/v2/email-finder',
            'github': 'https://api.github.com/users',
            'twitter': 'https://twitter.com',
            'instagram': 'https://www.instagram.com',
            'facebook': 'https://www.facebook.com',
            'linkedin': 'https://www.linkedin.com/in'
        }
        self.paid_apis = {
            'pipl_key': os.getenv('PIPL_API_KEY', ''),
            'fullcontact_key': os.getenv('FULLCONTACT_API_KEY', '')
        }
        
        # 40+ platforms for username enumeration
        self.platforms = [
            'github', 'twitter', 'instagram', 'facebook', 'linkedin', 'reddit',
            'youtube', 'tiktok', 'snapchat', 'pinterest', 'tumblr', 'medium',
            'behance', 'dribbble', 'deviantart', 'flickr', 'vimeo', 'soundcloud',
            'spotify', 'twitch', 'discord', 'telegram', 'whatsapp', 'signal',
            'skype', 'slack', 'patreon', 'onlyfans', 'cashapp', 'venmo',
            'paypal', 'bitcoin', 'ethereum', 'steam', 'xbox', 'playstation',
            'nintendo', 'roblox', 'minecraft', 'fortnite', 'chess.com', 'lichess'
        ]
    
    def investigate(self, query: str) -> Dict:
        """Deep person investigation - 40+ platforms + ML clustering"""
        results = {
            'query': query,
            'sources': [],
            'profiles': [],
            'emails': [],
            'phones': [],
            'usernames': [],
            'addresses': [],
            'names': [],
            'jobs': [],
            'education': [],
            'social_media': [],
            'images': [],
            'documents': [],
            'websites': [],
            'risk_score': 0.0,
            'identity_score': 0.0,
            'clusters': [],
            'relationships': [],
            'writing_style': {},
            'fake_profile_probability': 0.0
        }
        
        # Detect query type
        is_email = '@' in query
        is_phone = query.replace('+', '').replace('-', '').replace(' ', '').isdigit()
        is_username = not is_email and not is_phone
        
        # === FREE APIs (No Key Required) ===
        
        # 1. GitHub - Username/email search
        try:
            if is_username:
                r = requests.get(f"{self.free_apis['github']}/{query}", timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    results['profiles'].append({
                        'platform': 'github',
                        'username': data.get('login'),
                        'name': data.get('name'),
                        'email': data.get('email'),
                        'bio': data.get('bio'),
                        'company': data.get('company'),
                        'location': data.get('location'),
                        'blog': data.get('blog'),
                        'twitter': data.get('twitter_username'),
                        'followers': data.get('followers'),
                        'following': data.get('following'),
                        'repos': data.get('public_repos'),
                        'avatar': data.get('avatar_url'),
                        'url': data.get('html_url'),
                        'created': data.get('created_at')
                    })
                    
                    if data.get('email'):
                        results['emails'].append(data['email'])
                    if data.get('name'):
                        results['names'].append(data['name'])
                    if data.get('location'):
                        results['addresses'].append(data['location'])
                    
                    results['sources'].append('github')
        except: pass
        
        # 2. Social-Searcher - Multi-platform search
        try:
            r = requests.get(self.free_apis['social_searcher'],
                           params={'q': query, 'network': 'all'}, timeout=10)
            if r.status_code == 200:
                data = r.json()
                for post in data.get('posts', [])[:20]:
                    results['social_media'].append({
                        'platform': post.get('network'),
                        'url': post.get('url'),
                        'text': post.get('text', '')[:200],
                        'posted': post.get('posted'),
                        'user': post.get('user')
                    })
                results['sources'].append('social_searcher')
        except: pass
        
        # === PAID APIs (If Keys Available) ===
        
        # 3. Pipl - Deep person search
        if self.paid_apis['pipl_key']:
            try:
                params = {'key': self.paid_apis['pipl_key']}
                if is_email:
                    params['email'] = query
                elif is_phone:
                    params['phone'] = query
                else:
                    params['username'] = query
                
                r = requests.get(self.free_apis['pipl'], params=params, timeout=15)
                if r.status_code == 200:
                    data = r.json()
                    person = data.get('person', {})
                    
                    # Extract all data
                    results['emails'].extend([e.get('address') for e in person.get('emails', [])])
                    results['phones'].extend([p.get('display') for p in person.get('phones', [])])
                    results['usernames'].extend([u.get('content') for u in person.get('usernames', [])])
                    results['addresses'].extend([a.get('display') for a in person.get('addresses', [])])
                    results['names'].extend([n.get('display') for n in person.get('names', [])])
                    results['jobs'].extend([j.get('display') for j in person.get('jobs', [])])
                    results['education'].extend([e.get('display') for e in person.get('educations', [])])
                    results['images'].extend([i.get('url') for i in person.get('images', [])])
                    results['websites'].extend([u.get('url') for u in person.get('urls', [])])
                    
                    results['sources'].append('pipl')
            except: pass
        
        # 4. FullContact - Person enrichment
        if self.paid_apis['fullcontact_key']:
            try:
                headers = {'Authorization': f"Bearer {self.paid_apis['fullcontact_key']}"}
                payload = {}
                if is_email:
                    payload['email'] = query
                elif is_phone:
                    payload['phone'] = query
                else:
                    payload['profile'] = {'url': f"https://twitter.com/{query}"}
                
                r = requests.post(self.free_apis['fullcontact'], headers=headers, json=payload, timeout=15)
                if r.status_code == 200:
                    data = r.json()
                    
                    # Extract data
                    if data.get('details'):
                        details = data['details']
                        if details.get('emails'):
                            results['emails'].extend([e.get('value') for e in details['emails']])
                        if details.get('phones'):
                            results['phones'].extend([p.get('value') for p in details['phones']])
                        if details.get('locations'):
                            results['addresses'].extend([l.get('formatted') for l in details['locations']])
                    
                    results['sources'].append('fullcontact')
            except: pass
        
        # === SENTINEL PRO MODULE INTEGRATION ===
        
        # 5. Use existing person_osint module
        try:
            from modules.recon.person_osint import PersonOSINT
            osint = PersonOSINT()
            osint_data = osint.investigate(query)
            
            # Merge results
            if osint_data.get('profiles'):
                results['profiles'].extend(osint_data['profiles'])
            if osint_data.get('emails'):
                results['emails'].extend(osint_data['emails'])
            if osint_data.get('phones'):
                results['phones'].extend(osint_data['phones'])
            if osint_data.get('usernames'):
                results['usernames'].extend(osint_data['usernames'])
            if osint_data.get('social_media'):
                results['social_media'].extend(osint_data['social_media'])
            
            results['sources'].append('sentinel_person_osint')
        except: pass
        
        # 6. Username enumeration across 40+ platforms
        if is_username:
            try:
                from modules.recon.relation_mapper import check_username_platforms
                platform_results = check_username_platforms(query)
                
                for platform, exists in platform_results.items():
                    if exists:
                        results['profiles'].append({
                            'platform': platform,
                            'username': query,
                            'exists': True,
                            'url': self._get_platform_url(platform, query)
                        })
                
                results['sources'].append('username_enum')
            except: pass
        
        # === ML ANALYSIS ===
        
        # 7. Entity Matching - Cross-platform identity resolution
        try:
            from modules.ml_engine.entity_matcher import EntityMatcher
            matcher = EntityMatcher()
            
            # Match profiles across platforms
            if len(results['profiles']) > 1:
                matches = matcher.match_entities(results['profiles'])
                results['identity_score'] = matches.get('confidence', 0.0)
                results['sources'].append('entity_matcher')
        except: pass
        
        # 8. Username Clustering - DBSCAN identity clustering
        try:
            from modules.ml_engine.username_clusterer import UsernameClusterer
            clusterer = UsernameClusterer()
            
            all_usernames = results['usernames'] + [p.get('username') for p in results['profiles'] if p.get('username')]
            if len(all_usernames) > 2:
                clusters = clusterer.cluster_usernames(all_usernames)
                results['clusters'] = clusters
                results['sources'].append('username_clusterer')
        except: pass
        
        # 9. Identity Scoring - Bayesian confidence scoring
        try:
            from modules.ml_engine.identity_scorer import IdentityScorer
            scorer = IdentityScorer()
            
            evidence = {
                'emails': results['emails'],
                'phones': results['phones'],
                'usernames': results['usernames'],
                'profiles': results['profiles'],
                'names': results['names']
            }
            
            identity_score = scorer.calculate_identity_score(evidence)
            results['identity_score'] = identity_score.get('score', 0.0)
            results['confidence_breakdown'] = identity_score.get('breakdown', {})
            results['sources'].append('identity_scorer')
        except: pass
        
        # 10. NLP Profile Analysis
        try:
            from modules.ml_engine.nlp_analyzer import NLPProfileAnalyzer
            nlp = NLPProfileAnalyzer()
            
            # Collect all text data
            text_data = ' '.join([
                ' '.join([p.get('bio', '') for p in results['profiles']]),
                ' '.join([s.get('text', '') for s in results['social_media']]),
                ' '.join(results['names'])
            ])
            
            if text_data.strip():
                nlp_result = nlp.analyze_profile_text(text_data)
                results['nlp_analysis'] = nlp_result
                results['sources'].append('nlp_analyzer')
        except: pass
        
        # 11. Writing Fingerprinting - Authorship attribution
        try:
            from modules.ml_engine.writing_fingerprinter import WritingFingerprinter
            fingerprinter = WritingFingerprinter()
            
            # Collect writing samples
            writing_samples = [s.get('text', '') for s in results['social_media'] if s.get('text')]
            
            if len(writing_samples) > 3:
                fingerprint = fingerprinter.create_fingerprint(writing_samples)
                results['writing_style'] = fingerprint
                results['sources'].append('writing_fingerprinter')
        except: pass
        
        # 12. Fake Profile Detection
        try:
            from modules.fake_profile_detector import FakeProfileDetector
            detector = FakeProfileDetector()
            
            # Check each profile
            for profile in results['profiles']:
                fake_prob = detector.detect_fake_profile(profile)
                profile['fake_probability'] = fake_prob
            
            # Overall fake probability
            if results['profiles']:
                results['fake_profile_probability'] = sum([p.get('fake_probability', 0) for p in results['profiles']]) / len(results['profiles'])
            
            results['sources'].append('fake_detector')
        except: pass
        
        # 13. Timeline Analysis - Activity patterns
        try:
            from modules.ml_engine.timeline_analyzer import TimelineAnalyzer
            timeline = TimelineAnalyzer()
            
            # Analyze posting patterns
            timestamps = [s.get('posted') for s in results['social_media'] if s.get('posted')]
            if len(timestamps) > 10:
                timeline_analysis = timeline.analyze_activity_patterns(timestamps)
                results['timeline_analysis'] = timeline_analysis
                results['sources'].append('timeline_analyzer')
        except: pass
        
        # 14. ML Risk Scoring with SentinelNet
        try:
            from modules.ml_engine.trainer import ModelTrainer
            trainer = ModelTrainer()
            
            # Build threat context
            threat_text = f"""
            person: {query}
            profiles: {len(results['profiles'])}
            emails: {len(results['emails'])}
            phones: {len(results['phones'])}
            social_media: {len(results['social_media'])}
            fake_probability: {results['fake_profile_probability']}
            identity_score: {results['identity_score']}
            """
            
            ml_pred = trainer.predict_threat(threat_text)
            risk_map = {'LOW': 0.2, 'MEDIUM': 0.5, 'HIGH': 0.75, 'CRITICAL': 1.0}
            results['risk_score'] = risk_map.get(ml_pred.get('label', 'LOW'), 0.0)
            results['ml_prediction'] = ml_pred
            results['sources'].append('sentinelnet_ml')
        except: pass
        
        # === GROQ IDENTITY ANALYSIS ===
        
        try:
            from modules.ml_engine.groq_llm import get_groq
            import time
            groq = get_groq()
            
            if groq and groq.is_ready:
                # Build profile summary
                profile_summary = []
                for p in results.get('profiles', [])[:5]:
                    profile_summary.append(f"- {p.get('platform', 'Unknown')}: @{p.get('username', 'N/A')}")
                
                context = f"""
Person Intelligence Summary:
- Query: {query}
- Query Type: {results.get('query_type', 'Unknown')}
- Social Profiles Found: {len(results.get('profiles', []))}
- Emails: {', '.join(results.get('emails', [])[:3]) or 'None'}
- Phones: {', '.join(results.get('phones', [])[:3]) or 'None'}
- Usernames: {', '.join(results.get('usernames', [])[:5]) or 'None'}
- Addresses: {len(results.get('addresses', []))}
- Images: {len(results.get('images', []))}
- ML Risk Score: {results.get('risk_score', 0):.0%}

Top Profiles:
{chr(10).join(profile_summary) if profile_summary else 'None'}
"""
                
                prompt = f"""Analyze this person's digital footprint:

1. **Identity Confidence Score**: How confident are we this is the same person? (0-100%)
2. **Behavioral Patterns**: What patterns emerge from their online presence?
3. **Potential Fake Profiles**: Any indicators of fake or bot accounts?
4. **Privacy Exposure Level**: How much personal data is publicly exposed?
5. **OSINT Investigation Recommendations**: Next steps for deeper investigation

{context}

Provide detailed professional analysis."""
                
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
        results['emails'] = list(set([e for e in results['emails'] if e]))
        results['phones'] = list(set([p for p in results['phones'] if p]))
        results['usernames'] = list(set([u for u in results['usernames'] if u]))
        results['names'] = list(set([n for n in results['names'] if n]))
        results['addresses'] = list(set([a for a in results['addresses'] if a]))
        
        return results
    
    def _get_platform_url(self, platform: str, username: str) -> str:
        """Generate platform URL from username"""
        urls = {
            'github': f'https://github.com/{username}',
            'twitter': f'https://twitter.com/{username}',
            'instagram': f'https://instagram.com/{username}',
            'facebook': f'https://facebook.com/{username}',
            'linkedin': f'https://linkedin.com/in/{username}',
            'reddit': f'https://reddit.com/user/{username}',
            'youtube': f'https://youtube.com/@{username}',
            'tiktok': f'https://tiktok.com/@{username}',
            'medium': f'https://medium.com/@{username}',
            'telegram': f'https://t.me/{username}'
        }
        return urls.get(platform, f'https://{platform}.com/{username}')
