"""
Username Intelligence Engine - 50+ Platform Enumeration
Sherlock-style username search across social media, gaming, crypto, dev platforms
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
import requests
from typing import Dict, List
import concurrent.futures

class UsernameEngine:
    def __init__(self):
        # 50+ platforms with direct check URLs
        self.platforms = {
            # Social Media
            'twitter': 'https://twitter.com/{}',
            'instagram': 'https://www.instagram.com/{}',
            'facebook': 'https://www.facebook.com/{}',
            'linkedin': 'https://www.linkedin.com/in/{}',
            'reddit': 'https://www.reddit.com/user/{}',
            'pinterest': 'https://www.pinterest.com/{}',
            'tumblr': 'https://{}.tumblr.com',
            'snapchat': 'https://www.snapchat.com/add/{}',
            'tiktok': 'https://www.tiktok.com/@{}',
            'youtube': 'https://www.youtube.com/@{}',
            
            # Developer Platforms
            'github': 'https://github.com/{}',
            'gitlab': 'https://gitlab.com/{}',
            'bitbucket': 'https://bitbucket.org/{}',
            'stackoverflow': 'https://stackoverflow.com/users/{}',
            'codepen': 'https://codepen.io/{}',
            'replit': 'https://replit.com/@{}',
            'hackerrank': 'https://www.hackerrank.com/{}',
            'leetcode': 'https://leetcode.com/{}',
            
            # Creative Platforms
            'behance': 'https://www.behance.net/{}',
            'dribbble': 'https://dribbble.com/{}',
            'deviantart': 'https://www.deviantart.com/{}',
            'artstation': 'https://www.artstation.com/{}',
            'flickr': 'https://www.flickr.com/people/{}',
            'vimeo': 'https://vimeo.com/{}',
            'soundcloud': 'https://soundcloud.com/{}',
            'spotify': 'https://open.spotify.com/user/{}',
            'bandcamp': 'https://{}.bandcamp.com',
            
            # Gaming Platforms
            'steam': 'https://steamcommunity.com/id/{}',
            'twitch': 'https://www.twitch.tv/{}',
            'discord': 'https://discord.com/users/{}',
            'xbox': 'https://account.xbox.com/en-us/profile?gamertag={}',
            'playstation': 'https://psnprofiles.com/{}',
            'roblox': 'https://www.roblox.com/users/profile?username={}',
            'minecraft': 'https://namemc.com/profile/{}',
            'fortnite': 'https://fortnitetracker.com/profile/all/{}',
            'chess.com': 'https://www.chess.com/member/{}',
            'lichess': 'https://lichess.org/@/{}',
            
            # Messaging Apps
            'telegram': 'https://t.me/{}',
            'skype': 'https://web.skype.com/{}',
            'slack': 'https://{}.slack.com',
            'discord_tag': 'https://discord.com/users/{}',
            
            # Finance/Crypto
            'cashapp': 'https://cash.app/${}',
            'venmo': 'https://venmo.com/{}',
            'paypal': 'https://www.paypal.me/{}',
            'patreon': 'https://www.patreon.com/{}',
            'ko-fi': 'https://ko-fi.com/{}',
            
            # Professional
            'medium': 'https://medium.com/@{}',
            'substack': 'https://{}.substack.com',
            'wordpress': 'https://{}.wordpress.com',
            'blogger': 'https://{}.blogspot.com',
            'about.me': 'https://about.me/{}',
            'linktree': 'https://linktr.ee/{}',
            
            # Additional Social
            'mastodon': 'https://mastodon.social/@{}',
            'clubhouse': 'https://www.clubhouse.com/@{}',
            'quora': 'https://www.quora.com/profile/{}',
            'goodreads': 'https://www.goodreads.com/{}',
            'letterboxd': 'https://letterboxd.com/{}',
            'trakt': 'https://trakt.tv/users/{}',
            'myanimelist': 'https://myanimelist.net/profile/{}',
            'anilist': 'https://anilist.co/user/{}',
            
            # Adult/NSFW
            'onlyfans': 'https://onlyfans.com/{}',
            'fansly': 'https://fansly.com/{}',
            
            # Forums
            '4chan': 'https://boards.4chan.org/{}',
            'hackernews': 'https://news.ycombinator.com/user?id={}',
            'producthunt': 'https://www.producthunt.com/@{}',
            
            # Messaging (profile check)
            'whatsapp': 'https://wa.me/{}',
            'signal': 'https://signal.me/#p/{}',
            'line': 'https://line.me/ti/p/~{}'
        }
    
    def investigate(self, username: str) -> Dict:
        """Check username across 50+ platforms"""
        results = {
            'username': username,
            'sources': [],
            'found_platforms': [],
            'not_found_platforms': [],
            'total_checked': 0,
            'total_found': 0,
            'risk_score': 0.0,
            'profile_links': []
        }
        
        # Parallel checking for speed
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_platform = {
                executor.submit(self._check_platform, platform, url.format(username)): platform
                for platform, url in self.platforms.items()
            }
            
            for future in concurrent.futures.as_completed(future_to_platform):
                platform = future_to_platform[future]
                try:
                    exists, url, extra_data = future.result()
                    results['total_checked'] += 1
                    
                    if exists:
                        results['found_platforms'].append(platform)
                        results['total_found'] += 1
                        results['profile_links'].append({
                            'platform': platform,
                            'url': url,
                            'data': extra_data
                        })
                    else:
                        results['not_found_platforms'].append(platform)
                except: pass
        
        results['sources'].append('username_enum')
        results['sources'].append('spiderfoot_inspired_detection')
        
        # === ML ANALYSIS (SpiderFoot-inspired correlation) ===
        
        # SpiderFoot technique: Cross-platform correlation for identity resolution
        try:
            from modules.ml_engine.trainer import ModelTrainer
            from modules.ml_engine.username_clusterer import UsernameClusterer
            
            trainer = ModelTrainer()
            clusterer = UsernameClusterer()
            
            # Build threat context
            threat_text = f"""
            username: {username}
            platforms_found: {results['total_found']}
            platforms_checked: {results['total_checked']}
            presence_ratio: {results['total_found'] / max(results['total_checked'], 1)}
            high_value_platforms: {', '.join([p for p in results['found_platforms'] if p in ['github', 'linkedin', 'twitter', 'stackoverflow']])}
            """
            
            ml_pred = trainer.predict_threat(threat_text)
            risk_map = {'LOW': 0.2, 'MEDIUM': 0.5, 'HIGH': 0.75, 'CRITICAL': 1.0}
            results['risk_score'] = risk_map.get(ml_pred.get('label', 'LOW'), 0.0)
            results['ml_prediction'] = ml_pred
            results['sources'].append('sentinelnet_ml')
            
            # SpiderFoot-style: Username variant detection
            variants = clusterer.generate_variants(username)
            results['username_variants'] = variants[:10]  # Top 10 variants
            results['sources'].append('username_clustering')
        except: pass
        
        # === GROQ USERNAME PATTERN ANALYSIS ===
        
        try:
            from modules.ml_engine.groq_llm import get_groq
            import time
            groq = get_groq()
            
            if groq and groq.is_ready:
                found_platforms = ', '.join(results['found_platforms'][:10])
                
                context = f"""
Username Intelligence Summary:
- Username: {username}
- Platforms Found: {results['total_found']} out of {results['total_checked']} checked
- Found On: {found_platforms}
- Profile Links: {len(results['profile_links'])}
- ML Risk Score: {results['risk_score']:.0%}
"""
                
                prompt = f"""Analyze this username across platforms:

1. **Cross-Platform Identity**: Is this likely the same person across all platforms?
2. **Username Pattern Analysis**: What does the username pattern reveal?
3. **Platform Preference Insights**: What do the chosen platforms suggest?
4. **Potential Alternate Usernames**: Likely variations or related usernames
5. **Privacy Exposure Assessment**: How exposed is this identity?

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
            pass
        
        return results
    
    def _check_platform(self, platform: str, url: str) -> tuple:
        """Check if username exists on platform - SpiderFoot-inspired multi-method detection"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            r = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
            
            # SpiderFoot-style: Multi-method detection (status + content + redirect)
            exists = False
            extra_data = {}
            
            # Method 1: Status code check
            if r.status_code == 200:
                # Method 2: Content-based detection (platform-specific)
                text_lower = r.text.lower()
                
                if platform in ['twitter', 'instagram', 'facebook', 'linkedin']:
                    exists = 'not found' not in text_lower and "doesn't exist" not in text_lower and 'suspended' not in text_lower
                elif platform in ['github', 'gitlab', 'bitbucket']:
                    exists = 'not found' not in text_lower and '404' not in text_lower
                    if exists and platform == 'github':
                        # Extract GitHub metadata
                        import re
                        followers = re.search(r'(\d+)\s*followers?', text_lower)
                        repos = re.search(r'(\d+)\s*repositories', text_lower)
                        if followers: extra_data['followers'] = followers.group(1)
                        if repos: extra_data['repos'] = repos.group(1)
                elif platform in ['reddit']:
                    exists = 'page not found' not in text_lower and 'user not found' not in text_lower
                elif platform in ['youtube']:
                    exists = 'channel' in text_lower or 'subscriber' in text_lower
                elif platform in ['stackoverflow']:
                    exists = 'user not found' not in text_lower
                elif platform in ['medium', 'substack']:
                    exists = 'page not found' not in text_lower
                else:
                    # Generic detection
                    exists = 'not found' not in text_lower and '404' not in text_lower
                
                # Method 3: Redirect detection (SpiderFoot technique)
                if len(r.history) > 0:
                    final_url = r.url.lower()
                    if 'error' in final_url or 'notfound' in final_url or '404' in final_url:
                        exists = False
            
            return exists, url, extra_data
        except:
            return False, url, {}
