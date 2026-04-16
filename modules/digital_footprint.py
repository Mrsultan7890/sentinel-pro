"""
Advanced Digital Footprint Collector Module
Enhanced multi-source collection with stealth capabilities
"""

import subprocess
import json
import os
import re
import logging
import warnings
from bs4 import BeautifulSoup
import requests
from modules.utils import tor_session
from urllib.parse import urljoin, urlparse
import time
import random
from .enhanced_profile_extractor import EnhancedProfileExtractor

# Disable SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
requests.packages.urllib3.disable_warnings()

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AdvancedFootprintCollector:
    def __init__(self):
        self.scraped_data = []
        self.extracted_entities = {}
        self.user_agents = [
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]
        self.stealth_mode = False
        self.enhanced_extractor = EnhancedProfileExtractor()
        self.request_count = 0
        self.max_requests_per_minute = 10
        
    def collect_surface_data(self, target):
        """Enhanced surface web collection with multiple sources"""
        print(f"[*] Advanced collection for: {target}")
        
        # Multi-source collection
        sources = [
            self._search_engines_collection(target),
            self._social_media_collection(target),
            self._professional_networks_collection(target),
            self._code_repositories_collection(target)
        ]
        
        # Combine all sources
        combined_data = []
        for source_data in sources:
            if source_data:
                combined_data.extend(source_data)
        
        return combined_data
    
    def collect_social_data(self, target):
        """Enhanced social media profile collection with 40+ platforms"""
        clean_target = target.replace('@', '').replace(' ', '')
        
        social_platforms = {
            # Major Social Media
            'facebook': f"https://www.facebook.com/{clean_target}",
            'instagram': f"https://www.instagram.com/{clean_target}",
            'twitter': f"https://twitter.com/{clean_target}",
            'linkedin': f"https://www.linkedin.com/in/{clean_target}",
            'tiktok': f"https://www.tiktok.com/@{clean_target}",
            'snapchat': f"https://www.snapchat.com/add/{clean_target}",
            'youtube': f"https://www.youtube.com/@{clean_target}",
            
            # Professional Networks
            'github': f"https://github.com/{clean_target}",
            'gitlab': f"https://gitlab.com/{clean_target}",
            'bitbucket': f"https://bitbucket.org/{clean_target}",
            'stackoverflow': f"https://stackoverflow.com/users/{clean_target}",
            'behance': f"https://www.behance.net/{clean_target}",
            'dribbble': f"https://dribbble.com/{clean_target}",
            'devto': f"https://dev.to/{clean_target}",
            
            # Content Platforms
            'medium': f"https://medium.com/@{clean_target}",
            'substack': f"https://{clean_target}.substack.com",
            'wordpress': f"https://{clean_target}.wordpress.com",
            'blogger': f"https://{clean_target}.blogspot.com",
            'tumblr': f"https://{clean_target}.tumblr.com",
            
            # Communication
            'telegram': f"https://t.me/{clean_target}",
            'discord': f"https://discord.com/users/{clean_target}",
            'whatsapp': f"https://wa.me/{clean_target}",
            'signal': f"https://signal.me/#p/{clean_target}",
            'skype': f"https://join.skype.com/invite/{clean_target}",
            
            # Media & Entertainment
            'twitch': f"https://www.twitch.tv/{clean_target}",
            'spotify': f"https://open.spotify.com/user/{clean_target}",
            'soundcloud': f"https://soundcloud.com/{clean_target}",
            'vimeo': f"https://vimeo.com/{clean_target}",
            'dailymotion': f"https://www.dailymotion.com/{clean_target}",
            
            # Gaming
            'steam': f"https://steamcommunity.com/id/{clean_target}",
            'xbox': f"https://account.xbox.com/en-us/profile?gamertag={clean_target}",
            'playstation': f"https://psnprofiles.com/{clean_target}",
            'twitch': f"https://www.twitch.tv/{clean_target}",
            'roblox': f"https://www.roblox.com/users/profile?username={clean_target}",
            
            # Forums & Communities
            'reddit': f"https://www.reddit.com/user/{clean_target}",
            'quora': f"https://www.quora.com/profile/{clean_target}",
            'hackernews': f"https://news.ycombinator.com/user?id={clean_target}",
            'producthunt': f"https://www.producthunt.com/@{clean_target}",
            
            # Visual Platforms
            'pinterest': f"https://www.pinterest.com/{clean_target}",
            'flickr': f"https://www.flickr.com/people/{clean_target}",
            '500px': f"https://500px.com/p/{clean_target}",
            'unsplash': f"https://unsplash.com/@{clean_target}",
            
            # Dating & Adult (for fake profile detection)
            'onlyfans': f"https://onlyfans.com/{clean_target}",
            'patreon': f"https://www.patreon.com/{clean_target}",
            
            # Other
            'linktree': f"https://linktr.ee/{clean_target}",
            'about_me': f"https://about.me/{clean_target}",
            'carrd': f"https://{clean_target}.carrd.co",
        }
        
        social_data = []
        
        for platform, url in social_platforms.items():
            try:
                # Rate limiting
                self._apply_rate_limit()
                
                session = self._get_stealth_session()
                response = session.get(url, timeout=10, allow_redirects=True, verify=True)
                
                # Only process successful responses
                if response.status_code == 200:
                    try:
                        profile_info = self._extract_profile_info_direct(response.text, platform, url)
                        bio_data = self._extract_bio_direct(response.text, platform)
                        posts_data = self._extract_posts_direct(response.text, platform)
                        contact_info = self._extract_contact_direct(response.text)
                        
                        # CRITICAL: Only add if we have REAL data
                        has_real_data = (
                            profile_info.get('display_name') or 
                            profile_info.get('username') or 
                            bio_data.get('bio') or 
                            posts_data.get('posts')
                        )
                        
                        if has_real_data:
                            social_data.append({
                                'platform': platform,
                                'url': url,
                                'profile_info': profile_info,
                                'bio_data': bio_data,
                                'posts_data': posts_data,
                                'tags_data': self._extract_tags_and_hashtags(response.text, platform),
                                'contact_info': contact_info,
                                'content': response.text[:5000],
                                'status': 'success',
                                'verified': True
                            })
                            logger.info(f"{platform}: Real profile data collected - {profile_info.get('display_name', 'N/A')}")
                        else:
                            logger.debug(f"{platform}: No real data found, skipping")
                    
                    except Exception as parse_error:
                        logger.error(f"{platform}: Parse error - {str(parse_error)}", exc_info=True)
                        continue
                else:
                    logger.warning(f"{platform}: HTTP {response.status_code} - skipping")
                
                time.sleep(random.uniform(2, 4))  # Human-like delay
                
            except requests.exceptions.Timeout:
                logger.error(f"{platform}: Request timeout")
                continue
            except requests.exceptions.RequestException as e:
                logger.error(f"{platform}: Connection error - {str(e)}")
                continue
            except Exception as e:
                logger.error(f"{platform}: Unexpected error - {str(e)}", exc_info=True)
                continue
        
        return social_data
    
    def _search_engines_collection(self, target):
        """Enhanced search engine scraping"""
        search_engines = [
            f"https://duckduckgo.com/html/?q={target}",
            f"https://www.bing.com/search?q={target}",
            f"https://search.yahoo.com/search?p={target}"
        ]
        
        search_data = []
        
        for engine_url in search_engines:
            try:
                session = self._get_stealth_session()
                response = session.get(engine_url, timeout=15)
                
                if response.status_code == 200:
                    # Extract search results
                    results = self._extract_search_results(response.text)
                    
                    search_data.append({
                        'source': 'search_engine',
                        'url': engine_url,
                        'results': results,
                        'content': response.text[:5000],
                        'status': 'success'
                    })
                
                time.sleep(random.uniform(2, 4))
                
            except Exception as e:
                search_data.append({
                    'source': 'search_engine',
                    'url': engine_url,
                    'results': [],
                    'content': '',
                    'status': f'error: {str(e)}'
                })
        
        return search_data
    
    def _social_media_collection(self, target):
        """Dedicated social media scraping"""
        # Use Go scraper for high-performance collection
        try:
            result = subprocess.run(
                ['./scraper/scraper', target, '--social'], 
                cwd='/home/kali/osints', 
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return self._fallback_social_scraping(target)
                
        except Exception as e:
            return self._fallback_social_scraping(target)
    
    def _professional_networks_collection(self, target):
        """Professional networks (LinkedIn, GitHub, etc.)"""
        professional_sites = [
            f"https://github.com/search?q={target}&type=users",
            f"https://stackoverflow.com/users?tab=reputation&filter={target}",
            f"https://www.behance.net/search/users?search={target}"
        ]
        
        professional_data = []
        
        for site_url in professional_sites:
            try:
                session = self._get_stealth_session()
                response = session.get(site_url, timeout=10)
                
                if response.status_code == 200:
                    # Extract professional profiles
                    profiles = self._extract_professional_profiles(response.text)
                    
                    professional_data.append({
                        'source': 'professional_network',
                        'url': site_url,
                        'profiles': profiles,
                        'content': response.text[:3000],
                        'status': 'success'
                    })
                
                time.sleep(random.uniform(1, 3))
                
            except Exception as e:
                professional_data.append({
                    'source': 'professional_network',
                    'url': site_url,
                    'profiles': [],
                    'content': '',
                    'status': f'error: {str(e)}'
                })
        
        return professional_data
    
    def _code_repositories_collection(self, target):
        """Code repositories and development platforms"""
        code_sites = [
            f"https://github.com/{target.replace('@', '')}",
            f"https://gitlab.com/{target.replace('@', '')}",
            f"https://bitbucket.org/{target.replace('@', '')}"
        ]
        
        code_data = []
        
        for site_url in code_sites:
            try:
                session = self._get_stealth_session()
                response = session.get(site_url, timeout=10)
                
                if response.status_code == 200:
                    # Extract repository information
                    repo_info = self._extract_repository_info(response.text)
                    
                    code_data.append({
                        'source': 'code_repository',
                        'url': site_url,
                        'repository_info': repo_info,
                        'content': response.text[:3000],
                        'status': 'success'
                    })
                
                time.sleep(random.uniform(1, 2))
                
            except Exception as e:
                code_data.append({
                    'source': 'code_repository',
                    'url': site_url,
                    'repository_info': {},
                    'content': '',
                    'status': f'error: {str(e)}'
                })
        
        return code_data
    
    def _get_stealth_session(self):
        """Get stealth-configured session with proper security"""
        session = tor_session()
        
        # Random user agent rotation
        session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'DNT': '1'
        })
        
        # SSL verification enabled by default
        session.verify = True
        
        return session
    
    def _apply_rate_limit(self):
        """Apply rate limiting to avoid detection and bans"""
        self.request_count += 1
        if self.request_count >= self.max_requests_per_minute:
            logger.info("Rate limit reached, waiting 60 seconds...")
            time.sleep(60)
            self.request_count = 0
    

    
    def _extract_text(self, soup, selector, attribute=None):
        """Safely extract text or attribute from BeautifulSoup element"""
        try:
            if not selector or not soup:
                return ''
            
            element = soup.select_one(selector)
            if element:
                if attribute:
                    return element.get(attribute, '')
                return element.get_text(strip=True)
            return ''
        except Exception as e:
            # print(f"[DEBUG] Selector error for '{selector}': {str(e)}")
            return ''
    
    def _extract_display_name(self, soup, platform):
        """Extract display name based on platform"""
        selectors = {
            'github': '.p-name, .vcard-fullname, .h-card .p-name',
            'reddit': '.ProfileHeader-displayName, ._1LCAhi_8JjayVo7pJ0KIh0',
            'twitter': '[data-testid="UserName"] span, .ProfileHeaderCard-name, .css-901oao',
            'instagram': 'h2._aa3b, h1._aacl, ._7UhW9, .rhpdm',
            'linkedin': '.text-heading-xlarge, .pv-text-details__left-panel h1',
            'tiktok': '[data-e2e="user-title"], .share-title',
            'youtube': '.ytd-channel-name, #channel-name, .style-scope.ytd-c4-tabbed-header-renderer',
            'facebook': '.x1heor9g, .d2edcug0, .hpfvmrgz',
            'discord': '.username, .header-23xsNx',
            'telegram': '.tgme_page_title, .tgme_page_extra'
        }
        
        # Try multiple selectors for better extraction
        for selector in selectors.get(platform, '').split(', '):
            if selector:
                result = self._extract_text(soup, selector.strip())
                if result:
                    return result
        
        # Fallback: try to extract from meta tags
        meta_selectors = [
            'meta[property="og:title"]',
            'meta[name="twitter:title"]',
            'title'
        ]
        
        for meta_sel in meta_selectors:
            result = self._extract_text(soup, meta_sel, 'content' if 'meta' in meta_sel else None)
            if result and platform.lower() in result.lower():
                return result.split('|')[0].split('(')[0].strip()
        
        return ''
    
    def _extract_username(self, soup, platform):
        """Extract username based on platform"""
        selectors = {
            'github': '.p-nickname',
            'reddit': '.ProfileHeader-username',
            'twitter': '[data-testid="UserScreenName"]',
            'instagram': 'h1._aacl',
            'tiktok': '[data-e2e="user-subtitle"]',
            'youtube': '.ytd-channel-handle',
            'telegram': '.tgme_page_extra'
        }
        return self._extract_text(soup, selectors.get(platform, ''))
    
    def _extract_follower_count(self, soup, platform):
        """Extract follower count based on platform"""
        selectors = {
            'github': '.js-profile-editable-area .Counter, .Counter.js-profile-editable-area',
            'reddit': '.karma-breakdown, ._1fCdbQCDX6yeFXDQu6NBhd',
            'twitter': '[data-testid="UserFollowers"] span, .ProfileNav-item--followers .ProfileNav-value',
            'instagram': 'meta[name="description"], ._ac2a span, .g47SY',
            'tiktok': '[data-e2e="followers-count"], .number',
            'youtube': '#subscriber-count, .yt-subscription-button-subscriber-count-branded-horizontal',
            'linkedin': '.pv-top-card--list-bullet, .pv-top-card-v2-ctas .pv-top-card-v2-ctas__connections'
        }
        
        # Try direct selectors first
        for selector in selectors.get(platform, '').split(', '):
            if selector:
                result = self._extract_text(soup, selector.strip())
                if result:
                    return result
        
        # Platform-specific extraction logic
        if platform == 'instagram':
            # Try to extract from meta description
            meta_desc = self._extract_text(soup, 'meta[name="description"]', 'content')
            if meta_desc:
                import re
                # Look for patterns like "1.2M Followers"
                follower_match = re.search(r'([0-9,.]+[KMB]?)\s*[Ff]ollowers?', meta_desc)
                if follower_match:
                    return follower_match.group(1)
        
        elif platform == 'twitter':
            # Look for follower text patterns
            text_content = soup.get_text()
            import re
            follower_match = re.search(r'([0-9,.]+[KMB]?)\s*[Ff]ollowing', text_content)
            if follower_match:
                return follower_match.group(1)
        
        return ''
    
    def _extract_following_count(self, soup, platform):
        """Extract following count based on platform"""
        selectors = {
            'twitter': '[data-testid="UserFollowing"] span',
            'instagram': 'a[href*="/following/"] span',
            'tiktok': '[data-e2e="following-count"]',
            'github': '.js-profile-editable-area a[href*="/following"]'
        }
        return self._extract_text(soup, selectors.get(platform, ''))
    
    def _extract_post_count(self, soup, platform):
        """Extract post count based on platform"""
        selectors = {
            'instagram': 'div._ac2a span',
            'twitter': '[data-testid="UserTweets"] span',
            'reddit': '.karma',
            'tiktok': '[data-e2e="video-count"]'
        }
        return self._extract_text(soup, selectors.get(platform, ''))
    
    def _extract_profile_image(self, soup, platform):
        """Extract profile image URL based on platform"""
        selectors = {
            'github': '.avatar img',
            'twitter': '[data-testid="UserAvatar"] img',
            'instagram': 'img[alt*="profile picture"]',
            'linkedin': '.pv-top-card__photo img',
            'youtube': '.ytd-c4-tabbed-header-renderer img'
        }
        return self._extract_text(soup, selectors.get(platform, ''), 'src')
    
    def _check_verification(self, soup, platform):
        """Check if account is verified"""
        verification_selectors = {
            'twitter': '[data-testid="icon-verified"]',
            'instagram': 'span[title="Verified"]',
            'youtube': '.badge-style-type-verified',
            'tiktok': '[data-e2e="user-verified"]',
            'facebook': '.x1lliihq'
        }
        return bool(soup.select(verification_selectors.get(platform, '')))
    
    def _extract_join_date(self, soup, platform):
        """Extract account creation/join date"""
        selectors = {
            'github': '.js-profile-editable-area time',
            'reddit': '.cake-day',
            'twitter': '[data-testid="UserJoinDate"] span',
            'youtube': '.ytd-c4-tabbed-header-renderer .style-scope'
        }
        return self._extract_text(soup, selectors.get(platform, ''))
    
    def _extract_contact_info(self, soup):
        """Extract contact information from profile"""
        contact_info = {}
        
        # Email patterns
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, soup.get_text())
        if emails:
            contact_info['emails'] = emails
        
        # Phone patterns
        phone_pattern = r'(\+\d{1,3}[-\.\s]?)?\(?\d{3}\)?[-\.\s]?\d{3}[-\.\s]?\d{4}'
        phones = re.findall(phone_pattern, soup.get_text())
        if phones:
            contact_info['phones'] = phones
        
        # Website links
        links = [a.get('href') for a in soup.select('a[href^="http"]')]
        if links:
            contact_info['websites'] = links[:5]  # Limit to 5 links
        
        return contact_info
    
    def _extract_search_results(self, html_content):
        """Extract search results from search engine HTML"""
        soup = BeautifulSoup(html_content, 'html.parser')
        results = []
        
        # Generic search result extraction
        result_selectors = [
            '.result__title a',  # DuckDuckGo
            '.b_algo h2 a',      # Bing
            '.compTitle a'       # Yahoo
        ]
        
        for selector in result_selectors:
            links = soup.select(selector)
            for link in links[:10]:  # Limit to 10 results
                href = link.get('href', '')
                title = link.get_text(strip=True)
                
                if href and title:
                    results.append({
                        'title': title,
                        'url': href,
                        'snippet': ''  # Could extract snippets too
                    })
        
        return results
    
    def _extract_professional_profiles(self, html_content):
        """Extract professional profile information"""
        soup = BeautifulSoup(html_content, 'html.parser')
        profiles = []
        
        # Generic profile extraction patterns
        profile_patterns = [
            {'name': '.user-name', 'link': '.user-link'},
            {'name': '.profile-name', 'link': '.profile-url'},
            {'name': '.username', 'link': '.user-url'}
        ]
        
        for pattern in profile_patterns:
            names = soup.select(pattern['name'])
            links = soup.select(pattern['link'])
            
            for name, link in zip(names[:5], links[:5]):  # Limit results
                profiles.append({
                    'name': name.get_text(strip=True),
                    'profile_url': link.get('href', ''),
                    'platform': 'professional'
                })
        
        return profiles
    
    def _extract_repository_info(self, html_content):
        """Extract code repository information"""
        soup = BeautifulSoup(html_content, 'html.parser')
        repo_info = {}
        
        # GitHub repository info
        repo_info['name'] = self._extract_text(soup, '.js-repo-nav-name')
        repo_info['description'] = self._extract_text(soup, '.f4.my-3')
        repo_info['language'] = self._extract_text(soup, '.ml-0.mr-3')
        repo_info['stars'] = self._extract_text(soup, '#repo-stars-counter-star')
        repo_info['forks'] = self._extract_text(soup, '#repo-network-counter')
        
        return repo_info
    
    def _extract_posts_and_comments(self, html_content, platform):
        """Extract posts and comments from profile page"""
        soup = BeautifulSoup(html_content, 'html.parser')
        posts_data = {'posts': [], 'comments': []}
        
        # Platform-specific post extraction
        if platform == 'twitter':
            # Multiple selectors for tweets
            tweet_selectors = [
                '[data-testid="tweet"]',
                '.tweet',
                '.js-stream-tweet',
                'article[data-testid="tweet"]'
            ]
            
            tweets = []
            for selector in tweet_selectors:
                found_tweets = soup.select(selector)
                if found_tweets:
                    tweets = found_tweets
                    break
            
            for tweet in tweets[:10]:  # Limit to 10 tweets
                # Try multiple selectors for tweet text
                post_text = (self._extract_text(tweet, '[data-testid="tweetText"]') or 
                           self._extract_text(tweet, '.tweet-text') or
                           self._extract_text(tweet, '.js-tweet-text'))
                
                post_time = (self._extract_text(tweet, 'time') or
                           self._extract_text(tweet, '.tweet-timestamp'))
                
                likes = (self._extract_text(tweet, '[data-testid="like"] span') or
                        self._extract_text(tweet, '.ProfileTweet-action--favorite .ProfileTweet-actionCount'))
                
                retweets = (self._extract_text(tweet, '[data-testid="retweet"] span') or
                          self._extract_text(tweet, '.ProfileTweet-action--retweet .ProfileTweet-actionCount'))
                
                if post_text:
                    posts_data['posts'].append({
                        'text': post_text,
                        'timestamp': post_time,
                        'likes': likes,
                        'retweets': retweets,
                        'platform': platform
                    })
        
        elif platform == 'reddit':
            posts = soup.select('.Post')
            for post in posts[:10]:
                title = self._extract_text(post, '.Post__title')
                content = self._extract_text(post, '.Post__content')
                upvotes = self._extract_text(post, '.vote__up-vote-button')
                comments_count = self._extract_text(post, '.Post__comments-count')
                
                if title or content:
                    posts_data['posts'].append({
                        'title': title,
                        'content': content,
                        'upvotes': upvotes,
                        'comments_count': comments_count,
                        'platform': platform
                    })
        
        elif platform == 'instagram':
            # Multiple selectors for Instagram posts
            post_selectors = [
                'article',
                '._aabd',
                '.v1Nh3',
                '._ac7v'
            ]
            
            posts = []
            for selector in post_selectors:
                found_posts = soup.select(selector)
                if found_posts:
                    posts = found_posts
                    break
            
            for post in posts[:10]:
                # Try multiple selectors for caption
                caption = (self._extract_text(post, '.C4VMK span') or
                          self._extract_text(post, '._a9zs') or
                          self._extract_text(post, '.ZyFrc') or
                          self._extract_text(post, 'meta[property="og:description"]', 'content'))
                
                # Try multiple selectors for likes
                likes = (self._extract_text(post, '.Nm9Fw button span') or
                        self._extract_text(post, '._aacl') or
                        self._extract_text(post, '.zV_Nj span'))
                
                if caption:
                    posts_data['posts'].append({
                        'caption': caption,
                        'likes': likes,
                        'platform': platform
                    })
            
            # Also try to extract from meta description if no posts found
            if not posts_data['posts']:
                meta_desc = self._extract_text(soup, 'meta[property="og:description"]', 'content')
                if meta_desc and len(meta_desc) > 50:
                    posts_data['posts'].append({
                        'caption': meta_desc,
                        'likes': 'N/A',
                        'platform': platform
                    })
        
        elif platform == 'github':
            # Extract recent activity with multiple selectors
            activity_selectors = [
                '.js-recent-activity-container .Box-row',
                '.contribution-activity .Box-row',
                '.js-yearly-contributions',
                '.ContributionCalendar-day'
            ]
            
            activities = []
            for selector in activity_selectors:
                found_activities = soup.select(selector)
                if found_activities:
                    activities = found_activities
                    break
            
            for activity in activities[:10]:
                activity_text = (self._extract_text(activity, '.text-gray') or
                               self._extract_text(activity, '.f6') or
                               activity.get_text(strip=True))
                
                activity_time = (self._extract_text(activity, 'relative-time') or
                               self._extract_text(activity, 'time'))
                
                if activity_text:
                    posts_data['posts'].append({
                        'activity': activity_text,
                        'timestamp': activity_time,
                        'platform': platform
                    })
            
            # Also extract repository information
            repos = soup.select('.repo')
            for repo in repos[:5]:
                repo_name = self._extract_text(repo, '.repo-name')
                repo_desc = self._extract_text(repo, '.repo-description')
                
                if repo_name:
                    posts_data['posts'].append({
                        'activity': f'Repository: {repo_name} - {repo_desc}',
                        'timestamp': 'N/A',
                        'platform': platform
                    })
        
        # Generic fallback extraction for any platform
        if not posts_data['posts']:
            # Try to extract any text content that looks like posts
            text_elements = soup.find_all(['p', 'div', 'span'], string=True)
            for element in text_elements[:5]:
                text = element.get_text(strip=True)
                if len(text) > 20 and len(text) < 500:  # Reasonable post length
                    posts_data['posts'].append({
                        'text': text,
                        'timestamp': 'N/A',
                        'platform': platform
                    })
        
        return posts_data
    
    def _extract_bio_and_description(self, html_content, platform):
        """Extract bio and description information"""
        soup = BeautifulSoup(html_content, 'html.parser')
        bio_data = {}
        
        # Platform-specific bio extraction
        bio_selectors = {
            'github': '.p-note, .user-profile-bio',
            'twitter': '[data-testid="UserDescription"]',
            'instagram': '.-vDIg span, .C4VMK span',
            'linkedin': '.pv-about__summary-text',
            'tiktok': '[data-e2e="user-bio"]',
            'youtube': '.ytd-channel-about-metadata-renderer .content',
            'reddit': '.ProfileHeader--description',
            'facebook': '.x1i10hfl',
            'telegram': '.tgme_page_description'
        }
        
        bio_text = self._extract_text(soup, bio_selectors.get(platform, ''))
        if bio_text:
            bio_data['bio'] = bio_text
            
            # Extract mentions, hashtags, and links from bio
            bio_data['mentions'] = re.findall(r'@([A-Za-z0-9_]+)', bio_text)
            bio_data['hashtags'] = re.findall(r'#([A-Za-z0-9_]+)', bio_text)
            bio_data['urls'] = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', bio_text)
        
        return bio_data
    
    def _extract_tags_and_hashtags(self, html_content, platform):
        """Extract tags, hashtags, and keywords"""
        soup = BeautifulSoup(html_content, 'html.parser')
        tags_data = {'hashtags': [], 'mentions': [], 'keywords': []}
        
        # Extract all text content
        all_text = soup.get_text()
        
        # Find hashtags
        hashtags = re.findall(r'#([A-Za-z0-9_]+)', all_text)
        tags_data['hashtags'] = list(set(hashtags))[:20]  # Remove duplicates and limit
        
        # Find mentions
        mentions = re.findall(r'@([A-Za-z0-9_]+)', all_text)
        tags_data['mentions'] = list(set(mentions))[:20]
        
        # Platform-specific tag extraction
        if platform == 'github':
            # Extract programming languages and topics
            languages = soup.select('.BorderGrid-cell .color-fg-default')
            for lang in languages:
                lang_text = lang.get_text(strip=True)
                if lang_text:
                    tags_data['keywords'].append(lang_text)
        
        return tags_data
    
    def _fallback_social_scraping(self, target):
        """Enhanced fallback social media scraping with better search"""
        fallback_data = []
        
        # Enhanced search queries for better results
        search_queries = [
            f'"{target}" site:github.com',
            f'"{target}" site:reddit.com',
            f'"{target}" site:twitter.com',
            f'"{target}" site:instagram.com',
            f'"{target}" site:linkedin.com',
            f'{target} username OR handle OR account'
        ]
        
        for query in search_queries[:3]:  # Limit queries
            try:
                session = self._get_stealth_session()
                search_url = f"https://duckduckgo.com/html/?q={query}"
                response = session.get(search_url, timeout=10)
                
                if response.status_code == 200:
                    # Extract search results
                    soup = BeautifulSoup(response.text, 'html.parser')
                    results = soup.select('.result__title a')
                    
                    for result in results[:3]:  # Limit to 3 results per query
                        title = result.get_text(strip=True)
                        url = result.get('href', '')
                        
                        if title and url:
                            fallback_data.append({
                                'source': 'enhanced_search',
                                'query': query,
                                'title': title,
                                'url': url,
                                'target': target,
                                'status': 'found'
                            })
                
                time.sleep(random.uniform(1, 2))  # Rate limiting
                
            except Exception as e:
                fallback_data.append({
                    'source': 'search_error',
                    'query': query,
                    'target': target,
                    'error': str(e),
                    'status': 'error'
                })
        
        return fallback_data
    
    def _extract_profile_info_direct(self, html_content, platform, url):
        """Direct profile information extraction with better selectors"""
        soup = BeautifulSoup(html_content, 'html.parser')
        profile_info = {}
        
        # Extract from meta tags first (most reliable)
        og_title = soup.find('meta', {'property': 'og:title'})
        if og_title:
            title = og_title.get('content', '')
            if title and platform.lower() not in title.lower():
                profile_info['display_name'] = title.split('|')[0].split('(')[0].strip()
        
        # Extract profile image from multiple sources
        profile_image = None
        
        # Try og:image first
        og_image = soup.find('meta', {'property': 'og:image'})
        if og_image:
            img_url = og_image.get('content', '')
            # Validate it's a real profile image URL
            if img_url and ('profile' in img_url.lower() or 'avatar' in img_url.lower() or 'user' in img_url.lower()):
                profile_image = img_url
        
        # Platform-specific profile image extraction
        if not profile_image:
            image_selectors = {
                'instagram': ['img[alt*="profile picture"]', 'img[alt*="avatar"]', '._6q-tv img', 'img[data-testid="user-avatar"]'],
                'twitter': ['img[alt*="avatar"]', '[data-testid="UserAvatar"] img', '.ProfileAvatar-image'],
                'github': ['.avatar img', '.avatar-user img', '.Header-link img'],
                'linkedin': ['.pv-top-card__photo img', '.profile-photo img'],
                'youtube': ['.ytd-c4-tabbed-header-renderer img', '#avatar img'],
                'facebook': ['.profilePicThumb img', '._11kf img'],
                'reddit': ['img[alt*="avatar"]', '._3Z6MIaeww5ZKy3s_'],
                'tiktok': ['img[alt*="avatar"]', '[data-e2e="user-avatar"] img']
            }
            
            for selector in image_selectors.get(platform, []):
                img_elem = soup.select_one(selector)
                if img_elem:
                    src = img_elem.get('src') or img_elem.get('data-src') or img_elem.get('data-lazy-src')
                    if src and ('http' in src or src.startswith('//')): 
                        # Convert relative URLs to absolute
                        if src.startswith('//'):
                            src = 'https:' + src
                        elif src.startswith('/'):
                            from urllib.parse import urljoin
                            src = urljoin(url, src)
                        profile_image = src
                        break
        
        if profile_image:
            profile_info['profile_image'] = profile_image
        
        # Platform-specific extraction
        if platform == 'instagram':
            # Instagram meta description contains follower info
            meta_desc = soup.find('meta', {'name': 'description'})
            if meta_desc:
                desc = meta_desc.get('content', '')
                # Extract followers from description like "1,234 Followers, 567 Following"
                import re
                follower_match = re.search(r'([0-9,.KMB]+)\s*Followers?', desc, re.IGNORECASE)
                if follower_match:
                    profile_info['follower_count'] = follower_match.group(1)
                
                following_match = re.search(r'([0-9,.KMB]+)\s*Following', desc, re.IGNORECASE)
                if following_match:
                    profile_info['following_count'] = following_match.group(1)
                
                posts_match = re.search(r'([0-9,.KMB]+)\s*Posts?', desc, re.IGNORECASE)
                if posts_match:
                    profile_info['post_count'] = posts_match.group(1)
            
            # Extract real name from meta property
            og_description = soup.find('meta', {'property': 'og:description'})
            if og_description:
                og_desc = og_description.get('content', '')
                # Instagram format: "Name (@username) • Instagram photos and videos"
                if '(@' in og_desc and ')' in og_desc:
                    name_part = og_desc.split('(@')[0].strip()
                    username_part = og_desc.split('(@')[1].split(')')[0]
                    if name_part and name_part != username_part:
                        profile_info['display_name'] = name_part
                        profile_info['username'] = username_part
            
            # Try to extract username from URL as fallback
            if not profile_info.get('display_name'):
                username = url.split('/')[-1] if not url.endswith('/') else url.split('/')[-2]
                if username and username != 'instagram.com':
                    profile_info['display_name'] = username
        
        elif platform == 'twitter':
            # Twitter title format: "Name (@username) / Twitter"
            if og_title:
                title = og_title.get('content', '')
                if '(@' in title:
                    name_part = title.split('(@')[0].strip()
                    username_part = title.split('(@')[1].split(')')[0] if ')' in title else ''
                    profile_info['display_name'] = name_part
                    profile_info['username'] = username_part
        
        elif platform == 'github':
            # GitHub profile extraction
            name_elem = soup.find('span', class_='p-name')
            if name_elem:
                profile_info['display_name'] = name_elem.get_text(strip=True)
            
            # GitHub followers
            followers_link = soup.find('a', href=lambda x: x and 'followers' in x)
            if followers_link:
                followers_text = followers_link.get_text(strip=True)
                profile_info['follower_count'] = followers_text.split()[0] if followers_text else '0'
        
        elif platform == 'reddit':
            # Reddit username from URL
            if '/user/' in url:
                username = url.split('/user/')[-1]
                profile_info['display_name'] = username
            
            # Reddit profile image
            avatar_img = soup.find('img', alt=lambda x: x and 'avatar' in x.lower())
            if avatar_img:
                profile_info['profile_image'] = avatar_img.get('src', '')
        
        elif platform == 'youtube':
            # YouTube channel name
            channel_name = soup.find('meta', {'name': 'title'})
            if channel_name:
                profile_info['display_name'] = channel_name.get('content', '').replace(' - YouTube', '')
            
            # YouTube subscriber count from meta description
            meta_desc = soup.find('meta', {'name': 'description'})
            if meta_desc:
                desc = meta_desc.get('content', '')
                import re
                sub_match = re.search(r'([0-9.]+[KMB]?)\s*subscribers?', desc, re.IGNORECASE)
                if sub_match:
                    profile_info['follower_count'] = sub_match.group(1)
        
        # Fallback: extract from page title
        if not profile_info.get('display_name'):
            title_elem = soup.find('title')
            if title_elem:
                title = title_elem.get_text(strip=True)
                # Clean up common suffixes
                for suffix in [' - Instagram', ' / Twitter', ' - YouTube', ' | LinkedIn']:
                    title = title.replace(suffix, '')
                if title and len(title) < 100:
                    profile_info['display_name'] = title
        
        return profile_info
    
    def _extract_bio_direct(self, html_content, platform):
        """Direct bio extraction"""
        soup = BeautifulSoup(html_content, 'html.parser')
        bio_data = {}
        
        # Try meta description first
        meta_desc = soup.find('meta', {'name': 'description'})
        if meta_desc:
            desc = meta_desc.get('content', '')
            if desc and len(desc) > 20:
                bio_data['bio'] = desc
        
        # Platform-specific bio selectors
        bio_selectors = {
            'instagram': ['.-vDIg span', '.C4VMK span'],
            'twitter': ['[data-testid="UserDescription"]'],
            'github': ['.p-note', '.user-profile-bio'],
            'linkedin': ['.pv-about__summary-text'],
            'youtube': ['#description']
        }
        
        if platform in bio_selectors:
            for selector in bio_selectors[platform]:
                bio_elem = soup.select_one(selector)
                if bio_elem:
                    bio_text = bio_elem.get_text(strip=True)
                    if bio_text:
                        bio_data['bio'] = bio_text
                        break
        
        return bio_data
    
    def _extract_posts_direct(self, html_content, platform):
        """Direct posts extraction"""
        soup = BeautifulSoup(html_content, 'html.parser')
        posts_data = {'posts': []}
        
        # Platform-specific post extraction
        if platform == 'twitter':
            # Look for tweet-like content
            tweets = soup.find_all('div', string=lambda x: x and len(x) > 10 and len(x) < 280)
            for tweet in tweets[:5]:
                tweet_text = tweet.get_text(strip=True)
                if tweet_text:
                    posts_data['posts'].append({
                        'text': tweet_text,
                        'platform': platform
                    })
        
        elif platform == 'instagram':
            # Instagram posts from meta description or alt text
            meta_desc = soup.find('meta', {'property': 'og:description'})
            if meta_desc:
                desc = meta_desc.get('content', '')
                if len(desc) > 50:
                    posts_data['posts'].append({
                        'caption': desc,
                        'platform': platform
                    })
        
        elif platform == 'github':
            # GitHub repositories as "posts"
            repo_links = soup.find_all('a', href=lambda x: x and '/repos/' in x or (x and x.startswith('/') and len(x.split('/')) == 3))
            for repo in repo_links[:5]:
                repo_name = repo.get_text(strip=True)
                if repo_name and len(repo_name) < 100:
                    posts_data['posts'].append({
                        'repository': repo_name,
                        'platform': platform
                    })
        
        return posts_data
    
    def _extract_contact_direct(self, html_content):
        """Direct contact information extraction - only real contact info"""
        contact_info = {}
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract emails from visible text and links
        import re
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        
        # Check mailto links first
        mailto_links = soup.find_all('a', href=lambda x: x and x.startswith('mailto:'))
        if mailto_links:
            email = mailto_links[0]['href'].replace('mailto:', '')
            contact_info['email'] = email
        else:
            # Check visible text for emails
            visible_text = soup.get_text()
            emails = re.findall(email_pattern, visible_text)
            # Filter out common false positives
            real_emails = [e for e in emails if not any(fake in e.lower() for fake in ['noreply', 'example', 'test', 'admin', 'support'])]
            if real_emails:
                contact_info['email'] = real_emails[0]
        
        # Extract phone numbers - only from contact sections or tel: links
        tel_links = soup.find_all('a', href=lambda x: x and x.startswith('tel:'))
        if tel_links:
            phone = tel_links[0]['href'].replace('tel:', '').replace('+', '').replace('-', '').replace(' ', '')
            if len(phone) >= 10:
                contact_info['phone'] = phone
        else:
            # Look for phone in contact sections only
            contact_sections = soup.find_all(['div', 'section'], class_=lambda x: x and any(word in x.lower() for word in ['contact', 'phone', 'mobile']))
            for section in contact_sections:
                section_text = section.get_text()
                phone_pattern = r'\+?[1-9][0-9]{9,14}'
                phones = re.findall(phone_pattern, section_text)
                if phones:
                    contact_info['phone'] = phones[0]
                    break
        
        return contact_info