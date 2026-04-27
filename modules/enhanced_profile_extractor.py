# ============================================================================
# Sentinel Pro v3.0 — Professional OSINT & Bug Bounty Platform
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
#
# Unauthorized copying, distribution, or modification of this software,
# via any medium, is strictly prohibited without written permission.
#
# Licensed users may use this software under the terms of their license.
# For licensing: https://github.com/Mrsultan7890/osints
# ============================================================================

"""
Enhanced Profile Information Extractor
Detailed extraction of profile photos, bio, comments, posts, followers, etc.
"""

import re
from bs4 import BeautifulSoup
import json
import requests
from modules.utils import tor_session
import time
import random

class EnhancedProfileExtractor:
    def __init__(self):
        self.user_agents = [
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
    
    def extract_complete_profile(self, html_content, platform, url):
        """Extract complete profile information with all details"""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        profile_data = {
            'platform': platform,
            'url': url,
            'profile_info': self._extract_profile_info(soup, platform),
            'bio_data': self._extract_bio_data(soup, platform),
            'posts_data': self._extract_posts_data(soup, platform),
            'media_data': self._extract_media_data(soup, platform),
            'contact_info': self._extract_contact_info(soup, platform),
            'social_metrics': self._extract_social_metrics(soup, platform),
            'verification_info': self._extract_verification_info(soup, platform),
            'activity_data': self._extract_activity_data(soup, platform)
        }
        
        return profile_data
    
    def _extract_profile_info(self, soup, platform):
        """Extract basic profile information"""
        profile_info = {}
        
        # Platform-specific extraction with comprehensive selectors
        if platform == 'github':
            profile_info.update({
                'display_name': self._get_text_by_selectors(soup, [
                    '.p-name', '.vcard-fullname', '.h-card .p-name', 'h1.vcard-names'
                ]),
                'username': self._get_text_by_selectors(soup, [
                    '.p-nickname', '.vcard-username', 'span.p-nickname'
                ]).replace('@', ''),
                'follower_count': self._get_text_by_selectors(soup, [
                    'a[href*="followers"] .Counter',
                    'a[href*="followers"] strong',
                    '.js-profile-editable-area a[href*="followers"]'
                ]),
                'following_count': self._get_text_by_selectors(soup, [
                    'a[href*="following"] .Counter',
                    'a[href*="following"] strong'
                ]),
                'repositories_count': self._get_text_by_selectors(soup, [
                    'span.Counter', 'a[data-tab-item="repositories"] .Counter'
                ]),
                'profile_image': self._get_attribute_by_selectors(soup, [
                    '.avatar img', '.Header-link img', 'img.avatar'
                ], 'src'),
                'join_date': self._get_attribute_by_selectors(soup, [
                    'relative-time', 'time[datetime]'
                ], 'datetime'),
                'location': self._get_text_by_selectors(soup, [
                    '.p-label', '.vcard-detail[itemprop="homeLocation"]'
                ]),
                'company': self._get_text_by_selectors(soup, [
                    '.p-org', '.vcard-detail[itemprop="worksFor"]'
                ]),
                'website': self._get_attribute_by_selectors(soup, [
                    '.vcard-detail[itemprop="url"] a'
                ], 'href')
            })
        
        elif platform == 'twitter':
            profile_info.update({
                'display_name': self._get_text_by_selectors(soup, [
                    '[data-testid="UserName"] span:first-child',
                    '.ProfileHeaderCard-name a',
                    'h1[role="heading"]'
                ]),
                'username': self._get_text_by_selectors(soup, [
                    '[data-testid="UserName"] span[dir="ltr"]',
                    '.ProfileHeaderCard-screenname'
                ]).replace('@', ''),
                'follower_count': self._get_text_by_selectors(soup, [
                    '[data-testid="UserFollowersCount"] span',
                    'a[href*="followers"] span[data-count]',
                    '.ProfileNav-item--followers .ProfileNav-value'
                ]),
                'following_count': self._get_text_by_selectors(soup, [
                    '[data-testid="UserFollowingCount"] span',
                    'a[href*="following"] span[data-count]'
                ]),
                'tweets_count': self._get_text_by_selectors(soup, [
                    '[data-testid="UserTweets"] span',
                    '.ProfileNav-item--tweets .ProfileNav-value'
                ]),
                'profile_image': self._get_attribute_by_selectors(soup, [
                    '[data-testid="UserAvatar"] img',
                    '.ProfileAvatar-image'
                ], 'src'),
                'banner_image': self._get_attribute_by_selectors(soup, [
                    '[data-testid="UserBanner"] img',
                    '.ProfileCanopy-headerBg img'
                ], 'src'),
                'verified': self._check_verification(soup, [
                    '[data-testid="icon-verified"]',
                    '.ProfileHeaderCard-badges .Icon--verified'
                ]),
                'join_date': self._get_text_by_selectors(soup, [
                    '[data-testid="UserJoinDate"] span',
                    '.ProfileHeaderCard-joinDateText'
                ])
            })
        
        elif platform == 'instagram':
            profile_info.update({
                'display_name': self._get_text_by_selectors(soup, [
                    'h2._aacl._aaco._aacu._aacx._aad7._aade',
                    'h1._aacl._aaco._aacu._aacx._aad7._aade',
                    'h2', 'h1'
                ]),
                'username': self._extract_instagram_username(soup),
                'follower_count': self._extract_instagram_stats(soup, 'followers'),
                'following_count': self._extract_instagram_stats(soup, 'following'),
                'posts_count': self._extract_instagram_stats(soup, 'posts'),
                'profile_image': self._get_attribute_by_selectors(soup, [
                    'img[alt*="profile picture"]',
                    '._aadp img',
                    '.be6sR img'
                ], 'src'),
                'verified': self._check_verification(soup, [
                    'span[title="Verified"]',
                    '.coreSpriteVerifiedBadge'
                ]),
                'business_account': 'Contact' in soup.get_text() or 'Email' in soup.get_text()
            })
        
        elif platform == 'linkedin':
            profile_info.update({
                'display_name': self._get_text_by_selectors(soup, [
                    'h1.text-heading-xlarge',
                    'h1[data-anonymize="person-name"]',
                    '.pv-text-details__left-panel h1'
                ]),
                'headline': self._get_text_by_selectors(soup, [
                    '.text-body-medium.break-words',
                    '.pv-text-details__left-panel .text-body-medium'
                ]),
                'location': self._get_text_by_selectors(soup, [
                    '.text-body-small.inline.t-black--light.break-words',
                    '.pv-text-details__left-panel .pb2'
                ]),
                'connections_count': self._get_text_by_selectors(soup, [
                    '.pv-top-card--list-bullet li',
                    'span[aria-label*="connection"]'
                ]),
                'profile_image': self._get_attribute_by_selectors(soup, [
                    '.pv-top-card__photo img',
                    '.presence-entity__image img'
                ], 'src'),
                'company': self._get_text_by_selectors(soup, [
                    '.pv-text-details__left-panel .text-body-medium',
                    '.pv-entity__secondary-title'
                ])
            })
        
        elif platform == 'youtube':
            profile_info.update({
                'display_name': self._get_text_by_selectors(soup, [
                    'yt-formatted-string#text.style-scope.ytd-channel-name',
                    '#channel-name yt-formatted-string',
                    'h1.ytd-channel-name'
                ]),
                'subscriber_count': self._get_text_by_selectors(soup, [
                    'yt-formatted-string#subscriber-count',
                    '#subscriber-count',
                    '.yt-subscription-button-subscriber-count-branded-horizontal'
                ]),
                'videos_count': self._extract_youtube_video_count(soup),
                'profile_image': self._get_attribute_by_selectors(soup, [
                    '.ytd-c4-tabbed-header-renderer img',
                    '#channel-header-container img'
                ], 'src'),
                'banner_image': self._get_attribute_by_selectors(soup, [
                    '.ytd-c4-tabbed-header-renderer .style-scope.ytd-c4-tabbed-header-renderer',
                    '#channel-header img'
                ], 'src'),
                'verified': self._check_verification(soup, [
                    '.badge-style-type-verified',
                    '.ytd-badge-supported-renderer'
                ])
            })
        
        elif platform == 'tiktok':
            profile_info.update({
                'display_name': self._get_text_by_selectors(soup, [
                    'h2[data-e2e="user-title"]',
                    'h1[data-e2e="user-title"]'
                ]),
                'username': self._get_text_by_selectors(soup, [
                    'h1[data-e2e="user-subtitle"]',
                    '[data-e2e="user-subtitle"]'
                ]).replace('@', ''),
                'follower_count': self._get_text_by_selectors(soup, [
                    '[data-e2e="followers-count"]'
                ]),
                'following_count': self._get_text_by_selectors(soup, [
                    '[data-e2e="following-count"]'
                ]),
                'likes_count': self._get_text_by_selectors(soup, [
                    '[data-e2e="likes-count"]'
                ]),
                'profile_image': self._get_attribute_by_selectors(soup, [
                    '[data-e2e="user-avatar"] img',
                    '.avatar img'
                ], 'src'),
                'verified': self._check_verification(soup, [
                    '[data-e2e="user-verified"]'
                ])
            })
        
        elif platform == 'facebook':
            profile_info.update({
                'display_name': self._get_text_by_selectors(soup, [
                    'h1[data-overviewsection="ContactInfo"]',
                    'h1.uiHeaderTitle',
                    '.x1heor9g'
                ]),
                'profile_image': self._get_attribute_by_selectors(soup, [
                    '.profilePicThumb img',
                    '._11kf img'
                ], 'src'),
                'cover_image': self._get_attribute_by_selectors(soup, [
                    '.cover img',
                    '._2nlw img'
                ], 'src')
            })
        
        # Generic fallbacks
        if not profile_info.get('display_name'):
            profile_info['display_name'] = self._get_text_by_selectors(soup, [
                'h1', 'h2', '.name', '.username', '.display-name'
            ])
        
        if not profile_info.get('profile_image'):
            profile_info['profile_image'] = self._get_attribute_by_selectors(soup, [
                'img[alt*="profile"]', 'img[alt*="avatar"]', '.avatar img', 'img'
            ], 'src')
        
        return profile_info
    
    def _extract_bio_data(self, soup, platform):
        """Extract bio and description information"""
        bio_data = {}
        
        bio_selectors = {
            'github': ['.p-note', '.user-profile-bio', '.js-profile-editable-area .p-note'],
            'twitter': ['[data-testid="UserDescription"]', '.ProfileHeaderCard-bio'],
            'instagram': ['.-vDIg span', '.C4VMK span', '._aa_c span'],
            'linkedin': ['.pv-about__summary-text', '.pv-about-section .pv-about__summary-text'],
            'tiktok': ['[data-e2e="user-bio"]', '.share-desc'],
            'youtube': ['.ytd-channel-about-metadata-renderer .content', '#description'],
            'reddit': ['.ProfileHeader--description', '._1fCdbQCDX6yeFXDQu6NBhd'],
            'facebook': ['.x1i10hfl', '.profileIntroCard'],
            'telegram': ['.tgme_page_description']
        }
        
        bio_text = self._get_text_by_selectors(soup, bio_selectors.get(platform, []))
        
        if bio_text:
            bio_data['bio'] = bio_text
            bio_data['bio_length'] = len(bio_text)
            
            # Extract entities from bio
            bio_data['mentions'] = re.findall(r'@([A-Za-z0-9_]+)', bio_text)
            bio_data['hashtags'] = re.findall(r'#([A-Za-z0-9_]+)', bio_text)
            bio_data['urls'] = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', bio_text)
            bio_data['emails'] = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', bio_text)
            
            # Extract location if mentioned in bio
            location_keywords = ['from', 'based in', 'located in', 'living in', '📍', '🌍', '🏠']
            for keyword in location_keywords:
                if keyword in bio_text.lower():
                    # Extract text after location keyword
                    location_match = re.search(f'{keyword}\\s+([^\\n\\r,]+)', bio_text, re.IGNORECASE)
                    if location_match:
                        bio_data['location'] = location_match.group(1).strip()
                        break
        
        return bio_data
    
    def _extract_posts_data(self, soup, platform):
        """Extract posts, tweets, and content"""
        posts_data = {'posts': [], 'total_posts': 0}
        
        if platform == 'twitter':
            posts = self._extract_twitter_posts(soup)
        elif platform == 'instagram':
            posts = self._extract_instagram_posts(soup)
        elif platform == 'reddit':
            posts = self._extract_reddit_posts(soup)
        elif platform == 'github':
            posts = self._extract_github_activity(soup)
        elif platform == 'linkedin':
            posts = self._extract_linkedin_posts(soup)
        elif platform == 'tiktok':
            posts = self._extract_tiktok_videos(soup)
        elif platform == 'youtube':
            posts = self._extract_youtube_videos(soup)
        else:
            posts = self._extract_generic_posts(soup)
        
        posts_data['posts'] = posts[:20]  # Limit to 20 posts
        posts_data['total_posts'] = len(posts)
        
        return posts_data
    
    def _extract_media_data(self, soup, platform):
        """Extract media files, images, videos"""
        media_data = {'images': [], 'videos': [], 'total_media': 0}
        
        # Extract images
        img_selectors = [
            'img[src*="http"]',
            'img[data-src*="http"]',
            '.image img',
            '.photo img',
            '.media img'
        ]
        
        for selector in img_selectors:
            images = soup.select(selector)
            for img in images[:10]:  # Limit to 10 images
                src = img.get('src') or img.get('data-src')
                if src and src.startswith('http'):
                    media_data['images'].append({
                        'url': src,
                        'alt': img.get('alt', ''),
                        'type': 'image'
                    })
        
        # Extract videos
        video_selectors = [
            'video[src*="http"]',
            'video source[src*="http"]',
            '[data-video-url]'
        ]
        
        for selector in video_selectors:
            videos = soup.select(selector)
            for video in videos[:5]:  # Limit to 5 videos
                src = video.get('src') or video.get('data-video-url')
                if src and src.startswith('http'):
                    media_data['videos'].append({
                        'url': src,
                        'type': 'video'
                    })
        
        media_data['total_media'] = len(media_data['images']) + len(media_data['videos'])
        
        return media_data
    
    def _extract_contact_info(self, soup, platform):
        """Extract contact information"""
        contact_info = {}
        
        # Extract from entire page text
        page_text = soup.get_text()
        
        # Email extraction
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', page_text)
        if emails:
            contact_info['email'] = emails[0]  # Take first email found
            contact_info['all_emails'] = list(set(emails))
        
        # Phone extraction
        phone_patterns = [
            r'\+\d{1,3}[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}',
            r'\(\d{3}\)\s?\d{3}[-.\s]?\d{4}',
            r'\d{3}[-.\s]?\d{3}[-.\s]?\d{4}'
        ]
        
        phones = []
        for pattern in phone_patterns:
            phones.extend(re.findall(pattern, page_text))
        
        if phones:
            contact_info['phone'] = phones[0]
            contact_info['all_phones'] = list(set(phones))
        
        # Website/URL extraction
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', page_text)
        if urls:
            # Filter out social media URLs
            external_urls = [url for url in urls if not any(social in url for social in ['twitter.com', 'instagram.com', 'facebook.com', 'linkedin.com'])]
            if external_urls:
                contact_info['website'] = external_urls[0]
                contact_info['all_websites'] = list(set(external_urls))
        
        return contact_info
    
    def _extract_social_metrics(self, soup, platform):
        """Extract social media metrics and engagement"""
        metrics = {}
        
        # Platform-specific metrics extraction
        if platform == 'twitter':
            metrics.update({
                'tweets_count': self._get_text_by_selectors(soup, ['[data-testid="UserTweets"] span']),
                'media_count': self._get_text_by_selectors(soup, ['[data-testid="UserMedia"] span']),
                'likes_count': self._get_text_by_selectors(soup, ['[data-testid="UserLikes"] span'])
            })
        
        elif platform == 'instagram':
            metrics.update({
                'posts_count': self._extract_instagram_stats(soup, 'posts'),
                'followers_count': self._extract_instagram_stats(soup, 'followers'),
                'following_count': self._extract_instagram_stats(soup, 'following')
            })
        
        elif platform == 'youtube':
            metrics.update({
                'subscribers_count': self._get_text_by_selectors(soup, ['#subscriber-count']),
                'videos_count': self._extract_youtube_video_count(soup),
                'views_count': self._extract_youtube_views(soup)
            })
        
        elif platform == 'github':
            metrics.update({
                'repositories_count': self._get_text_by_selectors(soup, ['.Counter']),
                'followers_count': self._get_text_by_selectors(soup, ['a[href*="followers"] .Counter']),
                'following_count': self._get_text_by_selectors(soup, ['a[href*="following"] .Counter']),
                'contributions': self._get_text_by_selectors(soup, ['.js-yearly-contributions h2'])
            })
        
        return metrics
    
    def _extract_verification_info(self, soup, platform):
        """Extract verification and badge information"""
        verification_info = {}
        
        verification_selectors = {
            'twitter': ['[data-testid="icon-verified"]', '.ProfileHeaderCard-badges .Icon--verified'],
            'instagram': ['span[title="Verified"]', '.coreSpriteVerifiedBadge'],
            'youtube': ['.badge-style-type-verified', '.ytd-badge-supported-renderer'],
            'tiktok': ['[data-e2e="user-verified"]'],
            'facebook': ['.x1lliihq', '.verified-badge']
        }
        
        is_verified = self._check_verification(soup, verification_selectors.get(platform, []))
        verification_info['verified'] = is_verified
        
        # Check for other badges
        badge_selectors = ['.badge', '.icon', '.verification', '.premium', '.pro']
        badges = []
        
        for selector in badge_selectors:
            badge_elements = soup.select(selector)
            for badge in badge_elements:
                badge_text = badge.get_text(strip=True)
                if badge_text and len(badge_text) < 50:
                    badges.append(badge_text)
        
        verification_info['badges'] = list(set(badges))[:5]  # Limit to 5 badges
        
        return verification_info
    
    def _extract_activity_data(self, soup, platform):
        """Extract recent activity and engagement data"""
        activity_data = {'recent_activity': [], 'last_active': ''}
        
        # Platform-specific activity extraction
        if platform == 'github':
            activity_elements = soup.select('.js-recent-activity-container .Box-row')
            for activity in activity_elements[:5]:
                activity_text = activity.get_text(strip=True)
                if activity_text:
                    activity_data['recent_activity'].append(activity_text)
        
        elif platform == 'reddit':
            posts = soup.select('.Post')
            for post in posts[:5]:
                post_title = self._get_text_by_selectors(post, ['.Post__title'])
                if post_title:
                    activity_data['recent_activity'].append(f"Posted: {post_title}")
        
        # Extract last active time if available
        time_selectors = ['time[datetime]', '.timestamp', '.time', 'relative-time']
        for selector in time_selectors:
            time_elem = soup.select_one(selector)
            if time_elem:
                time_value = time_elem.get('datetime') or time_elem.get_text(strip=True)
                if time_value:
                    activity_data['last_active'] = time_value
                    break
        
        return activity_data
    
    # Helper methods
    def _get_text_by_selectors(self, soup, selectors):
        """Get text using multiple selectors as fallback"""
        for selector in selectors:
            if selector:
                element = soup.select_one(selector)
                if element:
                    text = element.get_text(strip=True)
                    if text:
                        return text
        return ''
    
    def _get_attribute_by_selectors(self, soup, selectors, attribute):
        """Get attribute using multiple selectors as fallback"""
        for selector in selectors:
            if selector:
                element = soup.select_one(selector)
                if element:
                    attr_value = element.get(attribute)
                    if attr_value:
                        return attr_value
        return ''
    
    def _check_verification(self, soup, selectors):
        """Check if account is verified using multiple selectors"""
        for selector in selectors:
            if selector and soup.select_one(selector):
                return True
        return False
    
    def _extract_instagram_username(self, soup):
        """Extract Instagram username from various sources"""
        # Try URL extraction
        canonical_link = soup.find('link', {'rel': 'canonical'})
        if canonical_link:
            href = canonical_link.get('href', '')
            if '/p/' not in href:  # Not a post URL
                username = href.split('/')[-2] if href.endswith('/') else href.split('/')[-1]
                if username:
                    return username
        
        # Try meta property
        og_url = soup.find('meta', {'property': 'og:url'})
        if og_url:
            url = og_url.get('content', '')
            username = url.split('/')[-2] if url.endswith('/') else url.split('/')[-1]
            if username and username != 'instagram.com':
                return username
        
        return ''
    
    def _extract_instagram_stats(self, soup, stat_type):
        """Extract Instagram statistics (posts, followers, following)"""
        # Try multiple approaches for Instagram stats
        
        # Method 1: Meta description
        meta_desc = soup.find('meta', {'name': 'description'})
        if meta_desc:
            desc = meta_desc.get('content', '')
            if stat_type == 'followers':
                match = re.search(r'([0-9,.]+[KMB]?)\s*[Ff]ollowers?', desc)
                if match:
                    return match.group(1)
            elif stat_type == 'following':
                match = re.search(r'([0-9,.]+[KMB]?)\s*[Ff]ollowing', desc)
                if match:
                    return match.group(1)
            elif stat_type == 'posts':
                match = re.search(r'([0-9,.]+[KMB]?)\s*[Pp]osts?', desc)
                if match:
                    return match.group(1)
        
        # Method 2: Direct selectors
        stat_selectors = {
            'posts': ['ul._a9z6._a9za li:first-child', '._ac2a span'],
            'followers': ['ul._a9z6._a9za li:nth-child(2)', 'a[href*="/followers/"] span'],
            'following': ['ul._a9z6._a9za li:nth-child(3)', 'a[href*="/following/"] span']
        }
        
        return self._get_text_by_selectors(soup, stat_selectors.get(stat_type, []))
    
    def _extract_youtube_video_count(self, soup):
        """Extract YouTube video count"""
        # Try multiple selectors for video count
        selectors = [
            '.yt-formatted-string[aria-label*="video"]',
            '.style-scope.ytd-c4-tabbed-header-renderer .yt-formatted-string',
            '#videos-count'
        ]
        
        for selector in selectors:
            element = soup.select_one(selector)
            if element:
                text = element.get_text(strip=True)
                # Extract number from text like "123 videos"
                match = re.search(r'([0-9,.]+)', text)
                if match:
                    return match.group(1)
        
        return ''
    
    def _extract_youtube_views(self, soup):
        """Extract total YouTube channel views"""
        view_selectors = [
            '.yt-formatted-string[aria-label*="view"]',
            '.style-scope.ytd-about-channel-renderer .yt-formatted-string'
        ]
        
        return self._get_text_by_selectors(soup, view_selectors)
    
    def _extract_twitter_posts(self, soup):
        """Extract Twitter posts/tweets"""
        posts = []
        tweet_selectors = [
            '[data-testid="tweet"]',
            'article[data-testid="tweet"]',
            '.tweet'
        ]
        
        for selector in tweet_selectors:
            tweets = soup.select(selector)
            if tweets:
                for tweet in tweets[:10]:
                    post_text = self._get_text_by_selectors(tweet, [
                        '[data-testid="tweetText"]',
                        '.tweet-text',
                        '.js-tweet-text'
                    ])
                    
                    if post_text:
                        posts.append({
                            'text': post_text,
                            'timestamp': self._get_text_by_selectors(tweet, ['time']),
                            'likes': self._get_text_by_selectors(tweet, ['[data-testid="like"] span']),
                            'retweets': self._get_text_by_selectors(tweet, ['[data-testid="retweet"] span']),
                            'type': 'tweet'
                        })
                break
        
        return posts
    
    def _extract_instagram_posts(self, soup):
        """Extract Instagram posts"""
        posts = []
        
        # Try to extract from meta description first
        meta_desc = soup.find('meta', {'property': 'og:description'})
        if meta_desc:
            desc = meta_desc.get('content', '')
            if len(desc) > 50:  # Likely a post caption
                posts.append({
                    'caption': desc,
                    'type': 'instagram_post',
                    'source': 'meta_description'
                })
        
        # Try to extract from page content
        post_selectors = [
            'article',
            '._aabd',
            '.v1Nh3'
        ]
        
        for selector in post_selectors:
            post_elements = soup.select(selector)
            for post in post_elements[:5]:
                caption = self._get_text_by_selectors(post, [
                    '.C4VMK span',
                    '._a9zs',
                    '.ZyFrc'
                ])
                
                if caption and len(caption) > 10:
                    posts.append({
                        'caption': caption,
                        'type': 'instagram_post'
                    })
            
            if posts:
                break
        
        return posts
    
    def _extract_reddit_posts(self, soup):
        """Extract Reddit posts"""
        posts = []
        post_elements = soup.select('.Post')
        
        for post in post_elements[:10]:
            title = self._get_text_by_selectors(post, ['.Post__title'])
            content = self._get_text_by_selectors(post, ['.Post__content'])
            upvotes = self._get_text_by_selectors(post, ['.vote__up-vote-button'])
            
            if title:
                posts.append({
                    'title': title,
                    'content': content,
                    'upvotes': upvotes,
                    'type': 'reddit_post'
                })
        
        return posts
    
    def _extract_github_activity(self, soup):
        """Extract GitHub activity"""
        activities = []
        activity_elements = soup.select('.js-recent-activity-container .Box-row')
        
        for activity in activity_elements[:10]:
            activity_text = activity.get_text(strip=True)
            if activity_text:
                activities.append({
                    'activity': activity_text,
                    'type': 'github_activity'
                })
        
        return activities
    
    def _extract_linkedin_posts(self, soup):
        """Extract LinkedIn posts"""
        posts = []
        # LinkedIn has complex structure, try basic extraction
        post_elements = soup.select('.feed-shared-update-v2')
        
        for post in post_elements[:5]:
            content = self._get_text_by_selectors(post, [
                '.feed-shared-text',
                '.break-words'
            ])
            
            if content:
                posts.append({
                    'content': content,
                    'type': 'linkedin_post'
                })
        
        return posts
    
    def _extract_tiktok_videos(self, soup):
        """Extract TikTok videos"""
        videos = []
        video_elements = soup.select('[data-e2e="user-post-item"]')
        
        for video in video_elements[:10]:
            # TikTok video extraction is limited due to dynamic loading
            videos.append({
                'type': 'tiktok_video',
                'note': 'Video content requires dynamic loading'
            })
        
        return videos
    
    def _extract_youtube_videos(self, soup):
        """Extract YouTube videos"""
        videos = []
        video_elements = soup.select('.ytd-grid-video-renderer')
        
        for video in video_elements[:10]:
            title = self._get_text_by_selectors(video, [
                '#video-title',
                '.ytd-video-meta-block h3'
            ])
            
            if title:
                videos.append({
                    'title': title,
                    'type': 'youtube_video'
                })
        
        return videos
    
    def _extract_generic_posts(self, soup):
        """Generic post extraction for unknown platforms"""
        posts = []
        
        # Look for common post patterns
        text_elements = soup.find_all(['p', 'div'], string=True)
        for element in text_elements[:5]:
            text = element.get_text(strip=True)
            if 20 < len(text) < 500:  # Reasonable post length
                posts.append({
                    'text': text,
                    'type': 'generic_post'
                })
        
        return posts