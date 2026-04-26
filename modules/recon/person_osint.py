"""
Person OSINT - Name/Email/Phone/Image se complete digital footprint dhundho
Relation mapping ke saath sab entities ko connect karta hai
"""

import logging
import re
import json
import hashlib
from modules.utils import rate_limited_get

logger = logging.getLogger(__name__)


class PersonOSINT:

    SOCIAL_PLATFORMS = {
        'github':    'https://github.com/{username}',
        'twitter':   'https://twitter.com/{username}',
        'instagram': 'https://www.instagram.com/{username}/',
        'linkedin':  'https://www.linkedin.com/in/{username}',
        'facebook':  'https://www.facebook.com/{username}',
        'tiktok':    'https://www.tiktok.com/@{username}',
        'reddit':    'https://www.reddit.com/user/{username}',
        'pinterest': 'https://www.pinterest.com/{username}/',
        'youtube':   'https://www.youtube.com/@{username}',
        'telegram':  'https://t.me/{username}',
    }

    SOCIAL_MARKERS = {
        'github':    ['itemprop="name"', 'class="p-name"'],
        'twitter':   ['data-screen-name', 'og:title'],
        'instagram': ['"username":', '"is_private"'],
        'linkedin':  ['class="top-card__title"', 'og:title'],
        'facebook':  ['og:title', 'profile_id'],
        'tiktok':    ['"uniqueId"', '"nickname"'],
        'reddit':    ['class="ProfilePage"', '"name":'],
        'pinterest': ['og:title', '"username"'],
        'youtube':   ['channelId', 'og:title'],
        'telegram':  ['tgme_page_title', 'og:title'],
    }

    def run(self, query: str, query_type: str = 'auto') -> dict:
        """
        query_type: 'name', 'email', 'phone', 'username', 'auto'
        """
        result = {
            'query':        query,
            'query_type':   query_type,
            'entities':     {},      # discovered entities
            'social_profiles': [],
            'possible_usernames': [],
            'addresses':    [],
            'emails_found': [],
            'phones_found': [],
            'images_found': [],
            'relations':    [],      # relation graph edges
            'risk_level':   'LOW',
            'risk_flags':   [],
            'error':        None,
        }

        if query_type == 'auto':
            query_type = self._detect_type(query)
            result['query_type'] = query_type

        # Generate username variations from input
        usernames = self._generate_usernames(query, query_type)
        result['possible_usernames'] = usernames

        # Search social platforms
        self._search_social_platforms(result, usernames)

        # Search public data sources
        self._search_public_sources(result, query, query_type)

        # Search people search engines
        self._search_people_engines(result, query, query_type)

        # Build relation graph
        self._build_relations(result)

        # ── ML Engine Integration ──────────────────────────────────────────────
        self._run_ml_analysis(result)

        # Calculate risk
        self._calc_risk(result)

        return result

    # ── Type Detection ─────────────────────────────────────────────────────────

    def _detect_type(self, query: str) -> str:
        if re.match(r'^[^@]+@[^@]+\.[^@]+$', query):
            return 'email'
        if re.match(r'^\+?\d[\d\s\-]{7,14}$', query):
            return 'phone'
        if re.match(r'^[a-zA-Z0-9_]{3,30}$', query) and ' ' not in query:
            return 'username'
        return 'name'

    # ── Username Generation ────────────────────────────────────────────────────

    def _generate_usernames(self, query: str, query_type: str) -> list:
        usernames = set()

        if query_type == 'email':
            local = query.split('@')[0]
            usernames.add(local)
            usernames.update(self._name_variations(local))

        elif query_type == 'name':
            parts = query.lower().split()
            if len(parts) >= 2:
                first, last = parts[0], parts[-1]
                usernames.update([
                    f"{first}{last}",
                    f"{first}.{last}",
                    f"{first}_{last}",
                    f"{last}{first}",
                    f"{first[0]}{last}",
                    f"{first}{last[0]}",
                    f"{first}",
                    f"{last}",
                ])
            elif parts:
                usernames.update(self._name_variations(parts[0]))

        elif query_type == 'username':
            usernames.add(query.lower())
            usernames.update(self._name_variations(query.lower()))

        elif query_type == 'phone':
            # Phone se username nahi banta, sirf number use karein
            clean = re.sub(r'[^\d]', '', query)
            usernames.add(clean)

        return list(usernames)[:15]  # Max 15 variations

    def _name_variations(self, name: str) -> list:
        name = name.lower().replace(' ', '')
        return [name, f"{name}1", f"{name}2", f"_{name}", f"{name}_"]

    def _extract_bio(self, platform: str, html: str) -> str:
        """Platform-specific bio extraction"""
        bio = ''
        try:
            if platform == 'github':
                # Try multiple patterns
                m = re.search(r'"bio":"([^"]{3,300})"', html)
                if not m:
                    m = re.search(r'class="p-note[^"]*"[^>]*>\s*<div[^>]*>([^<]{5,300})', html)
                if not m:
                    m = re.search(r'<meta[^>]+name="description"[^>]+content="([^"]{5,300})"', html)
                if m:
                    bio = m.group(1).strip()

            elif platform == 'twitter':
                # og:description meta tag
                m = re.search(r'<meta[^>]+property="og:description"[^>]+content="([^"]{5,300})"', html)
                if not m:
                    m = re.search(r'"description":"([^"]{5,300})"', html)
                if m:
                    bio = m.group(1).strip()

            elif platform == 'instagram':
                # JSON data mein biography field
                m = re.search(r'"biography":"([^"]{3,300})"', html)
                if not m:
                    m = re.search(r'"bio":"([^"]{3,300})"', html)
                if m:
                    bio = m.group(1).strip()

            elif platform == 'reddit':
                m = re.search(r'"publicDescription":"([^"]{3,300})"', html)
                if not m:
                    m = re.search(r'"subreddit":\{[^}]*"publicDescription":"([^"]{3,300})"', html)
                if m:
                    bio = m.group(1).strip()

            elif platform == 'pinterest':
                m = re.search(r'"about":"([^"]{3,300})"', html)
                if not m:
                    m = re.search(r'<meta[^>]+name="description"[^>]+content="([^"]{5,300})"', html)
                if m:
                    bio = m.group(1).strip()

            elif platform == 'youtube':
                m = re.search(r'"description":\{"simpleText":"([^"]{5,300})"', html)
                if not m:
                    m = re.search(r'"shortDescription":"([^"]{5,300})"', html)
                if m:
                    bio = m.group(1).strip()

            elif platform == 'tiktok':
                m = re.search(r'"signature":"([^"]{3,300})"', html)
                if not m:
                    m = re.search(r'"desc":"([^"]{3,300})"', html)
                if m:
                    bio = m.group(1).strip()

            elif platform == 'telegram':
                m = re.search(r'class="tgme_page_description"[^>]*>([^<]{3,300})<', html)
                if not m:
                    m = re.search(r'<meta[^>]+property="og:description"[^>]+content="([^"]{3,300})"', html)
                if m:
                    bio = m.group(1).strip()

            elif platform == 'linkedin':
                m = re.search(r'<meta[^>]+name="description"[^>]+content="([^"]{5,300})"', html)
                if m:
                    bio = m.group(1).strip()

            elif platform == 'facebook':
                m = re.search(r'<meta[^>]+name="description"[^>]+content="([^"]{5,300})"', html)
                if not m:
                    m = re.search(r'"biography":"([^"]{3,300})"', html)
                if m:
                    bio = m.group(1).strip()

        except Exception as e:
            logger.debug(f"Bio extraction failed for {platform}: {e}")

        # Clean up — HTML entities, newlines
        if bio:
            bio = re.sub(r'\\n', ' ', bio)
            bio = re.sub(r'\\u[0-9a-fA-F]{4}', '', bio)
            bio = re.sub(r'<[^>]+>', '', bio)
            bio = bio.strip()[:300]

        return bio

    # ── Social Platform Search ─────────────────────────────────────────────────

    def _search_social_platforms(self, result: dict, usernames: list):
        found_profiles = []

        for username in usernames:
            for platform, url_tpl in self.SOCIAL_PLATFORMS.items():
                url = url_tpl.format(username=username)
                markers = self.SOCIAL_MARKERS.get(platform, ['og:title'])

                resp = rate_limited_get(
                    url,
                    namespace='social',
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
                    allow_redirects=True,
                )

                if resp and resp.status_code == 200 and any(m in resp.text for m in markers):

                    # Telegram false positive filter
                    # Default Telegram page = no real user
                    if platform == 'telegram':
                        tg_false = [
                            'Fast. Secure. Powerful.',
                            'Telegram Messenger',
                            'tgme_page_extra',  # empty profile indicator
                        ]
                        # Real profile hona chahiye — tgme_page_title class
                        has_real_profile = 'tgme_page_title' in resp.text
                        is_default_page  = any(fp in resp.text for fp in tg_false) and not has_real_profile
                        if is_default_page:
                            continue

                    # GitHub default page filter
                    if platform == 'github':
                        if 'GitHub is where' in resp.text and 'builds software' in resp.text:
                            # Generic GitHub page — no real bio
                            pass  # still valid, just generic

                    profile = {
                        'platform': platform,
                        'username': username,
                        'url':      url,
                        'status':   'found',
                        'bio':      '',
                    }

                    # Display name
                    name_match = re.search(r'<title>([^<|]+)', resp.text)
                    if name_match:
                        import html as _html
                        profile['display_name'] = _html.unescape(name_match.group(1).strip())

                    # Bio extraction — platform specific
                    bio = self._extract_bio(platform, resp.text)
                    if bio:
                        profile['bio'] = bio

                    found_profiles.append(profile)

                    # Add to entities
                    result['entities'][f"{platform}_{username}"] = {
                        'type': 'social_profile',
                        'platform': platform,
                        'username': username,
                        'url': url,
                    }

                    # Extract emails from page — strict filter
                    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', resp.text)
                    for email in emails:
                        # Image filenames filter karo — @2x, @3x, retina suffixes
                        if re.search(r'@[23]x\.(png|jpg|jpeg|gif|svg|webp)$', email, re.I):
                            continue
                        # Common false positives skip karo
                        if any(fp in email.lower() for fp in [
                            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp',
                            '.css', '.js', '.ico', 'example.com', 'domain.com',
                            'email.com', 'test.com', 'your@', 'user@',
                        ]):
                            continue
                        # Valid TLD check — min 2 chars, max 6
                        tld = email.rsplit('.', 1)[-1]
                        if not (2 <= len(tld) <= 6):
                            continue
                        if email not in result['emails_found']:
                            result['emails_found'].append(email)
                            result['entities'][f"email_{email}"] = {'type': 'email', 'value': email, 'source': platform}

        result['social_profiles'] = found_profiles

    # ── Public Data Sources ────────────────────────────────────────────────────

    def _search_public_sources(self, result: dict, query: str, query_type: str):
        """Search public APIs and data sources"""

        # Pipl-style search via free APIs
        if query_type == 'name':
            self._search_name_apis(result, query)
        elif query_type == 'email':
            self._search_email_apis(result, query)
        elif query_type == 'phone':
            self._search_phone_apis(result, query)

    def _search_name_apis(self, result: dict, name: str):
        """Search name across free public APIs"""

        # Gravatar - email hash se image dhundho
        parts = name.lower().split()
        for variation in [name.lower().replace(' ', ''), name.lower().replace(' ', '.')]:
            for domain in ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']:
                test_email = f"{variation}@{domain}"
                email_hash = hashlib.md5(test_email.lower().encode()).hexdigest()
                gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
                resp = rate_limited_get(gravatar_url, namespace='gravatar')
                if resp and resp.status_code == 200:
                    result['images_found'].append({
                        'source': 'gravatar',
                        'url': gravatar_url,
                        'email_hint': test_email,
                    })
                    result['entities'][f"gravatar_{email_hash[:8]}"] = {
                        'type': 'image',
                        'source': 'gravatar',
                        'email_hint': test_email,
                        'url': gravatar_url,
                    }

    def _search_email_apis(self, result: dict, email: str):
        """Email se linked data dhundho"""

        # Gravatar
        email_hash = hashlib.md5(email.lower().encode()).hexdigest()
        gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
        resp = rate_limited_get(gravatar_url, namespace='gravatar')
        if resp and resp.status_code == 200:
            result['images_found'].append({'source': 'gravatar', 'url': gravatar_url})
            result['entities']['gravatar'] = {'type': 'image', 'source': 'gravatar', 'url': gravatar_url}

        # Gravatar profile
        profile_url = f"https://www.gravatar.com/{email_hash}.json"
        resp2 = rate_limited_get(profile_url, namespace='gravatar')
        if resp2 and resp2.status_code == 200:
            try:
                data = resp2.json()
                entry = data.get('entry', [{}])[0]
                if entry.get('displayName'):
                    result['entities']['gravatar_name'] = {
                        'type': 'name',
                        'value': entry['displayName'],
                        'source': 'gravatar',
                    }
                for url_entry in entry.get('urls', []):
                    result['entities'][f"url_{url_entry.get('value','')}"] = {
                        'type': 'url',
                        'value': url_entry.get('value'),
                        'title': url_entry.get('title'),
                        'source': 'gravatar',
                    }
            except Exception:
                pass

        # HudsonRock stealer logs
        resp3 = rate_limited_get(
            'https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-login',
            namespace='breach',
            params={'username': email},
        )
        if resp3 and resp3.status_code == 200:
            data = resp3.json()
            for stealer in data.get('stealers', []):
                computer = stealer.get('computer_name', '')
                if computer:
                    result['entities'][f"computer_{computer}"] = {
                        'type': 'device',
                        'value': computer,
                        'source': 'stealer_log',
                    }

    def _search_phone_apis(self, result: dict, phone: str):
        """Phone se linked data dhundho"""
        clean = re.sub(r'[^\d+]', '', phone)

        # NumLookup (free, no key)
        resp = rate_limited_get(
            f'https://api.numlookupapi.com/v1/info/{clean}',
            namespace='phone',
        )
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if data.get('country_name'):
                    result['entities']['phone_country'] = {
                        'type': 'location',
                        'value': data['country_name'],
                        'source': 'numlookup',
                    }
                if data.get('carrier'):
                    result['entities']['phone_carrier'] = {
                        'type': 'carrier',
                        'value': data['carrier'],
                        'source': 'numlookup',
                    }
            except Exception:
                pass

    # ── People Search Engines ──────────────────────────────────────────────────

    def _search_people_engines(self, result: dict, query: str, query_type: str):
        """Free people search engines scrape karo"""

        if query_type not in ('name', 'email', 'username'):
            return

        # Spokeo public search (no key needed for basic)
        search_query = query.replace(' ', '+')
        resp = rate_limited_get(
            f'https://www.spokeo.com/search?q={search_query}',
            namespace='people',
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html',
            },
        )
        if resp and resp.status_code == 200:
            # Spokeo ke apne numbers blacklist karo
            SPOKEO_OWN_NUMBERS = {'877-913-3088', '888-271-9562', '888-271-9562'}

            # Extract any addresses/locations mentioned
            addresses = re.findall(
                r'\b([A-Z][a-z]+(?:\s[A-Z][a-z]+)*,\s*[A-Z]{2}\s*\d{5})\b',
                resp.text
            )
            for addr in addresses[:5]:
                if addr not in result['addresses']:
                    result['addresses'].append(addr)
                    result['entities'][f"address_{addr[:20]}"] = {
                        'type': 'address',
                        'value': addr,
                        'source': 'spokeo',
                    }

            # Extract phone numbers — Spokeo ke apne numbers skip karo
            phones = re.findall(r'\(?\d{3}\)?[\s\-]\d{3}[\s\-]\d{4}', resp.text)
            for phone in phones[:10]:
                phone_clean = phone.strip()
                # Spokeo ke apne customer service numbers skip karo
                if phone_clean in SPOKEO_OWN_NUMBERS:
                    continue
                # Toll-free numbers (800, 833, 844, 855, 866, 877, 888) skip karo
                # yeh personal numbers nahi hote
                prefix = re.sub(r'[^\d]', '', phone_clean)[:3]
                if prefix in ('800', '833', '844', '855', '866', '877', '888'):
                    continue
                if phone_clean not in result['phones_found']:
                    result['phones_found'].append(phone_clean)
                    result['entities'][f"phone_{phone_clean}"] = {
                        'type': 'phone',
                        'value': phone_clean,
                        'source': 'spokeo',
                    }

    # ── Relation Graph Builder ─────────────────────────────────────────────────

    def _build_relations(self, result: dict):
        """
        Entities ke beech relations dhundho aur graph edges banao
        Ye ML-style relation mapping hai
        """
        relations = []
        entities = result['entities']
        entity_keys = list(entities.keys())

        # Rule 1: Same username → different platforms = same person
        social_profiles = result['social_profiles']
        usernames_seen = {}
        for profile in social_profiles:
            uname = profile['username']
            if uname not in usernames_seen:
                usernames_seen[uname] = []
            usernames_seen[uname].append(profile['platform'])

        for uname, platforms in usernames_seen.items():
            if len(platforms) > 1:
                for i in range(len(platforms) - 1):
                    relations.append({
                        'from':     f"{platforms[i]}:{uname}",
                        'to':       f"{platforms[i+1]}:{uname}",
                        'relation': 'same_username',
                        'confidence': 0.9,
                        'evidence': f"Username '{uname}' found on both {platforms[i]} and {platforms[i+1]}",
                    })

        # Rule 2: Email → Social profile (username match)
        for email in result['emails_found']:
            local = email.split('@')[0]
            for profile in social_profiles:
                if profile['username'].lower() == local.lower():
                    relations.append({
                        'from':     f"email:{email}",
                        'to':       f"{profile['platform']}:{profile['username']}",
                        'relation': 'email_matches_username',
                        'confidence': 0.85,
                        'evidence': f"Email local part '{local}' matches username on {profile['platform']}",
                    })

        # Rule 3: Gravatar image → email link
        for key, entity in entities.items():
            if entity.get('type') == 'image' and entity.get('email_hint'):
                relations.append({
                    'from':     f"email:{entity['email_hint']}",
                    'to':       f"image:{entity['url']}",
                    'relation': 'gravatar_linked',
                    'confidence': 0.75,
                    'evidence': f"Gravatar profile image linked to {entity['email_hint']}",
                })

        # Rule 4: Address → Phone (same source)
        addresses = [e for e in entities.values() if e.get('type') == 'address']
        phones    = [e for e in entities.values() if e.get('type') == 'phone']
        for addr in addresses:
            for phone in phones:
                if addr.get('source') == phone.get('source'):
                    relations.append({
                        'from':     f"address:{addr['value'][:20]}",
                        'to':       f"phone:{phone['value']}",
                        'relation': 'co_located',
                        'confidence': 0.7,
                        'evidence': f"Both found together on {addr['source']}",
                    })

        # Rule 5: Name entity → all social profiles (query was name)
        if result['query_type'] == 'name':
            for profile in social_profiles:
                relations.append({
                    'from':     f"name:{result['query']}",
                    'to':       f"{profile['platform']}:{profile['username']}",
                    'relation': 'name_to_profile',
                    'confidence': 0.6,
                    'evidence': f"Username variation of '{result['query']}' found on {profile['platform']}",
                })

        result['relations'] = relations

    # ── Risk Calculation ───────────────────────────────────────────────────────

    def _run_ml_analysis(self, result: dict):
        """
        ML Engine se person profile analyze karo:
        1. NLP — bios/posts se traits, topics, personality
        2. FakeDetector — profile genuine hai ya fake/bot
        3. IdentityScorer — multiple profiles same person hain?
        4. UsernameClusterer — username variations cluster karo
        """
        try:
            profiles = result.get('social_profiles', [])

            # 1. NLP Analysis — bios collect karo
            texts, labels = [], []
            for p in profiles:
                bio = p.get('bio', '')
                if bio and len(bio.split()) >= 3:
                    texts.append(bio)
                    labels.append(f"{p['platform']}_{p['username']}")

            if texts:
                from modules.ml_engine.nlp_analyzer import NLPProfileAnalyzer
                nlp = NLPProfileAnalyzer()
                nlp_result = nlp.analyze(texts, labels)
                result['ml_nlp'] = {
                    'risk_level':    nlp_result.get('risk_level', 'LOW'),
                    'professions':   nlp_result.get('professions', [])[:3],
                    'interests':     nlp_result.get('interests', [])[:5],
                    'personality':   nlp_result.get('personality', [])[:3],
                    'languages':     nlp_result.get('languages', {}),
                    'osint_flags':   nlp_result.get('osint_flags', []),
                    'key_topics':    nlp_result.get('key_topics', [])[:8],
                    'writing_style': nlp_result.get('writing_style', {}),
                    'ml_threat':     nlp_result.get('ml_threat', {}),
                }
                # NLP risk level se main risk update karo
                nlp_risk = nlp_result.get('risk_level', 'LOW')
                ml_label = nlp_result.get('ml_threat', {}).get('label', 'LOW')
                # Sirf HIGH/CRITICAL pe flag lagao, LOW/MEDIUM pe nahi
                risk_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
                if risk_order.index(nlp_risk) > risk_order.index(result.get('risk_level', 'LOW')):
                    result['risk_level'] = nlp_risk
                if nlp_risk in ('HIGH', 'CRITICAL'):
                    result['risk_flags'].append({
                        'severity': nlp_risk,
                        'flag': 'ML NLP threat detected',
                        'detail': f"NLP analysis: {nlp_risk} risk | ThreatClassifier: {ml_label}"
                    })

            # 2. FakeDetector — har profile ke liye fake score
            try:
                import joblib, warnings, logging as _logging
                # Training logs suppress karo scan ke dauran
                _logging.getLogger('modules.ml_engine.trainer').setLevel(_logging.ERROR)
                from pathlib import Path
                fake_path = Path(__file__).resolve().parents[2] / 'models' / 'ml_engine' / 'fake_detector.joblib'
                if fake_path.exists():
                    import warnings
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        fake_clf = joblib.load(fake_path)
                    fake_scores = []
                    for p in profiles:
                        bio = p.get('bio', '') or p.get('display_name', '') or p.get('username', '')
                        if bio:
                            proba = fake_clf.predict_proba([bio])[0]
                            fake_prob = round(float(proba[1]) if len(proba) > 1 else float(proba[0]), 3)
                            fake_scores.append({
                                'platform': p['platform'],
                                'username': p['username'],
                                'fake_probability': fake_prob,
                                'is_fake': fake_prob >= 0.5,
                            })
                    result['ml_fake_scores'] = fake_scores
                    avg_fake = sum(s['fake_probability'] for s in fake_scores) / len(fake_scores) if fake_scores else 0
                    result['ml_fake_avg'] = round(avg_fake, 3)
                    if avg_fake >= 0.6:
                        result['risk_flags'].append({
                            'severity': 'HIGH',
                            'flag': 'ML: High fake profile probability',
                            'detail': f"Average fake score: {avg_fake:.0%} across {len(fake_scores)} profiles"
                        })
            except Exception as e:
                logger.debug(f"FakeDetector error: {e}")

            # 3. UsernameClusterer — username variations cluster karo
            usernames = result.get('possible_usernames', [])
            if len(usernames) >= 2:
                from modules.ml_engine.username_clusterer import UsernameClusterer
                clusterer = UsernameClusterer()
                cluster_result = clusterer.cluster(usernames)
                result['ml_username_clusters'] = cluster_result

            # 4. IdentityScorer — cross-platform same person confidence
            if len(profiles) >= 2:
                from modules.ml_engine.entity_matcher import EntityMatcher
                from modules.ml_engine.identity_scorer import IdentityScorer
                matcher = EntityMatcher()
                scorer  = IdentityScorer()
                matches = matcher.match_profiles(profiles)
                identity_score = scorer.score_from_osint_result(result, matches)
                result['ml_identity'] = identity_score
                if identity_score.get('confidence', 0) >= 0.75:
                    result['risk_flags'].append({
                        'severity': 'HIGH',
                        'flag': 'ML: Same person confirmed across platforms',
                        'detail': f"Identity confidence: {identity_score['confidence_pct']}% — {identity_score['label']}"
                    })

        except Exception as e:
            logger.debug(f"ML analysis error: {e}")
            result['ml_error'] = str(e)

    def _calc_risk(self, result: dict):
        flags = result['risk_flags']
        profiles_count = len(result['social_profiles'])
        relations_count = len(result['relations'])

        if profiles_count >= 5:
            flags.append({
                'severity': 'HIGH',
                'flag': 'Large digital footprint',
                'detail': f"Found on {profiles_count} social platforms",
            })
        elif profiles_count >= 2:
            flags.append({
                'severity': 'MEDIUM',
                'flag': 'Multiple social profiles',
                'detail': f"Found on {profiles_count} platforms",
            })

        if result['emails_found']:
            flags.append({
                'severity': 'MEDIUM',
                'flag': 'Email addresses exposed',
                'detail': f"{len(result['emails_found'])} email(s) found in public profiles",
            })

        if result['addresses']:
            flags.append({
                'severity': 'HIGH',
                'flag': 'Physical addresses found',
                'detail': f"{len(result['addresses'])} address(es) in public records",
            })

        if relations_count >= 5:
            flags.append({
                'severity': 'HIGH',
                'flag': 'Strong entity correlation',
                'detail': f"{relations_count} cross-platform relations mapped",
            })

        severities = [f['severity'] for f in flags]
        if 'CRITICAL' in severities:
            result['risk_level'] = 'CRITICAL'
        elif 'HIGH' in severities:
            result['risk_level'] = 'HIGH'
        elif 'MEDIUM' in severities:
            result['risk_level'] = 'MEDIUM'
        else:
            result['risk_level'] = 'LOW'
