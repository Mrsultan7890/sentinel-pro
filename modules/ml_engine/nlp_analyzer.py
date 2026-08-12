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
NLP Profile Analyzer - OSINT Intelligence Grade
Bio/post text se person traits, topics, locations, organizations extract karta hai
NLTK + sklearn use karta hai — no API key needed
"""

import re
import logging
import numpy as np
from collections import Counter, defaultdict
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

import nltk
from nltk.tokenize import word_tokenize, sent_tokenize
from nltk.corpus import stopwords
from nltk.tag import pos_tag
from nltk.chunk import ne_chunk
from nltk.tree import Tree

# spaCy — better NER (optional, falls back to NLTK if not installed)
try:
    import spacy
    _nlp = spacy.load('en_core_web_sm')
    _SPACY_AVAILABLE = True
except (ImportError, OSError):
    _nlp = None
    _SPACY_AVAILABLE = False

# langdetect — 55 language detection (optional)
try:
    from langdetect import detect as _langdetect
    from langdetect import LangDetectException
    _LANGDETECT_AVAILABLE = True
except ImportError:
    _LANGDETECT_AVAILABLE = False

logger = logging.getLogger(__name__)

# ML models cache — SentinelThreatNet (primary) + TF-IDF (fallback)
import threading
_neural_trainer_cache = None
_threat_clf_cache     = None
_model_lock           = threading.Lock()

def _load_neural_model():
    """SentinelThreatNet load karo — primary intelligence model"""
    global _neural_trainer_cache
    if _neural_trainer_cache is not None:
        return _neural_trainer_cache
    with _model_lock:
        if _neural_trainer_cache is not None:
            return _neural_trainer_cache
        try:
            from modules.ml_engine.sentinel_octopus import SentinelOctopus
            nt = SentinelOctopus()
            if nt.load():
                _neural_trainer_cache = nt
                logger.info("SentinelOctopus loaded as primary intelligence model")
                return _neural_trainer_cache
        except Exception as e:
            logger.debug(f"SentinelThreatNet load failed: {e}")
    return None

def _load_threat_clf():
    """TF-IDF ThreatClassifier load karo — fallback model"""
    global _threat_clf_cache
    if _threat_clf_cache is not None:
        return _threat_clf_cache
    with _model_lock:
        if _threat_clf_cache is not None:
            return _threat_clf_cache
        try:
            import joblib, warnings
            from pathlib import Path
            path = __import__('config').get_base_dir() / 'models' / 'ml_engine' / 'threat_classifier.joblib'
            if path.exists():
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    _threat_clf_cache = joblib.load(path)
                logger.info("TF-IDF ThreatClassifier loaded as fallback model")
                return _threat_clf_cache
        except Exception as e:
            logger.debug(f"ThreatClassifier load failed: {e}")
    return None

# ── OSINT Intelligence Dictionaries ───────────────────────────────────────────

PROFESSION_KEYWORDS = {
    'developer':   ['developer', 'engineer', 'programmer', 'coder', 'dev', 'software', 'backend', 'frontend', 'fullstack', 'devops', 'sre', 'architect'],
    'security':    ['hacker', 'pentester', 'security', 'infosec', 'ctf', 'bugbounty', 'researcher', 'malware', 'forensics', 'osint', 'redteam', 'blueteam'],
    'designer':    ['designer', 'ui', 'ux', 'graphic', 'creative', 'artist', 'illustrator', 'photoshop', 'figma'],
    'student':     ['student', 'studying', 'university', 'college', 'school', 'grad', 'undergraduate', 'phd', 'msc', 'bsc'],
    'entrepreneur':['founder', 'ceo', 'cto', 'startup', 'entrepreneur', 'co-founder', 'business', 'venture'],
    'content':     ['blogger', 'youtuber', 'streamer', 'influencer', 'content', 'creator', 'writer', 'journalist'],
    'finance':     ['trader', 'investor', 'crypto', 'bitcoin', 'stocks', 'finance', 'analyst', 'banking'],
    'medical':     ['doctor', 'nurse', 'medical', 'health', 'physician', 'surgeon', 'dentist', 'pharmacist'],
    'legal':       ['lawyer', 'attorney', 'legal', 'law', 'advocate', 'counsel', 'judge', 'paralegal'],
    'military':    ['army', 'navy', 'military', 'veteran', 'soldier', 'officer', 'defense', 'airforce'],
}

INTEREST_KEYWORDS = {
    'gaming':      ['gaming', 'gamer', 'esports', 'twitch', 'steam', 'xbox', 'playstation', 'minecraft', 'fortnite'],
    'tech':        ['tech', 'ai', 'ml', 'blockchain', 'cloud', 'linux', 'open source', 'github', 'python', 'rust'],
    'sports':      ['football', 'cricket', 'basketball', 'soccer', 'tennis', 'gym', 'fitness', 'running', 'cycling'],
    'music':       ['music', 'guitar', 'piano', 'dj', 'producer', 'rap', 'hip-hop', 'rock', 'metal', 'jazz'],
    'travel':      ['travel', 'wanderlust', 'backpacker', 'explorer', 'adventure', 'nomad', 'tourist'],
    'food':        ['foodie', 'chef', 'cooking', 'baking', 'restaurant', 'cuisine', 'vegan', 'vegetarian'],
    'politics':    ['politics', 'activist', 'liberal', 'conservative', 'democrat', 'republican', 'socialist', 'freedom'],
    'religion':    ['muslim', 'christian', 'hindu', 'jewish', 'buddhist', 'atheist', 'spiritual', 'faith', 'god', 'allah'],
    'crypto':      ['bitcoin', 'ethereum', 'nft', 'defi', 'web3', 'crypto', 'hodl', 'blockchain', 'altcoin'],
    'hacking':     ['hacking', 'exploit', 'vulnerability', 'ctf', 'pwn', 'reverse', 'malware', 'rat', 'payload'],
}

PERSONALITY_MARKERS = {
    'aggressive':  ['hate', 'kill', 'destroy', 'fight', 'war', 'attack', 'revenge', 'enemy', 'threat'],
    'narcissistic':['i am the best', 'nobody', 'everyone knows me', 'famous', 'legend', 'goat', 'king', 'queen'],
    'paranoid':    ['they', 'watching', 'surveillance', 'tracked', 'monitored', 'spy', 'government', 'conspiracy'],
    'depressed':   ['alone', 'nobody cares', 'worthless', 'hopeless', 'sad', 'depressed', 'anxiety', 'suicidal'],
    'activist':    ['justice', 'rights', 'freedom', 'protest', 'resist', 'revolution', 'equality', 'movement'],
    'humorous':    ['lol', 'lmao', 'haha', 'joke', 'meme', 'funny', 'humor', 'sarcasm', 'irony'],
}

LOCATION_PATTERNS = [
    r'\b([A-Z][a-z]+(?:\s[A-Z][a-z]+)*),\s*([A-Z]{2,3})\b',           # City, State/Country
    r'\b(based in|from|located in|living in|lives in)\s+([A-Z][a-z]+(?:\s[A-Z][a-z]+)*)\b',
    r'\b([A-Z][a-z]+(?:\s[A-Z][a-z]+)*)\s*\|\s*([A-Z][a-z]+)\b',      # City | Country format
]

CONTACT_PATTERNS = {
    'email':   r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    'phone':   r'(?:\+\d{1,3}[\s-])?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}',
    'discord': r'[a-zA-Z0-9_]{2,32}#\d{4}',
    'telegram':r'@[a-zA-Z][a-zA-Z0-9_]{4,31}',
    'website': r'https?://[^\s<>"{}|\\^`\[\]]+',
}


class NLPProfileAnalyzer:
    """
    Bio/post text se OSINT intelligence extract karta hai.

    Kya karta hai:
    1. Named Entity Recognition (NER) — names, orgs, locations
    2. Profession detection — kya kaam karta hai
    3. Interest profiling — kya pasand hai
    4. Personality markers — psychological traits
    5. Writing style fingerprint — unique writing pattern
    6. Contact info extraction — hidden emails, phones, handles
    7. Language detection — kaunsi language use karta hai
    8. Activity timeline — kab active rehta hai
    """

    def __init__(self):
        try:
            self._stop_words = set(stopwords.words('english'))
        except Exception:
            self._stop_words = set()

    # ── Main Entry Point ───────────────────────────────────────────────────────

    def analyze(self, texts: list, source_labels: list = None) -> dict:
        """
        texts: list of strings (bio, posts, comments)
        source_labels: list of source names (optional)
        Returns: complete NLP analysis dict
        """
        if not texts:
            return self._empty_result()

        if source_labels is None:
            source_labels = [f"source_{i}" for i in range(len(texts))]

        combined_text = ' '.join(t for t in texts if t)

        result = {
            'total_texts':        len(texts),
            'total_chars':        len(combined_text),
            'named_entities':     self._extract_named_entities(combined_text),
            'professions':        self._detect_professions(combined_text),
            'interests':          self._detect_interests(combined_text),
            'personality':        self._detect_personality(combined_text),
            'writing_style':      self._analyze_writing_style(texts),
            'contact_info':       self._extract_contact_info(combined_text),
            'locations_mentioned':self._extract_locations(combined_text),
            'languages':          self._detect_language_hints(combined_text),
            'key_topics':         self._extract_key_topics(texts),
            'cross_text_similarity': self._cross_text_similarity(texts) if len(texts) > 1 else {},
            'osint_flags':        [],
            'risk_level':         'LOW',
        }

        # OSINT flags generate karo
        result['osint_flags'] = self._generate_osint_flags(result, combined_text)

        # Intelligence layer: SentinelThreatNet (primary) → TF-IDF (fallback)
        ml_threat = None
        if combined_text:
            # 1. SentinelThreatNet — BiLSTM neural model (primary)
            neural = _load_neural_model()
            if neural:
                try:
                    pred = neural.predict(combined_text[:1000])
                    ml_threat = {
                        'label':         pred['label'],
                        'confidence':    pred['confidence'],
                        'probabilities': pred['probabilities'],
                        'source':        'sentinel_threat_net',
                        'model':         'BiLSTM',
                    }
                    logger.debug(f"SentinelThreatNet: {pred['label']} ({pred['confidence']:.0%})")
                except Exception as e:
                    logger.debug(f"SentinelThreatNet inference failed: {e}")

            # 2. TF-IDF fallback agar neural fail hua
            if not ml_threat:
                clf = _load_threat_clf()
                if clf:
                    try:
                        pipeline, le = clf
                        proba    = pipeline.predict_proba([combined_text])[0]
                        pred_idx = proba.argmax()
                        ml_label = le.inverse_transform([pred_idx])[0]
                        ml_conf  = round(float(proba[pred_idx]), 4)
                        ml_threat = {
                            'label':         ml_label,
                            'confidence':    ml_conf,
                            'probabilities': {c: round(float(p), 4) for c, p in zip(le.classes_, proba)},
                            'source':        'tfidf_classifier',
                            'model':         'TF-IDF+LR',
                        }
                    except Exception as e:
                        logger.debug(f"ThreatClassifier inference failed: {e}")

        if ml_threat:
            result['ml_threat'] = ml_threat
            # High confidence pe risk override karo
            if ml_threat['confidence'] >= 0.65 and ml_threat['label'] in ('HIGH', 'CRITICAL'):
                result['risk_level'] = ml_threat['label']
            else:
                result['risk_level'] = self._calc_risk(result)
        else:
            result['risk_level'] = self._calc_risk(result)

        return result

    def analyze_single(self, text: str, source: str = 'unknown') -> dict:
        """Single text analyze karo"""
        return self.analyze([text], [source])

    # ── Named Entity Recognition ───────────────────────────────────────────────

    def _extract_named_entities(self, text: str) -> dict:
        """NER — spaCy if available (90% accuracy), else NLTK fallback (60%)"""
        entities = {'persons': [], 'organizations': [], 'locations': [], 'other': []}

        # spaCy path — much better accuracy
        if _SPACY_AVAILABLE and _nlp:
            try:
                if len(text) > 5000:
                    logger.debug(f"NER: text truncated from {len(text)} to 5000 chars")
                doc = _nlp(text[:5000])
                for ent in doc.ents:
                    name = ent.text.strip()
                    if ent.label_ == 'PERSON' and name not in entities['persons']:
                        entities['persons'].append(name)
                    elif ent.label_ == 'ORG' and name not in entities['organizations']:
                        entities['organizations'].append(name)
                    elif ent.label_ in ('GPE', 'LOC') and name not in entities['locations']:
                        entities['locations'].append(name)
                    elif name not in entities['other']:
                        entities['other'].append(name)
                for key in entities:
                    entities[key] = entities[key][:10]
                return entities
            except Exception as e:
                logger.debug(f"spaCy NER failed, falling back to NLTK: {e}")

        # NLTK fallback
        try:
            tokens  = word_tokenize(text[:5000])
            tagged  = pos_tag(tokens)
            chunked = ne_chunk(tagged, binary=False)
            for subtree in chunked:
                if isinstance(subtree, Tree):
                    entity_text = ' '.join(word for word, tag in subtree.leaves())
                    entity_type = subtree.label()
                    if entity_type == 'PERSON' and entity_text not in entities['persons']:
                        entities['persons'].append(entity_text)
                    elif entity_type == 'ORGANIZATION' and entity_text not in entities['organizations']:
                        entities['organizations'].append(entity_text)
                    elif entity_type in ('GPE', 'LOCATION') and entity_text not in entities['locations']:
                        entities['locations'].append(entity_text)
                    elif entity_text not in entities['other']:
                        entities['other'].append(entity_text)
        except Exception as e:
            logger.debug(f"NER failed: {e}")

        for key in entities:
            entities[key] = entities[key][:10]
        return entities

    # ── Profession Detection ───────────────────────────────────────────────────

    def _detect_professions(self, text: str) -> list:
        """Text se profession/job detect karo"""
        text_lower = text.lower()
        detected = []

        for profession, keywords in PROFESSION_KEYWORDS.items():
            matches = [kw for kw in keywords if kw in text_lower]
            if matches:
                score = len(matches) / len(keywords)
                detected.append({
                    'profession': profession,
                    'confidence': round(min(score * 3, 1.0), 3),
                    'keywords_found': matches[:5],
                })

        detected.sort(key=lambda x: x['confidence'], reverse=True)
        return detected[:5]

    # ── Interest Profiling ─────────────────────────────────────────────────────

    def _detect_interests(self, text: str) -> list:
        """Text se interests/hobbies detect karo"""
        text_lower = text.lower()
        detected = []

        for interest, keywords in INTEREST_KEYWORDS.items():
            matches = [kw for kw in keywords if kw in text_lower]
            if matches:
                score = len(matches) / len(keywords)
                detected.append({
                    'interest':       interest,
                    'confidence':     round(min(score * 4, 1.0), 3),
                    'keywords_found': matches[:5],
                })

        detected.sort(key=lambda x: x['confidence'], reverse=True)
        return detected[:8]

    # ── Personality Analysis ───────────────────────────────────────────────────

    def _detect_personality(self, text: str) -> list:
        """Psychological personality markers detect karo — context-aware"""
        text_lower = text.lower()
        detected = []

        # Negation words — agar yeh hain toh keyword ignore karo
        NEGATIONS = {'not', "don't", "doesn't", "didn't", "never", "no", "without", 'against'}

        for trait, keywords in PERSONALITY_MARKERS.items():
            matched_keywords = []
            for kw in keywords:
                idx = text_lower.find(kw)
                while idx != -1:
                    # 4-word window before keyword check karo for negation
                    window_start = max(0, idx - 40)
                    window = text_lower[window_start:idx]
                    window_words = set(window.split())
                    if not window_words.intersection(NEGATIONS):
                        matched_keywords.append(kw)
                        break
                    idx = text_lower.find(kw, idx + 1)

            if matched_keywords:
                score = len(matched_keywords) / len(keywords)
                detected.append({
                    'trait':          trait,
                    'confidence':     round(min(score * 5, 1.0), 3),
                    'keywords_found': matched_keywords[:3],
                })

        detected.sort(key=lambda x: x['confidence'], reverse=True)
        return detected[:5]

    # ── Writing Style Fingerprint ──────────────────────────────────────────────

    def _analyze_writing_style(self, texts: list) -> dict:
        """
        Writing style fingerprint banao — OSINT mein ye bahut useful hai
        kyunki ek hi insaan ka writing style consistent rehta hai
        """
        if not texts:
            return {}

        combined = ' '.join(t for t in texts if t)
        words    = combined.lower().split()
        try:
            sentences = sent_tokenize(combined) if combined else []
        except LookupError:
            sentences = [s.strip() for s in combined.split('.') if s.strip()]

        # Basic stats
        total_words     = len(words)
        unique_words    = len(set(words))
        avg_word_len    = np.mean([len(w) for w in words]) if words else 0
        avg_sent_len    = np.mean([len(s.split()) for s in sentences]) if sentences else 0

        # Vocabulary richness (Type-Token Ratio)
        ttr = unique_words / total_words if total_words > 0 else 0

        # Punctuation patterns
        exclamation_rate = combined.count('!') / max(len(sentences), 1)
        question_rate    = combined.count('?') / max(len(sentences), 1)
        ellipsis_rate    = combined.count('...') / max(len(sentences), 1)
        caps_words       = len(re.findall(r'\b[A-Z]{2,}\b', combined))

        # Emoji usage
        emoji_pattern = re.compile(
            "[\U00010000-\U0010ffff"
            "\U0001F600-\U0001F64F"
            "\U0001F300-\U0001F5FF"
            "\U0001F680-\U0001F6FF"
            "\U0001F1E0-\U0001F1FF]+",
            flags=re.UNICODE
        )
        emojis_found = emoji_pattern.findall(combined)
        emoji_rate   = len(emojis_found) / max(total_words, 1)

        # Common filler words (indicates casual vs formal)
        filler_words  = ['like', 'just', 'basically', 'literally', 'actually', 'honestly', 'tbh', 'ngl', 'imo']
        filler_count  = sum(words.count(fw) for fw in filler_words)
        formality_score = max(0, 1.0 - (filler_count / max(total_words, 1)) * 20)

        # Hashtag / mention usage
        hashtag_count = len(re.findall(r'#\w+', combined))
        mention_count = len(re.findall(r'@\w+', combined))

        # Unique signature words (words used frequently, not stopwords)
        filtered_words = [w for w in words if w not in self._stop_words and len(w) > 3]
        word_freq      = Counter(filtered_words)
        signature_words = [w for w, c in word_freq.most_common(10) if c >= 2]

        return {
            'total_words':       total_words,
            'unique_words':      unique_words,
            'vocabulary_richness': round(ttr, 3),
            'avg_word_length':   round(float(avg_word_len), 2),
            'avg_sentence_length': round(float(avg_sent_len), 2),
            'exclamation_rate':  round(exclamation_rate, 3),
            'question_rate':     round(question_rate, 3),
            'ellipsis_rate':     round(ellipsis_rate, 3),
            'caps_words':        caps_words,
            'emoji_rate':        round(emoji_rate, 4),
            'emojis_used':       list(set(emojis_found))[:10],
            'hashtag_count':     hashtag_count,
            'mention_count':     mention_count,
            'formality_score':   round(formality_score, 3),
            'signature_words':   signature_words,
            'style_label':       self._style_label(formality_score, ttr, avg_sent_len),
        }

    def _style_label(self, formality: float, ttr: float, avg_sent: float) -> str:
        if formality > 0.8 and avg_sent > 15:
            return 'formal_professional'
        elif formality > 0.6 and ttr > 0.6:
            return 'educated_casual'
        elif formality < 0.3:
            return 'very_casual_slang'
        elif avg_sent < 8:
            return 'short_punchy'
        else:
            return 'mixed_casual'

    # ── Contact Info Extraction ────────────────────────────────────────────────

    def _extract_contact_info(self, text: str) -> dict:
        """Hidden contact info extract karo"""
        found = {}
        for contact_type, pattern in CONTACT_PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            # Filter out common false positives
            if contact_type == 'email':
                matches = [m for m in matches if not any(
                    fp in m.lower() for fp in ['example.com', 'test.com', 'domain.com', 'email.com']
                )]
            if matches:
                found[contact_type] = list(set(matches))[:5]
        return found

    # ── Location Extraction ────────────────────────────────────────────────────

    def _extract_locations(self, text: str) -> list:
        """Text se locations extract karo"""
        # Known false positives — app taglines, common words jo location nahi hain
        FALSE_POSITIVE_LOCATIONS = {
            'Fast', 'Secure', 'Powerful', 'Free', 'Safe', 'Simple', 'Easy',
            'Smart', 'Quick', 'Best', 'New', 'Pro', 'Plus', 'Max', 'Ultra',
            'Premium', 'Basic', 'Standard', 'Advanced', 'Private', 'Public',
            'Open', 'Close', 'Dark', 'Light', 'Black', 'White', 'Red', 'Blue',
            'Green', 'Gold', 'Silver', 'Beta', 'Alpha', 'Live', 'Demo',
        }

        locations = []

        for pattern in LOCATION_PATTERNS:
            matches = re.findall(pattern, text)
            for match in matches:
                loc = ' '.join(m for m in match if m).strip()
                # False positive filter
                if loc and loc not in locations and loc not in FALSE_POSITIVE_LOCATIONS:
                    # Min 4 chars, not a single common word
                    if len(loc) >= 4 and not all(w in FALSE_POSITIVE_LOCATIONS for w in loc.split()):
                        locations.append(loc)

        # NER se bhi locations
        try:
            tokens  = word_tokenize(text[:3000])
            tagged  = pos_tag(tokens)
            chunked = ne_chunk(tagged, binary=False)
            for subtree in chunked:
                if isinstance(subtree, Tree) and subtree.label() in ('GPE', 'LOCATION'):
                    loc = ' '.join(w for w, t in subtree.leaves())
                    if loc not in locations and loc not in FALSE_POSITIVE_LOCATIONS and len(loc) >= 4:
                        locations.append(loc)
        except Exception:
            pass

        return locations[:10]

    # ── Language Detection ─────────────────────────────────────────────────────

    def _detect_language_hints(self, text: str) -> dict:
        """Language detection — langdetect if available (55 langs), else script-based fallback"""
        hints = {'scripts': [], 'likely_language': 'english', 'confidence': 0.0}

        # langdetect path — much more accurate
        if _LANGDETECT_AVAILABLE and len(text.split()) >= 5:
            try:
                lang_code = _langdetect(text)
                lang_map = {
                    'en': 'english', 'ar': 'arabic', 'ur': 'urdu', 'hi': 'hindi',
                    'zh-cn': 'chinese', 'zh-tw': 'chinese', 'ja': 'japanese',
                    'ko': 'korean', 'ru': 'russian', 'de': 'german', 'fr': 'french',
                    'es': 'spanish', 'pt': 'portuguese', 'it': 'italian',
                    'tr': 'turkish', 'fa': 'persian', 'bn': 'bengali',
                    'pa': 'punjabi', 'vi': 'vietnamese', 'th': 'thai',
                }
                hints['likely_language'] = lang_map.get(lang_code, lang_code)
                hints['lang_code']       = lang_code
                hints['confidence']      = 0.85
                hints['detector']        = 'langdetect'
            except Exception:
                pass

        # Script detection (always run — adds script info regardless)
        if re.search(r'[\u0600-\u06FF]', text):
            hints['scripts'].append('arabic')
            if not hints.get('lang_code'):
                hints['likely_language'] = 'arabic/urdu/persian'
        if re.search(r'[\u0900-\u097F]', text):
            hints['scripts'].append('devanagari')
            if not hints.get('lang_code'):
                hints['likely_language'] = 'hindi/marathi'
        if re.search(r'[\u4E00-\u9FFF]', text):
            hints['scripts'].append('chinese')
        if re.search(r'[\u3040-\u309F\u30A0-\u30FF]', text):
            hints['scripts'].append('japanese')
        if re.search(r'[\uAC00-\uD7AF]', text):
            hints['scripts'].append('korean')
        if re.search(r'[\u0400-\u04FF]', text):
            hints['scripts'].append('cyrillic')

        # Roman Urdu detection (script-based can't catch this)
        urdu_words = ['hai', 'hain', 'mera', 'meri', 'aur', 'nahi', 'kya', 'yeh', 'woh', 'bhi']
        urdu_count = sum(1 for w in urdu_words if f' {w} ' in text.lower())
        if urdu_count >= 3:
            hints['scripts'].append('roman_urdu')
            if not hints.get('lang_code'):
                hints['likely_language'] = 'urdu/hindi (roman script)'

        return hints

    # ── Key Topics (TF-IDF) ────────────────────────────────────────────────────

    def _extract_key_topics(self, texts: list) -> list:
        """TF-IDF se key topics extract karo"""
        valid_texts = [t for t in texts if t and len(t.split()) >= 3]
        if not valid_texts:
            return []

        try:
            vectorizer = TfidfVectorizer(
                max_features=30,
                stop_words='english',
                ngram_range=(1, 2),
                min_df=1,
            )
            matrix = vectorizer.fit_transform(valid_texts)
            feature_names = vectorizer.get_feature_names_out()
            mean_scores   = matrix.mean(axis=0).A1
            top_indices   = mean_scores.argsort()[-15:][::-1]
            return [
                {'topic': feature_names[i], 'score': round(float(mean_scores[i]), 4)}
                for i in top_indices if mean_scores[i] > 0
            ]
        except Exception as e:
            logger.debug(f"TF-IDF topics failed: {e}")
            return []

    # ── Cross-Text Similarity ──────────────────────────────────────────────────

    def _cross_text_similarity(self, texts: list) -> dict:
        """
        Multiple texts ke beech similarity check karo.
        OSINT use: Same person ke alag platforms pe posts kitne similar hain?
        High similarity = same person confirm
        """
        valid = [t for t in texts if t and len(t.split()) >= 5]
        if len(valid) < 2:
            return {}

        try:
            vectorizer = TfidfVectorizer(stop_words='english', max_features=200)
            matrix     = vectorizer.fit_transform(valid)
            sim_matrix = cosine_similarity(matrix)

            # Average similarity (excluding diagonal)
            n = len(valid)
            total_sim = 0.0
            count = 0
            for i in range(n):
                for j in range(i + 1, n):
                    total_sim += sim_matrix[i][j]
                    count += 1

            avg_sim = total_sim / count if count > 0 else 0.0

            return {
                'avg_similarity':    round(float(avg_sim), 4),
                'same_author_likely': avg_sim > 0.3,
                'interpretation':    self._interpret_similarity(avg_sim),
            }
        except Exception as e:
            logger.debug(f"Cross-text similarity failed: {e}")
            return {}

    def _interpret_similarity(self, sim: float) -> str:
        if sim > 0.6:
            return 'Very likely same author — highly consistent writing style'
        elif sim > 0.3:
            return 'Possibly same author — moderate style consistency'
        elif sim > 0.1:
            return 'Weak similarity — may or may not be same person'
        else:
            return 'Low similarity — different writing styles'

    # ── OSINT Flags ────────────────────────────────────────────────────────────

    def _generate_osint_flags(self, result: dict, text: str) -> list:
        flags = []

        # Real names found
        persons = result['named_entities'].get('persons', [])
        if persons:
            flags.append({
                'severity': 'HIGH',
                'flag':     'Real names detected in text',
                'detail':   f"Possible real names: {', '.join(persons[:3])}",
                'type':     'identity_leak',
            })

        # Organizations
        orgs = result['named_entities'].get('organizations', [])
        if orgs:
            flags.append({
                'severity': 'MEDIUM',
                'flag':     'Organizations mentioned',
                'detail':   f"Linked to: {', '.join(orgs[:3])}",
                'type':     'affiliation',
            })

        # Location leak
        locs = result['locations_mentioned']
        if locs:
            flags.append({
                'severity': 'HIGH',
                'flag':     'Location information leaked',
                'detail':   f"Locations found: {', '.join(locs[:3])}",
                'type':     'location_leak',
            })

        # Contact info
        contacts = result['contact_info']
        if contacts.get('email'):
            flags.append({
                'severity': 'HIGH',
                'flag':     'Email address in bio/posts',
                'detail':   f"Emails: {', '.join(contacts['email'][:2])}",
                'type':     'contact_leak',
            })
        if contacts.get('phone'):
            flags.append({
                'severity': 'CRITICAL',
                'flag':     'Phone number in bio/posts',
                'detail':   f"Phones: {', '.join(contacts['phone'][:2])}",
                'type':     'contact_leak',
            })
        if contacts.get('discord'):
            flags.append({
                'severity': 'MEDIUM',
                'flag':     'Discord handle found',
                'detail':   f"Discord: {', '.join(contacts['discord'][:2])}",
                'type':     'contact_leak',
            })

        # Security-related interests
        interests = [i['interest'] for i in result['interests']]
        if 'hacking' in interests:
            flags.append({
                'severity': 'HIGH',
                'flag':     'Hacking/security interest detected',
                'detail':   'Text contains hacking/exploit related keywords',
                'type':     'threat_indicator',
            })
        if 'crypto' in interests:
            flags.append({
                'severity': 'MEDIUM',
                'flag':     'Cryptocurrency interest detected',
                'detail':   'Crypto/blockchain keywords found',
                'type':     'financial_indicator',
            })

        # Personality flags — minimum 2 matched keywords required
        personality_traits = [p['trait'] for p in result['personality']]
        if 'aggressive' in personality_traits:
            agg = next((p for p in result['personality'] if p['trait'] == 'aggressive'), {})
            # Sirf tab flag karo jab 2+ keywords match hoon
            if len(agg.get('keywords_found', [])) >= 2:
                flags.append({
                    'severity': 'HIGH',
                    'flag':     'Aggressive language patterns',
                    'detail':   f"Aggressive keywords found: {', '.join(agg.get('keywords_found', []))}",
                    'type':     'behavioral_indicator',
                })
        if 'paranoid' in personality_traits:
            flags.append({
                'severity': 'MEDIUM',
                'flag':     'Paranoid/conspiracy language',
                'detail':   'Surveillance/conspiracy related language detected',
                'type':     'behavioral_indicator',
            })

        return flags

    def _calc_risk(self, result: dict) -> str:
        severities = [f['severity'] for f in result['osint_flags']]
        if 'CRITICAL' in severities:
            return 'CRITICAL'
        elif 'HIGH' in severities:
            return 'HIGH'
        elif 'MEDIUM' in severities:
            return 'MEDIUM'
        return 'LOW'

    def _empty_result(self) -> dict:
        return {
            'total_texts': 0, 'total_chars': 0,
            'named_entities': {}, 'professions': [], 'interests': [],
            'personality': [], 'writing_style': {}, 'contact_info': {},
            'locations_mentioned': [], 'languages': {}, 'key_topics': [],
            'cross_text_similarity': {}, 'osint_flags': [], 'risk_level': 'LOW',
        }
