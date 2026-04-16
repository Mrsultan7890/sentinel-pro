"""
Entity Matcher - ML-based same person detection
TF-IDF + Cosine Similarity se profiles match karta hai
OSINT Intelligence Grade
"""

import re
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.preprocessing import normalize
import logging

logger = logging.getLogger(__name__)


class EntityMatcher:
    """
    Do entities (profiles, usernames, emails) same person ki hain ya nahi
    ye ML se decide karta hai.

    Approach:
    - Har entity ko ek feature vector mein convert karo
    - TF-IDF se text similarity nikalo
    - Structural features (username patterns, email domains) add karo
    - Cosine similarity se final match score nikalo
    """

    # Thresholds - OSINT grade
    SAME_PERSON_THRESHOLD   = 0.72   # >= ye score = same person (high confidence)
    LIKELY_SAME_THRESHOLD   = 0.50   # >= ye = likely same person
    POSSIBLE_SAME_THRESHOLD = 0.35   # >= ye = possible match

    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            analyzer='char_wb',   # character n-grams — username variations pakad lega
            ngram_range=(2, 4),   # bigrams to 4-grams
            min_df=1,
            max_features=500,
            sublinear_tf=True,
        )
        self._fitted = False

    # ── Public API ─────────────────────────────────────────────────────────────

    def match_profiles(self, profiles: list) -> list:
        """
        profiles: list of dicts with keys: username, platform, display_name, bio, url
        Returns: list of match pairs with confidence scores
        """
        if len(profiles) < 2:
            return []

        # Feature strings banao har profile ke liye
        feature_strings = [self._profile_to_string(p) for p in profiles]

        # TF-IDF vectors — har call pe fresh fit (profiles dynamic hain)
        try:
            vectorizer = TfidfVectorizer(
                analyzer='char_wb',
                ngram_range=(2, 4),
                min_df=1,
                max_features=500,
                sublinear_tf=True,
            )
            tfidf_matrix = vectorizer.fit_transform(feature_strings)
            self._fitted = True
        except Exception as e:
            logger.warning(f"TF-IDF fitting failed: {e}")
            return self._fallback_match(profiles)

        # Cosine similarity matrix
        sim_matrix = cosine_similarity(tfidf_matrix)

        matches = []
        n = len(profiles)
        for i in range(n):
            for j in range(i + 1, n):
                text_sim = float(sim_matrix[i][j])

                # Structural similarity (username patterns, etc.)
                struct_sim = self._structural_similarity(profiles[i], profiles[j])

                # Weighted final score
                # Text similarity 60% + structural 40%
                final_score = (text_sim * 0.60) + (struct_sim * 0.40)

                if final_score >= self.POSSIBLE_SAME_THRESHOLD:
                    label = self._score_to_label(final_score)
                    matches.append({
                        'profile_a':    profiles[i],
                        'profile_b':    profiles[j],
                        'text_sim':     round(text_sim, 4),
                        'struct_sim':   round(struct_sim, 4),
                        'confidence':   round(final_score, 4),
                        'label':        label,
                        'evidence':     self._build_evidence(profiles[i], profiles[j], text_sim, struct_sim),
                    })

        # Sort by confidence descending
        matches.sort(key=lambda x: x['confidence'], reverse=True)
        return matches

    def match_usernames(self, usernames: list) -> list:
        """
        Sirf usernames ko compare karo — same person ke variations dhundho
        e.g. johndoe, john.doe, john_doe, j0hndoe → same person
        """
        if len(usernames) < 2:
            return []

        matches = []
        for i in range(len(usernames)):
            for j in range(i + 1, len(usernames)):
                score = self._username_similarity(usernames[i], usernames[j])
                if score >= self.POSSIBLE_SAME_THRESHOLD:
                    matches.append({
                        'username_a': usernames[i],
                        'username_b': usernames[j],
                        'confidence': round(score, 4),
                        'label':      self._score_to_label(score),
                        'technique':  'username_pattern_analysis',
                    })

        matches.sort(key=lambda x: x['confidence'], reverse=True)
        return matches

    def score_entity_pair(self, entity_a: dict, entity_b: dict) -> dict:
        """
        Do specific entities ka match score nikalo
        entity: {'type': 'email/username/profile', 'value': '...', ...}
        """
        type_a = entity_a.get('type', '')
        type_b = entity_b.get('type', '')

        # Same type comparison
        if type_a == 'email' and type_b == 'email':
            return self._compare_emails(entity_a['value'], entity_b['value'])

        if type_a in ('username', 'social_profile') and type_b in ('username', 'social_profile'):
            uname_a = entity_a.get('username') or entity_a.get('value', '')
            uname_b = entity_b.get('username') or entity_b.get('value', '')
            score = self._username_similarity(uname_a, uname_b)
            return {
                'confidence': round(score, 4),
                'label':      self._score_to_label(score),
                'method':     'username_similarity',
            }

        # Cross-type: email local part vs username
        if type_a == 'email' and type_b in ('username', 'social_profile'):
            local = entity_a['value'].split('@')[0]
            uname = entity_b.get('username') or entity_b.get('value', '')
            score = self._username_similarity(local, uname)
            return {
                'confidence': round(score, 4),
                'label':      self._score_to_label(score),
                'method':     'email_local_vs_username',
            }

        return {'confidence': 0.0, 'label': 'no_match', 'method': 'incompatible_types'}

    # ── Feature Engineering ────────────────────────────────────────────────────

    def _profile_to_string(self, profile: dict) -> str:
        """Profile ko ek rich text string mein convert karo for TF-IDF"""
        parts = []

        # Username — most important, repeat karo weight badhane ke liye
        username = profile.get('username', '')
        if username:
            parts.extend([username] * 3)
            # Normalized version bhi add karo
            parts.append(self._normalize_username(username))

        # Display name
        display = profile.get('display_name', '')
        if display:
            parts.extend([display] * 2)
            parts.append(display.lower().replace(' ', ''))

        # Bio / description
        bio = profile.get('bio', '') or profile.get('description', '')
        if bio:
            parts.append(bio[:200])  # First 200 chars

        # Platform
        platform = profile.get('platform', '')
        if platform:
            parts.append(platform)

        return ' '.join(parts).strip() or 'unknown'

    def _normalize_username(self, username: str) -> str:
        """Username normalize karo — dots, underscores, numbers remove karo"""
        # Lowercase
        u = username.lower()
        # Remove separators
        u = re.sub(r'[._\-]', '', u)
        # Remove trailing numbers (john1 → john)
        u = re.sub(r'\d+$', '', u)
        return u

    def _structural_similarity(self, profile_a: dict, profile_b: dict) -> float:
        """
        Structural features compare karo:
        - Username normalized match
        - Email domain match
        - Same platform (penalize)
        - Display name similarity
        """
        scores = []

        # 1. Normalized username comparison
        uname_a = profile_a.get('username', '')
        uname_b = profile_b.get('username', '')
        if uname_a and uname_b:
            norm_a = self._normalize_username(uname_a)
            norm_b = self._normalize_username(uname_b)
            if norm_a and norm_b:
                # Exact normalized match = 1.0
                if norm_a == norm_b:
                    scores.append(1.0)
                else:
                    # Levenshtein-style ratio
                    scores.append(self._char_overlap(norm_a, norm_b))

        # 2. Display name comparison
        name_a = (profile_a.get('display_name') or '').lower().replace(' ', '')
        name_b = (profile_b.get('display_name') or '').lower().replace(' ', '')
        if name_a and name_b and name_a != 'unknown' and name_b != 'unknown':
            if name_a == name_b:
                scores.append(1.0)
            else:
                scores.append(self._char_overlap(name_a, name_b))

        # 3. Same platform = different accounts, slight penalty
        plat_a = profile_a.get('platform', '')
        plat_b = profile_b.get('platform', '')
        if plat_a and plat_b and plat_a == plat_b:
            scores.append(0.1)  # Same platform = probably different people

        # 4. Email local part vs username
        email_a = profile_a.get('email', '')
        if email_a and uname_b:
            local_a = email_a.split('@')[0]
            if self._normalize_username(local_a) == self._normalize_username(uname_b):
                scores.append(0.95)

        return float(np.mean(scores)) if scores else 0.0

    def _username_similarity(self, uname_a: str, uname_b: str) -> float:
        """
        Username similarity — OSINT-grade
        Handles: john.doe vs johndoe vs john_doe vs j0hndoe
        """
        if not uname_a or not uname_b:
            return 0.0

        a = uname_a.lower()
        b = uname_b.lower()

        # Exact match
        if a == b:
            return 1.0

        # Normalized match (remove separators + trailing numbers)
        norm_a = self._normalize_username(a)
        norm_b = self._normalize_username(b)
        if norm_a == norm_b:
            return 0.95

        # One is prefix of other (john vs johndoe)
        if norm_a.startswith(norm_b) or norm_b.startswith(norm_a):
            shorter = min(len(norm_a), len(norm_b))
            longer  = max(len(norm_a), len(norm_b))
            return 0.7 * (shorter / longer)

        # Leet speak normalization (0→o, 1→i, 3→e, 4→a)
        leet_a = self._deleet(norm_a)
        leet_b = self._deleet(norm_b)
        if leet_a == leet_b:
            return 0.88

        # Character overlap ratio
        overlap = self._char_overlap(norm_a, norm_b)
        return overlap * 0.8  # Scale down for partial matches

    def _compare_emails(self, email_a: str, email_b: str) -> dict:
        """Email comparison"""
        if email_a.lower() == email_b.lower():
            return {'confidence': 1.0, 'label': 'definite_match', 'method': 'exact_email'}

        local_a = email_a.split('@')[0].lower()
        local_b = email_b.split('@')[0].lower()
        domain_a = email_a.split('@')[1].lower() if '@' in email_a else ''
        domain_b = email_b.split('@')[1].lower() if '@' in email_b else ''

        local_score  = self._username_similarity(local_a, local_b)
        domain_score = 1.0 if domain_a == domain_b else 0.0

        # Same local, different domain = likely same person
        score = (local_score * 0.8) + (domain_score * 0.2)
        return {
            'confidence': round(score, 4),
            'label':      self._score_to_label(score),
            'method':     'email_comparison',
        }

    # ── Utility Methods ────────────────────────────────────────────────────────

    def _char_overlap(self, a: str, b: str) -> float:
        """Character-level overlap ratio (Jaccard on bigrams)"""
        if not a or not b:
            return 0.0
        bigrams_a = set(a[i:i+2] for i in range(len(a)-1))
        bigrams_b = set(b[i:i+2] for i in range(len(b)-1))
        if not bigrams_a or not bigrams_b:
            return 1.0 if a == b else 0.0
        intersection = bigrams_a & bigrams_b
        union = bigrams_a | bigrams_b
        return len(intersection) / len(union)

    def _deleet(self, text: str) -> str:
        """Leet speak ko normal text mein convert karo"""
        leet_map = {'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's'}
        return ''.join(leet_map.get(c, c) for c in text)

    def _score_to_label(self, score: float) -> str:
        if score >= self.SAME_PERSON_THRESHOLD:
            return 'same_person'
        elif score >= self.LIKELY_SAME_THRESHOLD:
            return 'likely_same_person'
        elif score >= self.POSSIBLE_SAME_THRESHOLD:
            return 'possible_match'
        return 'no_match'

    def _build_evidence(self, pa: dict, pb: dict, text_sim: float, struct_sim: float) -> str:
        parts = []
        na = self._normalize_username(pa.get('username', ''))
        nb = self._normalize_username(pb.get('username', ''))
        if na == nb:
            parts.append(f"Normalized username match: '{na}'")
        if text_sim > 0.6:
            parts.append(f"High text similarity: {text_sim:.0%}")
        if struct_sim > 0.7:
            parts.append(f"Strong structural match: {struct_sim:.0%}")
        da = (pa.get('display_name') or '').lower()
        db = (pb.get('display_name') or '').lower()
        if da and db and da == db:
            parts.append(f"Same display name: '{da}'")
        return ' | '.join(parts) if parts else f"Similarity score: {(text_sim+struct_sim)/2:.0%}"

    def _fallback_match(self, profiles: list) -> list:
        """TF-IDF fail hone par simple username matching"""
        matches = []
        for i in range(len(profiles)):
            for j in range(i + 1, len(profiles)):
                score = self._structural_similarity(profiles[i], profiles[j])
                if score >= self.POSSIBLE_SAME_THRESHOLD:
                    matches.append({
                        'profile_a':  profiles[i],
                        'profile_b':  profiles[j],
                        'confidence': round(score, 4),
                        'label':      self._score_to_label(score),
                        'evidence':   'fallback structural match',
                    })
        return matches
