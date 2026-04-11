"""
Writing Style Fingerprinter - OSINT Intelligence Grade
Same person ke alag accounts identify karo writing style se
sklearn TF-IDF + Cosine Similarity + Feature Engineering
"""

import re
import numpy as np
import logging
from collections import Counter
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.preprocessing import normalize

logger = logging.getLogger(__name__)

# Authorship attribution thresholds
SAME_AUTHOR_THRESHOLD   = 0.65
LIKELY_SAME_THRESHOLD   = 0.45
POSSIBLE_SAME_THRESHOLD = 0.28


class WritingFingerprinter:
    """
    Multiple text samples se writing fingerprint banata hai.

    Features used:
    1. Character n-gram TF-IDF (most powerful for authorship)
    2. Word n-gram TF-IDF
    3. Stylometric features (punctuation, caps, emoji, sentence length)
    4. Function word frequencies (the, a, is, are — hard to fake)
    5. Vocabulary richness

    OSINT use case:
    - Do alag platforms ke posts same insaan ne likhe hain?
    - Anonymous account aur known account same person hai?
    """

    # Top 50 English function words — very author-specific
    FUNCTION_WORDS = [
        'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'it',
        'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at', 'this',
        'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she', 'or',
        'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their', 'what',
        'so', 'up', 'out', 'if', 'about', 'who', 'get', 'which', 'go', 'me',
    ]

    def __init__(self):
        # Character n-gram vectorizer (2-4 grams) — best for authorship
        self.char_vectorizer = TfidfVectorizer(
            analyzer='char_wb',
            ngram_range=(2, 4),
            max_features=300,
            sublinear_tf=True,
            min_df=1,
        )
        # Word n-gram vectorizer
        self.word_vectorizer = TfidfVectorizer(
            analyzer='word',
            ngram_range=(1, 2),
            max_features=200,
            sublinear_tf=True,
            stop_words=None,  # Keep all words including function words
            min_df=1,
        )

    # ── Main API ───────────────────────────────────────────────────────────────

    def fingerprint(self, text: str) -> dict:
        """Single text ka fingerprint banao"""
        if not text or len(text.split()) < 5:
            return {'error': 'Text too short for fingerprinting'}

        return {
            'stylometric':    self._stylometric_features(text),
            'function_words': self._function_word_profile(text),
            'vocabulary':     self._vocabulary_features(text),
            'punctuation':    self._punctuation_profile(text),
            'text_length':    len(text),
            'word_count':     len(text.split()),
        }

    def compare(self, text_a: str, text_b: str) -> dict:
        """Do texts compare karo — same author hain?"""
        if not text_a or not text_b:
            return {'error': 'Empty text provided'}

        min_words = 10
        if len(text_a.split()) < min_words or len(text_b.split()) < min_words:
            # Short texts ke liye simplified comparison
            return self._short_text_compare(text_a, text_b)

        scores = {}

        # 1. Character n-gram similarity (most reliable)
        char_sim = self._char_ngram_similarity(text_a, text_b)
        scores['char_ngram'] = char_sim

        # 2. Word n-gram similarity
        word_sim = self._word_ngram_similarity(text_a, text_b)
        scores['word_ngram'] = word_sim

        # 3. Function word profile similarity
        fw_sim = self._function_word_similarity(text_a, text_b)
        scores['function_words'] = fw_sim

        # 4. Stylometric similarity
        style_sim = self._stylometric_similarity(text_a, text_b)
        scores['stylometric'] = style_sim

        # 5. Punctuation pattern similarity
        punct_sim = self._punctuation_similarity(text_a, text_b)
        scores['punctuation'] = punct_sim

        # Weighted final score
        # Char n-gram is most reliable for authorship attribution
        weights = {
            'char_ngram':     0.35,
            'word_ngram':     0.25,
            'function_words': 0.20,
            'stylometric':    0.12,
            'punctuation':    0.08,
        }
        final_score = sum(scores[k] * weights[k] for k in weights)

        label = self._score_to_label(final_score)

        return {
            'final_score':    round(final_score, 4),
            'label':          label,
            'component_scores': {k: round(v, 4) for k, v in scores.items()},
            'interpretation': self._interpret(final_score),
            'evidence':       self._build_evidence(text_a, text_b, scores),
        }

    def compare_multiple(self, texts: list, labels: list = None) -> dict:
        """
        Multiple texts compare karo — cross-platform authorship attribution
        texts: list of text strings
        labels: list of source labels (e.g., ['github_bio', 'reddit_post', 'twitter_bio'])
        """
        if len(texts) < 2:
            return {'error': 'Need at least 2 texts'}

        if labels is None:
            labels = [f"text_{i}" for i in range(len(texts))]

        # Filter out empty/short texts
        valid = [(t, l) for t, l in zip(texts, labels) if t and len(t.split()) >= 5]
        if len(valid) < 2:
            return {'error': 'Not enough valid texts (min 10 words each)'}

        valid_texts, valid_labels = zip(*valid)

        # Pairwise comparisons
        comparisons = []
        for i in range(len(valid_texts)):
            for j in range(i + 1, len(valid_texts)):
                result = self.compare(valid_texts[i], valid_texts[j])
                result['source_a'] = valid_labels[i]
                result['source_b'] = valid_labels[j]
                comparisons.append(result)

        # Sort by score
        comparisons.sort(key=lambda x: x.get('final_score', 0), reverse=True)

        # Overall authorship verdict
        same_author_pairs = [c for c in comparisons if c.get('label') == 'same_author']
        likely_pairs      = [c for c in comparisons if c.get('label') == 'likely_same_author']

        avg_score = np.mean([c.get('final_score', 0) for c in comparisons])

        return {
            'comparisons':         comparisons,
            'same_author_pairs':   same_author_pairs,
            'likely_same_pairs':   likely_pairs,
            'avg_similarity':      round(float(avg_score), 4),
            'overall_verdict':     self._overall_verdict(comparisons),
            'strongest_match':     comparisons[0] if comparisons else None,
        }

    # ── Feature Extractors ─────────────────────────────────────────────────────

    def _stylometric_features(self, text: str) -> dict:
        words     = text.split()
        sentences = re.split(r'[.!?]+', text)
        sentences = [s.strip() for s in sentences if s.strip()]

        return {
            'avg_word_len':      round(np.mean([len(w) for w in words]) if words else 0, 2),
            'avg_sent_len':      round(np.mean([len(s.split()) for s in sentences]) if sentences else 0, 2),
            'type_token_ratio':  round(len(set(w.lower() for w in words)) / len(words) if words else 0, 3),
            'long_word_ratio':   round(sum(1 for w in words if len(w) > 6) / len(words) if words else 0, 3),
            'short_word_ratio':  round(sum(1 for w in words if len(w) <= 3) / len(words) if words else 0, 3),
        }

    def _function_word_profile(self, text: str) -> dict:
        """Function word frequencies — very author-specific"""
        words = re.findall(r'\b\w+\b', text.lower())
        total = len(words)
        if total == 0:
            return {}
        return {fw: round(words.count(fw) / total, 5) for fw in self.FUNCTION_WORDS}

    def _vocabulary_features(self, text: str) -> dict:
        words = re.findall(r'\b[a-zA-Z]+\b', text.lower())
        if not words:
            return {}
        word_freq = Counter(words)
        hapax = sum(1 for w, c in word_freq.items() if c == 1)  # Words used only once
        return {
            'vocabulary_size':  len(set(words)),
            'hapax_ratio':      round(hapax / len(set(words)) if set(words) else 0, 3),
            'top_words':        [w for w, _ in word_freq.most_common(10)],
        }

    def _punctuation_profile(self, text: str) -> dict:
        total_chars = len(text) or 1
        return {
            'exclamation': round(text.count('!') / total_chars * 100, 3),
            'question':    round(text.count('?') / total_chars * 100, 3),
            'comma':       round(text.count(',') / total_chars * 100, 3),
            'ellipsis':    round(text.count('...') / total_chars * 100, 3),
            'caps_ratio':  round(sum(1 for c in text if c.isupper()) / total_chars, 3),
            'emoji_count': len(re.findall(r'[\U00010000-\U0010ffff\U0001F600-\U0001F64F]', text)),
        }

    # ── Similarity Calculators ─────────────────────────────────────────────────

    def _char_ngram_similarity(self, text_a: str, text_b: str) -> float:
        try:
            vectorizer = TfidfVectorizer(
                analyzer='char_wb', ngram_range=(2, 4),
                max_features=300, sublinear_tf=True, min_df=1,
            )
            matrix = vectorizer.fit_transform([text_a, text_b])
            return float(cosine_similarity(matrix[0], matrix[1])[0][0])
        except Exception:
            return 0.0

    def _word_ngram_similarity(self, text_a: str, text_b: str) -> float:
        try:
            vectorizer = TfidfVectorizer(
                analyzer='word', ngram_range=(1, 2),
                max_features=200, sublinear_tf=True, min_df=1,
            )
            matrix = vectorizer.fit_transform([text_a, text_b])
            return float(cosine_similarity(matrix[0], matrix[1])[0][0])
        except Exception:
            return 0.0

    def _function_word_similarity(self, text_a: str, text_b: str) -> float:
        """Function word profiles ka cosine similarity"""
        prof_a = self._function_word_profile(text_a)
        prof_b = self._function_word_profile(text_b)
        if not prof_a or not prof_b:
            return 0.0

        vec_a = np.array([prof_a.get(fw, 0) for fw in self.FUNCTION_WORDS])
        vec_b = np.array([prof_b.get(fw, 0) for fw in self.FUNCTION_WORDS])

        norm_a = np.linalg.norm(vec_a)
        norm_b = np.linalg.norm(vec_b)
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return float(np.dot(vec_a, vec_b) / (norm_a * norm_b))

    def _stylometric_similarity(self, text_a: str, text_b: str) -> float:
        feat_a = self._stylometric_features(text_a)
        feat_b = self._stylometric_features(text_b)
        if not feat_a or not feat_b:
            return 0.0

        keys  = list(feat_a.keys())
        vec_a = np.array([feat_a[k] for k in keys])
        vec_b = np.array([feat_b[k] for k in keys])

        # Normalized difference (1 - normalized_distance)
        max_vals = np.maximum(np.abs(vec_a), np.abs(vec_b))
        max_vals[max_vals == 0] = 1
        diffs = np.abs(vec_a - vec_b) / max_vals
        return float(1.0 - np.mean(diffs))

    def _punctuation_similarity(self, text_a: str, text_b: str) -> float:
        prof_a = self._punctuation_profile(text_a)
        prof_b = self._punctuation_profile(text_b)
        if not prof_a or not prof_b:
            return 0.0

        keys  = ['exclamation', 'question', 'comma', 'ellipsis', 'caps_ratio']
        vec_a = np.array([prof_a.get(k, 0) for k in keys])
        vec_b = np.array([prof_b.get(k, 0) for k in keys])

        max_vals = np.maximum(np.abs(vec_a), np.abs(vec_b))
        max_vals[max_vals == 0] = 1
        diffs = np.abs(vec_a - vec_b) / max_vals
        return float(1.0 - np.mean(diffs))

    def _short_text_compare(self, text_a: str, text_b: str) -> dict:
        """Short texts ke liye simplified comparison"""
        char_sim = self._char_ngram_similarity(text_a, text_b)
        punct_sim = self._punctuation_similarity(text_a, text_b)
        score = (char_sim * 0.6) + (punct_sim * 0.4)
        return {
            'final_score':    round(score, 4),
            'label':          self._score_to_label(score),
            'component_scores': {'char_ngram': round(char_sim, 4), 'punctuation': round(punct_sim, 4)},
            'interpretation': self._interpret(score),
            'note':           'Short text — limited accuracy',
        }

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _score_to_label(self, score: float) -> str:
        if score >= SAME_AUTHOR_THRESHOLD:
            return 'same_author'
        elif score >= LIKELY_SAME_THRESHOLD:
            return 'likely_same_author'
        elif score >= POSSIBLE_SAME_THRESHOLD:
            return 'possible_same_author'
        return 'different_author'

    def _interpret(self, score: float) -> str:
        if score >= SAME_AUTHOR_THRESHOLD:
            return f'Strong evidence of same author ({score:.0%} similarity)'
        elif score >= LIKELY_SAME_THRESHOLD:
            return f'Likely same author ({score:.0%} similarity)'
        elif score >= POSSIBLE_SAME_THRESHOLD:
            return f'Possible same author ({score:.0%} similarity) — needs more data'
        return f'Likely different authors ({score:.0%} similarity)'

    def _build_evidence(self, text_a: str, text_b: str, scores: dict) -> list:
        evidence = []
        if scores.get('char_ngram', 0) > 0.5:
            evidence.append(f"Character patterns match: {scores['char_ngram']:.0%}")
        if scores.get('function_words', 0) > 0.6:
            evidence.append(f"Function word usage similar: {scores['function_words']:.0%}")
        if scores.get('stylometric', 0) > 0.7:
            evidence.append(f"Writing style consistent: {scores['stylometric']:.0%}")
        if scores.get('punctuation', 0) > 0.7:
            evidence.append(f"Punctuation patterns match: {scores['punctuation']:.0%}")
        return evidence

    def _overall_verdict(self, comparisons: list) -> str:
        if not comparisons:
            return 'insufficient_data'
        same   = sum(1 for c in comparisons if c.get('label') == 'same_author')
        likely = sum(1 for c in comparisons if c.get('label') == 'likely_same_author')
        total  = len(comparisons)
        if same / total > 0.5:
            return 'SAME_AUTHOR_CONFIRMED'
        elif (same + likely) / total > 0.5:
            return 'LIKELY_SAME_AUTHOR'
        elif (same + likely) / total > 0.2:
            return 'POSSIBLE_SAME_AUTHOR'
        return 'DIFFERENT_AUTHORS'
