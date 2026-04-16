"""
Identity Scorer - ML Feature Engineering se Identity Confidence Score
OSINT Intelligence Grade: Kitna sure hain ki ye sab ek hi insaan hai
"""

import numpy as np
import re
import logging
from sklearn.preprocessing import MinMaxScaler

logger = logging.getLogger(__name__)


# ── OSINT Feature Weights (Intelligence Grade) ─────────────────────────────────
# Ye weights real OSINT methodology se liye gaye hain
# Higher weight = stronger evidence of same identity

FEATURE_WEIGHTS = {
    # Strongest evidence
    'exact_username_match':         1.00,
    'exact_email_match':            1.00,
    'normalized_username_match':    0.95,
    'leet_username_match':          0.88,
    'email_local_username_match':   0.85,
    'gravatar_linked':              0.82,
    'same_display_name':            0.80,

    # Strong evidence
    'cross_platform_same_username': 0.78,
    'bio_text_similarity':          0.72,
    'same_profile_image_hash':      0.90,
    'stealer_log_device_match':     0.88,

    # Medium evidence
    'username_prefix_match':        0.60,
    'partial_name_match':           0.55,
    'same_location':                0.50,
    'same_carrier':                 0.45,
    'co_located_address_phone':     0.65,

    # Weak evidence
    'same_writing_style':           0.40,
    'similar_posting_time':         0.35,
    'same_platform_category':       0.25,
}


class IdentityScorer:
    """
    Multiple evidence pieces ko combine karke ek final
    identity confidence score nikalta hai (0-100%).

    Bayesian-inspired approach:
    - Har evidence piece independently score karo
    - Combine karo using log-odds aggregation
    - Final probability mein convert karo
    """

    def score_identity(self, evidence_list: list) -> dict:
        """
        evidence_list: [
            {'type': 'exact_username_match', 'details': '...'},
            {'type': 'cross_platform_same_username', 'details': '...'},
            ...
        ]
        Returns: {
            'confidence': 0.87,        # 0-1
            'confidence_pct': 87.0,    # 0-100
            'label': 'HIGH_CONFIDENCE',
            'evidence_count': 3,
            'strongest_evidence': [...],
            'breakdown': {...},
        }
        """
        if not evidence_list:
            return self._empty_result()

        # Har evidence ka weight nikalo
        weighted_scores = []
        breakdown = {}

        for ev in evidence_list:
            ev_type = ev.get('type', '')
            weight = FEATURE_WEIGHTS.get(ev_type, 0.3)  # Default 0.3 for unknown
            weighted_scores.append(weight)
            breakdown[ev_type] = {
                'weight':  weight,
                'details': ev.get('details', ''),
            }

        # Log-odds aggregation (Bayesian combination)
        # Prior: 0.5 (50% chance same person before any evidence)
        prior_odds = 1.0  # log(0.5/0.5) = 0

        # Har evidence piece ke liye log-odds update karo
        log_odds = 0.0
        for w in weighted_scores:
            # w = P(evidence | same person)
            # Assume P(evidence | different person) = 1 - w
            if w >= 1.0:
                log_odds += 4.0   # Very strong evidence
            elif w <= 0.0:
                log_odds -= 4.0
            else:
                likelihood_ratio = w / (1.0 - w)
                log_odds += np.log(likelihood_ratio)

        # Log-odds → probability (clip karo overflow se bachne ke liye)
        log_odds = np.clip(log_odds, -500.0, 500.0)
        probability = 1.0 / (1.0 + np.exp(-log_odds))

        # Confidence label
        label = self._probability_to_label(probability)

        # Strongest evidence sort karke
        sorted_evidence = sorted(
            evidence_list,
            key=lambda x: FEATURE_WEIGHTS.get(x.get('type', ''), 0),
            reverse=True
        )

        return {
            'confidence':         round(float(probability), 4),
            'confidence_pct':     round(float(probability) * 100, 1),
            'label':              label,
            'evidence_count':     len(evidence_list),
            'strongest_evidence': sorted_evidence[:3],
            'breakdown':          breakdown,
            'log_odds':           round(log_odds, 3),
        }

    def score_from_osint_result(self, person_result: dict, match_results: list = None) -> dict:
        """
        PersonOSINT result se automatically evidence extract karke score karo
        """
        evidence = []

        # Social profiles
        profiles = person_result.get('social_profiles', [])
        if len(profiles) >= 2:
            # Cross-platform same username check
            usernames = [p['username'] for p in profiles]
            username_counts = {}
            for u in usernames:
                username_counts[u] = username_counts.get(u, 0) + 1

            for uname, count in username_counts.items():
                if count >= 2:
                    evidence.append({
                        'type':    'cross_platform_same_username',
                        'details': f"Username '{uname}' found on {count} platforms",
                    })

        # Email matches
        emails = person_result.get('emails_found', [])
        for email in emails:
            local = email.split('@')[0]
            for profile in profiles:
                norm_local = re.sub(r'[._\-\d]', '', local.lower())
                norm_uname = re.sub(r'[._\-\d]', '', profile['username'].lower())
                if norm_local == norm_uname:
                    evidence.append({
                        'type':    'email_local_username_match',
                        'details': f"Email '{email}' local part matches @{profile['username']} on {profile['platform']}",
                    })

        # Gravatar
        images = person_result.get('images_found', [])
        for img in images:
            if img.get('source') == 'gravatar':
                evidence.append({
                    'type':    'gravatar_linked',
                    'details': f"Gravatar profile image found (email hint: {img.get('email_hint', 'N/A')})",
                })

        # Address + phone co-location
        if person_result.get('addresses') and person_result.get('phones_found'):
            evidence.append({
                'type':    'co_located_address_phone',
                'details': f"Address and phone found together in same source",
            })

        # ML match results
        if match_results:
            for match in match_results:
                if match.get('label') == 'same_person':
                    evidence.append({
                        'type':    'normalized_username_match',
                        'details': match.get('evidence', 'ML entity match'),
                    })
                elif match.get('label') == 'likely_same_person':
                    evidence.append({
                        'type':    'username_prefix_match',
                        'details': match.get('evidence', 'ML partial match'),
                    })

        return self.score_identity(evidence)

    def score_relation_edge(self, relation_type: str, context: dict = None) -> float:
        """
        Ek single relation edge ka confidence score nikalo
        Relation mapper ke liye use hota hai
        """
        base_weight = FEATURE_WEIGHTS.get(relation_type, 0.3)

        # Context se adjust karo
        if context:
            # Agar multiple platforms pe same username = boost
            if context.get('platform_count', 1) > 2:
                base_weight = min(base_weight * 1.1, 1.0)

            # Agar email domain common (gmail, yahoo) = slight penalty
            email = context.get('email', '')
            if email and any(d in email for d in ['gmail.com', 'yahoo.com', 'hotmail.com']):
                base_weight = base_weight * 0.95  # Slight penalty, common domains

        return round(base_weight, 4)

    def compare_feature_vectors(self, vec_a: np.ndarray, vec_b: np.ndarray) -> float:
        """
        Do feature vectors ka similarity score nikalo
        Cosine similarity use karta hai
        """
        if vec_a is None or vec_b is None:
            return 0.0
        if vec_a.shape != vec_b.shape:
            return 0.0

        norm_a = np.linalg.norm(vec_a)
        norm_b = np.linalg.norm(vec_b)

        if norm_a == 0 or norm_b == 0:
            return 0.0

        return float(np.dot(vec_a, vec_b) / (norm_a * norm_b))

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _probability_to_label(self, prob: float) -> str:
        if prob >= 0.90:
            return 'DEFINITE_MATCH'
        elif prob >= 0.75:
            return 'HIGH_CONFIDENCE'
        elif prob >= 0.55:
            return 'MEDIUM_CONFIDENCE'
        elif prob >= 0.35:
            return 'LOW_CONFIDENCE'
        else:
            return 'UNLIKELY_MATCH'

    def _empty_result(self) -> dict:
        return {
            'confidence':         0.0,
            'confidence_pct':     0.0,
            'label':              'NO_EVIDENCE',
            'evidence_count':     0,
            'strongest_evidence': [],
            'breakdown':          {},
            'log_odds':           0.0,
        }
