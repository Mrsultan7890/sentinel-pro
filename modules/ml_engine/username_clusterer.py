"""
Username Clusterer - DBSCAN se similar usernames group karo
OSINT Intelligence: Ek hi insaan ke multiple accounts dhundho
"""

import numpy as np
import re
import logging
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)


class UsernameClusterer:
    """
    DBSCAN clustering se similar usernames ko group karta hai.

    Kaise kaam karta hai:
    1. Har username ko feature vector mein convert karo
       - Character n-gram frequencies
       - Length, digit count, separator count
       - Leet speak normalized form
    2. DBSCAN se density-based clustering karo
       - Noise points = unique usernames (kisi cluster mein nahi)
       - Clusters = same person ke different accounts
    3. Har cluster ke liye canonical username nikalo
    """

    def __init__(self, eps: float = None, min_samples: int = 2):
        """
        eps: Maximum distance between two samples to be in same cluster.
             None = auto-estimate from data (recommended).
        min_samples: Minimum usernames to form a cluster
        """
        self.eps = eps
        self.min_samples = min_samples

    def cluster(self, usernames: list) -> dict:
        """
        usernames: list of username strings
        Returns: {
            'clusters': [{'id': 0, 'usernames': [...], 'canonical': '...', 'confidence': 0.9}],
            'noise':    ['unique_user1', ...],
            'total_clusters': N,
        }
        """
        if len(usernames) < 2:
            return {'clusters': [], 'noise': usernames, 'total_clusters': 0}

        # Deduplicate
        unique_usernames = list(dict.fromkeys(u.lower() for u in usernames if u))

        if len(unique_usernames) < 2:
            return {'clusters': [], 'noise': unique_usernames, 'total_clusters': 0}

        # Feature matrix banao
        feature_matrix = self._build_feature_matrix(unique_usernames)

        # DBSCAN
        try:
            scaler = StandardScaler()
            scaled = scaler.fit_transform(feature_matrix)

            # eps auto-estimate: k-distance (k=min_samples) ka 90th percentile
            if self.eps is None:
                from sklearn.neighbors import NearestNeighbors
                k = min(self.min_samples, len(scaled) - 1)
                nbrs = NearestNeighbors(n_neighbors=k).fit(scaled)
                distances, _ = nbrs.kneighbors(scaled)
                eps = float(np.percentile(distances[:, -1], 90))
                eps = max(eps, 0.1)  # minimum floor
            else:
                eps = self.eps

            db = DBSCAN(
                eps=eps,
                min_samples=self.min_samples,
                metric='euclidean',
                n_jobs=1,
            )
            labels = db.fit_predict(scaled)
        except Exception as e:
            logger.warning(f"DBSCAN clustering failed: {e}")
            return self._fallback_cluster(unique_usernames)

        # Results parse karo
        clusters_dict = {}
        noise = []

        for idx, label in enumerate(labels):
            username = unique_usernames[idx]
            if label == -1:
                noise.append(username)
            else:
                if label not in clusters_dict:
                    clusters_dict[label] = []
                clusters_dict[label].append(username)

        # Clusters format karo
        clusters = []
        for cluster_id, members in clusters_dict.items():
            canonical = self._find_canonical(members)
            confidence = self._cluster_confidence(members)
            clusters.append({
                'id':         int(cluster_id),
                'usernames':  members,
                'canonical':  canonical,
                'confidence': confidence,
                'size':       len(members),
                'reason':     self._explain_cluster(members),
            })

        # Sort by size descending
        clusters.sort(key=lambda x: x['size'], reverse=True)

        return {
            'clusters':       clusters,
            'noise':          noise,
            'total_clusters': len(clusters),
            'total_usernames': len(unique_usernames),
        }

    def cluster_cross_platform(self, profiles: list) -> dict:
        """
        Cross-platform profiles ko cluster karo
        profiles: [{'username': '...', 'platform': '...', 'display_name': '...'}]
        """
        if len(profiles) < 2:
            return {'clusters': [], 'noise': profiles}

        # Username list nikalo
        usernames = [p.get('username', '') for p in profiles]
        username_result = self.cluster(usernames)

        # Clusters ko profiles se map karo
        enriched_clusters = []
        for cluster in username_result['clusters']:
            cluster_profiles = [
                p for p in profiles
                if p.get('username', '').lower() in cluster['usernames']
            ]
            platforms = list(set(p.get('platform', '') for p in cluster_profiles))
            enriched_clusters.append({
                **cluster,
                'profiles':  cluster_profiles,
                'platforms': platforms,
                'cross_platform': len(platforms) > 1,
            })

        return {
            'clusters':       enriched_clusters,
            'noise':          username_result['noise'],
            'total_clusters': len(enriched_clusters),
        }

    # ── Feature Engineering ────────────────────────────────────────────────────

    def _build_feature_matrix(self, usernames: list) -> np.ndarray:
        """
        Har username ke liye feature vector banao:
        [length, digit_count, separator_count, uppercase_count,
         leet_score, normalized_length, bigram_hash_1..N]
        """
        features = []
        for username in usernames:
            vec = self._username_to_vector(username)
            features.append(vec)
        return np.array(features, dtype=float)

    def _username_to_vector(self, username: str) -> list:
        """Username → numerical feature vector"""
        u = username.lower()
        norm = self._normalize(u)

        # Basic features
        length          = len(u)
        digit_count     = sum(c.isdigit() for c in u)
        separator_count = u.count('.') + u.count('_') + u.count('-')
        upper_count     = sum(c.isupper() for c in username)  # original case
        leet_score      = self._leet_score(u)
        norm_length     = len(norm)

        # Character frequency features (a-z, 26 features)
        char_freq = [u.count(chr(ord('a') + i)) / max(len(u), 1) for i in range(26)]

        # Bigram presence (top 20 common username bigrams)
        common_bigrams = [
            'jo', 'oh', 'hn', 'an', 'en', 'er', 'in', 'on', 'ar', 'al',
            'le', 'li', 'ic', 'ch', 'ha', 'ma', 'at', 'th', 'he', 'is'
        ]
        bigrams_in_u = set(u[i:i+2] for i in range(len(u)-1))
        bigram_features = [1.0 if bg in bigrams_in_u else 0.0 for bg in common_bigrams]

        return [length, digit_count, separator_count, upper_count,
                leet_score, norm_length] + char_freq + bigram_features

    def _normalize(self, username: str) -> str:
        """Separators aur trailing numbers remove karo"""
        u = re.sub(r'[._\-]', '', username.lower())
        u = re.sub(r'\d+$', '', u)
        leet_map = {'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't'}
        return ''.join(leet_map.get(c, c) for c in u)

    def _leet_score(self, username: str) -> float:
        """Kitna leet speak use ho raha hai (0-1)"""
        leet_chars = set('013457@$')
        count = sum(1 for c in username if c in leet_chars)
        return count / max(len(username), 1)

    # ── Cluster Analysis ───────────────────────────────────────────────────────

    def _find_canonical(self, usernames: list) -> str:
        """
        Cluster ka canonical (most likely real) username dhundho.
        Heuristic: Sabse simple, no numbers, no separators
        """
        scored = []
        for u in usernames:
            score = 0
            # No digits = better
            score += 3 if not any(c.isdigit() for c in u) else 0
            # No separators = better
            score += 2 if '.' not in u and '_' not in u and '-' not in u else 0
            # Shorter = better (but not too short)
            score += max(0, 5 - abs(len(u) - 8))
            # No leet = better
            score += 2 if self._leet_score(u) == 0 else 0
            scored.append((u, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[0][0]

    def _cluster_confidence(self, usernames: list) -> float:
        """
        Cluster ki confidence calculate karo.
        Zyada similar usernames = higher confidence
        """
        if len(usernames) < 2:
            return 0.5

        norms = [self._normalize(u) for u in usernames]

        # Kitne normalized forms same hain
        unique_norms = set(norms)
        if len(unique_norms) == 1:
            return 0.97  # Sab same normalized form = very high confidence

        # Average pairwise similarity
        similarities = []
        for i in range(len(norms)):
            for j in range(i + 1, len(norms)):
                sim = self._jaccard_bigrams(norms[i], norms[j])
                similarities.append(sim)

        avg_sim = np.mean(similarities) if similarities else 0.5
        # Scale: 0.5 similarity → 0.6 confidence, 1.0 similarity → 0.97
        return round(0.4 + (avg_sim * 0.57), 3)

    def _explain_cluster(self, usernames: list) -> str:
        """Cluster kyun bana — human readable explanation"""
        norms = [self._normalize(u) for u in usernames]
        unique_norms = set(norms)

        if len(unique_norms) == 1:
            return f"All normalize to '{list(unique_norms)[0]}' (separators/numbers removed)"

        # Check leet speak
        deleet = [re.sub(r'[013457@$]', lambda m: {'0':'o','1':'i','3':'e','4':'a','5':'s','7':'t','@':'a','$':'s'}.get(m.group(),''), n) for n in norms]
        if len(set(deleet)) == 1:
            return f"Same base after leet-speak normalization: '{deleet[0]}'"

        return f"High character similarity across {len(usernames)} usernames"

    def _jaccard_bigrams(self, a: str, b: str) -> float:
        if not a or not b:
            return 0.0
        bg_a = set(a[i:i+2] for i in range(len(a)-1))
        bg_b = set(b[i:i+2] for i in range(len(b)-1))
        if not bg_a or not bg_b:
            return 1.0 if a == b else 0.0
        return len(bg_a & bg_b) / len(bg_a | bg_b)

    def _fallback_cluster(self, usernames: list) -> dict:
        """DBSCAN fail hone par simple normalization-based clustering"""
        groups = {}
        for u in usernames:
            key = self._normalize(u)
            if key not in groups:
                groups[key] = []
            groups[key].append(u)

        clusters = []
        noise = []
        for key, members in groups.items():
            if len(members) >= self.min_samples:
                clusters.append({
                    'id':         len(clusters),
                    'usernames':  members,
                    'canonical':  self._find_canonical(members),
                    'confidence': 0.85,
                    'size':       len(members),
                    'reason':     f"Same normalized form: '{key}'",
                })
            else:
                noise.extend(members)

        return {
            'clusters':       clusters,
            'noise':          noise,
            'total_clusters': len(clusters),
        }
