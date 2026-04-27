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
ML Engine - OSINT Intelligence Grade Machine Learning
No API key required — runs fully locally

Modules:
- EntityMatcher      : TF-IDF + Cosine Similarity (profile matching)
- UsernameClusterer  : DBSCAN (username grouping)
- IdentityScorer     : Bayesian log-odds (confidence scoring)
- NLPProfileAnalyzer : NLTK NER + profession/interest/personality detection
- TimelineAnalyzer   : KMeans activity clustering + timezone estimation
- WritingFingerprinter: Authorship attribution via stylometrics
"""

from modules.ml_engine.entity_matcher       import EntityMatcher
from modules.ml_engine.username_clusterer    import UsernameClusterer
from modules.ml_engine.identity_scorer       import IdentityScorer
from modules.ml_engine.nlp_analyzer          import NLPProfileAnalyzer
from modules.ml_engine.timeline_analyzer     import TimelineAnalyzer
from modules.ml_engine.writing_fingerprinter import WritingFingerprinter

__all__ = [
    'EntityMatcher',
    'UsernameClusterer',
    'IdentityScorer',
    'NLPProfileAnalyzer',
    'TimelineAnalyzer',
    'WritingFingerprinter',
]
