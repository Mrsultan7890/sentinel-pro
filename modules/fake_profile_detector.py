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
Fake Profile & Deepfake Detection Module
Hybrid ML + Rule-based detection of fake profiles
"""

import re
import logging
from datetime import datetime
from collections import Counter

logger = logging.getLogger(__name__)

# --- ML Model Loader (lazy, loads once) ---
_ml_classifier = None
_ml_tokenizer  = None
_trained_fake_clf = None  # CRL-trained model


def _load_trained_model():
    """CRL-trained FakeProfileDetector load karo agar available ho."""
    global _trained_fake_clf
    if _trained_fake_clf is not None:
        return True
    try:
        import joblib
        from pathlib import Path
        model_path = __import__('config').get_base_dir() / 'models' / 'ml_engine' / 'fake_detector.joblib'
        if model_path.exists():
            _trained_fake_clf = joblib.load(model_path)
            logger.info("CRL-trained FakeDetector loaded")
            return True
    except Exception as e:
        logger.debug(f"Trained model load failed: {e}")
    return False

def _load_ml_model():
    global _ml_classifier, _ml_tokenizer
    if _ml_classifier is not None:
        return True
    try:
        from transformers import pipeline
        logger.info("Loading ML model (first run may take a moment)...")
        _ml_classifier = pipeline(
            "text-classification",
            model="martin-ha/toxic-comment-model",
            truncation=True,
            max_length=512
        )
        logger.info("ML model loaded successfully.")
        return True
    except Exception as e:
        logger.warning(f"ML model unavailable, using rule-based only: {e}")
        return False


def _ml_score_text(text: str) -> tuple[float, str]:
    """
    Returns (score_0_to_1, label) using ML model.
    score closer to 1.0 = more toxic/fake/spam.
    Falls back to 0.0 if model not available.
    """
    if not text or not text.strip():
        return 0.0, "NEUTRAL"
    if not _load_ml_model():
        return 0.0, "UNAVAILABLE"
    try:
        result = _ml_classifier(text[:512])[0]
        label = result['label'].upper()
        score = result['score']
        # Model labels: TOXIC / NON_TOXIC
        if "TOXIC" in label and "NON" not in label:
            return score, "TOXIC"
        else:
            return 1.0 - score, "CLEAN"
    except Exception as e:
        logger.warning(f"ML inference failed: {e}")
        return 0.0, "ERROR"


class FakeProfileDetector:
    def __init__(self):
        self.suspicious_indicators = []
        self.fake_score = 0

    def analyze_profile(self, collected_data):
        """Hybrid ML + rule-based fake profile analysis"""
        logger.info("Starting fake profile detection analysis...")

        analysis_results = {
            'overall_fake_score': 0,
            'risk_level': 'UNKNOWN',
            'suspicious_indicators': [],
            'ml_analysis': {},
            'profile_consistency': {},
            'behavioral_patterns': {},
            'recommendations': [],
            'timestamp': datetime.now().isoformat()
        }

        social_data = collected_data.get('social_data', [])
        if not social_data:
            return analysis_results

        score = 0
        indicators = []

        # --- Rule-based checks ---
        s, i = self._check_profile_consistency(social_data)
        score += s; indicators.extend(i)

        s, i = self._analyze_profile_images(social_data)
        score += s; indicators.extend(i)

        s, i = self._analyze_activity_patterns(social_data)
        score += s; indicators.extend(i)

        s, i = self._analyze_content_authenticity(social_data)
        score += s; indicators.extend(i)

        s, i = self._analyze_network_patterns(social_data)
        score += s; indicators.extend(i)

        # --- ML-based content analysis ---
        # Priority 1: CRL-trained model (agar available ho)
        if _load_trained_model() and _trained_fake_clf:
            combined_text = ' '.join(
                (p.get('bio_data', {}).get('bio', '') or '') + ' ' +
                ' '.join(
                    post.get('text', post.get('content', '')) or ''
                    for post in p.get('posts_data', {}).get('posts', [])[:5]
                    if isinstance(post, dict)
                )
                for p in social_data
            ).strip()
            if combined_text:
                try:
                    proba = _trained_fake_clf.predict_proba([combined_text])[0]
                    fake_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
                    trained_score = int(fake_prob * 30)  # max 30 points
                    score += trained_score
                    analysis_results['ml_analysis'] = {
                        'status': 'trained_model',
                        'fake_probability': round(fake_prob, 4),
                        'score_added': trained_score,
                    }
                    if trained_score >= 15:
                        indicators.append({
                            'type': 'TRAINED_MODEL_FLAG',
                            'severity': 'HIGH' if trained_score >= 20 else 'MEDIUM',
                            'description': f'CRL-trained model: {fake_prob:.0%} fake probability',
                            'score_impact': trained_score,
                        })
                except Exception as e:
                    logger.debug(f"Trained model inference failed: {e}")
                    ml_score, ml_details = self._ml_analyze_content(social_data)
                    score += ml_score
                    analysis_results['ml_analysis'] = ml_details
            else:
                ml_score, ml_details = self._ml_analyze_content(social_data)
                score += ml_score
                analysis_results['ml_analysis'] = ml_details
        else:
            # Priority 2: HuggingFace toxic classifier fallback
            ml_score, ml_details = self._ml_analyze_content(social_data)
            score += ml_score
            analysis_results['ml_analysis'] = ml_details

        analysis_results['overall_fake_score'] = min(score, 100)
        analysis_results['suspicious_indicators'] = indicators

        if score >= 70:
            analysis_results['risk_level'] = 'CRITICAL - Likely Fake Profile'
        elif score >= 50:
            analysis_results['risk_level'] = 'HIGH - Suspicious Activity'
        elif score >= 30:
            analysis_results['risk_level'] = 'MEDIUM - Some Red Flags'
        else:
            analysis_results['risk_level'] = 'LOW - Appears Authentic'

        analysis_results['recommendations'] = self._generate_recommendations(score, indicators)
        return analysis_results

    # ------------------------------------------------------------------ #
    #  ML Analysis                                                         #
    # ------------------------------------------------------------------ #

    def _ml_analyze_content(self, social_data):
        """
        Run ML model on bios + posts.
        Returns (score_to_add: int, details: dict)
        """
        texts = []
        for profile in social_data:
            bio = profile.get('bio_data', {}).get('bio', '')
            if bio:
                texts.append(('bio', bio))
            for post in profile.get('posts_data', {}).get('posts', []):
                if isinstance(post, dict):
                    text = post.get('text', post.get('content', post.get('caption', '')))
                    if text:
                        texts.append(('post', text))

        if not texts:
            return 0, {'status': 'no_content'}

        toxic_count = 0
        total = len(texts)
        flagged_samples = []

        for source, text in texts:
            ml_score, label = _ml_score_text(text)
            if label == "UNAVAILABLE":
                return 0, {'status': 'model_unavailable'}
            if label == "TOXIC" and ml_score > 0.7:
                toxic_count += 1
                if len(flagged_samples) < 3:
                    flagged_samples.append({
                        'source': source,
                        'confidence': round(ml_score, 3),
                        'snippet': text[:80]
                    })

        toxic_ratio = toxic_count / total if total > 0 else 0
        details = {
            'status': 'completed',
            'texts_analyzed': total,
            'toxic_count': toxic_count,
            'toxic_ratio': round(toxic_ratio, 3),
            'flagged_samples': flagged_samples
        }

        # Score: up to 25 points based on toxic ratio
        added_score = int(toxic_ratio * 25)
        return added_score, details

    # ------------------------------------------------------------------ #
    #  Rule-based checks (unchanged logic, kept intact)                   #
    # ------------------------------------------------------------------ #

    def _check_profile_consistency(self, social_data):
        score = 0
        indicators = []

        names = []
        for profile in social_data:
            name = profile.get('profile_info', {}).get('display_name', '')
            if name:
                names.append(name.lower().strip())

        if len(set(names)) > len(names) * 0.5:
            score += 15
            indicators.append({
                'type': 'INCONSISTENT_NAMES', 'severity': 'HIGH',
                'description': f'Multiple different names across platforms: {set(names)}',
                'score_impact': 15
            })

        creation_dates = [
            p.get('profile_info', {}).get('join_date', '')
            for p in social_data if p.get('profile_info', {}).get('join_date')
        ]
        if len(creation_dates) >= 3:
            score += 10
            indicators.append({
                'type': 'SIMULTANEOUS_CREATION', 'severity': 'MEDIUM',
                'description': 'Multiple profiles created around the same time',
                'score_impact': 10
            })

        missing_bio = sum(1 for p in social_data if not p.get('bio_data', {}).get('bio'))
        if missing_bio > len(social_data) * 0.7:
            score += 10
            indicators.append({
                'type': 'MISSING_BIO_INFO', 'severity': 'MEDIUM',
                'description': f'{missing_bio}/{len(social_data)} profiles have no bio',
                'score_impact': 10
            })

        return score, indicators

    # Known CDNs/patterns used by AI image generators and stock photo sites
    _AI_IMAGE_DOMAINS = (
        'thispersondoesnotexist.com', 'generated.photos', 'ai-generated',
        'midjourney', 'stablediffusion', 'dalle', 'artbreeder',
    )
    _STOCK_DOMAINS = (
        'shutterstock.com', 'gettyimages.com', 'istockphoto.com',
        'dreamstime.com', 'depositphotos.com', 'stock.adobe.com',
    )
    _DEFAULT_IMG_PATTERNS = re.compile(
        r'default[_-]?(avatar|profile|user|photo)|placeholder|no[_-]?photo'
        r'|anonymous|silhouette|blank[_-]?profile',
        re.I
    )

    def _analyze_profile_images(self, social_data):
        score = 0
        indicators = []
        profiles_with_images = 0
        suspicious_images = 0

        for profile in social_data:
            img = profile.get('profile_info', {}).get('profile_image', '') or ''
            if not img:
                continue
            profiles_with_images += 1
            img_lower = img.lower()

            # Check for known AI image generator domains/patterns
            if any(d in img_lower for d in self._AI_IMAGE_DOMAINS):
                suspicious_images += 1
                score += 20
                indicators.append({
                    'type': 'AI_GENERATED_IMAGE', 'severity': 'CRITICAL',
                    'description': f'Profile image from known AI generator: {img}',
                    'score_impact': 20
                })
            # Check for stock photo domains
            elif any(d in img_lower for d in self._STOCK_DOMAINS):
                suspicious_images += 1
                score += 10
                indicators.append({
                    'type': 'STOCK_PHOTO_IMAGE', 'severity': 'HIGH',
                    'description': f'Profile image from stock photo site: {img}',
                    'score_impact': 10
                })
            # Check for default/placeholder image patterns in URL path
            elif self._DEFAULT_IMG_PATTERNS.search(img):
                suspicious_images += 1
                score += 5

        if profiles_with_images == 0 and social_data:
            score += 20
            indicators.append({
                'type': 'NO_PROFILE_IMAGES', 'severity': 'HIGH',
                'description': 'No profile images found across any platform',
                'score_impact': 20
            })

        if suspicious_images > len(social_data) * 0.5:
            score += 10
            indicators.append({
                'type': 'SUSPICIOUS_IMAGES', 'severity': 'HIGH',
                'description': f'{suspicious_images} suspicious profile images detected',
                'score_impact': 10
            })

        return score, indicators

    def _analyze_activity_patterns(self, social_data):
        score = 0
        indicators = []
        suspicious_ratios = 0

        for profile in social_data:
            info = profile.get('profile_info', {})
            followers = self._extract_number(info.get('follower_count', '0'))
            following = self._extract_number(info.get('following_count', '0'))
            if followers > 0 and following > 0:
                ratio = following / max(followers, 1)
                if ratio > 10:
                    suspicious_ratios += 1
                    score += 8
                if followers > 10000:
                    score += 5

        if suspicious_ratios > 0:
            indicators.append({
                'type': 'SUSPICIOUS_FOLLOWER_RATIO', 'severity': 'MEDIUM',
                'description': f'{suspicious_ratios} profiles with suspicious follower/following ratios',
                'score_impact': 8 * suspicious_ratios
            })

        low_activity = sum(
            1 for p in social_data
            if len(p.get('posts_data', {}).get('posts', [])) < 3
        )
        if low_activity > len(social_data) * 0.6:
            score += 12
            indicators.append({
                'type': 'LOW_ACTIVITY', 'severity': 'MEDIUM',
                'description': 'Minimal posting activity across platforms',
                'score_impact': 12
            })

        return score, indicators

    def _analyze_content_authenticity(self, social_data):
        score = 0
        indicators = []
        all_content = []

        for profile in social_data:
            bio = profile.get('bio_data', {}).get('bio', '')
            if bio:
                all_content.append(bio)
            for post in profile.get('posts_data', {}).get('posts', []):
                if isinstance(post, dict):
                    text = post.get('text', post.get('content', post.get('caption', '')))
                    if text:
                        all_content.append(text)

        if not all_content:
            score += 15
            indicators.append({
                'type': 'NO_CONTENT', 'severity': 'HIGH',
                'description': 'No textual content found across profiles',
                'score_impact': 15
            })
            return score, indicators

        spam_keywords = [
            'click here', 'buy now', 'limited offer', 'earn money', 'work from home',
            'bitcoin', 'crypto', 'investment', 'forex', 'casino', 'dating'
        ]
        spam_count = sum(
            1 for c in all_content
            if any(k in c.lower() for k in spam_keywords)
        )
        if spam_count > len(all_content) * 0.3:
            score += 20
            indicators.append({
                'type': 'SPAM_CONTENT', 'severity': 'CRITICAL',
                'description': f'{spam_count}/{len(all_content)} posts contain spam keywords',
                'score_impact': 20
            })

        if len(all_content) > 1:
            unique = len(set(all_content))
            if unique < len(all_content) * 0.5:
                score += 15
                indicators.append({
                    'type': 'REPETITIVE_CONTENT', 'severity': 'HIGH',
                    'description': 'High amount of duplicate/repetitive content',
                    'score_impact': 15
                })

        return score, indicators

    def _analyze_network_patterns(self, social_data):
        score = 0
        indicators = []
        platforms = [p.get('platform', '') for p in social_data]

        if len(platforms) > 15:
            score += 10
            indicators.append({
                'type': 'EXCESSIVE_PLATFORMS', 'severity': 'MEDIUM',
                'description': f'Presence on {len(platforms)} platforms (unusual for genuine users)',
                'score_impact': 10
            })

        verified_count = sum(
            1 for p in social_data
            if p.get('profile_info', {}).get('verified')
        )
        if verified_count == 0 and len(platforms) > 5:
            score += 8
            indicators.append({
                'type': 'NO_VERIFICATION', 'severity': 'MEDIUM',
                'description': 'No verified accounts despite presence on multiple platforms',
                'score_impact': 8
            })

        return score, indicators

    def _generate_recommendations(self, score, indicators):
        recommendations = []

        if score >= 70:
            recommendations += [
                '🚨 IMMEDIATE ACTION: Strong indicators of fake/fraudulent profile',
                '📸 Perform reverse image search on all profile pictures',
                '🔍 Cross-reference with official databases',
                '⚖️ Consider legal action if identity theft suspected',
                '🛡️ Report to platform admins and law enforcement'
            ]
        elif score >= 50:
            recommendations += [
                '⚠️ HIGH SUSPICION: Further investigation strongly recommended',
                '📊 Analyze posting patterns and engagement metrics',
                '🔗 Check connections to known fake profile networks',
                '📞 Attempt direct verification through alternative channels'
            ]
        elif score >= 30:
            recommendations += [
                '⚡ MODERATE CONCERN: Some red flags detected',
                '👁️ Monitor account activity for suspicious changes',
                '✅ Verify identity through trusted sources',
                '📝 Document findings for future reference'
            ]
        else:
            recommendations += [
                '✅ LOW RISK: Profile appears mostly authentic',
                '🔄 Continue periodic monitoring',
                '📋 Maintain records for baseline comparison'
            ]

        types = {ind['type'] for ind in indicators}
        if 'AI_GENERATED_IMAGE' in types:
            recommendations.append('🤖 CRITICAL: AI-generated images detected - likely deepfake')
        if 'SPAM_CONTENT' in types:
            recommendations.append('📧 Spam content detected - possible bot or scam account')
        if 'ML_CONTENT_FLAG' in types:
            recommendations.append('🧠 ML model flagged content as toxic/suspicious')
        if 'NO_PROFILE_IMAGES' in types:
            recommendations.append('📷 No profile images - request video verification')

        return recommendations

    def _extract_number(self, text):
        if not text or not isinstance(text, str):
            return 0
        text = text.replace(',', '').replace(' ', '').upper()
        match = re.search(r'([0-9.]+)([KMB]?)', text)
        if match:
            number = float(match.group(1))
            mult = match.group(2)
            if mult == 'K': return int(number * 1_000)
            if mult == 'M': return int(number * 1_000_000)
            if mult == 'B': return int(number * 1_000_000_000)
            return int(number)
        return 0
