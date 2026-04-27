#!/usr/bin/env python3
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


import re
import json
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Any
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN
from sklearn.metrics.pairwise import cosine_similarity

class SemanticAnalyzer:
    def __init__(self):
        self.hate_keywords = [
            'kill', 'murder', 'bomb', 'attack', 'destroy', 'eliminate', 'target',
            'revenge', 'payback', 'violence', 'threat', 'harm', 'hurt', 'damage'
        ]
        
        self.propaganda_patterns = [
            r'\b(fake news|mainstream media|deep state|conspiracy|cover[- ]?up)\b',
            r'\b(they don\'t want you to know|wake up|sheep|brainwashed)\b',
            r'\b(the truth|real story|hidden agenda|puppet|controlled)\b'
        ]
        
        self.radicalization_indicators = [
            'us vs them', 'enemy', 'traitor', 'pure', 'cleanse', 'holy war',
            'martyr', 'sacrifice', 'brotherhood', 'awakening', 'chosen'
        ]
        
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        
    def analyze_content(self, content: str, source: str = "unknown") -> Dict[str, Any]:
        """Comprehensive semantic analysis of text content"""
        
        analysis = {
            'source': source,
            'content_length': len(content),
            'sentiment_score': self._calculate_sentiment(content),
            'hate_speech_score': self._detect_hate_speech(content),
            'propaganda_score': self._detect_propaganda(content),
            'radicalization_risk': self._assess_radicalization(content),
            'emotional_tone': self._analyze_emotional_tone(content),
            'key_topics': self._extract_topics(content),
            'threat_indicators': self._identify_threats(content),
            'manipulation_tactics': self._detect_manipulation(content),
            'overall_risk': 0
        }
        
        # Calculate overall risk score
        analysis['overall_risk'] = self._calculate_overall_risk(analysis)
        
        return analysis
    
    def _calculate_sentiment(self, text: str) -> float:
        """Calculate sentiment polarity (-1 to 1)"""
        positive_words = ['good', 'great', 'excellent', 'amazing', 'wonderful', 'fantastic', 'love', 'like', 'happy', 'joy']
        negative_words = ['bad', 'terrible', 'awful', 'hate', 'disgusting', 'horrible', 'sad', 'angry', 'fear', 'scared']
        
        words = text.lower().split()
        pos_count = sum(1 for word in words if word in positive_words)
        neg_count = sum(1 for word in words if word in negative_words)
        
        total = pos_count + neg_count
        if total == 0:
            return 0.0
        
        return (pos_count - neg_count) / total
    
    def _detect_hate_speech(self, text: str) -> float:
        """Detect hate speech indicators (0-1 scale)"""
        text_lower = text.lower()
        hate_count = sum(1 for keyword in self.hate_keywords if keyword in text_lower)
        
        # Check for slurs and offensive language patterns
        offensive_patterns = [
            r'\b(kill|murder|die|death)\s+(all|every|those)\b',
            r'\b(should|must|need to)\s+(die|burn|suffer)\b',
            r'\b(eliminate|destroy|remove)\s+(them|those|all)\b'
        ]
        
        pattern_matches = sum(1 for pattern in offensive_patterns if re.search(pattern, text_lower))
        
        total_score = (hate_count + pattern_matches * 2) / max(len(text.split()) / 10, 1)
        return min(total_score, 1.0)
    
    def _detect_propaganda(self, text: str) -> float:
        """Detect propaganda and disinformation patterns"""
        text_lower = text.lower()
        propaganda_score = 0
        
        for pattern in self.propaganda_patterns:
            matches = len(re.findall(pattern, text_lower))
            propaganda_score += matches
        
        # Check for emotional manipulation
        emotional_triggers = ['outraged', 'shocked', 'disgusted', 'furious', 'betrayed', 'exposed']
        emotional_count = sum(1 for trigger in emotional_triggers if trigger in text_lower)
        
        total_score = (propaganda_score + emotional_count) / max(len(text.split()) / 20, 1)
        return min(total_score, 1.0)
    
    def _assess_radicalization(self, text: str) -> float:
        """Assess radicalization risk indicators"""
        text_lower = text.lower()
        radical_count = sum(1 for indicator in self.radicalization_indicators if indicator in text_lower)
        
        # Check for extremist language patterns
        extremist_patterns = [
            r'\b(final solution|race war|holy war|crusade|jihad)\b',
            r'\b(pure|cleanse|purify|eliminate|exterminate)\b',
            r'\b(chosen|superior|master|inferior|subhuman)\b'
        ]
        
        pattern_matches = sum(1 for pattern in extremist_patterns if re.search(pattern, text_lower))
        
        total_score = (radical_count + pattern_matches * 3) / max(len(text.split()) / 15, 1)
        return min(total_score, 1.0)
    
    def _analyze_emotional_tone(self, text: str) -> Dict[str, float]:
        """Analyze emotional tone categories"""
        emotions = {
            'anger': ['angry', 'furious', 'rage', 'mad', 'pissed', 'outraged'],
            'fear': ['scared', 'afraid', 'terrified', 'worried', 'anxious', 'panic'],
            'disgust': ['disgusted', 'sick', 'revolted', 'appalled', 'repulsed'],
            'sadness': ['sad', 'depressed', 'miserable', 'heartbroken', 'devastated'],
            'joy': ['happy', 'excited', 'thrilled', 'delighted', 'ecstatic']
        }
        
        text_lower = text.lower()
        emotion_scores = {}
        
        for emotion, keywords in emotions.items():
            count = sum(1 for keyword in keywords if keyword in text_lower)
            emotion_scores[emotion] = count / max(len(text.split()) / 10, 1)
        
        return emotion_scores
    
    def _extract_topics(self, text: str) -> List[str]:
        """Extract key topics using simple keyword extraction"""
        # Remove common words and extract meaningful terms
        words = re.findall(r'\b[a-zA-Z]{4,}\b', text.lower())
        
        # Filter out common words
        stop_words = {'that', 'this', 'with', 'from', 'they', 'have', 'been', 'were', 'said', 'each', 'which', 'their', 'time', 'will', 'about', 'would', 'there', 'could', 'other', 'more', 'very', 'what', 'know', 'just', 'first', 'into', 'over', 'think', 'also', 'your', 'work', 'life', 'only', 'new', 'years', 'way', 'may', 'say', 'come', 'its', 'now', 'find', 'long', 'down', 'day', 'did', 'get', 'has', 'him', 'his', 'how', 'man', 'old', 'see', 'two', 'who', 'boy', 'did', 'number', 'no', 'way', 'use', 'her', 'many', 'oil', 'sit', 'water', 'but', 'now', 'head', 'far', 'left', 'put', 'end', 'why', 'turn', 'here', 'show', 'every', 'good', 'me', 'give', 'our', 'under', 'name', 'very', 'through', 'just', 'form', 'sentence', 'great', 'think', 'say', 'help', 'low', 'line', 'differ', 'turn', 'cause', 'much', 'mean', 'before', 'move', 'right', 'too', 'any', 'same', 'tell', 'does', 'set', 'three', 'want', 'air', 'well', 'also', 'play', 'small', 'end', 'put', 'home', 'read', 'hand', 'port', 'large', 'spell', 'add', 'even', 'land', 'here', 'must', 'big', 'high', 'such', 'follow', 'act', 'why', 'ask', 'men', 'change', 'went', 'light', 'kind', 'off', 'need', 'house', 'picture', 'try', 'us', 'again', 'animal', 'point', 'mother', 'world', 'near', 'build', 'self', 'earth', 'father', 'head', 'stand', 'own', 'page', 'should', 'country', 'found', 'answer', 'school', 'grow', 'study', 'still', 'learn', 'plant', 'cover', 'food', 'sun', 'four', 'between', 'state', 'keep', 'eye', 'never', 'last', 'let', 'thought', 'city', 'tree', 'cross', 'farm', 'hard', 'start', 'might', 'story', 'saw', 'far', 'sea', 'draw', 'left', 'late', 'run', 'dont', 'while', 'press', 'close', 'night', 'real', 'life', 'few', 'north', 'open', 'seem', 'together', 'next', 'white', 'children', 'begin', 'got', 'walk', 'example', 'ease', 'paper', 'group', 'always', 'music', 'those', 'both', 'mark', 'often', 'letter', 'until', 'mile', 'river', 'car', 'feet', 'care', 'second', 'book', 'carry', 'took', 'science', 'eat', 'room', 'friend', 'began', 'idea', 'fish', 'mountain', 'stop', 'once', 'base', 'hear', 'horse', 'cut', 'sure', 'watch', 'color', 'face', 'wood', 'main', 'enough', 'plain', 'girl', 'usual', 'young', 'ready', 'above', 'ever', 'red', 'list', 'though', 'feel', 'talk', 'bird', 'soon', 'body', 'dog', 'family', 'direct', 'pose', 'leave', 'song', 'measure', 'door', 'product', 'black', 'short', 'numeral', 'class', 'wind', 'question', 'happen', 'complete', 'ship', 'area', 'half', 'rock', 'order', 'fire', 'south', 'problem', 'piece', 'told', 'knew', 'pass', 'since', 'top', 'whole', 'king', 'space', 'heard', 'best', 'hour', 'better', 'during', 'hundred', 'five', 'remember', 'step', 'early', 'hold', 'west', 'ground', 'interest', 'reach', 'fast', 'verb', 'sing', 'listen', 'six', 'table', 'travel', 'less', 'morning', 'ten', 'simple', 'several', 'vowel', 'toward', 'war', 'lay', 'against', 'pattern', 'slow', 'center', 'love', 'person', 'money', 'serve', 'appear', 'road', 'map', 'rain', 'rule', 'govern', 'pull', 'cold', 'notice', 'voice', 'unit', 'power', 'town', 'fine', 'certain', 'fly', 'fall', 'lead', 'cry', 'dark', 'machine', 'note', 'wait', 'plan', 'figure', 'star', 'box', 'noun', 'field', 'rest', 'correct', 'able', 'pound', 'done', 'beauty', 'drive', 'stood', 'contain', 'front', 'teach', 'week', 'final', 'gave', 'green', 'oh', 'quick', 'develop', 'ocean', 'warm', 'free', 'minute', 'strong', 'special', 'mind', 'behind', 'clear', 'tail', 'produce', 'fact', 'street', 'inch', 'multiply', 'nothing', 'course', 'stay', 'wheel', 'full', 'force', 'blue', 'object', 'decide', 'surface', 'deep', 'moon', 'island', 'foot', 'system', 'busy', 'test', 'record', 'boat', 'common', 'gold', 'possible', 'plane', 'stead', 'dry', 'wonder', 'laugh', 'thousands', 'ago', 'ran', 'check', 'game', 'shape', 'equate', 'hot', 'miss', 'brought', 'heat', 'snow', 'tire', 'bring', 'yes', 'distant', 'fill', 'east', 'paint', 'language', 'among'}
        
        filtered_words = [word for word in words if word not in stop_words and len(word) > 3]
        
        # Get most common topics
        word_counts = Counter(filtered_words)
        return [word for word, count in word_counts.most_common(10)]
    
    def _identify_threats(self, text: str) -> List[str]:
        """Identify specific threat indicators"""
        threats = []
        text_lower = text.lower()
        
        threat_patterns = [
            (r'\b(going to|gonna|will)\s+(kill|murder|hurt|harm|attack)\b', 'Direct threat of violence'),
            (r'\b(bomb|explosive|weapon|gun|knife)\b', 'Weapon reference'),
            (r'\b(target|eliminate|destroy|remove)\s+[a-zA-Z]+\b', 'Targeting language'),
            (r'\b(plan|planning|prepare|ready)\s+(to|for)\s+(attack|strike)\b', 'Attack planning'),
            (r'\b(meet|find|locate|track)\s+(you|them|him|her)\b', 'Stalking behavior')
        ]
        
        for pattern, threat_type in threat_patterns:
            if re.search(pattern, text_lower):
                threats.append(threat_type)
        
        return threats
    
    def _detect_manipulation(self, text: str) -> List[str]:
        """Detect manipulation tactics"""
        tactics = []
        text_lower = text.lower()
        
        manipulation_patterns = [
            (r'\b(everyone knows|everybody says|all experts agree)\b', 'False consensus'),
            (r'\b(you must|you have to|you need to)\b', 'Pressure tactics'),
            (r'\b(if you don\'t|unless you|or else)\b', 'Threat conditioning'),
            (r'\b(trust me|believe me|take my word)\b', 'Trust exploitation'),
            (r'\b(secret|hidden|they don\'t want you to know)\b', 'Conspiracy appeal')
        ]
        
        for pattern, tactic in manipulation_patterns:
            if re.search(pattern, text_lower):
                tactics.append(tactic)
        
        return tactics
    
    def _calculate_overall_risk(self, analysis: Dict[str, Any]) -> float:
        """Calculate overall risk score based on all factors"""
        weights = {
            'hate_speech_score': 0.3,
            'propaganda_score': 0.2,
            'radicalization_risk': 0.35,
            'threat_count': 0.15
        }
        
        threat_count = len(analysis['threat_indicators']) / 5.0  # Normalize to 0-1
        
        risk_score = (
            analysis['hate_speech_score'] * weights['hate_speech_score'] +
            analysis['propaganda_score'] * weights['propaganda_score'] +
            analysis['radicalization_risk'] * weights['radicalization_risk'] +
            min(threat_count, 1.0) * weights['threat_count']
        )
        
        return min(risk_score, 1.0)

    def analyze_batch(self, content_list: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
        """Analyze multiple content pieces and identify patterns"""
        results = []
        
        for content, source in content_list:
            analysis = self.analyze_content(content, source)
            results.append(analysis)
        
        return results
    
    def generate_semantic_report(self, analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive semantic analysis report"""
        if not analyses:
            return {}
        
        # Aggregate statistics
        avg_sentiment = np.mean([a['sentiment_score'] for a in analyses])
        avg_hate_score = np.mean([a['hate_speech_score'] for a in analyses])
        avg_propaganda = np.mean([a['propaganda_score'] for a in analyses])
        avg_radicalization = np.mean([a['radicalization_risk'] for a in analyses])
        avg_risk = np.mean([a['overall_risk'] for a in analyses])
        
        # Collect all topics
        all_topics = []
        for analysis in analyses:
            all_topics.extend(analysis['key_topics'])
        
        topic_frequency = Counter(all_topics)
        
        # Collect all threats
        all_threats = []
        for analysis in analyses:
            all_threats.extend(analysis['threat_indicators'])
        
        threat_frequency = Counter(all_threats)
        
        return {
            'total_analyzed': len(analyses),
            'average_sentiment': avg_sentiment,
            'average_hate_score': avg_hate_score,
            'average_propaganda_score': avg_propaganda,
            'average_radicalization_risk': avg_radicalization,
            'overall_risk_assessment': avg_risk,
            'risk_level': self._categorize_risk(avg_risk),
            'top_topics': dict(topic_frequency.most_common(10)),
            'threat_summary': dict(threat_frequency.most_common(5)),
            'high_risk_sources': [a['source'] for a in analyses if a['overall_risk'] > 0.7],
            'recommendations': self._generate_recommendations(avg_risk, analyses)
        }
    
    def _categorize_risk(self, risk_score: float) -> str:
        """Categorize risk level"""
        if risk_score >= 0.8:
            return "CRITICAL"
        elif risk_score >= 0.6:
            return "HIGH"
        elif risk_score >= 0.4:
            return "MEDIUM"
        elif risk_score >= 0.2:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _generate_recommendations(self, avg_risk: float, analyses: List[Dict[str, Any]]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if avg_risk >= 0.7:
            recommendations.append("IMMEDIATE ESCALATION: High threat level detected - notify law enforcement")
            recommendations.append("Implement enhanced monitoring of all identified accounts")
            recommendations.append("Document all evidence with legal chain of custody")
        
        if avg_risk >= 0.5:
            recommendations.append("Increase surveillance frequency and depth")
            recommendations.append("Cross-reference with known threat databases")
            recommendations.append("Monitor for escalation patterns")
        
        # Check for specific patterns
        high_hate_sources = [a for a in analyses if a['hate_speech_score'] > 0.6]
        if high_hate_sources:
            recommendations.append(f"Focus on {len(high_hate_sources)} sources with high hate speech indicators")
        
        high_radical_sources = [a for a in analyses if a['radicalization_risk'] > 0.6]
        if high_radical_sources:
            recommendations.append(f"Monitor {len(high_radical_sources)} sources showing radicalization patterns")
        
        return recommendations