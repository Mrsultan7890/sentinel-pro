"""
Predictive Anomaly Analyzer Module
AI-powered threat prediction and behavioral analysis
"""

import subprocess
import json
import os
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.preprocessing import StandardScaler
import time
import pickle
from datetime import datetime, timedelta

# Suppress CPU core detection warnings
os.environ['LOKY_MAX_CPU_COUNT'] = '1'

class PredictiveAnalyzer:
    def __init__(self):
        self.connections = []
        self.behavioral_patterns = {}
        self.threat_model = None
        self.anomaly_detector = None
        self._initialize_ai_models()
        
    def _initialize_ai_models(self):
        """Initialize AI models for threat prediction"""
        # Isolation Forest for anomaly detection
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        
        # Random Forest for threat classification
        self.threat_model = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            max_depth=10
        )
        
        # Load pre-trained models if available
        self._load_pretrained_models()
    
    def _load_pretrained_models(self):
        """Load pre-trained models from disk"""
        try:
            model_path = 'models'
            if os.path.exists(f'{model_path}/threat_model.pkl'):
                with open(f'{model_path}/threat_model.pkl', 'rb') as f:
                    self.threat_model = pickle.load(f)
            
            if os.path.exists(f'{model_path}/anomaly_detector.pkl'):
                with open(f'{model_path}/anomaly_detector.pkl', 'rb') as f:
                    self.anomaly_detector = pickle.load(f)
        except Exception as e:
            print(f"Model loading failed: {e}")
    
    def analyze_behavior(self, collected_data):
        """Advanced behavioral pattern analysis"""
        print("[*] Analyzing behavioral patterns...")
        
        # Extract behavioral features
        behavioral_features = self._extract_behavioral_features(collected_data)
        
        # Temporal analysis
        temporal_patterns = self._analyze_temporal_patterns(collected_data)
        
        # Communication patterns
        communication_patterns = self._analyze_communication_patterns(collected_data)
        
        # Network behavior
        network_behavior = self._analyze_network_behavior(collected_data)
        
        return {
            'behavioral_features': behavioral_features,
            'temporal_patterns': temporal_patterns,
            'communication_patterns': communication_patterns,
            'network_behavior': network_behavior,
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def predict_threats(self, collected_data):
        """AI-powered threat prediction"""
        print("[*] Running threat prediction models...")
        
        # Extract features for prediction
        features = self._extract_prediction_features(collected_data)
        
        if not features:
            return []
        
        # Convert to numpy array
        feature_array = np.array(features).reshape(1, -1)
        
        # Predict threat probability
        threat_predictions = []
        
        try:
            # Train models with sample data if not fitted
            if not hasattr(self.anomaly_detector, 'offset_'):
                # Generate sample training data
                sample_data = self._generate_sample_training_data()
                self.anomaly_detector.fit(sample_data)
            
            # Anomaly score
            anomaly_score = self.anomaly_detector.decision_function(feature_array)[0]
            is_anomaly = self.anomaly_detector.predict(feature_array)[0] == -1
            
            # Generate predictions based on analysis
            if is_anomaly or anomaly_score < -0.5:
                threat_predictions.append({
                    'type': 'behavioral_anomaly',
                    'description': 'Unusual behavioral patterns detected',
                    'probability': abs(anomaly_score),
                    'severity': 'high' if anomaly_score < -0.7 else 'medium',
                    'indicators': self._identify_anomaly_indicators(collected_data)
                })
            
            # Specific threat predictions
            threat_predictions.extend(self._generate_specific_predictions(collected_data, features))
            
        except Exception as e:
            print(f"Threat prediction error: {e}")
            # Fallback to rule-based predictions
            threat_predictions = self._fallback_threat_prediction(collected_data)
        
        return threat_predictions
    
    def detect_anomalies(self, collected_data):
        """Advanced anomaly detection"""
        print("[*] Detecting anomalies...")
        
        anomalies = []
        
        # Content anomalies
        content_anomalies = self._detect_content_anomalies(collected_data)
        anomalies.extend(content_anomalies)
        
        # Behavioral anomalies
        behavioral_anomalies = self._detect_behavioral_anomalies(collected_data)
        anomalies.extend(behavioral_anomalies)
        
        # Network anomalies
        network_anomalies = self._detect_network_anomalies(collected_data)
        anomalies.extend(network_anomalies)
        
        # Temporal anomalies
        temporal_anomalies = self._detect_temporal_anomalies(collected_data)
        anomalies.extend(temporal_anomalies)
        
        return anomalies
    
    def calculate_enhanced_risk(self, collected_data):
        """Enhanced risk scoring with multiple factors"""
        risk_score = 0
        risk_factors = []
        
        # Data volume risk
        surface_data = collected_data.get('surface_data', [])
        social_data = collected_data.get('social_data', [])
        
        total_sources = len(surface_data) + len(social_data)
        if total_sources > 10:
            risk_score += 15
            risk_factors.append('High digital footprint')
        
        # Content analysis risk
        suspicious_content = self._analyze_suspicious_content(collected_data)
        risk_score += len(suspicious_content) * 10
        
        if suspicious_content:
            risk_factors.extend([f"Suspicious content: {item}" for item in suspicious_content[:3]])
        
        # Platform diversity risk
        platforms = set()
        for item in social_data:
            platforms.add(item.get('platform', 'unknown'))
        
        if len(platforms) > 5:
            risk_score += 20
            risk_factors.append('Multi-platform presence')
        
        # Professional vs personal mix
        professional_indicators = self._count_professional_indicators(collected_data)
        personal_indicators = self._count_personal_indicators(collected_data)
        
        if professional_indicators > 0 and personal_indicators > 0:
            risk_score += 10
            risk_factors.append('Mixed professional/personal presence')
        
        # Encryption/privacy indicators
        privacy_indicators = self._detect_privacy_indicators(collected_data)
        risk_score += len(privacy_indicators) * 5
        
        # Temporal patterns
        temporal_risk = self._calculate_temporal_risk(collected_data)
        risk_score += temporal_risk
        
        return min(risk_score, 100)  # Cap at 100
    
    def _extract_behavioral_features(self, collected_data):
        """Extract behavioral features from collected data"""
        features = {
            'posting_frequency': 0,
            'content_diversity': 0,
            'platform_count': 0,
            'interaction_patterns': {},
            'language_patterns': {},
            'time_patterns': {}
        }
        
        # Analyze social data for behavioral patterns
        social_data = collected_data.get('social_data', [])
        
        for item in social_data:
            platform = item.get('platform', 'unknown')
            profile_info = item.get('profile_info', {})
            
            # Count platforms
            features['platform_count'] += 1
            
            # Analyze profile information
            if profile_info:
                features['interaction_patterns'][platform] = len(profile_info)
        
        return features
    
    def _analyze_temporal_patterns(self, collected_data):
        """Analyze temporal activity patterns"""
        patterns = {
            'activity_times': [],
            'frequency_analysis': {},
            'temporal_anomalies': []
        }
        
        # Extract timestamps from data
        timestamps = []
        
        for source in ['surface_data', 'social_data']:
            data_list = collected_data.get(source, [])
            for item in data_list:
                if 'timestamp' in item:
                    timestamps.append(item['timestamp'])
        
        # Analyze patterns
        if timestamps:
            patterns['activity_times'] = timestamps
            patterns['frequency_analysis'] = self._analyze_frequency(timestamps)
        
        return patterns
    
    def _analyze_communication_patterns(self, collected_data):
        """Analyze communication and interaction patterns"""
        patterns = {
            'communication_style': {},
            'interaction_frequency': 0,
            'response_patterns': {},
            'content_themes': []
        }
        
        # Analyze content for communication patterns
        all_content = []
        
        for source in ['surface_data', 'social_data']:
            data_list = collected_data.get(source, [])
            for item in data_list:
                content = item.get('content', '')
                if content:
                    all_content.append(content)
        
        if all_content:
            # Text analysis for communication style
            patterns['content_themes'] = self._extract_content_themes(all_content)
            patterns['communication_style'] = self._analyze_writing_style(all_content)
        
        return patterns
    
    def _analyze_network_behavior(self, collected_data):
        """Analyze network and connection behavior"""
        behavior = {
            'connection_patterns': {},
            'network_diversity': 0,
            'cross_platform_links': [],
            'network_centrality': 0
        }
        
        # Analyze connections across platforms
        platforms = {}
        
        social_data = collected_data.get('social_data', [])
        for item in social_data:
            platform = item.get('platform', 'unknown')
            profile_info = item.get('profile_info', {})
            
            platforms[platform] = profile_info
        
        behavior['network_diversity'] = len(platforms)
        behavior['connection_patterns'] = platforms
        
        return behavior
    
    def _extract_prediction_features(self, collected_data):
        """Extract numerical features for ML prediction"""
        features = []
        
        # Basic counts
        surface_count = len(collected_data.get('surface_data', []))
        social_count = len(collected_data.get('social_data', []))
        
        features.extend([surface_count, social_count])
        
        # Content analysis features
        all_content = self._get_all_content(collected_data)
        
        if all_content:
            # Text-based features
            total_text_length = sum(len(content) for content in all_content)
            avg_text_length = total_text_length / len(all_content) if all_content else 0
            
            features.extend([total_text_length, avg_text_length])
            
            # Keyword-based features
            suspicious_keywords = ['hack', 'exploit', 'breach', 'leak', 'stolen', 'fraud']
            keyword_count = sum(
                content.lower().count(keyword) 
                for content in all_content 
                for keyword in suspicious_keywords
            )
            
            features.append(keyword_count)
        else:
            features.extend([0, 0, 0])  # Default values
        
        # Platform diversity
        platforms = set()
        for item in collected_data.get('social_data', []):
            platforms.add(item.get('platform', 'unknown'))
        
        features.append(len(platforms))
        
        return features
    
    def _generate_specific_predictions(self, collected_data, features):
        """Generate specific threat predictions based on analysis"""
        predictions = []
        
        # High activity prediction
        if features[0] + features[1] > 15:  # High source count
            predictions.append({
                'type': 'high_activity_threat',
                'description': 'Unusually high digital activity detected',
                'probability': 0.7,
                'severity': 'medium',
                'indicators': ['Multiple data sources', 'High online presence']
            })
        
        # Multi-platform coordination
        if features[-1] > 5:  # Many platforms
            predictions.append({
                'type': 'coordinated_activity',
                'description': 'Potential coordinated activity across platforms',
                'probability': 0.6,
                'severity': 'high',
                'indicators': ['Multi-platform presence', 'Coordinated profiles']
            })
        
        # Content-based threats
        if len(features) > 4 and features[4] > 0:  # Suspicious keywords
            predictions.append({
                'type': 'content_threat',
                'description': 'Suspicious content patterns detected',
                'probability': 0.8,
                'severity': 'high',
                'indicators': ['Suspicious keywords', 'Threat-related content']
            })
        
        return predictions
    
    def _fallback_threat_prediction(self, collected_data):
        """Fallback rule-based threat prediction"""
        predictions = []
        
        # Simple rule-based analysis
        total_sources = len(collected_data.get('surface_data', [])) + len(collected_data.get('social_data', []))
        
        if total_sources > 10:
            predictions.append({
                'type': 'high_exposure_risk',
                'description': 'High digital exposure may indicate threat activity',
                'probability': 0.6,
                'severity': 'medium',
                'indicators': ['High source count', 'Extensive digital footprint']
            })
        
        return predictions
    
    def _detect_content_anomalies(self, collected_data):
        """Detect content-based anomalies"""
        anomalies = []
        
        all_content = self._get_all_content(collected_data)
        
        # Unusual content patterns
        for content in all_content:
            if len(content) > 10000:  # Very long content
                anomalies.append({
                    'type': 'content_length_anomaly',
                    'description': 'Unusually long content detected',
                    'severity': 'low',
                    'content_sample': content[:200] + '...'
                })
        
        return anomalies
    
    def _detect_behavioral_anomalies(self, collected_data):
        """Detect behavioral anomalies"""
        anomalies = []
        
        # Platform usage anomalies
        social_data = collected_data.get('social_data', [])
        platform_count = len(set(item.get('platform', '') for item in social_data))
        
        if platform_count > 8:
            anomalies.append({
                'type': 'platform_usage_anomaly',
                'description': f'Unusual number of platforms: {platform_count}',
                'severity': 'medium',
                'platform_count': platform_count
            })
        
        return anomalies
    
    def _detect_network_anomalies(self, collected_data):
        """Detect network-based anomalies"""
        return []  # Placeholder for network analysis
    
    def _detect_temporal_anomalies(self, collected_data):
        """Detect temporal anomalies"""
        return []  # Placeholder for temporal analysis
    
    def _analyze_suspicious_content(self, collected_data):
        """Analyze content for suspicious indicators"""
        suspicious_items = []
        
        suspicious_patterns = [
            r'\b(hack|exploit|breach|leak|stolen|fraud|scam|phishing)\b',
            r'\b(malware|botnet|ddos|crack|bypass)\b',
            r'\b(darkweb|tor|onion|bitcoin|crypto)\b'
        ]
        
        all_content = self._get_all_content(collected_data)
        
        for content in all_content:
            content_lower = content.lower()
            for pattern in suspicious_patterns:
                import re
                matches = re.findall(pattern, content_lower)
                if matches:
                    suspicious_items.extend(matches)
        
        return list(set(suspicious_items))  # Remove duplicates
    
    def _count_professional_indicators(self, collected_data):
        """Count professional indicators"""
        professional_keywords = ['linkedin', 'github', 'stackoverflow', 'resume', 'cv', 'work', 'company']
        count = 0
        
        all_content = self._get_all_content(collected_data)
        
        for content in all_content:
            content_lower = content.lower()
            for keyword in professional_keywords:
                if keyword in content_lower:
                    count += 1
        
        return count
    
    def _count_personal_indicators(self, collected_data):
        """Count personal indicators"""
        personal_keywords = ['instagram', 'facebook', 'twitter', 'personal', 'hobby', 'family', 'friend']
        count = 0
        
        all_content = self._get_all_content(collected_data)
        
        for content in all_content:
            content_lower = content.lower()
            for keyword in personal_keywords:
                if keyword in content_lower:
                    count += 1
        
        return count
    
    def _detect_privacy_indicators(self, collected_data):
        """Detect privacy/security indicators"""
        privacy_keywords = ['vpn', 'tor', 'proxy', 'encrypted', 'anonymous', 'privacy', 'secure']
        indicators = []
        
        all_content = self._get_all_content(collected_data)
        
        for content in all_content:
            content_lower = content.lower()
            for keyword in privacy_keywords:
                if keyword in content_lower:
                    indicators.append(keyword)
        
        return list(set(indicators))
    
    def _calculate_temporal_risk(self, collected_data):
        """Calculate risk based on temporal patterns"""
        # Placeholder for temporal risk calculation
        return 5  # Default temporal risk
    
    def _get_all_content(self, collected_data):
        """Extract all text content from collected data"""
        all_content = []
        
        for source in ['surface_data', 'social_data']:
            data_list = collected_data.get(source, [])
            for item in data_list:
                content = item.get('content', '')
                if content:
                    all_content.append(content)
        
        return all_content
    
    def _analyze_frequency(self, timestamps):
        """Analyze frequency patterns in timestamps"""
        return {'pattern': 'regular'}  # Placeholder
    
    def _extract_content_themes(self, content_list):
        """Extract themes from content using TF-IDF"""
        if not content_list:
            return []
        
        try:
            vectorizer = TfidfVectorizer(max_features=20, stop_words='english')
            tfidf_matrix = vectorizer.fit_transform(content_list)
            feature_names = vectorizer.get_feature_names_out()
            
            # Get top themes
            mean_scores = tfidf_matrix.mean(axis=0).A1
            top_indices = mean_scores.argsort()[-10:][::-1]
            
            return [feature_names[i] for i in top_indices]
        except:
            return []
    
    def _analyze_writing_style(self, content_list):
        """Analyze writing style patterns"""
        style = {
            'avg_sentence_length': 0,
            'vocabulary_diversity': 0,
            'formality_score': 0
        }
        
        if content_list:
            total_words = sum(len(content.split()) for content in content_list)
            total_sentences = sum(content.count('.') + content.count('!') + content.count('?') for content in content_list)
            
            if total_sentences > 0:
                style['avg_sentence_length'] = total_words / total_sentences
        
        return style
    
    def _generate_sample_training_data(self):
        """Generate sample training data for models"""
        # Create sample feature vectors for training
        np.random.seed(42)
        
        # Normal behavior samples
        normal_samples = np.random.normal(5, 2, (50, 6))  # 6 features
        
        # Anomalous behavior samples
        anomaly_samples = np.random.normal(15, 5, (10, 6))
        
        # Combine samples
        training_data = np.vstack([normal_samples, anomaly_samples])
        
        return training_data
    
    def _identify_anomaly_indicators(self, collected_data):
        """Identify specific indicators that triggered anomaly detection"""
        indicators = []
        
        # Check for unusual patterns
        total_sources = len(collected_data.get('surface_data', [])) + len(collected_data.get('social_data', []))
        
        if total_sources > 15:
            indicators.append('Excessive data sources')
        
        # Check for suspicious content
        suspicious_content = self._analyze_suspicious_content(collected_data)
        if suspicious_content:
            indicators.append(f'Suspicious keywords: {", ".join(suspicious_content[:3])}')
        
        return indicators