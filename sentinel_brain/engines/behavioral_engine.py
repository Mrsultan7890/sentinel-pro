"""
Behavioral Intelligence Engine (BIE)
Detects AI-powered attacks through behavioral analysis
"""
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict
import hashlib
from .behavioral_db import BehavioralDB
from .behavioral_models import BehavioralModelManager, features_to_vector
from .feedback_loop import FeedbackLoop

class BehavioralEngine:
    def __init__(self):
        self.db = BehavioralDB()
        self.session_tracker = defaultdict(list)  # session_id -> [requests]
        self.ip_tracker = defaultdict(list)       # ip -> [requests]
        self.ml_models = BehavioralModelManager()
        self.feedback_loop = FeedbackLoop(self)
        
    def extract_features(self, request_data):
        """Extract behavioral features from HTTP request"""
        features = {
            'method': request_data.get('method', 'GET'),
            'url_length': len(request_data.get('url', '')),
            'has_params': '?' in request_data.get('url', ''),
            'param_count': request_data.get('url', '').count('&') + 1 if '?' in request_data.get('url', '') else 0,
            'header_count': len(request_data.get('headers', {})),
            'user_agent_length': len(request_data.get('user_agent', '')),
            'request_size': request_data.get('request_size', 0),
            'response_time': request_data.get('response_time', 0),
            'status_code': request_data.get('status_code', 200),
        }
        return features
    
    def analyze_request(self, request_data):
        """
        Analyze single HTTP request for AI attack signatures
        Returns: (is_ai_attack: bool, confidence: float, reason: str)
        """
        features = self.extract_features(request_data)
        session_id = request_data.get('session_id', 'unknown')
        ip_address = request_data.get('ip_address', 'unknown')
        
        # Track request
        self.session_tracker[session_id].append({
            'timestamp': datetime.now(),
            'features': features,
            'features_vec': features_to_vector(features),
        })
        self.ip_tracker[ip_address].append({
            'timestamp': datetime.now(),
            'features': features,
        })
        
        # Log to database
        traffic_id = self.db.log_traffic(
            method=features['method'],
            url=request_data.get('url', ''),
            status_code=features['status_code'],
            response_time=features['response_time'],
            request_size=features['request_size'],
            response_size=request_data.get('response_size', 0),
            headers=request_data.get('headers'),
            user_agent=request_data.get('user_agent'),
            ip_address=ip_address,
            session_id=session_id,
            features=features
        )
        
        # AI Detection Logic
        detections = []
        
        # 1. Request Diversity Check (AI tries many variations)
        diversity_score = self._check_diversity(session_id)
        if diversity_score > 0.7:
            detections.append(('high_diversity', diversity_score, 
                             f'Session shows {diversity_score:.2f} diversity - typical of AI scanning'))
        
        # 2. Timing Analysis (AI is too consistent)
        timing_score = self._check_timing_consistency(session_id)
        if timing_score > 0.8:
            detections.append(('consistent_timing', timing_score,
                             f'Requests too consistent ({timing_score:.2f}) - likely automated'))
        
        # 3. Error Handling Pattern (AI adapts to errors)
        adaptation_score = self._check_adaptation(session_id)
        if adaptation_score > 0.6:
            detections.append(('adaptive_behavior', adaptation_score,
                             f'Adaptive error handling ({adaptation_score:.2f}) - AI signature'))
        
        # 4. Request Rate (AI is faster than humans)
        rate_score = self._check_request_rate(ip_address)
        if rate_score > 0.75:
            detections.append(('high_rate', rate_score,
                             f'Request rate {rate_score:.2f} - faster than human'))

        # 5. Phase 2: ML model scoring (Isolation Forest + Autoencoder + LSTM)
        session_seq = [r['features_vec'] for r in self.session_tracker[session_id]
                       if 'features_vec' in r]
        ml_result = self.ml_models.score_request(features, session_seq or None)
        if ml_result['is_anomaly']:
            detections.append(('ml_anomaly', ml_result['combined'],
                             f"ML anomaly: IF={ml_result['isolation_forest']:.2f} "
                             f"AE={ml_result['autoencoder']:.2f} "
                             f"LSTM={ml_result['lstm']:.2f}"))
        
        # Aggregate detections
        if detections:
            avg_confidence = np.mean([d[1] for d in detections])
            reasons = ' | '.join([d[2] for d in detections])
            detection_types = ','.join([d[0] for d in detections])
            
            # Mark as AI attack if confidence > 0.7
            if avg_confidence > 0.7:
                self.db.mark_ai_attack(traffic_id, detection_types, avg_confidence, reasons)
                return True, avg_confidence, reasons
        
        return False, 0.0, "Normal behavior"
    
    def _check_diversity(self, session_id):
        """Check URL/parameter diversity in session"""
        requests = self.session_tracker.get(session_id, [])
        if len(requests) < 5:
            return 0.0
        
        # Calculate unique URL patterns
        url_hashes = set()
        for req in requests[-20:]:  # Last 20 requests
            url_pattern = f"{req['features']['method']}_{req['features']['param_count']}"
            url_hashes.add(hashlib.md5(url_pattern.encode()).hexdigest()[:8])
        
        diversity = len(url_hashes) / min(len(requests), 20)
        return diversity
    
    def _check_timing_consistency(self, session_id):
        """Check if request timing is too consistent (bot-like)"""
        requests = self.session_tracker.get(session_id, [])
        if len(requests) < 3:
            return 0.0
        
        # Calculate time intervals
        intervals = []
        for i in range(1, min(len(requests), 10)):
            delta = (requests[i]['timestamp'] - requests[i-1]['timestamp']).total_seconds()
            intervals.append(delta)
        
        if not intervals:
            return 0.0
        
        # Low variance = consistent timing = bot
        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        
        if mean_interval == 0:
            return 0.0
        
        consistency = 1.0 - min(std_interval / mean_interval, 1.0)
        return consistency
    
    def _check_adaptation(self, session_id):
        """Check if behavior adapts to errors (AI learning)"""
        requests = self.session_tracker.get(session_id, [])
        if len(requests) < 5:
            return 0.0
        
        # Look for pattern: errors → behavior change
        error_count = 0
        success_after_error = 0
        
        for i in range(len(requests) - 1):
            status = requests[i]['features']['status_code']
            next_status = requests[i+1]['features']['status_code']
            
            if status >= 400:  # Error
                error_count += 1
                if next_status < 400:  # Success after error
                    success_after_error += 1
        
        if error_count == 0:
            return 0.0
        
        adaptation = success_after_error / error_count
        return adaptation
    
    def _check_request_rate(self, ip_address):
        """Check request rate (requests per second)"""
        requests = self.ip_tracker.get(ip_address, [])
        if len(requests) < 3:
            return 0.0
        
        # Calculate rate over last 10 seconds
        now = datetime.now()
        recent = [r for r in requests if (now - r['timestamp']).total_seconds() < 10]
        
        if len(recent) < 3:
            return 0.0
        
        time_span = (recent[-1]['timestamp'] - recent[0]['timestamp']).total_seconds()
        if time_span == 0:
            return 1.0  # All requests at same time = bot
        
        rate = len(recent) / time_span
        
        # Normalize: >5 req/sec = likely bot
        normalized_rate = min(rate / 5.0, 1.0)
        return normalized_rate
    
    def get_session_stats(self, session_id):
        """Get statistics for a session"""
        requests = self.session_tracker.get(session_id, [])
        if not requests:
            return None
        
        return {
            'total_requests': len(requests),
            'diversity': self._check_diversity(session_id),
            'timing_consistency': self._check_timing_consistency(session_id),
            'adaptation': self._check_adaptation(session_id),
            'duration': (requests[-1]['timestamp'] - requests[0]['timestamp']).total_seconds()
        }
    
    def cleanup_old_data(self, hours=24):
        """Remove tracking data older than N hours"""
        cutoff = datetime.now() - timedelta(hours=hours)
        
        for session_id in list(self.session_tracker.keys()):
            self.session_tracker[session_id] = [
                r for r in self.session_tracker[session_id] 
                if r['timestamp'] > cutoff
            ]
            if not self.session_tracker[session_id]:
                del self.session_tracker[session_id]
        
        for ip in list(self.ip_tracker.keys()):
            self.ip_tracker[ip] = [
                r for r in self.ip_tracker[ip]
                if r['timestamp'] > cutoff
            ]
            if not self.ip_tracker[ip]:
                del self.ip_tracker[ip]
    
    def get_recent_detections(self, limit=100):
        """Get recent AI attack detections"""
        return self.db.get_ai_detections(limit)
    
    def train_models(self):
        """Train Phase 2 ML models from stored traffic data"""
        rows = self.db.get_recent_traffic(limit=5000)
        if not rows:
            return False, "No traffic data available"
        # Convert sqlite rows to dicts
        traffic = []
        for row in rows:
            traffic.append({
                'features': row[14],       # features column
                'session_id': row[11],     # session_id column
            })
        ok = self.ml_models.train(traffic)
        return ok, f"Trained on {len(traffic)} samples" if ok else "Not enough data (need 10+)"

    def get_ml_status(self) -> dict:
        """Get Phase 2 ML model status"""
        return self.ml_models.get_status()

    def submit_feedback(self, traffic_id: int, user_label: str, comment: str = None) -> bool:
        """Submit user feedback on a detection for retraining."""
        return self.feedback_loop.submit_feedback(traffic_id, user_label, comment)

    def get_feedback_stats(self) -> dict:
        """Get feedback loop statistics."""
        return self.feedback_loop.get_feedback_stats()

    def trigger_retrain(self) -> bool:
        """Manually trigger model retraining with feedback."""
        return self.feedback_loop.trigger_retrain()

    def close(self):
        self.db.close()
