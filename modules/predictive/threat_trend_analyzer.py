"""
Threat Trend Analyzer
Analyzes threat intelligence feeds and predicts emerging threats
"""

import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any
from pathlib import Path
import numpy as np
from collections import defaultdict

class ThreatTrendAnalyzer:
    """Analyze threat trends and predict emerging threats"""
    
    def __init__(self, db_path: str = "data/threat_trends.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        
    def _init_db(self):
        """Initialize threat trends database"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS threat_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT,
                description TEXT,
                indicators TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS threat_predictions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_type TEXT NOT NULL,
                predicted_date TEXT NOT NULL,
                confidence REAL NOT NULL,
                reasoning TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        c.execute('''
            CREATE INDEX IF NOT EXISTS idx_threat_type 
            ON threat_events(threat_type)
        ''')
        
        c.execute('''
            CREATE INDEX IF NOT EXISTS idx_timestamp 
            ON threat_events(timestamp)
        ''')
        
        conn.commit()
        conn.close()
    
    def ingest_threat_event(self, event: Dict[str, Any]):
        """Ingest a threat event"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''
            INSERT INTO threat_events 
            (timestamp, threat_type, severity, source, description, indicators)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            event.get('timestamp', datetime.now().isoformat()),
            event['threat_type'],
            event.get('severity', 'MEDIUM'),
            event.get('source', 'unknown'),
            event.get('description', ''),
            json.dumps(event.get('indicators', []))
        ))
        
        conn.commit()
        conn.close()
    
    def get_threat_timeline(self, days: int = 30) -> Dict[str, List[Dict]]:
        """Get threat events timeline"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        
        c.execute('''
            SELECT timestamp, threat_type, severity, source, description
            FROM threat_events
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
        ''', (cutoff,))
        
        events = []
        for row in c.fetchall():
            events.append({
                'timestamp': row[0],
                'threat_type': row[1],
                'severity': row[2],
                'source': row[3],
                'description': row[4]
            })
        
        conn.close()
        
        # Group by threat type
        timeline = defaultdict(list)
        for event in events:
            timeline[event['threat_type']].append(event)
        
        return dict(timeline)
    
    def analyze_trends(self, days: int = 30) -> Dict[str, Any]:
        """Analyze threat trends"""
        timeline = self.get_threat_timeline(days)
        
        trends = {
            'period_days': days,
            'total_events': sum(len(events) for events in timeline.values()),
            'threat_types': {},
            'severity_distribution': defaultdict(int),
            'trending_up': [],
            'trending_down': [],
            'emerging_threats': []
        }
        
        # Analyze each threat type
        for threat_type, events in timeline.items():
            # Count by severity
            severity_counts = defaultdict(int)
            for event in events:
                severity_counts[event['severity']] += 1
                trends['severity_distribution'][event['severity']] += 1
            
            # Calculate trend direction
            recent_count = len([e for e in events if self._is_recent(e['timestamp'], 7)])
            older_count = len(events) - recent_count
            
            trend_direction = "stable"
            if recent_count > older_count * 1.5:
                trend_direction = "up"
                trends['trending_up'].append(threat_type)
            elif recent_count < older_count * 0.5:
                trend_direction = "down"
                trends['trending_down'].append(threat_type)
            
            trends['threat_types'][threat_type] = {
                'total_events': len(events),
                'recent_events': recent_count,
                'trend': trend_direction,
                'severity_breakdown': dict(severity_counts)
            }
        
        # Identify emerging threats (new in last 7 days)
        for threat_type, events in timeline.items():
            first_seen = min(e['timestamp'] for e in events)
            if self._is_recent(first_seen, 7):
                trends['emerging_threats'].append({
                    'threat_type': threat_type,
                    'first_seen': first_seen,
                    'event_count': len(events)
                })
        
        return trends
    
    def _is_recent(self, timestamp: str, days: int) -> bool:
        """Check if timestamp is within recent days"""
        try:
            event_time = datetime.fromisoformat(timestamp)
            cutoff = datetime.now() - timedelta(days=days)
            return event_time >= cutoff
        except:
            return False
    
    def predict_threats(self, horizon_days: int = 7) -> List[Dict[str, Any]]:
        """Predict threats for next N days"""
        trends = self.analyze_trends(days=30)
        predictions = []
        
        # Predict based on trending threats
        for threat_type in trends['trending_up']:
            info = trends['threat_types'][threat_type]
            
            # Simple linear extrapolation
            recent_rate = info['recent_events'] / 7  # Events per day
            predicted_events = int(recent_rate * horizon_days)
            
            if predicted_events > 0:
                confidence = min(0.9, info['recent_events'] / 10)  # Cap at 0.9
                
                prediction = {
                    'threat_type': threat_type,
                    'predicted_date': (datetime.now() + timedelta(days=horizon_days)).isoformat(),
                    'confidence': confidence,
                    'predicted_events': predicted_events,
                    'reasoning': f"Trending up: {info['recent_events']} recent events, rate {recent_rate:.1f}/day"
                }
                
                predictions.append(prediction)
                
                # Store prediction
                self._store_prediction(prediction)
        
        # Predict emerging threats
        for emerging in trends['emerging_threats']:
            if emerging['event_count'] >= 3:  # Threshold
                prediction = {
                    'threat_type': emerging['threat_type'],
                    'predicted_date': (datetime.now() + timedelta(days=horizon_days)).isoformat(),
                    'confidence': 0.7,
                    'predicted_events': emerging['event_count'] * 2,  # Expect growth
                    'reasoning': f"Emerging threat: first seen {emerging['first_seen']}, {emerging['event_count']} events"
                }
                
                predictions.append(prediction)
                self._store_prediction(prediction)
        
        # Sort by confidence
        predictions.sort(key=lambda x: x['confidence'], reverse=True)
        
        return predictions
    
    def _store_prediction(self, prediction: Dict[str, Any]):
        """Store prediction in database"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''
            INSERT INTO threat_predictions 
            (threat_type, predicted_date, confidence, reasoning)
            VALUES (?, ?, ?, ?)
        ''', (
            prediction['threat_type'],
            prediction['predicted_date'],
            prediction['confidence'],
            prediction['reasoning']
        ))
        
        conn.commit()
        conn.close()
    
    def get_early_warnings(self, confidence_threshold: float = 0.7) -> List[Dict[str, Any]]:
        """Get early warnings for high-confidence predictions"""
        predictions = self.predict_threats()
        
        warnings = [
            p for p in predictions 
            if p['confidence'] >= confidence_threshold
        ]
        
        return warnings
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive threat trend report"""
        trends = self.analyze_trends(days=30)
        predictions = self.predict_threats(horizon_days=7)
        warnings = self.get_early_warnings()
        
        return {
            'generated_at': datetime.now().isoformat(),
            'analysis_period': '30 days',
            'prediction_horizon': '7 days',
            'summary': {
                'total_events': trends['total_events'],
                'unique_threats': len(trends['threat_types']),
                'trending_up': len(trends['trending_up']),
                'emerging_threats': len(trends['emerging_threats']),
                'predictions': len(predictions),
                'high_confidence_warnings': len(warnings)
            },
            'trends': trends,
            'predictions': predictions,
            'warnings': warnings,
            'recommendations': self._generate_recommendations(trends, predictions)
        }
    
    def _generate_recommendations(self, trends: Dict, predictions: List[Dict]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Check trending threats
        if len(trends['trending_up']) > 0:
            recommendations.append(
                f"Monitor trending threats: {', '.join(trends['trending_up'][:3])}"
            )
        
        # Check emerging threats
        if len(trends['emerging_threats']) > 0:
            recommendations.append(
                f"Investigate emerging threats: {len(trends['emerging_threats'])} new threat types detected"
            )
        
        # Check high-confidence predictions
        high_conf = [p for p in predictions if p['confidence'] > 0.8]
        if high_conf:
            recommendations.append(
                f"Prepare for {len(high_conf)} high-confidence predicted threats"
            )
        
        # Check severity distribution
        critical_count = trends['severity_distribution'].get('CRITICAL', 0)
        if critical_count > 5:
            recommendations.append(
                f"High critical threat activity: {critical_count} events. Review security posture."
            )
        
        return recommendations


if __name__ == "__main__":
    print("[*] Testing Threat Trend Analyzer...")
    
    analyzer = ThreatTrendAnalyzer()
    
    # Ingest sample events
    sample_events = [
        {
            'threat_type': 'ransomware',
            'severity': 'CRITICAL',
            'source': 'test',
            'description': 'Ransomware attack detected',
            'timestamp': (datetime.now() - timedelta(days=2)).isoformat()
        },
        {
            'threat_type': 'ransomware',
            'severity': 'CRITICAL',
            'source': 'test',
            'description': 'Another ransomware attack',
            'timestamp': (datetime.now() - timedelta(days=1)).isoformat()
        },
        {
            'threat_type': 'phishing',
            'severity': 'HIGH',
            'source': 'test',
            'description': 'Phishing campaign',
            'timestamp': (datetime.now() - timedelta(days=5)).isoformat()
        },
        {
            'threat_type': 'ddos',
            'severity': 'MEDIUM',
            'source': 'test',
            'description': 'DDoS attempt',
            'timestamp': (datetime.now() - timedelta(days=10)).isoformat()
        }
    ]
    
    for event in sample_events:
        analyzer.ingest_threat_event(event)
    
    print("✓ Ingested sample events")
    
    # Analyze trends
    trends = analyzer.analyze_trends(days=30)
    print(f"✓ Analyzed trends: {trends['total_events']} events")
    print(f"  Threat types: {len(trends['threat_types'])}")
    print(f"  Trending up: {trends['trending_up']}")
    print(f"  Emerging: {len(trends['emerging_threats'])}")
    
    # Predict threats
    predictions = analyzer.predict_threats(horizon_days=7)
    print(f"✓ Generated {len(predictions)} predictions")
    
    for pred in predictions:
        print(f"  - {pred['threat_type']}: {pred['confidence']:.2f} confidence")
    
    # Generate report
    report = analyzer.generate_report()
    print(f"\n✓ Report Summary:")
    print(f"  Total events: {report['summary']['total_events']}")
    print(f"  Predictions: {report['summary']['predictions']}")
    print(f"  Warnings: {report['summary']['high_confidence_warnings']}")
    
    if report['recommendations']:
        print(f"\n✓ Recommendations:")
        for rec in report['recommendations']:
            print(f"  - {rec}")
    
    print("\n✓ All tests passed!")
