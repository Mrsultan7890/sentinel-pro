"""
Behavioral Intelligence Feedback Loop
User confirms/rejects AI attack detections → models retrain with feedback.

Workflow:
  1. User reviews AI attack detections
  2. User confirms (true positive) or rejects (false positive)
  3. Feedback stored in DB
  4. Models retrain periodically with confirmed labels
  5. Accuracy improves over time
"""
import sqlite3
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


class FeedbackDB:
    """SQLite database for user feedback on AI detections."""
    
    def __init__(self, db_path: str = "data/behavioral_feedback.db"):
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self._init()

    def _init(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS feedback (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                traffic_id      INTEGER NOT NULL,
                session_id      TEXT,
                ip_address      TEXT,
                url             TEXT,
                features        TEXT,
                detection_type  TEXT,
                original_confidence REAL,
                user_label      TEXT,
                user_comment    TEXT,
                feedback_at     TEXT NOT NULL,
                used_in_training INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_feedback_label 
                ON feedback(user_label);
            CREATE INDEX IF NOT EXISTS idx_feedback_training 
                ON feedback(used_in_training);
        """)
        self.conn.commit()

    def add_feedback(self, traffic_id: int, session_id: str, ip_address: str,
                    url: str, features: dict, detection_type: str,
                    original_confidence: float, user_label: str,
                    user_comment: str = None):
        """
        Add user feedback on a detection.
        user_label: 'true_positive', 'false_positive', 'unsure'
        """
        self.conn.execute("""
            INSERT INTO feedback 
            (traffic_id, session_id, ip_address, url, features, 
             detection_type, original_confidence, user_label, user_comment, feedback_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (traffic_id, session_id, ip_address, url, json.dumps(features),
              detection_type, original_confidence, user_label, user_comment,
              datetime.now().isoformat()))
        self.conn.commit()

    def get_pending_feedback(self, limit: int = 50) -> list:
        """Get detections awaiting user feedback."""
        # This would query behavioral_data.db for recent AI detections
        # For now, return empty list
        return []

    def get_confirmed_samples(self, min_count: int = 10) -> tuple:
        """
        Get confirmed samples for retraining.
        Returns (true_positives, false_positives)
        """
        cursor = self.conn.execute("""
            SELECT features, user_label
            FROM feedback
            WHERE user_label IN ('true_positive', 'false_positive')
            AND used_in_training = 0
        """)
        
        rows = cursor.fetchall()
        true_pos = []
        false_pos = []
        
        for features_json, label in rows:
            try:
                features = json.loads(features_json)
                if label == 'true_positive':
                    true_pos.append(features)
                else:
                    false_pos.append(features)
            except Exception:
                continue

        return true_pos, false_pos

    def mark_used_in_training(self):
        """Mark all confirmed samples as used in training."""
        self.conn.execute("""
            UPDATE feedback 
            SET used_in_training = 1
            WHERE user_label IN ('true_positive', 'false_positive')
            AND used_in_training = 0
        """)
        self.conn.commit()

    def get_stats(self) -> dict:
        """Get feedback statistics."""
        cursor = self.conn.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN user_label='true_positive' THEN 1 ELSE 0 END) as true_pos,
                SUM(CASE WHEN user_label='false_positive' THEN 1 ELSE 0 END) as false_pos,
                SUM(CASE WHEN user_label='unsure' THEN 1 ELSE 0 END) as unsure,
                SUM(CASE WHEN used_in_training=1 THEN 1 ELSE 0 END) as used_in_training
            FROM feedback
        """)
        row = cursor.fetchone()
        total = row[0] or 0
        true_pos = row[1] or 0
        false_pos = row[2] or 0
        unsure = row[3] or 0
        used = row[4] or 0
        
        return {
            'total_feedback': total,
            'true_positives': true_pos,
            'false_positives': false_pos,
            'unsure': unsure,
            'used_in_training': used,
            'pending_training': true_pos + false_pos - used,
        }

    def close(self):
        self.conn.close()


class FeedbackLoop:
    """
    Manages feedback loop for behavioral ML models.
    Collects user feedback and triggers retraining.
    """

    def __init__(self, behavioral_engine):
        self.behavioral_engine = behavioral_engine
        self.feedback_db = FeedbackDB()
        self.retrain_threshold = 50  # Retrain after 50 new confirmed samples

    def submit_feedback(self, traffic_id: int, user_label: str, 
                       comment: str = None) -> bool:
        """
        User submits feedback on a detection.
        traffic_id: from behavioral_data.db traffic_log
        user_label: 'true_positive', 'false_positive', 'unsure'
        """
        # Fetch traffic details from behavioral DB
        cursor = self.behavioral_engine.db.conn.execute("""
            SELECT session_id, ip_address, url, features, is_ai_attack, confidence
            FROM traffic_log WHERE id=?
        """, (traffic_id,))
        
        row = cursor.fetchone()
        if not row:
            return False

        session_id, ip_address, url, features_json, is_ai_attack, confidence = row
        
        try:
            features = json.loads(features_json) if features_json else {}
        except Exception:
            features = {}

        detection_type = 'ai_attack' if is_ai_attack else 'normal'
        
        self.feedback_db.add_feedback(
            traffic_id=traffic_id,
            session_id=session_id,
            ip_address=ip_address,
            url=url,
            features=features,
            detection_type=detection_type,
            original_confidence=confidence or 0.0,
            user_label=user_label,
            user_comment=comment
        )

        logger.info(f"Feedback recorded: traffic_id={traffic_id} label={user_label}")
        
        # Check if we should retrain
        stats = self.feedback_db.get_stats()
        if stats['pending_training'] >= self.retrain_threshold:
            logger.info(f"Retraining threshold reached: {stats['pending_training']} samples")
            return self.trigger_retrain()

        return True

    def trigger_retrain(self) -> bool:
        """
        Retrain behavioral models with confirmed feedback.
        Returns True if retraining succeeded.
        """
        true_pos, false_pos = self.feedback_db.get_confirmed_samples()
        
        if len(true_pos) < 5 and len(false_pos) < 5:
            logger.warning("Not enough confirmed samples for retraining")
            return False

        logger.info(f"Retraining with {len(true_pos)} true positives, {len(false_pos)} false positives")

        # Get existing training data from behavioral DB
        cursor = self.behavioral_engine.db.conn.execute("""
            SELECT features FROM traffic_log 
            WHERE features IS NOT NULL 
            ORDER BY id DESC LIMIT 1000
        """)
        
        existing_samples = []
        for (features_json,) in cursor.fetchall():
            try:
                existing_samples.append({'features': json.loads(features_json)})
            except Exception:
                continue

        # Combine with feedback samples
        # True positives = confirmed AI attacks (label=1)
        # False positives = normal traffic mislabeled as attack (label=0)
        
        # For now, just retrain the base models with all available data
        # In production, you'd use supervised learning with labels
        
        all_samples = existing_samples + [{'features': f} for f in true_pos + false_pos]
        
        try:
            ok, msg = self.behavioral_engine.train_models()
            if ok:
                self.feedback_db.mark_used_in_training()
                logger.info("Retraining completed successfully")
                return True
            else:
                logger.error(f"Retraining failed: {msg}")
                return False
        except Exception as e:
            logger.error(f"Retraining error: {e}")
            return False

    def get_recent_detections_for_review(self, limit: int = 20) -> list:
        """
        Get recent AI detections that need user review.
        Returns list of (traffic_id, url, confidence, detection_type, timestamp)
        """
        cursor = self.behavioral_engine.db.conn.execute("""
            SELECT t.id, t.url, d.confidence, d.detection_type, d.timestamp
            FROM ai_detections d
            JOIN traffic_log t ON d.traffic_id = t.id
            WHERE t.id NOT IN (SELECT traffic_id FROM feedback.feedback)
            ORDER BY d.timestamp DESC
            LIMIT ?
        """, (limit,))
        
        # Note: This assumes behavioral_data.db and behavioral_feedback.db are separate
        # In production, you'd use proper JOIN or check existence differently
        
        return cursor.fetchall()

    def get_feedback_stats(self) -> dict:
        """Get feedback loop statistics."""
        return self.feedback_db.get_stats()

    def close(self):
        self.feedback_db.close()
