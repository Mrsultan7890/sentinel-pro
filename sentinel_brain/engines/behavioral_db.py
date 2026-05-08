"""
Behavioral Intelligence Database
Stores HTTP traffic patterns for AI attack detection
"""
import sqlite3
import json
from datetime import datetime
from pathlib import Path

class BehavioralDB:
    def __init__(self, db_path="data/behavioral_data.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._init_tables()
    
    def _init_tables(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS traffic_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                method TEXT,
                url TEXT,
                status_code INTEGER,
                response_time REAL,
                request_size INTEGER,
                response_size INTEGER,
                headers TEXT,
                user_agent TEXT,
                ip_address TEXT,
                session_id TEXT,
                is_ai_attack INTEGER DEFAULT 0,
                confidence REAL DEFAULT 0.0,
                features TEXT
            )
        """)
        
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS behavioral_baseline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                feature_name TEXT UNIQUE,
                mean_value REAL,
                std_value REAL,
                min_value REAL,
                max_value REAL,
                updated_at TEXT
            )
        """)
        
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS ai_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                traffic_id INTEGER,
                detection_type TEXT,
                confidence REAL,
                reason TEXT,
                FOREIGN KEY(traffic_id) REFERENCES traffic_log(id)
            )
        """)
        self.conn.commit()
    
    def log_traffic(self, method, url, status_code, response_time, 
                   request_size, response_size, headers, user_agent, 
                   ip_address, session_id, features=None):
        cursor = self.conn.execute("""
            INSERT INTO traffic_log 
            (timestamp, method, url, status_code, response_time, 
             request_size, response_size, headers, user_agent, 
             ip_address, session_id, features)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().isoformat(),
            method, url, status_code, response_time,
            request_size, response_size,
            json.dumps(headers) if headers else None,
            user_agent, ip_address, session_id,
            json.dumps(features) if features else None
        ))
        self.conn.commit()
        return cursor.lastrowid
    
    def mark_ai_attack(self, traffic_id, detection_type, confidence, reason):
        self.conn.execute("""
            UPDATE traffic_log SET is_ai_attack=1, confidence=? WHERE id=?
        """, (confidence, traffic_id))
        
        self.conn.execute("""
            INSERT INTO ai_detections (timestamp, traffic_id, detection_type, confidence, reason)
            VALUES (?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), traffic_id, detection_type, confidence, reason))
        self.conn.commit()
    
    def get_recent_traffic(self, limit=1000):
        cursor = self.conn.execute("""
            SELECT * FROM traffic_log ORDER BY timestamp DESC LIMIT ?
        """, (limit,))
        return cursor.fetchall()
    
    def get_baseline(self, feature_name):
        cursor = self.conn.execute("""
            SELECT mean_value, std_value, min_value, max_value 
            FROM behavioral_baseline WHERE feature_name=?
        """, (feature_name,))
        return cursor.fetchone()
    
    def update_baseline(self, feature_name, mean, std, min_val, max_val):
        self.conn.execute("""
            INSERT OR REPLACE INTO behavioral_baseline 
            (feature_name, mean_value, std_value, min_value, max_value, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (feature_name, mean, std, min_val, max_val, datetime.now().isoformat()))
        self.conn.commit()
    
    def get_ai_detections(self, limit=100):
        cursor = self.conn.execute("""
            SELECT d.*, t.url, t.method, t.user_agent 
            FROM ai_detections d
            JOIN traffic_log t ON d.traffic_id = t.id
            ORDER BY d.timestamp DESC LIMIT ?
        """, (limit,))
        return cursor.fetchall()
    
    def close(self):
        self.conn.close()
