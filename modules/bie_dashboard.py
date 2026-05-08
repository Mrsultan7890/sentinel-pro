#!/usr/bin/env python3
"""BIE Behavioral Metrics Dashboard - Simple CLI visualization"""
import sqlite3
from datetime import datetime, timedelta

class BIEDashboard:
    def __init__(self):
        self.db_path = "data/behavioral_data.db"
    
    def show(self):
        """Display behavioral metrics"""
        print("\n" + "="*60)
        print("🧠 BIE BEHAVIORAL METRICS DASHBOARD")
        print("="*60)
        
        self._show_recent_activity()
        self._show_risk_distribution()
        self._show_top_threats()
        self._show_feedback_stats()
    
    def _show_recent_activity(self):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM behavioral_data WHERE timestamp > datetime('now', '-24 hours')")
            count = c.fetchone()[0]
            conn.close()
            print(f"\n📊 Activity (Last 24h): {count} events")
        except:
            print("\n📊 Activity: No data")
    
    def _show_risk_distribution(self):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                SELECT 
                    CASE 
                        WHEN risk_score >= 0.8 THEN 'CRITICAL'
                        WHEN risk_score >= 0.6 THEN 'HIGH'
                        WHEN risk_score >= 0.4 THEN 'MEDIUM'
                        ELSE 'LOW'
                    END as level,
                    COUNT(*) as count
                FROM behavioral_data
                WHERE timestamp > datetime('now', '-7 days')
                GROUP BY level
            """)
            results = c.fetchall()
            conn.close()
            
            print("\n🎯 Risk Distribution (Last 7 days):")
            for level, count in results:
                bar = "█" * min(count, 50)
                print(f"  {level:8s} [{count:4d}] {bar}")
        except:
            print("\n🎯 Risk Distribution: No data")
    
    def _show_top_threats(self):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                SELECT target, COUNT(*) as count, AVG(risk_score) as avg_risk
                FROM behavioral_data
                WHERE timestamp > datetime('now', '-7 days')
                GROUP BY target
                ORDER BY avg_risk DESC
                LIMIT 5
            """)
            results = c.fetchall()
            conn.close()
            
            print("\n⚠️  Top Threats (Last 7 days):")
            for i, (target, count, risk) in enumerate(results, 1):
                print(f"  {i}. {target[:40]:40s} Risk: {risk:.2f} ({count} events)")
        except:
            print("\n⚠️  Top Threats: No data")
    
    def _show_feedback_stats(self):
        try:
            conn = sqlite3.connect("data/behavioral_feedback.db")
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM feedback WHERE is_correct=1")
            correct = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM feedback WHERE is_correct=0")
            incorrect = c.fetchone()[0]
            conn.close()
            
            total = correct + incorrect
            accuracy = (correct / total * 100) if total > 0 else 0
            print(f"\n✅ Model Accuracy: {accuracy:.1f}% ({correct}/{total} correct)")
        except:
            print("\n✅ Model Accuracy: No feedback data")
        
        print("\n" + "="*60 + "\n")

if __name__ == "__main__":
    dashboard = BIEDashboard()
    dashboard.show()
