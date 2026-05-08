#!/usr/bin/env python3
"""SHE Health Checker - System health monitoring"""
import psutil
import sqlite3
from datetime import datetime

class SHEHealthChecker:
    def __init__(self):
        self.db_path = "data/incidents.db"
    
    def check_all(self):
        """Run all health checks"""
        return {
            "cpu": self._check_cpu(),
            "memory": self._check_memory(),
            "disk": self._check_disk(),
            "patches": self._check_patches(),
            "incidents": self._check_incidents()
        }
    
    def _check_cpu(self):
        usage = psutil.cpu_percent(interval=1)
        return {"status": "OK" if usage < 80 else "WARNING", "usage": usage}
    
    def _check_memory(self):
        mem = psutil.virtual_memory()
        return {"status": "OK" if mem.percent < 85 else "WARNING", "usage": mem.percent}
    
    def _check_disk(self):
        disk = psutil.disk_usage('/')
        return {"status": "OK" if disk.percent < 90 else "WARNING", "usage": disk.percent}
    
    def _check_patches(self):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM patches WHERE status='pending'")
            pending = c.fetchone()[0]
            conn.close()
            return {"status": "OK" if pending == 0 else "WARNING", "pending": pending}
        except:
            return {"status": "UNKNOWN", "pending": 0}
    
    def _check_incidents(self):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM incidents WHERE status='open'")
            open_incidents = c.fetchone()[0]
            conn.close()
            return {"status": "OK" if open_incidents == 0 else "WARNING", "open": open_incidents}
        except:
            return {"status": "UNKNOWN", "open": 0}

if __name__ == "__main__":
    checker = SHEHealthChecker()
    health = checker.check_all()
    print("🏥 SHE Health Check")
    for component, data in health.items():
        print(f"  {component}: {data['status']}")
