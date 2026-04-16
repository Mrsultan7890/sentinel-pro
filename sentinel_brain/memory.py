"""
Sentinel Memory — Long-term memory + context
Agent ko yaad rehta hai: kya kiya, kya mila, kya seekha.

Author: @who_is_the_black_hat
"""

import json
import sqlite3
import time
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

DB_PATH = Path('/home/kali/osints/data/sentinel_memory.db')


class Memory:
    """
    SQLite-backed long-term memory.
    - Target history (kya kiya, kab kiya)
    - Findings (kya mila)
    - Learned patterns (kya kaam aaya)
    - Agent decisions (kyun kiya)
    """

    def __init__(self, db_path: str = None):
        self.db_path = Path(db_path or DB_PATH)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _conn(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS target_memory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    scan_type TEXT,
                    risk TEXT,
                    summary TEXT,
                    raw_json TEXT,
                    ts REAL DEFAULT (unixepoch())
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    agent TEXT,
                    severity TEXT,
                    title TEXT,
                    detail TEXT,
                    fix TEXT,
                    ts REAL DEFAULT (unixepoch())
                );
                CREATE TABLE IF NOT EXISTS agent_decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    agent TEXT,
                    action TEXT,
                    reason TEXT,
                    outcome TEXT,
                    ts REAL DEFAULT (unixepoch())
                );
                CREATE TABLE IF NOT EXISTS learned_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern TEXT UNIQUE,
                    action TEXT,
                    success_count INTEGER DEFAULT 1,
                    ts REAL DEFAULT (unixepoch())
                );
                CREATE INDEX IF NOT EXISTS idx_target ON target_memory(target);
                CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
            """)

    # ── Store ──────────────────────────────────────────────────────────────────

    def remember_scan(self, target: str, scan_type: str, risk: str,
                      summary: str, raw: dict = None):
        # SQLite memory
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO target_memory (target, scan_type, risk, summary, raw_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (target, scan_type, risk, summary[:500],
                 json.dumps(raw or {})[:10000])
            )
        # Unified DB
        try:
            from modules.database import SentinelDB
            SentinelDB.save_scan(target, scan_type, risk, raw or {'summary': summary}, source='brain')
            SentinelDB.remember(target, scan_type, risk, summary)
        except Exception:
            pass

    def remember_finding(self, target: str, agent: str, severity: str,
                         title: str, detail: str, fix: str = ''):
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO findings (target, agent, severity, title, detail, fix) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (target, agent, severity, title[:200], detail[:500], fix[:300])
            )
        # Unified DB
        try:
            from modules.database import SentinelDB
            SentinelDB.save_finding(target, title, severity, detail, fix, tool=agent)
        except Exception:
            pass

    def remember_decision(self, target: str, agent: str, action: str,
                          reason: str, outcome: str = ''):
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO agent_decisions (target, agent, action, reason, outcome) "
                "VALUES (?, ?, ?, ?, ?)",
                (target, agent, action, reason[:300], outcome[:300])
            )

    def learn_pattern(self, pattern: str, action: str):
        """Successful pattern yaad karo — next time same situation mein use karo"""
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO learned_patterns (pattern, action) VALUES (?, ?) "
                "ON CONFLICT(pattern) DO UPDATE SET success_count = success_count + 1",
                (pattern[:200], action)
            )

    # ── Recall ─────────────────────────────────────────────────────────────────

    def recall_target(self, target: str, limit: int = 5) -> list:
        """Target ke baare mein kya pata hai"""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT scan_type, risk, summary, ts FROM target_memory "
                "WHERE target = ? ORDER BY ts DESC LIMIT ?",
                (target, limit)
            ).fetchall()
        return [dict(r) for r in rows]

    def recall_findings(self, target: str) -> list:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT agent, severity, title, detail, fix FROM findings "
                "WHERE target = ? ORDER BY "
                "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 "
                "WHEN 'MEDIUM' THEN 2 ELSE 3 END",
                (target,)
            ).fetchall()
        return [dict(r) for r in rows]

    def recall_pattern(self, situation: str) -> str:
        """Similar situation mein kya kaam aaya tha"""
        with self._conn() as conn:
            # Simple keyword match
            words = situation.lower().split()[:5]
            for word in words:
                row = conn.execute(
                    "SELECT action FROM learned_patterns WHERE pattern LIKE ? "
                    "ORDER BY success_count DESC LIMIT 1",
                    (f'%{word}%',)
                ).fetchone()
                if row:
                    return row['action']
        return ''

    def get_context(self, target: str) -> str:
        """Agent ke liye context string banao"""
        history = self.recall_target(target)
        findings = self.recall_findings(target)

        parts = []
        if history:
            parts.append(f"Previous scans on {target}:")
            for h in history:
                ts = datetime.fromtimestamp(h['ts']).strftime('%Y-%m-%d %H:%M')
                parts.append(f"  [{ts}] {h['scan_type']} → risk={h['risk']}: {h['summary']}")

        if findings:
            parts.append(f"\nKnown findings ({len(findings)}):")
            for f in findings[:5]:
                parts.append(f"  [{f['severity']}] {f['title']}: {f['detail'][:80]}")

        return '\n'.join(parts) if parts else f"No previous data for {target}"

    def stats(self) -> dict:
        with self._conn() as conn:
            return {
                'scans':    conn.execute("SELECT COUNT(*) FROM target_memory").fetchone()[0],
                'findings': conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
                'decisions':conn.execute("SELECT COUNT(*) FROM agent_decisions").fetchone()[0],
                'patterns': conn.execute("SELECT COUNT(*) FROM learned_patterns").fetchone()[0],
            }
