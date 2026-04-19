"""
SentinelProxy Database — SQLite request history
"""

import sqlite3
import json
import threading
from datetime import datetime
from pathlib import Path

DB_PATH = Path('/home/kali/osints/data/sentinel_proxy.db')


class ProxyDB:

    def __init__(self):
        self._lock = threading.Lock()
        self._init_db()

    def _conn(self):
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS requests (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id     TEXT,
                    timestamp   TEXT,
                    method      TEXT,
                    url         TEXT,
                    host        TEXT,
                    path        TEXT,
                    headers     TEXT,
                    body        TEXT,
                    params      TEXT,
                    status_code INTEGER,
                    resp_body   TEXT,
                    resp_length INTEGER,
                    content_type TEXT,
                    ai_risk     TEXT DEFAULT 'UNKNOWN',
                    ai_vulns    TEXT DEFAULT '[]',
                    ai_summary  TEXT DEFAULT '',
                    flagged     INTEGER DEFAULT 0,
                    notes       TEXT DEFAULT '',
                    created_at  TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS saved_requests (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    name        TEXT,
                    method      TEXT,
                    url         TEXT,
                    headers     TEXT,
                    body        TEXT,
                    created_at  TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS intruder_results (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id  TEXT,
                    payload     TEXT,
                    status_code INTEGER,
                    length      INTEGER,
                    response    TEXT,
                    interesting INTEGER DEFAULT 0,
                    created_at  TEXT DEFAULT (datetime('now'))
                );
            """)

    def save_request(self, flow: dict) -> int:
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute("""
                    INSERT INTO requests
                    (flow_id, timestamp, method, url, host, path,
                     headers, body, params, status_code, resp_body,
                     resp_length, content_type)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    flow.get('id',''),
                    flow.get('timestamp',''),
                    flow.get('method',''),
                    flow.get('url',''),
                    flow.get('host',''),
                    flow.get('path',''),
                    json.dumps(flow.get('headers',{})),
                    flow.get('body',''),
                    json.dumps(flow.get('params',{})),
                    flow.get('status_code'),
                    flow.get('resp_body',''),
                    flow.get('resp_length',0),
                    flow.get('content_type',''),
                ))
                return cur.lastrowid

    def update_ai(self, row_id: int, risk: str, vulns: list, summary: str):
        with self._lock:
            with self._conn() as conn:
                conn.execute("""
                    UPDATE requests SET ai_risk=?, ai_vulns=?, ai_summary=?
                    WHERE id=?
                """, (risk, json.dumps(vulns), summary, row_id))

    def get_requests(self, limit=200, host_filter='', method_filter='',
                     flagged_only=False) -> list:
        with self._conn() as conn:
            q = "SELECT * FROM requests WHERE 1=1"
            params = []
            if host_filter:
                q += " AND host LIKE ?"
                params.append(f'%{host_filter}%')
            if method_filter:
                q += " AND method=?"
                params.append(method_filter)
            if flagged_only:
                q += " AND flagged=1"
            q += " ORDER BY id DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(q, params).fetchall()
            return [dict(r) for r in rows]

    def get_request(self, row_id: int) -> dict:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM requests WHERE id=?", (row_id,)
            ).fetchone()
            return dict(row) if row else {}

    def flag_request(self, row_id: int, flagged: bool):
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE requests SET flagged=? WHERE id=?",
                    (1 if flagged else 0, row_id)
                )

    def add_note(self, row_id: int, note: str):
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE requests SET notes=? WHERE id=?",
                    (note, row_id)
                )

    def save_to_repeater(self, name: str, method: str, url: str,
                         headers: dict, body: str) -> int:
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute("""
                    INSERT INTO saved_requests (name, method, url, headers, body)
                    VALUES (?,?,?,?,?)
                """, (name, method, url, json.dumps(headers), body))
                return cur.lastrowid

    def get_saved_requests(self) -> list:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM saved_requests ORDER BY id DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def save_intruder_result(self, session_id: str, payload: str,
                              status: int, length: int, response: str,
                              interesting: bool = False):
        with self._lock:
            with self._conn() as conn:
                conn.execute("""
                    INSERT INTO intruder_results
                    (session_id, payload, status_code, length, response, interesting)
                    VALUES (?,?,?,?,?,?)
                """, (session_id, payload, status, length, response[:2000],
                      1 if interesting else 0))

    def get_intruder_results(self, session_id: str) -> list:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM intruder_results WHERE session_id=? ORDER BY id",
                (session_id,)
            ).fetchall()
            return [dict(r) for r in rows]

    def clear_history(self):
        with self._lock:
            with self._conn() as conn:
                conn.execute("DELETE FROM requests")

    def stats(self) -> dict:
        with self._conn() as conn:
            total   = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
            flagged = conn.execute("SELECT COUNT(*) FROM requests WHERE flagged=1").fetchone()[0]
            risky   = conn.execute(
                "SELECT COUNT(*) FROM requests WHERE ai_risk IN ('HIGH','CRITICAL')"
            ).fetchone()[0]
            return {'total': total, 'flagged': flagged, 'risky': risky}
