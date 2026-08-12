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

"""
SentinelProxy Database — SQLite request history
"""

import sqlite3
import json
import threading
import fnmatch
from pathlib import Path

DB_PATH = Path('/home/kali/osints/data/sentinel_proxy.db')


class ProxyDB:

    def __init__(self):
        self._lock        = threading.Lock()
        self._scope_cache = None
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        # Single persistent connection — WAL mode, shared across threads
        self._db = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute('PRAGMA journal_mode=WAL')
        self._db.execute('PRAGMA synchronous=NORMAL')
        self._db.execute('PRAGMA cache_size=-8000')
        self._db.execute('PRAGMA temp_store=MEMORY')
        self._init_db()

    def _init_db(self):
        with self._lock:
            self._db.executescript("""
                CREATE TABLE IF NOT EXISTS requests (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id       TEXT,
                    timestamp     TEXT,
                    method        TEXT,
                    url           TEXT,
                    host          TEXT,
                    path          TEXT,
                    headers       TEXT,
                    body          TEXT,
                    params        TEXT,
                    status_code   INTEGER,
                    resp_headers  TEXT DEFAULT '{}',
                    resp_body     TEXT,
                    resp_length   INTEGER,
                    content_type  TEXT,
                    response_time REAL DEFAULT 0,
                    ai_risk       TEXT DEFAULT 'UNKNOWN',
                    ai_vulns      TEXT DEFAULT '[]',
                    ai_summary    TEXT DEFAULT '',
                    flagged       INTEGER DEFAULT 0,
                    notes         TEXT DEFAULT '',
                    created_at    TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS scope_rules (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern    TEXT NOT NULL,
                    rule_type  TEXT DEFAULT 'include',
                    enabled    INTEGER DEFAULT 1,
                    created_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS saved_requests (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    name       TEXT,
                    method     TEXT,
                    url        TEXT,
                    headers    TEXT,
                    body       TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS intruder_results (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id  TEXT,
                    payload     TEXT,
                    payload2    TEXT DEFAULT '',
                    status_code INTEGER,
                    length      INTEGER,
                    response    TEXT,
                    interesting INTEGER DEFAULT 0,
                    created_at  TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS highlight_rules (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    match      TEXT NOT NULL,
                    field      TEXT DEFAULT 'URL',
                    color      TEXT DEFAULT 'Orange',
                    comment    TEXT DEFAULT '',
                    enabled    INTEGER DEFAULT 1,
                    created_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS match_replace_rules (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    match      TEXT NOT NULL,
                    replace    TEXT DEFAULT '',
                    target     TEXT DEFAULT 'Request Header',
                    rule_type  TEXT DEFAULT 'Literal',
                    enabled    INTEGER DEFAULT 1,
                    hits       INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS repeater_history (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    name       TEXT,
                    method     TEXT,
                    url        TEXT,
                    headers    TEXT,
                    body       TEXT,
                    response   TEXT,
                    status     INTEGER,
                    length     INTEGER,
                    resp_time  REAL,
                    created_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS organizer (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id  INTEGER,
                    method      TEXT,
                    url         TEXT,
                    host        TEXT,
                    path        TEXT,
                    headers     TEXT,
                    body        TEXT,
                    status_code INTEGER,
                    ai_risk     TEXT DEFAULT 'UNKNOWN',
                    ai_summary  TEXT DEFAULT '',
                    tags        TEXT DEFAULT '',
                    note        TEXT DEFAULT '',
                    saved_at    TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS collaborator_hits (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts         TEXT,
                    proto      TEXT,
                    token      TEXT,
                    src_ip     TEXT,
                    path       TEXT,
                    vuln       TEXT,
                    payload    TEXT DEFAULT '{}',
                    headers    TEXT DEFAULT '{}',
                    created_at TEXT DEFAULT (datetime('now'))
                );
            """)
            self._migrate()

    def _migrate(self):
        existing = {r[1] for r in self._db.execute('PRAGMA table_info(requests)').fetchall()}
        for col, sql in [
            ('resp_headers',  "ALTER TABLE requests ADD COLUMN resp_headers TEXT DEFAULT '{}'"),
            ('response_time', 'ALTER TABLE requests ADD COLUMN response_time REAL DEFAULT 0'),
            ('http_version',  "ALTER TABLE requests ADD COLUMN http_version TEXT DEFAULT 'HTTP/1.1'"),
        ]:
            if col not in existing:
                try:
                    self._db.execute(sql)
                except Exception:
                    pass
        int_cols = {r[1] for r in self._db.execute('PRAGMA table_info(intruder_results)').fetchall()}
        for col, sql in [
            ('payload',  "ALTER TABLE intruder_results ADD COLUMN payload TEXT DEFAULT ''"),
            ('payload2', "ALTER TABLE intruder_results ADD COLUMN payload2 TEXT DEFAULT ''"),
        ]:
            if col not in int_cols:
                try:
                    self._db.execute(sql)
                except Exception:
                    pass
        self._db.commit()

    # ── Requests ──────────────────────────────────────────────────────────────

    def save_request(self, flow: dict) -> int:
        body      = (flow.get('body') or '')[:10000]
        resp_body = (flow.get('resp_body') or '')[:50000]
        http_ver  = flow.get('http_version') or flow.get('http_ver', 'HTTP/1.1')
        with self._lock:
            cur = self._db.execute("""
                INSERT INTO requests
                (flow_id, timestamp, method, url, host, path,
                 headers, body, params, status_code, resp_headers,
                 resp_body, resp_length, content_type, response_time, http_version)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                flow.get('id', ''),
                flow.get('timestamp', ''),
                flow.get('method', ''),
                flow.get('url', ''),
                flow.get('host', ''),
                flow.get('path', ''),
                json.dumps(flow.get('headers', {})),
                body,
                json.dumps(flow.get('params', {})),
                flow.get('status_code'),
                json.dumps(flow.get('resp_headers', {})),
                resp_body,
                flow.get('resp_length', 0),
                flow.get('content_type', ''),
                flow.get('response_time', 0),
                http_ver,
            ))
            self._db.commit()
            return cur.lastrowid

    def update_response(self, flow_id: str, status_code: int, resp_headers: dict,
                        resp_body: str, resp_length: int, content_type: str,
                        response_time: float, http_version: str = 'HTTP/1.1'):
        with self._lock:
            self._db.execute("""
                UPDATE requests
                SET status_code=?, resp_headers=?, resp_body=?,
                    resp_length=?, content_type=?, response_time=?, http_version=?
                WHERE flow_id=?
            """, (
                status_code,
                json.dumps(resp_headers),
                resp_body[:50000],
                resp_length,
                content_type,
                response_time,
                http_version,
                flow_id,
            ))
            self._db.commit()

    def update_ai(self, row_id: int, risk: str, vulns: list, summary: str):
        with self._lock:
            self._db.execute("""
                UPDATE requests SET ai_risk=?, ai_vulns=?, ai_summary=?
                WHERE id=?
            """, (risk, json.dumps(vulns), summary, row_id))
            self._db.commit()

    def get_requests(self, limit=200, host_filter='', method_filter='',
                     flagged_only=False) -> list:
        q      = "SELECT * FROM requests WHERE 1=1"
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
        with self._lock:
            return [dict(r) for r in self._db.execute(q, params).fetchall()]

    def get_request(self, row_id: int) -> dict:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM requests WHERE id=?", (row_id,)
            ).fetchone()
            return dict(row) if row else {}

    def get_request_by_flow_id(self, flow_id: str) -> dict:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM requests WHERE flow_id=? ORDER BY id DESC LIMIT 1",
                (flow_id,)
            ).fetchone()
            return dict(row) if row else {}

    def flag_request(self, row_id: int, flagged: bool):
        with self._lock:
            self._db.execute(
                "UPDATE requests SET flagged=? WHERE id=?",
                (1 if flagged else 0, row_id)
            )
            self._db.commit()

    def add_note(self, row_id: int, note: str):
        with self._lock:
            self._db.execute(
                "UPDATE requests SET notes=? WHERE id=?",
                (note, row_id)
            )
            self._db.commit()

    def search_requests(self, keyword: str, limit: int = 500) -> list:
        kw = f'%{keyword}%'
        with self._lock:
            rows = self._db.execute("""
                SELECT * FROM requests
                WHERE url LIKE ? OR host LIKE ? OR path LIKE ?
                   OR body LIKE ? OR ai_summary LIKE ? OR ai_vulns LIKE ?
                ORDER BY id DESC LIMIT ?
            """, (kw, kw, kw, kw, kw, kw, limit)).fetchall()
        return [dict(r) for r in rows]

    def export_requests(self, row_ids: list = None) -> list:
        with self._lock:
            if row_ids:
                placeholders = ','.join('?' * len(row_ids))
                rows = self._db.execute(
                    f"SELECT * FROM requests WHERE id IN ({placeholders}) ORDER BY id",
                    row_ids).fetchall()
            else:
                rows = self._db.execute("SELECT * FROM requests ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def clear_history(self):
        with self._lock:
            self._db.execute("DELETE FROM requests")
            self._db.commit()

    def stats(self) -> dict:
        with self._lock:
            total   = self._db.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
            flagged = self._db.execute("SELECT COUNT(*) FROM requests WHERE flagged=1").fetchone()[0]
            risky   = self._db.execute(
                "SELECT COUNT(*) FROM requests WHERE ai_risk IN ('HIGH','CRITICAL')"
            ).fetchone()[0]
        return {'total': total, 'flagged': flagged, 'risky': risky}

    # ── Saved Requests / Repeater ─────────────────────────────────────────────

    def save_to_repeater(self, name: str, method: str, url: str,
                         headers: dict, body: str) -> int:
        with self._lock:
            cur = self._db.execute("""
                INSERT INTO saved_requests (name, method, url, headers, body)
                VALUES (?,?,?,?,?)
            """, (name, method, url, json.dumps(headers), body))
            self._db.commit()
            return cur.lastrowid

    def get_saved_requests(self) -> list:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM saved_requests ORDER BY id DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def save_repeater_history(self, method: str, url: str, headers: dict,
                               body: str, response: str, status: int,
                               length: int, resp_time: float) -> int:
        with self._lock:
            cur = self._db.execute("""
                INSERT INTO repeater_history
                (method, url, headers, body, response, status, length, resp_time)
                VALUES (?,?,?,?,?,?,?,?)
            """, (method, url, json.dumps(headers), body,
                  response[:20000], status, length, resp_time))
            self._db.commit()
            return cur.lastrowid

    def get_repeater_history(self, limit: int = 50) -> list:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM repeater_history ORDER BY id DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Intruder ──────────────────────────────────────────────────────────────

    def save_intruder_result(self, session_id: str, payload: str,
                              status: int, length: int, response: str,
                              interesting: bool = False, payload2: str = ''):
        with self._lock:
            self._db.execute("""
                INSERT INTO intruder_results
                (session_id, payload, payload2, status_code, length, response, interesting)
                VALUES (?,?,?,?,?,?,?)
            """, (session_id, payload, payload2, status, length,
                  response[:2000], 1 if interesting else 0))
            self._db.commit()

    def get_intruder_results(self, session_id: str) -> list:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM intruder_results WHERE session_id=? ORDER BY id",
                (session_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Scope Rules ───────────────────────────────────────────────────────────

    def add_scope_rule(self, pattern: str, rule_type: str = 'include') -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO scope_rules (pattern, rule_type) VALUES (?,?)",
                (pattern, rule_type))
            self._db.commit()
            self._scope_cache = None
            return cur.lastrowid

    def get_scope_rules(self) -> list:
        with self._lock:
            rows = self._db.execute("SELECT * FROM scope_rules ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def delete_scope_rule(self, rule_id: int):
        with self._lock:
            self._db.execute("DELETE FROM scope_rules WHERE id=?", (rule_id,))
            self._db.commit()
            self._scope_cache = None

    def toggle_scope_rule(self, rule_id: int, enabled: bool):
        with self._lock:
            self._db.execute("UPDATE scope_rules SET enabled=? WHERE id=?",
                (1 if enabled else 0, rule_id))
            self._db.commit()
            self._scope_cache = None

    def check_scope(self, host: str) -> bool:
        """Cached scope check — True if host is in scope (or no rules defined)."""
        if self._scope_cache is None:
            with self._lock:
                if self._scope_cache is None:
                    rows = self._db.execute("SELECT * FROM scope_rules ORDER BY id").fetchall()
                    self._scope_cache = [dict(r) for r in rows]
        active   = [r for r in self._scope_cache if r['enabled']]
        if not active:
            return True
        excludes = [r for r in active if r['rule_type'] == 'exclude']
        includes = [r for r in active if r['rule_type'] == 'include']
        for r in excludes:
            if fnmatch.fnmatch(host, r['pattern']) or host == r['pattern']:
                return False
        if includes:
            for r in includes:
                if fnmatch.fnmatch(host, r['pattern']) or host == r['pattern']:
                    return True
            return False
        return True

    # ── Highlight Rules ───────────────────────────────────────────────────────

    def add_highlight_rule(self, match: str, field: str, color: str,
                           comment: str = '') -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO highlight_rules (match, field, color, comment) VALUES (?,?,?,?)",
                (match, field, color, comment))
            self._db.commit()
            return cur.lastrowid

    def get_highlight_rules(self) -> list:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM highlight_rules ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def toggle_highlight_rule(self, rule_id: int, enabled: bool):
        with self._lock:
            self._db.execute("UPDATE highlight_rules SET enabled=? WHERE id=?",
                (1 if enabled else 0, rule_id))
            self._db.commit()

    def delete_highlight_rule(self, rule_id: int):
        with self._lock:
            self._db.execute("DELETE FROM highlight_rules WHERE id=?", (rule_id,))
            self._db.commit()

    # ── Match & Replace Rules ─────────────────────────────────────────────────

    def add_mr_rule(self, match: str, replace: str, target: str,
                    rule_type: str = 'Literal') -> int:
        with self._lock:
            cur = self._db.execute("""
                INSERT INTO match_replace_rules (match, replace, target, rule_type)
                VALUES (?,?,?,?)
            """, (match, replace, target, rule_type))
            self._db.commit()
            return cur.lastrowid

    def get_mr_rules(self) -> list:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM match_replace_rules ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def toggle_mr_rule(self, rule_id: int, enabled: bool):
        with self._lock:
            self._db.execute("UPDATE match_replace_rules SET enabled=? WHERE id=?",
                (1 if enabled else 0, rule_id))
            self._db.commit()

    def increment_mr_hits(self, rule_id: int):
        with self._lock:
            self._db.execute(
                "UPDATE match_replace_rules SET hits=hits+1 WHERE id=?",
                (rule_id,))
            self._db.commit()

    def delete_mr_rule(self, rule_id: int):
        with self._lock:
            self._db.execute("DELETE FROM match_replace_rules WHERE id=?", (rule_id,))
            self._db.commit()

    # ── Organizer ─────────────────────────────────────────────────────────────

    def save_to_organizer(self, request_id: int, req: dict) -> int:
        with self._lock:
            cur = self._db.execute("""
                INSERT INTO organizer
                (request_id, method, url, host, path, headers, body,
                 status_code, ai_risk, ai_summary)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (
                request_id,
                req.get('method', ''),
                req.get('url', ''),
                req.get('host', ''),
                req.get('path', ''),
                req.get('headers', '{}'),
                req.get('body', ''),
                req.get('status_code'),
                req.get('ai_risk', 'UNKNOWN'),
                req.get('ai_summary', ''),
            ))
            self._db.commit()
            return cur.lastrowid

    def get_organizer_items(self, tag_filter: str = '') -> list:
        with self._lock:
            if tag_filter:
                rows = self._db.execute(
                    "SELECT * FROM organizer WHERE tags LIKE ? ORDER BY id DESC",
                    (f'%{tag_filter}%',)).fetchall()
            else:
                rows = self._db.execute(
                    "SELECT * FROM organizer ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]

    def get_organizer_item(self, item_id: int) -> dict:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM organizer WHERE id=?", (item_id,)).fetchone()
        return dict(row) if row else {}

    def update_organizer_note(self, item_id: int, note: str):
        with self._lock:
            self._db.execute(
                "UPDATE organizer SET note=? WHERE id=?", (note, item_id))
            self._db.commit()

    def add_organizer_tag(self, item_id: int, tag: str):
        with self._lock:
            row = self._db.execute(
                "SELECT tags FROM organizer WHERE id=?", (item_id,)).fetchone()
            if row:
                existing = row[0] or ''
                tags = [t.strip() for t in existing.split(',') if t.strip()]
                if tag not in tags:
                    tags.append(tag)
                self._db.execute(
                    "UPDATE organizer SET tags=? WHERE id=?",
                    (', '.join(tags), item_id))
                self._db.commit()

    def delete_organizer_item(self, item_id: int):
        with self._lock:
            self._db.execute("DELETE FROM organizer WHERE id=?", (item_id,))
            self._db.commit()

    # ── Collaborator ──────────────────────────────────────────────────────────

    def save_collaborator_hit(self, hit: dict):
        with self._lock:
            self._db.execute("""
                INSERT INTO collaborator_hits
                (ts, proto, token, src_ip, path, vuln, payload, headers)
                VALUES (?,?,?,?,?,?,?,?)
            """, (
                hit.get('ts', ''),
                hit.get('proto', 'HTTP'),
                hit.get('token', ''),
                hit.get('src_ip', ''),
                hit.get('path', ''),
                hit.get('vuln', ''),
                json.dumps(hit.get('payload', {})),
                json.dumps(hit.get('headers', {})),
            ))
            self._db.commit()

    def get_collaborator_hits(self, limit: int = 200) -> list:
        with self._lock:
            try:
                rows = self._db.execute(
                    "SELECT * FROM collaborator_hits ORDER BY id DESC LIMIT ?",
                    (limit,)).fetchall()
                return [dict(r) for r in rows]
            except Exception:
                return []
