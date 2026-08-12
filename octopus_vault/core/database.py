import sqlite3
import os
from pathlib import Path

DB_PATH = Path.home() / ".octopus_vault" / "vault.db"

def get_connection():
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    conn = get_connection()
    c = conn.cursor()

    c.executescript("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'Active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            aliases TEXT,
            emails TEXT,
            phones TEXT,
            usernames TEXT,
            addresses TEXT,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            subject_id INTEGER,
            type TEXT NOT NULL,
            title TEXT,
            content TEXT,
            source TEXT,
            file_path TEXT,
            tags TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
            FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS timeline_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            event_date TEXT,
            linked_evidence_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            title TEXT,
            content TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            color TEXT DEFAULT '#E94560'
        );

        CREATE TABLE IF NOT EXISTS case_tags (
            case_id INTEGER,
            tag_id INTEGER,
            PRIMARY KEY (case_id, tag_id),
            FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
            FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS board_nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER,
            node_type TEXT NOT NULL,
            title TEXT,
            content TEXT,
            x REAL DEFAULT 100,
            y REAL DEFAULT 100,
            width REAL DEFAULT 180,
            height REAL DEFAULT 120,
            color TEXT DEFAULT '#FFFF88',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS board_connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER,
            from_node_id INTEGER NOT NULL,
            to_node_id INTEGER NOT NULL,
            label TEXT,
            strength INTEGER DEFAULT 2,
            FOREIGN KEY (from_node_id) REFERENCES board_nodes(id) ON DELETE CASCADE,
            FOREIGN KEY (to_node_id) REFERENCES board_nodes(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS board_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER,
            title TEXT DEFAULT 'Group',
            color TEXT DEFAULT '#FFAA0033',
            x REAL DEFAULT 0,
            y REAL DEFAULT 0,
            width REAL DEFAULT 300,
            height REAL DEFAULT 200
        );
    """)

    # migrations for existing DBs
    try:
        conn.execute("ALTER TABLE board_connections ADD COLUMN strength INTEGER DEFAULT 2")
        conn.commit()
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE board_nodes ADD COLUMN group_id INTEGER DEFAULT NULL")
        conn.commit()
    except Exception:
        pass

    conn.commit()
    conn.close()
