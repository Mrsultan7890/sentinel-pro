"""
Sentinel Unified Database
=========================
Ek hi DB — Brain, RL, Monitor, Agents, Memory sab yahan se kaam karte hain.
SQLite — fast, no server needed, Kali pe perfect.

Tables:
  scans      — har scan ka record
  findings   — vulnerabilities
  iocs       — IPs, domains, emails, hashes
  decisions  — brain ke decisions + RL episodes
  memory     — long-term target memory
  rl_episodes— RL training history
  tool_stats — kaunsa tool kitna effective hai

Author: @who_is_the_black_hat
"""

import json
import logging
import time
from datetime import datetime
from pathlib import Path

from sqlalchemy import (create_engine, Column, String, Float, Integer,
                        Text, DateTime, Boolean, Index)
from sqlalchemy.orm import DeclarativeBase, Session
from sqlalchemy import func

logger = logging.getLogger(__name__)

import config as _cfg
DB_PATH = _cfg.BASE_DIR / 'data' / 'sentinel.db'
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

from sqlalchemy.pool import NullPool

def _creator():
    import sqlite3 as _s
    c = _s.connect(str(DB_PATH), timeout=60.0, check_same_thread=False)
    c.execute('PRAGMA journal_mode=WAL')
    c.execute('PRAGMA busy_timeout=60000')
    c.execute('PRAGMA synchronous=NORMAL')
    return c

engine = create_engine('sqlite://', creator=_creator, echo=False, poolclass=NullPool)


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = 'scans'
    id         = Column(Integer, primary_key=True, autoincrement=True)
    target     = Column(String, index=True)
    scan_type  = Column(String)
    risk       = Column(String)
    summary    = Column(Text)
    raw_json   = Column(Text)
    source     = Column(String, default='manual')  # manual/brain/rl/monitor
    created_at = Column(DateTime, default=datetime.utcnow)


class Finding(Base):
    __tablename__ = 'findings'
    id         = Column(Integer, primary_key=True, autoincrement=True)
    target     = Column(String, index=True)
    vuln_type  = Column(String)
    severity   = Column(String)
    detail     = Column(Text)
    fix        = Column(Text)
    tool       = Column(String)
    confirmed  = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class IOC(Base):
    __tablename__ = 'iocs'
    id         = Column(Integer, primary_key=True, autoincrement=True)
    value      = Column(String, index=True, unique=True)
    ioc_type   = Column(String)   # ip/domain/email/hash/url
    threat     = Column(String)
    confidence = Column(Float)
    source     = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


class Decision(Base):
    __tablename__ = 'decisions'
    id         = Column(Integer, primary_key=True, autoincrement=True)
    target     = Column(String, index=True)
    agent      = Column(String)   # brain/rl/monitor
    action     = Column(String)
    reason     = Column(Text)
    priority   = Column(String)
    outcome    = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


class Memory(Base):
    __tablename__ = 'memory'
    id         = Column(Integer, primary_key=True, autoincrement=True)
    target     = Column(String, index=True)
    scan_type  = Column(String)
    risk       = Column(String)
    summary    = Column(Text)
    pattern    = Column(String)   # learned pattern
    created_at = Column(DateTime, default=datetime.utcnow)


class RLEpisode(Base):
    __tablename__ = 'rl_episodes'
    id           = Column(Integer, primary_key=True, autoincrement=True)
    target       = Column(String)
    episode      = Column(Integer)
    tools_used   = Column(Text)   # JSON list
    total_reward = Column(Float)
    findings     = Column(Integer)
    risk         = Column(String)
    epsilon      = Column(Float)
    created_at   = Column(DateTime, default=datetime.utcnow)


class ToolStat(Base):
    __tablename__ = 'tool_stats'
    id           = Column(Integer, primary_key=True, autoincrement=True)
    tool         = Column(String, unique=True)
    runs         = Column(Integer, default=0)
    findings     = Column(Integer, default=0)
    avg_time     = Column(Float, default=0)
    effectiveness= Column(Float, default=0.5)  # findings/runs ratio
    updated_at   = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(engine)

# WAL mode is set per-connection via _creator()

# Auto-migration: add missing columns to existing tables
def _run_migrations():
    """Add missing columns to existing DB without dropping data."""
    import sqlite3 as _sqlite3
    conn = None
    try:
        conn = _sqlite3.connect(str(DB_PATH), timeout=30.0)
        cur  = conn.cursor()
        migrations = [
            # (table, column, definition)
            ('decisions', 'agent',   "VARCHAR DEFAULT 'unknown'"),
            ('decisions', 'outcome', "TEXT DEFAULT ''"),
        ]
        for table, col, defn in migrations:
            try:
                cur.execute(f'ALTER TABLE {table} ADD COLUMN {col} {defn}')
                conn.commit()
                logger.debug(f"Migration: Added {table}.{col}")
            except _sqlite3.OperationalError:
                pass  # column already exists
    except Exception as e:
        logger.error(f"Migration failed: {e}")
    finally:
        if conn:
            conn.close()

_run_migrations()


class SentinelDB:
    """Unified DB interface — sab components yahi use karein"""

    # ── Scans ─────────────────────────────────────────────────────────────────

    @staticmethod
    def save_scan(target: str, scan_type: str, risk: str,
                  summary: dict, source: str = 'manual') -> int:
        for attempt in range(3):
            try:
                with Session(engine) as s:
                    scan = Scan(
                        target=target, scan_type=scan_type, risk=risk,
                        summary=str(summary)[:500],
                        raw_json=json.dumps(summary, default=str)[:10000],
                        source=source
                    )
                    s.add(scan)
                    s.commit()
                    return scan.id
            except Exception as e:
                if 'locked' in str(e).lower() and attempt < 2:
                    time.sleep(1 + attempt)
                    continue
                logger.error(f"Failed to save scan for {target}: {e}")
                return -1
        return -1

    @staticmethod
    def get_target_history(target: str, limit: int = 10) -> list:
        try:
            with Session(engine) as s:
                rows = s.query(Scan).filter(Scan.target.contains(target))\
                         .order_by(Scan.created_at.desc()).limit(limit).all()
                return [{'type': r.scan_type, 'risk': r.risk,
                         'summary': r.summary, 'source': r.source,
                         'date': str(r.created_at)[:16]} for r in rows]
        except Exception as e:
            logger.error(f"Failed to get history for {target}: {e}")
            return []

    # ── Findings ──────────────────────────────────────────────────────────────

    @staticmethod
    def save_finding(target: str, vuln_type: str, severity: str,
                     detail: str, fix: str = '', tool: str = '') -> int:
        try:
            with Session(engine) as s:
                f = Finding(target=target, vuln_type=vuln_type, severity=severity,
                            detail=detail[:500], fix=fix[:300], tool=tool)
                s.add(f)
                s.commit()
                return f.id
        except Exception as e:
            logger.error(f"Failed to save finding for {target}: {e}")
            return -1

    @staticmethod
    def get_findings(target: str) -> list:
        try:
            with Session(engine) as s:
                rows = s.query(Finding).filter(Finding.target == target)\
                         .order_by(Finding.severity).all()
                return [{'type': r.vuln_type, 'severity': r.severity,
                         'detail': r.detail, 'fix': r.fix, 'tool': r.tool} for r in rows]
        except Exception as e:
            logger.error(f"Failed to get findings for {target}: {e}")
            return []

    @staticmethod
    def get_critical_findings(limit: int = 20) -> list:
        try:
            with Session(engine) as s:
                rows = s.query(Finding).filter(
                    Finding.severity.in_(['CRITICAL', 'HIGH'])
                ).order_by(Finding.created_at.desc()).limit(limit).all()
                return [{'target': r.target, 'type': r.vuln_type,
                         'severity': r.severity, 'detail': r.detail} for r in rows]
        except Exception as e:
            logger.error(f"Failed to get critical findings: {e}")
            return []

    # ── IOCs ──────────────────────────────────────────────────────────────────

    @staticmethod
    def save_ioc(value: str, ioc_type: str, threat: str,
                 confidence: float = 0.8, source: str = 'scan'):
        try:
            with Session(engine) as s:
                ioc = IOC(value=value, ioc_type=ioc_type, threat=threat,
                          confidence=confidence, source=source)
                s.add(ioc)
                s.commit()
        except Exception as e:
            logger.debug(f"IOC already exists or save failed: {value} - {e}")

    @staticmethod
    def check_ioc(value: str) -> dict:
        with Session(engine) as s:
            ioc = s.query(IOC).filter(IOC.value == value).first()
            if ioc:
                return {'found': True, 'threat': ioc.threat,
                        'confidence': ioc.confidence, 'source': ioc.source}
            return {'found': False}

    # ── Decisions ─────────────────────────────────────────────────────────────

    @staticmethod
    def save_decision(target: str, agent: str, action: str,
                      reason: str, priority: str, outcome: str = ''):
        try:
            with Session(engine) as s:
                d = Decision(target=target, agent=agent, action=action,
                             reason=reason[:300], priority=priority, outcome=outcome[:300])
                s.add(d)
                s.commit()
        except Exception as e:
            logger.error(f"Failed to save decision for {target}: {e}")

    # ── Memory ────────────────────────────────────────────────────────────────

    @staticmethod
    def remember(target: str, scan_type: str, risk: str,
                 summary: str, pattern: str = ''):
        for attempt in range(3):
            try:
                with Session(engine) as s:
                    m = Memory(target=target, scan_type=scan_type, risk=risk,
                               summary=summary[:500], pattern=pattern[:200])
                    s.add(m)
                    s.commit()
                return
            except Exception as e:
                if 'locked' in str(e).lower() and attempt < 2:
                    time.sleep(1 + attempt)
                    continue
                logger.error(f"Failed to save memory for {target}: {e}")
                return

    @staticmethod
    def recall(target: str, limit: int = 5) -> list:
        with Session(engine) as s:
            rows = s.query(Memory).filter(Memory.target == target)\
                     .order_by(Memory.created_at.desc()).limit(limit).all()
            return [{'scan_type': r.scan_type, 'risk': r.risk,
                     'summary': r.summary, 'date': str(r.created_at)[:16]} for r in rows]

    # ── RL Episodes ───────────────────────────────────────────────────────────

    @staticmethod
    def save_rl_episode(target: str, episode: int, tools_used: list,
                        total_reward: float, findings: int,
                        risk: str, epsilon: float):
        try:
            with Session(engine) as s:
                ep = RLEpisode(
                    target=target, episode=episode,
                    tools_used=json.dumps(tools_used),
                    total_reward=total_reward, findings=findings,
                    risk=risk, epsilon=epsilon
                )
                s.add(ep)
                s.commit()
        except Exception as e:
            logger.error(f"Failed to save RL episode for {target}: {e}")

    @staticmethod
    def get_rl_history(limit: int = 50) -> list:
        with Session(engine) as s:
            rows = s.query(RLEpisode).order_by(
                RLEpisode.created_at.desc()).limit(limit).all()
            results = []
            for r in rows:
                try:
                    tools = json.loads(r.tools_used or '[]')
                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid JSON in RL episode {r.id}: {e}")
                    tools = []
                results.append({
                    'target': r.target, 'episode': r.episode,
                    'reward': r.total_reward, 'findings': r.findings,
                    'risk': r.risk, 'tools': tools
                })
            return results

    # ── Tool Stats ────────────────────────────────────────────────────────────

    @staticmethod
    def update_tool_stat(tool: str, found_something: bool, time_taken: float):
        with Session(engine) as s:
            stat = s.query(ToolStat).filter(ToolStat.tool == tool).first()
            if not stat:
                stat = ToolStat(tool=tool, runs=0, findings=0, avg_time=0)
                s.add(stat)
            stat.runs     += 1
            stat.findings += 1 if found_something else 0
            stat.avg_time  = (stat.avg_time * (stat.runs - 1) + time_taken) / stat.runs
            stat.effectiveness = stat.findings / stat.runs
            stat.updated_at    = datetime.utcnow()
            s.commit()

    @staticmethod
    def get_tool_stats() -> list:
        with Session(engine) as s:
            rows = s.query(ToolStat).order_by(
                ToolStat.effectiveness.desc()).all()
            return [{'tool': r.tool, 'runs': r.runs, 'findings': r.findings,
                     'effectiveness': round(r.effectiveness, 3),
                     'avg_time': round(r.avg_time, 1)} for r in rows]

    # ── Stats ─────────────────────────────────────────────────────────────────

    @staticmethod
    def stats() -> dict:
        with Session(engine) as s:
            return {
                'scans':     s.query(func.count(Scan.id)).scalar(),
                'findings':  s.query(func.count(Finding.id)).scalar(),
                'iocs':      s.query(func.count(IOC.id)).scalar(),
                'decisions': s.query(func.count(Decision.id)).scalar(),
                'memory':    s.query(func.count(Memory.id)).scalar(),
                'rl_episodes': s.query(func.count(RLEpisode.id)).scalar(),
            }

    @staticmethod
    def target_risk_summary() -> list:
        """Har target ka latest risk level"""
        with Session(engine) as s:
            rows = s.query(
                Scan.target,
                func.max(Scan.created_at).label('latest'),
                Scan.risk
            ).group_by(Scan.target).all()
            return [{'target': r.target, 'risk': r.risk,
                     'last_scan': str(r.latest)[:16]} for r in rows]
