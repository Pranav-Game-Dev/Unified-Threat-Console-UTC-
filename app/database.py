"""
UTC — Database Layer
app/database.py
"""

import json
import sqlite3
import logging
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

log = logging.getLogger("utc.database")

BASE_DIR = Path(__file__).parent.parent.resolve()
DB_PATH  = BASE_DIR / "data" / "events.db"

_db_lock = threading.Lock()

_SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS network_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    src_ip        TEXT,
    dst_ip        TEXT,
    src_port      INTEGER,
    dst_port      INTEGER,
    protocol      TEXT,
    packet_size   INTEGER,
    flags         TEXT,
    suspicious    INTEGER NOT NULL DEFAULT 0,
    note          TEXT
);
CREATE INDEX IF NOT EXISTS idx_ne_ts   ON network_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ne_ip   ON network_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_ne_susp ON network_events(suspicious);

CREATE TABLE IF NOT EXISTS ids_alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    severity      TEXT    NOT NULL DEFAULT 'medium',
    rule_name     TEXT    NOT NULL,
    src_ip        TEXT,
    dst_ip        TEXT,
    dst_port      INTEGER,
    protocol      TEXT,
    description   TEXT,
    raw_data      TEXT,
    acknowledged  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ia_ts   ON ids_alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ia_sev  ON ids_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_ia_ip   ON ids_alerts(src_ip);

CREATE TABLE IF NOT EXISTS vuln_reports (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    target_url     TEXT    NOT NULL,
    scan_type      TEXT,
    status         TEXT    NOT NULL DEFAULT 'running',
    total_tests    INTEGER DEFAULT 0,
    vulns_found    INTEGER DEFAULT 0,
    findings       TEXT,
    completed_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_vr_ts ON vuln_reports(timestamp DESC);

CREATE TABLE IF NOT EXISTS system_logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    source        TEXT    NOT NULL,
    level         TEXT    NOT NULL DEFAULT 'info',
    message       TEXT    NOT NULL,
    flagged       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sl_ts      ON system_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_sl_source  ON system_logs(source);
CREATE INDEX IF NOT EXISTS idx_sl_level   ON system_logs(level);
CREATE INDEX IF NOT EXISTS idx_sl_flagged ON system_logs(flagged);

CREATE TABLE IF NOT EXISTS file_transfers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    direction       TEXT    NOT NULL,
    original_name   TEXT    NOT NULL,
    stored_name     TEXT    NOT NULL,
    file_size_bytes INTEGER,
    encryption_alg  TEXT    DEFAULT 'AES-256-GCM',
    checksum_sha256 TEXT,
    status          TEXT    NOT NULL DEFAULT 'ok'
);
CREATE INDEX IF NOT EXISTS idx_ft_ts ON file_transfers(timestamp DESC);
"""


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        with _connect() as conn:
            conn.executescript(_SCHEMA_SQL)
        log.info(f"Database ready: {DB_PATH}")
    except sqlite3.Error as exc:
        log.critical(f"Database init failed: {exc}")
        raise


@contextmanager
def _connect() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def execute_write(sql: str, params: tuple = ()) -> int:
    with _db_lock:
        try:
            with _connect() as conn:
                cur = conn.execute(sql, params)
                return cur.lastrowid or cur.rowcount or 0
        except sqlite3.Error as exc:
            log.error(f"DB write error: {exc} | SQL: {sql[:80]}")
            return -1


def execute_read(sql: str, params: tuple = (), one: bool = False) -> Any:
    with _db_lock:
        try:
            with _connect() as conn:
                cur = conn.execute(sql, params)
                if one:
                    row = cur.fetchone()
                    return dict(row) if row else None
                return [dict(r) for r in cur.fetchall()]
        except sqlite3.Error as exc:
            log.error(f"DB read error: {exc} | SQL: {sql[:80]}")
            return None if one else []


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Network Events ─────────────────────────────────────────────────────────────
def insert_network_event(src_ip, dst_ip, src_port, dst_port,
                          protocol, packet_size, flags="",
                          suspicious=False, note="") -> int:
    return execute_write(
        """INSERT INTO network_events
           (timestamp,src_ip,dst_ip,src_port,dst_port,protocol,packet_size,flags,suspicious,note)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (now_utc(), src_ip, dst_ip, src_port, dst_port,
         protocol, packet_size, flags, int(suspicious), note),
    )


def get_network_events(limit=100, suspicious_only=False) -> list:
    if suspicious_only:
        return execute_read(
            "SELECT * FROM network_events WHERE suspicious=1 ORDER BY timestamp DESC LIMIT ?",
            (limit,))
    return execute_read(
        "SELECT * FROM network_events ORDER BY timestamp DESC LIMIT ?", (limit,))


def get_network_stats() -> dict:
    total   = execute_read("SELECT COUNT(*) as c FROM network_events", one=True)
    susp    = execute_read("SELECT COUNT(*) as c FROM network_events WHERE suspicious=1", one=True)
    proto   = execute_read(
        "SELECT protocol, COUNT(*) as cnt FROM network_events GROUP BY protocol ORDER BY cnt DESC LIMIT 5")
    top_src = execute_read(
        "SELECT src_ip, COUNT(*) as cnt FROM network_events GROUP BY src_ip ORDER BY cnt DESC LIMIT 5")
    return {
        "total_packets":     total["c"] if total else 0,
        "suspicious_packets": susp["c"] if susp else 0,
        "protocols":  proto,
        "top_sources": top_src,
    }


# ── IDS Alerts ─────────────────────────────────────────────────────────────────
def insert_ids_alert(severity, rule_name, src_ip="", dst_ip="",
                      dst_port=0, protocol="", description="", raw_data="") -> int:
    return execute_write(
        """INSERT INTO ids_alerts
           (timestamp,severity,rule_name,src_ip,dst_ip,dst_port,protocol,description,raw_data)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (now_utc(), severity, rule_name, src_ip, dst_ip,
         dst_port, protocol, description, raw_data),
    )


def get_ids_alerts(limit=100, severity=None) -> list:
    if severity:
        return execute_read(
            "SELECT * FROM ids_alerts WHERE severity=? ORDER BY timestamp DESC LIMIT ?",
            (severity, limit))
    return execute_read(
        "SELECT * FROM ids_alerts ORDER BY timestamp DESC LIMIT ?", (limit,))


def acknowledge_alert(alert_id: int) -> int:
    return execute_write("UPDATE ids_alerts SET acknowledged=1 WHERE id=?", (alert_id,))


def get_alert_counts() -> dict:
    rows = execute_read("SELECT severity, COUNT(*) as cnt FROM ids_alerts GROUP BY severity")
    return {r["severity"]: r["cnt"] for r in rows}


# ── Vuln Reports ───────────────────────────────────────────────────────────────
def insert_vuln_report(target_url, scan_type="full") -> int:
    return execute_write(
        "INSERT INTO vuln_reports (timestamp,target_url,scan_type,status) VALUES (?,?,?,?)",
        (now_utc(), target_url, scan_type, "running"),
    )


def update_vuln_report(report_id, status, total_tests, vulns_found, findings_json) -> int:
    return execute_write(
        """UPDATE vuln_reports
           SET status=?,total_tests=?,vulns_found=?,findings=?,completed_at=?
           WHERE id=?""",
        (status, total_tests, vulns_found, findings_json, now_utc(), report_id),
    )


def get_vuln_reports(limit=50) -> list:
    return execute_read(
        "SELECT id,timestamp,target_url,scan_type,status,total_tests,vulns_found,completed_at "
        "FROM vuln_reports ORDER BY timestamp DESC LIMIT ?", (limit,))


def get_vuln_report(report_id) -> dict | None:
    return execute_read("SELECT * FROM vuln_reports WHERE id=?", (report_id,), one=True)


# ── System Logs ────────────────────────────────────────────────────────────────
def insert_log(source, level, message, flagged=False) -> int:
    return execute_write(
        "INSERT INTO system_logs (timestamp,source,level,message,flagged) VALUES (?,?,?,?,?)",
        (now_utc(), source, level, message, int(flagged)),
    )


def get_logs(limit=200, source=None, level=None, flagged_only=False) -> list:
    conditions, params = [], []
    if source:       conditions.append("source=?");  params.append(source)
    if level:        conditions.append("level=?");   params.append(level)
    if flagged_only: conditions.append("flagged=1")
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params.append(limit)
    return execute_read(
        f"SELECT * FROM system_logs {where} ORDER BY timestamp DESC LIMIT ?",
        tuple(params))


def get_log_stats() -> dict:
    total   = execute_read("SELECT COUNT(*) as c FROM system_logs", one=True)
    flagged = execute_read("SELECT COUNT(*) as c FROM system_logs WHERE flagged=1", one=True)
    warns   = execute_read(
        "SELECT COUNT(*) as c FROM system_logs WHERE level IN ('warning','error','critical')", one=True)
    return {
        "total":   total["c"]   if total   else 0,
        "flagged": flagged["c"] if flagged else 0,
        "warnings": warns["c"] if warns   else 0,
    }


# ── File Transfers ─────────────────────────────────────────────────────────────
def insert_file_transfer(direction, original_name, stored_name,
                          file_size_bytes=0, checksum_sha256="", status="ok") -> int:
    return execute_write(
        """INSERT INTO file_transfers
           (timestamp,direction,original_name,stored_name,file_size_bytes,checksum_sha256,status)
           VALUES (?,?,?,?,?,?,?)""",
        (now_utc(), direction, original_name, stored_name,
         file_size_bytes, checksum_sha256, status),
    )


def get_file_transfers(limit=100) -> list:
    return execute_read(
        "SELECT * FROM file_transfers ORDER BY timestamp DESC LIMIT ?", (limit,))
