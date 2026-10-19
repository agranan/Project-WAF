import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "waf.db"


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                request_id TEXT NOT NULL,
                source_ip TEXT,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                action TEXT NOT NULL
            )
        """)


def log_event(
    request_id: str,
    source_ip: str,
    method: str,
    path: str,
    rule_id: str,
    reason: str,
    action: str,
) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO security_events (
                request_id, source_ip, method, path,
                rule_id, reason, action
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            request_id, source_ip, method, path,
            rule_id, reason, action,
        ))