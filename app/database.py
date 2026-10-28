
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "waf.db"

SEVERITY_LEVELS = {
    "SQLI-001": "High",
    "XSS-001": "High",
    "CMD-001": "High",
    "PATH-001": "High",
    "AUTH-001": "Medium",
    "RATE-001": "Medium",
    "RATE-002": "High",
    "BODY-001": "Medium",
    "BODY-002": "Low",
}


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
                action TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'Low'
            )
        """)

        # Migrate existing databases without deleting existing events.
        columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(security_events)"
            ).fetchall()
        }

        if "severity" not in columns:
            conn.execute("""
                ALTER TABLE security_events
                ADD COLUMN severity TEXT NOT NULL DEFAULT 'Low'
            """)

        # Assign severity to events already in the database.
        for rule_id, severity in SEVERITY_LEVELS.items():
            conn.execute("""
                UPDATE security_events
                SET severity = ?
                WHERE rule_id = ?
            """, (severity, rule_id))


def log_event(
    request_id: str,
    source_ip: str,
    method: str,
    path: str,
    rule_id: str,
    reason: str,
    action: str,
) -> None:
    severity = SEVERITY_LEVELS.get(rule_id, "Low")

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO security_events (
                request_id, source_ip, method, path,
                rule_id, reason, action, severity
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            request_id, source_ip, method, path,
            rule_id, reason, action, severity,
        ))
