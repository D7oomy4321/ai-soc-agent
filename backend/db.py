"""
db.py - سجل قرارات المحللين (Audit Log) في SQLite
ملف واحد soc_audit.db بجانب الكود، لا يحتاج تثبيت أي شيء.
"""
import sqlite3
from datetime import datetime, timezone

from config import DB_PATH


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with connect() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT, action TEXT, target TEXT, decision TEXT,
            analyst_note TEXT, severity TEXT, decided_at TEXT, received_at TEXT)""")


def save_decision(d: dict) -> int:
    """يحفظ قرارًا ويرجع رقمه. علامات ? = Parameterized Query (حماية من SQL Injection)."""
    with connect() as conn:
        cur = conn.execute(
            """INSERT INTO audit_log
               (incident_id, action, target, decision, analyst_note, severity, decided_at, received_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (d.get("incident_id"), d.get("action"), d.get("target"), d.get("decision"),
             d.get("analyst_note"), d.get("severity"), d.get("decided_at"),
             datetime.now(timezone.utc).isoformat()),
        )
        return cur.lastrowid


def list_decisions(limit: int = 100) -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]
