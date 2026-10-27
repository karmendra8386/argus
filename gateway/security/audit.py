"""Audit log: every security decision, queryable per key/task.

PII snippets are supplied from redacted text, and blocked events from the
secrets detector store a placeholder instead of any payload text. This is
the compliance backbone: who sent what, what fired, what happened.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass


@dataclass
class AuditEvent:
    key_id: int
    task_id: str | None
    direction: str          # "in" | "out"
    detector: str
    category: str
    action: str             # "block" | "redact" | "flag"
    snippet: str            # redacted context, <= 160 chars


_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    key_id INTEGER NOT NULL,
    task_id TEXT,
    direction TEXT NOT NULL,
    detector TEXT NOT NULL,
    category TEXT NOT NULL,
    action TEXT NOT NULL,
    snippet TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_key_ts ON audit (key_id, ts);
"""


class AuditLog:
    def __init__(self, db_path: str):
        self.db_path = db_path
        with sqlite3.connect(db_path) as c:
            c.executescript(_SCHEMA)

    def record(self, event: AuditEvent) -> None:
        snippet = event.snippet
        if event.detector == "secrets" and event.action == "block":
            # The caller may pass the full payload for context, but a blocked
            # secret must not be retained in the audit database.
            snippet = "[REDACTED:SECRET]"
        with sqlite3.connect(self.db_path) as c:
            c.execute(
                "INSERT INTO audit (ts, key_id, task_id, direction, detector,"
                " category, action, snippet) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (time.time(), event.key_id, event.task_id, event.direction,
                 event.detector, event.category, event.action,
                 snippet[:160]),
            )

    def recent(self, limit: int = 100, key_id: int | None = None) -> list[dict]:
        q = ("SELECT ts, key_id, task_id, direction, detector, category, action,"
             " snippet FROM audit")
        params: tuple = ()
        if key_id is not None:
            q += " WHERE key_id = ?"
            params = (key_id,)
        q += " ORDER BY id DESC LIMIT ?"
        with sqlite3.connect(self.db_path) as c:
            rows = c.execute(q, (*params, limit)).fetchall()
        return [
            {"ts": r[0], "key_id": r[1], "task_id": r[2], "direction": r[3],
             "detector": r[4], "category": r[5], "action": r[6], "snippet": r[7]}
            for r in rows
        ]
