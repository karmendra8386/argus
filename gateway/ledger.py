"""Cost ledger: every proxied call recorded; spend queryable per key and per task.

A task groups the turns of one agentic run (client passes X-Task-Id). This is
the per-task attribution LiteLLM-style gateways don't do.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass


@dataclass
class CallEntry:
    key_id: int
    task_id: str | None
    provider: str
    model: str
    tier: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    degraded: bool = False


_SCHEMA = """
CREATE TABLE IF NOT EXISTS calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    key_id INTEGER NOT NULL,
    task_id TEXT,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    tier TEXT NOT NULL,
    input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    cost_usd REAL NOT NULL,
    degraded INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_calls_key_ts ON calls (key_id, ts);
CREATE INDEX IF NOT EXISTS idx_calls_task ON calls (task_id);
"""


class Ledger:
    def __init__(self, db_path: str):
        self.db_path = db_path
        with sqlite3.connect(db_path) as c:
            c.executescript(_SCHEMA)

    def record(self, entry: CallEntry) -> int:
        with sqlite3.connect(self.db_path) as c:
            cur = c.execute(
                "INSERT INTO calls (ts, key_id, task_id, provider, model, tier,"
                " input_tokens, output_tokens, cost_usd, degraded)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (time.time(), entry.key_id, entry.task_id, entry.provider,
                 entry.model, entry.tier, entry.input_tokens, entry.output_tokens,
                 entry.cost_usd, int(entry.degraded)),
            )
            return cur.lastrowid

    def _period_start(self, period: str) -> float:
        now = time.time()
        if period == "daily":
            return now - 86400
        return now - 30 * 86400  # monthly ~= 30d

    def key_spend(self, key_id: int, period: str = "monthly") -> float:
        with sqlite3.connect(self.db_path) as c:
            row = c.execute(
                "SELECT COALESCE(SUM(cost_usd), 0) FROM calls WHERE key_id = ? AND ts >= ?",
                (key_id, self._period_start(period)),
            ).fetchone()
        return float(row[0])

    def task_spend(self, task_id: str) -> dict:
        """Totals + per-call breakdown for one task id."""
        with sqlite3.connect(self.db_path) as c:
            rows = c.execute(
                "SELECT ts, provider, model, tier, input_tokens, output_tokens,"
                " cost_usd, degraded FROM calls WHERE task_id = ? ORDER BY ts",
                (task_id,),
            ).fetchall()
        calls = [
            {"ts": r[0], "provider": r[1], "model": r[2], "tier": r[3],
             "input_tokens": r[4], "output_tokens": r[5],
             "cost_usd": r[6], "degraded": bool(r[7])}
            for r in rows
        ]
        return {
            "task_id": task_id,
            "calls": len(calls),
            "total_cost_usd": round(sum(c["cost_usd"] for c in calls), 6),
            "total_tokens": sum(c["input_tokens"] + c["output_tokens"] for c in calls),
            "breakdown": calls,
        }

    def total_spend(self) -> dict:
        with sqlite3.connect(self.db_path) as c:
            row = c.execute(
                "SELECT COUNT(*), COALESCE(SUM(cost_usd), 0),"
                " COALESCE(SUM(input_tokens + output_tokens), 0) FROM calls"
            ).fetchone()
        return {"calls": row[0], "total_cost_usd": round(row[1], 6), "total_tokens": row[2]}
