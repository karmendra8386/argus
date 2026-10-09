"""Virtual API keys: issuance, verification, and budget state.

Keys are stored as SHA-256 hashes (the raw key is shown once at creation).
Budgets are enforced per key; spend is read from the ledger.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
from dataclasses import dataclass


@dataclass
class KeyRecord:
    id: int
    name: str
    key_hash: str
    budget_usd: float
    period: str  # "daily" | "monthly"
    mode: str  # "degrade" | "hard"
    created_at: float
    policy_profile: str = "standard"
    revoked: bool = False


_SCHEMA = """
CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    budget_usd REAL NOT NULL,
    period TEXT NOT NULL DEFAULT 'monthly',
    mode TEXT NOT NULL DEFAULT 'degrade',
    created_at REAL NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);
"""


class KeyStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        with sqlite3.connect(db_path) as c:
            c.executescript(_SCHEMA)
            # migration: policy_profile added after v0.1.0
            cols = [r[1] for r in c.execute("PRAGMA table_info(keys)").fetchall()]
            if "policy_profile" not in cols:
                c.execute("ALTER TABLE keys ADD COLUMN policy_profile TEXT DEFAULT 'standard'")

    @staticmethod
    def _hash(raw: str) -> str:
        return hashlib.sha256(raw.encode()).hexdigest()

    def create(
        self,
        name: str,
        budget_usd: float = 10.0,
        period: str = "monthly",
        mode: str = "degrade",
        policy_profile: str = "standard",
    ) -> tuple[KeyRecord, str]:
        """Create a key; returns (record, raw_key). Raw key is shown once."""
        raw = "sk-gw-" + secrets.token_urlsafe(32)
        rec = KeyRecord(
            id=0,
            name=name,
            key_hash=self._hash(raw),
            budget_usd=budget_usd,
            period=period,
            mode=mode,
            created_at=time.time(),
            policy_profile=policy_profile,
        )
        with sqlite3.connect(self.db_path) as c:
            cur = c.execute(
                "INSERT INTO keys (name, key_hash, budget_usd, period, mode,"
                " created_at, policy_profile)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (rec.name, rec.key_hash, rec.budget_usd, rec.period, rec.mode,
                 rec.created_at, rec.policy_profile),
            )
            rec.id = cur.lastrowid
        return rec, raw

    def _row_to_record(self, row) -> KeyRecord:
        # policy_profile may be absent on very old rows -> default
        profile = row[8] if len(row) > 8 and row[8] else "standard"
        return KeyRecord(
            id=row[0], name=row[1], key_hash=row[2], budget_usd=row[3],
            period=row[4], mode=row[5], created_at=row[6],
            policy_profile=profile, revoked=bool(row[7]),
        )

    def verify(self, raw: str) -> KeyRecord | None:
        """Return the key record for a valid, non-revoked key, else None."""
        with sqlite3.connect(self.db_path) as c:
            row = c.execute(
                "SELECT id, name, key_hash, budget_usd, period, mode, created_at,"
                " revoked, policy_profile"
                " FROM keys WHERE key_hash = ?",
                (self._hash(raw),),
            ).fetchone()
        if not row or row[7]:
            return None
        return self._row_to_record(row)

    def revoke(self, key_id: int) -> None:
        with sqlite3.connect(self.db_path) as c:
            c.execute("UPDATE keys SET revoked = 1 WHERE id = ?", (key_id,))

    def list(self) -> list[KeyRecord]:
        with sqlite3.connect(self.db_path) as c:
            rows = c.execute(
                "SELECT id, name, key_hash, budget_usd, period, mode, created_at,"
                " revoked, policy_profile"
                " FROM keys ORDER BY id"
            ).fetchall()
        return [self._row_to_record(r) for r in rows]
