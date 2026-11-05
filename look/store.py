"""SQLite persistence, including a tamper-evident audit log."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from .models import Consent, Dispute, Report, Subject, now

SCHEMA = """
CREATE TABLE IF NOT EXISTS subjects (id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS consents (id TEXT PRIMARY KEY, subject_id TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reports (id TEXT PRIMARY KEY, subject_id TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS disputes (id TEXT PRIMARY KEY, report_id TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    subject_id TEXT,
    detail TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"""

GENESIS = "0" * 64


@dataclass
class AuditEntry:
    seq: int
    ts: str
    actor: str
    action: str
    subject_id: str | None
    detail: dict[str, Any]
    prev_hash: str
    hash: str

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def _entry_hash(prev_hash: str, ts: str, actor: str, action: str, subject_id: str | None, detail: str) -> str:
    payload = json.dumps([prev_hash, ts, actor, action, subject_id, detail], separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


class Store:
    def __init__(self, path: str = ":memory:") -> None:
        self.db = sqlite3.connect(path)
        self.db.executescript(SCHEMA)

    # generic blobs ----------------------------------------------------------

    def _put(self, table: str, id_: str, data: dict[str, Any], **cols: str) -> None:
        names = ["id", *cols.keys(), "data"]
        values = [id_, *cols.values(), json.dumps(data)]
        sql = f"INSERT OR REPLACE INTO {table} ({', '.join(names)}) VALUES ({', '.join('?' * len(names))})"
        with self.db:
            self.db.execute(sql, values)

    def _get(self, table: str, id_: str) -> dict[str, Any] | None:
        row = self.db.execute(f"SELECT data FROM {table} WHERE id = ?", (id_,)).fetchone()
        return json.loads(row[0]) if row else None

    def _where(self, table: str, col: str, value: str) -> list[dict[str, Any]]:
        rows = self.db.execute(f"SELECT data FROM {table} WHERE {col} = ? ORDER BY rowid", (value,))
        return [json.loads(r[0]) for r in rows]

    # typed accessors --------------------------------------------------------

    def save_subject(self, s: Subject) -> None:
        self._put("subjects", s.subject_id, s.to_dict())

    def get_subject(self, subject_id: str) -> Subject | None:
        d = self._get("subjects", subject_id)
        return Subject.from_dict(d) if d else None

    def save_consent(self, c: Consent) -> None:
        self._put("consents", c.consent_id, c.to_dict(), subject_id=c.subject_id)

    def get_consent(self, consent_id: str) -> Consent | None:
        d = self._get("consents", consent_id)
        return Consent.from_dict(d) if d else None

    def save_report(self, r: Report) -> None:
        self._put("reports", r.report_id, r.to_dict(), subject_id=r.subject_id)

    def get_report(self, report_id: str) -> Report | None:
        d = self._get("reports", report_id)
        return Report.from_dict(d) if d else None

    def save_dispute(self, d: Dispute) -> None:
        self._put("disputes", d.dispute_id, d.to_dict(), report_id=d.report_id)

    def get_dispute(self, dispute_id: str) -> Dispute | None:
        d = self._get("disputes", dispute_id)
        return Dispute.from_dict(d) if d else None

    def disputes_for_report(self, report_id: str) -> list[Dispute]:
        return [Dispute.from_dict(d) for d in self._where("disputes", "report_id", report_id)]

    # audit log --------------------------------------------------------------

    def audit(self, actor: str, action: str, subject_id: str | None = None, **detail: Any) -> AuditEntry:
        ts = now().isoformat()
        detail_json = json.dumps(detail, sort_keys=True, default=str)
        with self.db:
            row = self.db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev = row[0] if row else GENESIS
            h = _entry_hash(prev, ts, actor, action, subject_id, detail_json)
            cur = self.db.execute(
                "INSERT INTO audit (ts, actor, action, subject_id, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
                (ts, actor, action, subject_id, detail_json, prev, h),
            )
        return AuditEntry(cur.lastrowid, ts, actor, action, subject_id, detail, prev, h)

    def audit_entries(self, subject_id: str | None = None) -> list[AuditEntry]:
        sql = "SELECT seq, ts, actor, action, subject_id, detail, prev_hash, hash FROM audit"
        args: tuple[Any, ...] = ()
        if subject_id:
            sql += " WHERE subject_id = ?"
            args = (subject_id,)
        rows = self.db.execute(sql + " ORDER BY seq", args).fetchall()
        return [AuditEntry(r[0], r[1], r[2], r[3], r[4], json.loads(r[5]), r[6], r[7]) for r in rows]

    def verify_audit_chain(self) -> bool:
        """True if no audit entry has been altered, removed, or reordered."""
        prev = GENESIS
        rows = self.db.execute(
            "SELECT ts, actor, action, subject_id, detail, prev_hash, hash FROM audit ORDER BY seq"
        )
        for ts, actor, action, subject_id, detail, prev_hash, h in rows:
            if prev_hash != prev or _entry_hash(prev, ts, actor, action, subject_id, detail) != h:
                return False
            prev = h
        return True
