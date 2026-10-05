"""冻结结论的 SQLite 持久化（按稳定审计标识重开）。"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    audit_id   TEXT PRIMARY KEY,
    status     TEXT NOT NULL,
    verdict    TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
"""


class AuditStore:
    def __init__(self, path: str):
        self._path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            path, check_same_thread=False, isolation_level=None
        )
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute(SCHEMA)

    def save(self, audit_id: str, verdict: dict) -> bool:
        """冻结结论。返回 True 表示新建，False 表示该标识已冻结。"""
        payload = json.dumps(verdict, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO audits(audit_id, status, verdict) "
                "VALUES (?, ?, ?)",
                (audit_id, verdict["status"], payload),
            )
            return cur.rowcount == 1

    def get(self, audit_id: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT verdict FROM audits WHERE audit_id = ?", (audit_id,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def list_ids(self) -> list:
        with self._lock:
            rows = self._conn.execute(
                "SELECT audit_id, status, created_at FROM audits "
                "ORDER BY created_at DESC LIMIT 100"
            ).fetchall()
        return [
            {"audit_id": a, "status": s, "created_at": t} for a, s, t in rows
        ]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
