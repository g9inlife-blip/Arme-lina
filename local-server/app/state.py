"""Player State access layer (DRAFT)."""
from __future__ import annotations

import json
import sqlite3
from typing import Any


class PlayerState:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def get_dict_entry(self, dict_name: str, entry_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT data FROM state_dict WHERE dict_name = ? AND entry_id = ?",
            (dict_name, entry_id),
        ).fetchone()
        return json.loads(row["data"]) if row else None

    def set_dict_entry(self, dict_name: str, entry_id: str, data: dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO state_dict (dict_name, entry_id, data) VALUES (?, ?, ?)",
            (dict_name, entry_id, json.dumps(data, ensure_ascii=False)),
        )
        self.conn.commit()

    def get_dict_all(self, dict_name: str) -> dict[str, dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT entry_id, data FROM state_dict WHERE dict_name = ?", (dict_name,)
        ).fetchall()
        return {r["entry_id"]: json.loads(r["data"]) for r in rows}
