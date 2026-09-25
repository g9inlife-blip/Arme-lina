"""SQLite connection + minimal Player State schema (DRAFT).

Schema follows the OpInfo state fields observed in static evidence
(TASK-006-result.md section 3.6):
  User, Heros, Items, Weapons, Equiments, Mails, Chapters,
  Sections, Teams, Shops, Activities
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from .config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Generic state dictionaries, one row per entry: (dict_name, entry_id, json)
CREATE TABLE IF NOT EXISTS state_dict (
    dict_name TEXT NOT NULL,
    entry_id TEXT NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (dict_name, entry_id)
);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

# State dictionaries expected from OpInfo (static evidence, may grow)
STATE_DICTS = [
    "User",
    "Heros",
    "Items",
    "Weapons",
    "Equiments",
    "Mails",
    "Chapters",
    "Sections",
    "Teams",
    "Shops",
    "Activities",
]


def get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn
