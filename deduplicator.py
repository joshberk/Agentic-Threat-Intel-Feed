"""
deduplicator.py — Prevents re-processing items already seen in a previous cycle.

Storage: SQLite table `seen_items` keyed on a SHA-256 of the item's canonical ID.
The DB file is created automatically on first run at the path set in config.DB_PATH.
"""

import hashlib
import os
import sqlite3

import config

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS seen_items (
    fingerprint TEXT PRIMARY KEY,
    seen_at     TEXT NOT NULL DEFAULT (datetime('now'))
)
"""


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(config.DB_PATH), exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute(_CREATE_TABLE)
    conn.commit()
    return conn


def _fingerprint(item: dict) -> str:
    """Stable SHA-256 hash of the item's canonical URL/ID."""
    return hashlib.sha256(item["id"].encode("utf-8")).hexdigest()


def filter_new(items: list[dict]) -> list[dict]:
    """Return only items whose fingerprint is not already in the DB."""
    if not items:
        return []

    conn = _connect()
    try:
        fps   = [_fingerprint(i) for i in items]
        # Build a parameterised IN clause
        placeholders = ",".join("?" * len(fps))
        seen = {
            row[0]
            for row in conn.execute(
                f"SELECT fingerprint FROM seen_items WHERE fingerprint IN ({placeholders})",
                fps,
            )
        }
        return [item for item, fp in zip(items, fps) if fp not in seen]
    finally:
        conn.close()


def mark_seen(items: list[dict]) -> None:
    """Persist the fingerprints of all supplied items so they are skipped next time."""
    if not items:
        return

    conn = _connect()
    try:
        conn.executemany(
            "INSERT OR IGNORE INTO seen_items (fingerprint) VALUES (?)",
            [(_fingerprint(i),) for i in items],
        )
        conn.commit()
    finally:
        conn.close()
