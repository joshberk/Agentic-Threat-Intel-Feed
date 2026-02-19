"""
deduplicator.py — Prevents re-processing items already seen in a previous cycle.

Security hardening:
  • DB_PATH validated against path traversal before use (OWASP A03)
  • TTL-based cleanup: entries older than DEDUP_TTL_DAYS are pruned to keep
    the database from growing unboundedly (call prune_old_entries() periodically)

Storage: SQLite table `seen_items` keyed on a SHA-256 of the item's canonical ID.
The DB file is created automatically on first run at the path set in config.DB_PATH.
"""

import hashlib
import logging
import os
import pathlib
import sqlite3

import config

log = logging.getLogger(__name__)

# Items older than this are eligible for cleanup
DEDUP_TTL_DAYS: int = 30

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS seen_items (
    fingerprint TEXT PRIMARY KEY,
    seen_at     TEXT NOT NULL DEFAULT (datetime('now'))
)
"""


def _validated_db_path() -> str:
    """
    Resolve DB_PATH and reject any path containing '..' traversal components.
    Raises ValueError if the path is unsafe.
    """
    path = pathlib.Path(config.DB_PATH)
    if ".." in path.parts:
        raise ValueError(
            f"DB_PATH '{config.DB_PATH}' contains path-traversal components — rejected"
        )
    return str(path)


def _connect() -> sqlite3.Connection:
    db_path = _validated_db_path()
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path)
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
        # Parameterised IN clause — safe against SQL injection (OWASP A03)
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


def prune_old_entries(days: int = DEDUP_TTL_DAYS) -> int:
    """
    Delete seen_items entries older than `days` days.
    Returns the number of rows deleted.
    Call this periodically (e.g. once per agent startup) to bound DB growth.
    """
    conn = _connect()
    try:
        cur = conn.execute(
            "DELETE FROM seen_items WHERE seen_at < datetime('now', ?)",
            (f"-{days} days",),
        )
        conn.commit()
        deleted = cur.rowcount
        if deleted:
            log.info("Dedup DB pruned %d entries older than %d days", deleted, days)
        return deleted
    finally:
        conn.close()
