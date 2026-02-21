"""
Tests for deduplicator.py — SQLite-backed deduplication of seen items.
"""

import hashlib
import pytest
from unittest.mock import patch

from deduplicator import filter_new, mark_seen, _fingerprint


@pytest.fixture
def tmp_db(tmp_path):
    """Provide a temporary SQLite database path, isolated per test."""
    db_path = str(tmp_path / "test_seen.db")
    with patch("config.DB_PATH", db_path):
        # Also patch os.makedirs to avoid needing the data/ directory
        with patch("os.makedirs"):
            yield db_path


# ── _fingerprint ───────────────────────────────────────────────────────────────

class TestFingerprint:
    def test_is_sha256_of_item_id(self):
        item = {"id": "https://example.com/article-1"}
        expected = hashlib.sha256("https://example.com/article-1".encode()).hexdigest()
        assert _fingerprint(item) == expected

    def test_different_ids_produce_different_fingerprints(self):
        fp1 = _fingerprint({"id": "https://example.com/1"})
        fp2 = _fingerprint({"id": "https://example.com/2"})
        assert fp1 != fp2

    def test_same_id_always_produces_same_fingerprint(self):
        item = {"id": "https://example.com/stable"}
        assert _fingerprint(item) == _fingerprint(item)


# ── filter_new ─────────────────────────────────────────────────────────────────

class TestFilterNew:
    def test_returns_all_items_on_empty_database(self, tmp_db):
        items = [
            {"id": "https://example.com/1"},
            {"id": "https://example.com/2"},
            {"id": "https://example.com/3"},
        ]
        with patch("config.DB_PATH", tmp_db), patch("os.makedirs"):
            result = filter_new(items)

        assert result == items

    def test_returns_empty_list_for_empty_input(self, tmp_db):
        with patch("config.DB_PATH", tmp_db), patch("os.makedirs"):
            result = filter_new([])
        assert result == []

    def test_excludes_previously_marked_items(self, tmp_db):
        items = [
            {"id": "https://example.com/1"},
            {"id": "https://example.com/2"},
            {"id": "https://example.com/3"},
        ]
        with patch("config.DB_PATH", tmp_db), patch("os.makedirs"):
            mark_seen([items[0]])
            result = filter_new(items)

        assert len(result) == 2
        assert items[0] not in result
        assert items[1] in result
        assert items[2] in result

    def test_returns_only_unseen_items_in_mixed_batch(self, tmp_db):
        seen = [{"id": "https://example.com/seen-1"}, {"id": "https://example.com/seen-2"}]
        new  = [{"id": "https://example.com/new-1"},  {"id": "https://example.com/new-2"}]

        with patch("config.DB_PATH", tmp_db), patch("os.makedirs"):
            mark_seen(seen)
            result = filter_new(seen + new)

        assert len(result) == 2
        result_ids = {item["id"] for item in result}
        assert result_ids == {"https://example.com/new-1", "https://example.com/new-2"}

    def test_all_items_filtered_when_all_previously_seen(self, tmp_db):
        items = [{"id": "https://example.com/1"}, {"id": "https://example.com/2"}]

        with patch("config.DB_PATH", tmp_db), patch("os.makedirs"):
            mark_seen(items)
            result = filter_new(items)

        assert result == []


# ── mark_seen ──────────────────────────────────────────────────────────────────

class TestMarkSeen:
    def test_persists_items_so_they_are_excluded_next_call(self, tmp_db):
        items = [{"id": "https://example.com/1"}, {"id": "https://example.com/2"}]

        with patch("config.DB_PATH", tmp_db), patch("os.makedirs"):
            mark_seen(items)
            result = filter_new(items)

        assert result == []

    def test_does_not_raise_on_empty_list(self, tmp_db):
        with patch("config.DB_PATH", tmp_db), patch("os.makedirs"):
            mark_seen([])  # must not raise

    def test_is_idempotent_on_duplicate_calls(self, tmp_db):
        items = [{"id": "https://example.com/1"}]

        with patch("config.DB_PATH", tmp_db), patch("os.makedirs"):
            mark_seen(items)
            mark_seen(items)  # second call should not raise (INSERT OR IGNORE)
            result = filter_new(items)

        assert result == []

    def test_marks_multiple_items_in_single_call(self, tmp_db):
        items = [{"id": f"https://example.com/{i}"} for i in range(10)]

        with patch("config.DB_PATH", tmp_db), patch("os.makedirs"):
            mark_seen(items)
            result = filter_new(items)

        assert result == []
