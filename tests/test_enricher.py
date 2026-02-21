"""
Tests for enricher.py — Claude AI triage, severity scoring, and cost tracking.
"""

import json
from datetime import date
from unittest.mock import MagicMock, patch

import pytest

import enricher
from enricher import enrich, _build_user_prompt, BATCH_SIZE


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_items(n: int) -> list[dict]:
    return [
        {
            "id": f"https://example.com/{i}",
            "title": f"Article {i}",
            "url": f"https://example.com/{i}",
            "source": "TestSource",
            "published": "2024-01-15",
            "content": f"Content for item {i}",
        }
        for i in range(n)
    ]


def _make_api_response(results: list[dict], input_tokens: int = 1000, output_tokens: int = 500) -> MagicMock:
    response = MagicMock()
    response.content = [MagicMock(text=json.dumps(results))]
    response.usage.input_tokens = input_tokens
    response.usage.output_tokens = output_tokens
    return response


def _relevant_result(summary: str = "Summary", severity: int = 7, topics: list | None = None) -> dict:
    return {"relevant": True, "summary": summary, "severity": severity, "topics": topics or []}


def _irrelevant_result() -> dict:
    return {"relevant": False, "summary": "", "severity": 0, "topics": []}


@pytest.fixture(autouse=True)
def reset_cost_tracker():
    """Reset the in-memory daily cost tracker before every test."""
    enricher._today = ""
    enricher._today_cost = 0.0
    yield


# ── _build_user_prompt ─────────────────────────────────────────────────────────

class TestBuildUserPrompt:
    def test_includes_item_separator_for_each_item(self):
        items = _make_items(3)
        prompt = _build_user_prompt(items)
        assert "--- ITEM 0 ---" in prompt
        assert "--- ITEM 1 ---" in prompt
        assert "--- ITEM 2 ---" in prompt

    def test_includes_source_title_content_fields(self):
        items = _make_items(1)
        prompt = _build_user_prompt(items)
        assert "Source:" in prompt
        assert "Title:" in prompt
        assert "Content:" in prompt

    def test_truncates_content_at_600_chars(self):
        items = [{
            "id": "1",
            "title": "Test",
            "source": "Src",
            "content": "X" * 1000,
        }]
        prompt = _build_user_prompt(items)
        # The 601st character should not appear
        assert "X" * 601 not in prompt

    def test_handles_missing_content_field(self):
        items = [{"id": "1", "title": "No content", "source": "Src"}]
        prompt = _build_user_prompt(items)
        assert "Content:" in prompt  # key present, value just empty


# ── enrich ─────────────────────────────────────────────────────────────────────

class TestEnrich:
    def test_returns_empty_for_empty_input(self):
        assert enrich([]) == []

    def test_keeps_relevant_items_and_merges_enrichment_fields(self):
        items = _make_items(2)
        api_results = [
            _relevant_result("Summary 0", 8, ["CVE"]),
            _irrelevant_result(),
        ]
        mock_response = _make_api_response(api_results)

        with patch.object(enricher._client.messages, "create", return_value=mock_response):
            result = enrich(items)

        assert len(result) == 1
        assert result[0]["summary"] == "Summary 0"
        assert result[0]["severity"] == 8
        assert result[0]["topics"] == ["CVE"]

    def test_discards_all_irrelevant_items(self):
        items = _make_items(3)
        api_results = [_irrelevant_result() for _ in range(3)]
        mock_response = _make_api_response(api_results)

        with patch.object(enricher._client.messages, "create", return_value=mock_response):
            result = enrich(items)

        assert result == []

    def test_original_item_fields_are_preserved_after_enrichment(self):
        items = _make_items(1)
        api_results = [_relevant_result("Summary", 7, [])]
        mock_response = _make_api_response(api_results)

        with patch.object(enricher._client.messages, "create", return_value=mock_response):
            result = enrich(items)

        assert result[0]["id"] == items[0]["id"]
        assert result[0]["title"] == items[0]["title"]
        assert result[0]["source"] == items[0]["source"]

    def test_batches_items_in_groups_of_batch_size(self):
        # 32 items → ceil(32/15) = 3 batches
        items = _make_items(32)
        full_batch  = [_relevant_result(f"S{i}", 7, []) for i in range(BATCH_SIZE)]
        last_batch  = [_relevant_result(f"S{i}", 7, []) for i in range(2)]

        mock_responses = [
            _make_api_response(full_batch),
            _make_api_response(full_batch),
            _make_api_response(last_batch),
        ]

        with patch.object(enricher._client.messages, "create", side_effect=mock_responses) as mock_create:
            result = enrich(items)

        assert mock_create.call_count == 3
        assert len(result) == 32

    def test_handles_json_parse_error_with_severity_zero_fallback(self):
        items = _make_items(2)
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="not {{ valid json")]
        mock_response.usage.input_tokens = 100
        mock_response.usage.output_tokens = 50

        with patch.object(enricher._client.messages, "create", return_value=mock_response):
            result = enrich(items)

        assert len(result) == 2
        assert all(item["severity"] == 0 for item in result)

    def test_handles_api_exception_with_severity_zero_fallback(self):
        items = _make_items(2)

        with patch.object(enricher._client.messages, "create", side_effect=Exception("API unavailable")):
            result = enrich(items)

        assert len(result) == 2
        assert all(item["severity"] == 0 for item in result)

    def test_strips_markdown_code_fences_from_response(self):
        items = _make_items(1)
        results = [_relevant_result("Fenced response", 7, [])]
        fenced = f"```json\n{json.dumps(results)}\n```"

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text=fenced)]
        mock_response.usage.input_tokens = 100
        mock_response.usage.output_tokens = 50

        with patch.object(enricher._client.messages, "create", return_value=mock_response):
            result = enrich(items)

        assert len(result) == 1
        assert result[0]["severity"] == 7

    def test_stops_processing_when_daily_budget_exhausted(self):
        items = _make_items(30)
        # Pre-exhaust the budget
        enricher._today_cost = enricher.DAILY_COST_LIMIT_USD + 1.0
        enricher._today = date.today().isoformat()

        with patch.object(enricher._client.messages, "create") as mock_create:
            result = enrich(items)

        mock_create.assert_not_called()
        assert result == []

    def test_budget_resets_when_date_changes(self):
        items = _make_items(1)
        # Set cost tracker to yesterday's exhausted budget
        enricher._today = "2020-01-01"
        enricher._today_cost = enricher.DAILY_COST_LIMIT_USD + 1.0

        api_results = [_relevant_result("New day summary", 7, [])]
        mock_response = _make_api_response(api_results)

        with patch.object(enricher._client.messages, "create", return_value=mock_response):
            result = enrich(items)

        # Budget should have reset, allowing the call
        assert len(result) == 1

    def test_severity_is_cast_to_int(self):
        items = _make_items(1)
        # API might return severity as a string or float
        api_results = [{"relevant": True, "summary": "S", "severity": "8", "topics": []}]
        mock_response = _make_api_response(api_results)

        with patch.object(enricher._client.messages, "create", return_value=mock_response):
            result = enrich(items)

        assert isinstance(result[0]["severity"], int)
        assert result[0]["severity"] == 8


# ── Cost tracking ──────────────────────────────────────────────────────────────

class TestCostTracking:
    def test_cost_accumulates_across_batches(self):
        items = _make_items(20)  # 2 batches
        batch_results = [_relevant_result() for _ in range(BATCH_SIZE)]
        last_results  = [_relevant_result() for _ in range(5)]

        responses = [
            _make_api_response(batch_results, input_tokens=1000, output_tokens=500),
            _make_api_response(last_results,  input_tokens=500,  output_tokens=250),
        ]

        with patch.object(enricher._client.messages, "create", side_effect=responses):
            enrich(items)

        # Expected: (1000 * 3/1_000_000 + 500 * 15/1_000_000) + (500 * 3/1_000_000 + 250 * 15/1_000_000)
        expected_cost = (
            (1000 * 3 / 1_000_000 + 500 * 15 / 1_000_000) +
            (500 * 3 / 1_000_000 + 250 * 15 / 1_000_000)
        )
        assert abs(enricher._today_cost - expected_cost) < 1e-9
