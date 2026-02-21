"""
Tests for agent.py — pipeline orchestration, spike mode, and run modes.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agent import run_cycle, main


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_raw_item(i: int = 0) -> dict:
    return {
        "id": f"https://example.com/{i}",
        "title": f"Article {i}",
        "url": f"https://example.com/{i}",
        "source": "TestSource",
        "published": "2024-01-15",
        "content": f"Content {i}",
    }


def _make_enriched_item(i: int = 0, severity: int = 7) -> dict:
    return {
        **_make_raw_item(i),
        "summary": f"Summary {i}",
        "severity": severity,
        "topics": ["CVE"],
    }


# ── run_cycle ──────────────────────────────────────────────────────────────────

class TestRunCycle:
    @pytest.mark.asyncio
    async def test_returns_zero_when_no_new_items_after_dedup(self):
        with (
            patch("agent.collect_all", new=AsyncMock(return_value=[_make_raw_item()])),
            patch("agent.filter_new", return_value=[]),
        ):
            result = await run_cycle()

        assert result == 0

    @pytest.mark.asyncio
    async def test_returns_zero_when_all_items_below_severity_threshold(self):
        raw = [_make_raw_item()]
        enriched = [_make_enriched_item(severity=3)]

        with (
            patch("agent.collect_all", new=AsyncMock(return_value=raw)),
            patch("agent.filter_new", return_value=raw),
            patch("agent.enrich", return_value=enriched),
            patch("agent.mark_seen"),
            patch("config.SEVERITY_THRESHOLD", 6),
        ):
            result = await run_cycle()

        assert result == 0

    @pytest.mark.asyncio
    async def test_pipeline_stages_called_in_correct_order(self):
        call_order: list[str] = []

        async def mock_collect():
            call_order.append("collect")
            return [_make_raw_item()]

        def mock_filter(items):
            call_order.append("filter")
            return items

        def mock_enrich(items):
            call_order.append("enrich")
            return [_make_enriched_item(severity=8)]

        def mock_mark_seen(items):
            call_order.append("mark_seen")

        async def mock_deep_dive(items):
            call_order.append("deep_dive")
            return items

        async def mock_send_slack(item):
            call_order.append("send_slack")

        def mock_send_email(items):
            call_order.append("send_email")

        with (
            patch("agent.collect_all", new=mock_collect),
            patch("agent.filter_new", side_effect=mock_filter),
            patch("agent.enrich", side_effect=mock_enrich),
            patch("agent.mark_seen", side_effect=mock_mark_seen),
            patch("agent.deep_dive", new=mock_deep_dive),
            patch("agent.send_slack", new=mock_send_slack),
            patch("agent.send_email", side_effect=mock_send_email),
            patch("config.SEVERITY_THRESHOLD", 6),
        ):
            await run_cycle()

        assert call_order.index("collect") < call_order.index("filter")
        assert call_order.index("filter") < call_order.index("enrich")
        assert call_order.index("enrich") < call_order.index("mark_seen")
        assert call_order.index("mark_seen") < call_order.index("deep_dive")
        assert call_order.index("deep_dive") < call_order.index("send_slack")
        assert call_order.index("send_slack") < call_order.index("send_email")

    @pytest.mark.asyncio
    async def test_marks_all_new_items_seen_not_just_notifiable(self):
        """Even items that are irrelevant or below threshold must be marked seen."""
        raw = [_make_raw_item(0), _make_raw_item(1)]
        # Only one item enriched as relevant/above threshold
        enriched = [_make_enriched_item(0, severity=8)]

        mock_mark_seen = MagicMock()

        with (
            patch("agent.collect_all", new=AsyncMock(return_value=raw)),
            patch("agent.filter_new", return_value=raw),
            patch("agent.enrich", return_value=enriched),
            patch("agent.mark_seen", side_effect=mock_mark_seen),
            patch("agent.deep_dive", new=AsyncMock(return_value=enriched)),
            patch("agent.send_slack", new=AsyncMock()),
            patch("agent.send_email"),
            patch("config.SEVERITY_THRESHOLD", 6),
        ):
            await run_cycle()

        mock_mark_seen.assert_called_once_with(raw)

    @pytest.mark.asyncio
    async def test_returns_count_of_spike_severity_items(self):
        """Return value counts items at or above SPIKE_SEVERITY_MIN."""
        raw = [_make_raw_item(i) for i in range(4)]
        enriched = [
            _make_enriched_item(0, severity=10),  # counts
            _make_enriched_item(1, severity=9),   # counts
            _make_enriched_item(2, severity=8),   # counts (== min)
            _make_enriched_item(3, severity=5),   # does NOT count
        ]

        with (
            patch("agent.collect_all", new=AsyncMock(return_value=raw)),
            patch("agent.filter_new", return_value=raw),
            patch("agent.enrich", return_value=enriched),
            patch("agent.mark_seen"),
            patch("agent.deep_dive", new=AsyncMock(return_value=enriched)),
            patch("agent.send_slack", new=AsyncMock()),
            patch("agent.send_email"),
            patch("config.SEVERITY_THRESHOLD", 5),
            patch("config.SPIKE_SEVERITY_MIN", 8),
        ):
            count = await run_cycle()

        assert count == 3

    @pytest.mark.asyncio
    async def test_send_slack_called_once_per_notifiable_item(self):
        raw = [_make_raw_item(i) for i in range(3)]
        enriched = [_make_enriched_item(i, severity=8) for i in range(3)]
        mock_send_slack = AsyncMock()

        with (
            patch("agent.collect_all", new=AsyncMock(return_value=raw)),
            patch("agent.filter_new", return_value=raw),
            patch("agent.enrich", return_value=enriched),
            patch("agent.mark_seen"),
            patch("agent.deep_dive", new=AsyncMock(return_value=enriched)),
            patch("agent.send_slack", new=mock_send_slack),
            patch("agent.send_email"),
            patch("config.SEVERITY_THRESHOLD", 6),
        ):
            await run_cycle()

        assert mock_send_slack.call_count == 3

    @pytest.mark.asyncio
    async def test_send_email_called_with_all_notifiable_items(self):
        raw = [_make_raw_item(i) for i in range(2)]
        enriched = [_make_enriched_item(i, severity=8) for i in range(2)]
        mock_send_email = MagicMock()

        with (
            patch("agent.collect_all", new=AsyncMock(return_value=raw)),
            patch("agent.filter_new", return_value=raw),
            patch("agent.enrich", return_value=enriched),
            patch("agent.mark_seen"),
            patch("agent.deep_dive", new=AsyncMock(return_value=enriched)),
            patch("agent.send_slack", new=AsyncMock()),
            patch("agent.send_email", side_effect=mock_send_email),
            patch("config.SEVERITY_THRESHOLD", 6),
        ):
            await run_cycle()

        mock_send_email.assert_called_once()
        called_items = mock_send_email.call_args.args[0]
        assert len(called_items) == 2

    @pytest.mark.asyncio
    async def test_cycle_error_does_not_propagate(self):
        """Unhandled exceptions in a cycle should be caught and logged."""
        with (
            patch("agent.collect_all", new=AsyncMock(side_effect=Exception("Unexpected failure"))),
            patch("config.ANTHROPIC_API_KEY", "test-key"),
            patch("asyncio.sleep", new=AsyncMock(side_effect=KeyboardInterrupt)),
        ):
            try:
                await main(once=False)
            except KeyboardInterrupt:
                pass  # expected exit from the loop


# ── main ───────────────────────────────────────────────────────────────────────

class TestMain:
    @pytest.mark.asyncio
    async def test_returns_early_without_api_key(self, capsys):
        with (
            patch("config.ANTHROPIC_API_KEY", ""),
            patch("agent.run_cycle", new=AsyncMock()) as mock_cycle,
        ):
            await main(once=True)

        mock_cycle.assert_not_called()
        captured = capsys.readouterr()
        assert "ANTHROPIC_API_KEY" in captured.out

    @pytest.mark.asyncio
    async def test_once_flag_runs_exactly_one_cycle(self):
        mock_cycle = AsyncMock(return_value=0)

        with (
            patch("config.ANTHROPIC_API_KEY", "test-key"),
            patch("agent.run_cycle", new=mock_cycle),
        ):
            await main(once=True)

        mock_cycle.assert_called_once()

    @pytest.mark.asyncio
    async def test_continuous_mode_loops_until_interrupted(self):
        call_count = 0

        async def mock_cycle():
            nonlocal call_count
            call_count += 1
            return 0

        sleep_count = 0

        async def mock_sleep(duration):
            nonlocal sleep_count
            sleep_count += 1
            if sleep_count >= 3:
                raise KeyboardInterrupt

        with (
            patch("config.ANTHROPIC_API_KEY", "test-key"),
            patch("agent.run_cycle", new=mock_cycle),
            patch("asyncio.sleep", new=mock_sleep),
            patch("config.POLL_INTERVAL_SECONDS", 300),
            patch("config.SPIKE_TRIGGER_COUNT", 999),  # never triggers spike
        ):
            try:
                await main(once=False)
            except KeyboardInterrupt:
                pass

        assert call_count >= 2

    @pytest.mark.asyncio
    async def test_spike_mode_uses_shorter_poll_interval(self):
        call_count = 0
        sleep_durations: list[int] = []

        async def mock_cycle():
            nonlocal call_count
            call_count += 1
            return 5 if call_count == 1 else 0  # trigger spike on first cycle

        async def mock_sleep(duration):
            sleep_durations.append(duration)
            if len(sleep_durations) >= 2:
                raise KeyboardInterrupt

        with (
            patch("config.ANTHROPIC_API_KEY", "test-key"),
            patch("agent.run_cycle", new=mock_cycle),
            patch("asyncio.sleep", new=mock_sleep),
            patch("config.SPIKE_TRIGGER_COUNT", 3),
            patch("config.SPIKE_POLL_SECONDS", 60),
            patch("config.POLL_INTERVAL_SECONDS", 300),
            patch("config.SPIKE_DURATION_SECONDS", 7200),
            patch("config.SPIKE_SEVERITY_MIN", 8),
        ):
            try:
                await main(once=False)
            except KeyboardInterrupt:
                pass

        # First sleep after a spike cycle should use spike interval (60s)
        assert sleep_durations[0] == 60

    @pytest.mark.asyncio
    async def test_normal_polling_uses_configured_interval(self):
        sleep_durations: list[int] = []

        async def mock_cycle():
            return 0  # no spike

        async def mock_sleep(duration):
            sleep_durations.append(duration)
            raise KeyboardInterrupt

        with (
            patch("config.ANTHROPIC_API_KEY", "test-key"),
            patch("agent.run_cycle", new=mock_cycle),
            patch("asyncio.sleep", new=mock_sleep),
            patch("config.SPIKE_TRIGGER_COUNT", 999),
            patch("config.POLL_INTERVAL_SECONDS", 300),
            patch("config.SPIKE_DURATION_SECONDS", 7200),
        ):
            try:
                await main(once=False)
            except KeyboardInterrupt:
                pass

        assert sleep_durations[0] == 300
