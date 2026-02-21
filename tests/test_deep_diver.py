"""
Tests for deep_diver.py — autonomous article fetching and deep analysis.
"""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from deep_diver import (
    _is_paywalled,
    _extract_text,
    deep_dive,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_item(severity: int = 9, url: str = "https://example.com/article") -> dict:
    return {
        "id": url,
        "title": "Critical Security Vulnerability",
        "url": url,
        "source": "TestSource",
        "published": "2024-01-15",
        "content": "Article content here.",
        "summary": "Critical vulnerability found in production software.",
        "severity": severity,
        "topics": ["CVE", "exploit"],
    }


def _make_analysis() -> dict:
    return {
        "deep_summary": "Detailed multi-sentence analysis of the vulnerability.",
        "iocs": ["192.168.1.1", "evil.com"],
        "affected_products": ["Apache Log4j 2.14.1"],
        "cve_ids": ["CVE-2024-1234"],
        "threat_actor": "APT41",
        "mitigations": ["Update to Log4j 2.17.0", "Block C2 IP 192.168.1.1"],
    }


# ── _is_paywalled ──────────────────────────────────────────────────────────────

class TestIsPaywalled:
    LONG_CONTENT = "This is a full article with rich content. " * 20

    def test_401_status_is_paywalled(self):
        assert _is_paywalled(401, self.LONG_CONTENT) is True

    def test_402_status_is_paywalled(self):
        assert _is_paywalled(402, self.LONG_CONTENT) is True

    def test_403_status_is_paywalled(self):
        assert _is_paywalled(403, self.LONG_CONTENT) is True

    def test_200_with_long_content_is_not_paywalled(self):
        assert _is_paywalled(200, self.LONG_CONTENT) is False

    def test_subscribe_to_read_phrase_detected(self):
        text = "subscribe to read this article. " * 10
        assert _is_paywalled(200, text) is True

    def test_subscribe_to_continue_phrase_detected(self):
        text = "subscribe to continue reading this content. " * 10
        assert _is_paywalled(200, text) is True

    def test_members_only_phrase_detected(self):
        text = "members only content is restricted here. " * 10
        assert _is_paywalled(200, text) is True

    def test_premium_content_phrase_detected(self):
        text = "this is premium content for subscribers only. " * 10
        assert _is_paywalled(200, text) is True

    def test_sign_in_to_read_phrase_detected(self):
        text = "sign in to read the full article now. " * 10
        assert _is_paywalled(200, text) is True

    def test_very_short_body_is_paywalled(self):
        assert _is_paywalled(200, "Too short") is True

    def test_paywall_detection_is_case_insensitive(self):
        text = "SUBSCRIBE TO READ THIS PREMIUM CONTENT. " * 10
        assert _is_paywalled(200, text) is True

    def test_300_chars_boundary_not_paywalled(self):
        # Exactly 300 chars should not be considered too short
        text = "A" * 300
        assert _is_paywalled(200, text) is False


# ── _extract_text ──────────────────────────────────────────────────────────────

class TestExtractText:
    def test_prefers_article_tag_content(self):
        html = (
            "<html><body>"
            "<div>Noise</div>"
            "<article><p>Article text here.</p></article>"
            "</body></html>"
        )
        text = _extract_text(html)
        assert "Article text here." in text

    def test_falls_back_to_main_tag(self):
        html = "<html><body><main><p>Main content.</p></main></body></html>"
        text = _extract_text(html)
        assert "Main content." in text

    def test_removes_script_tags(self):
        html = (
            "<html><body><article>"
            "<script>alert('xss')</script>"
            "<p>Real content.</p>"
            "</article></body></html>"
        )
        text = _extract_text(html)
        assert "alert" not in text
        assert "Real content." in text

    def test_removes_nav_tag(self):
        html = (
            "<html><body>"
            "<nav>Navigation links</nav>"
            "<article><p>Article body.</p></article>"
            "</body></html>"
        )
        text = _extract_text(html)
        assert "Navigation links" not in text
        assert "Article body." in text

    def test_removes_footer_tag(self):
        html = (
            "<html><body>"
            "<article><p>Article body.</p></article>"
            "<footer>Footer text</footer>"
            "</body></html>"
        )
        text = _extract_text(html)
        assert "Footer text" not in text

    def test_falls_back_to_full_body_when_no_semantic_container(self):
        html = "<html><body><div><p>Body only content.</p></div></body></html>"
        text = _extract_text(html)
        assert "Body only content." in text

    def test_truncates_output_at_8000_chars(self):
        long_content = "A" * 10_000
        html = f"<html><body><article><p>{long_content}</p></article></body></html>"
        text = _extract_text(html)
        assert len(text) <= 8_000


# ── deep_dive ──────────────────────────────────────────────────────────────────

class TestDeepDive:
    @pytest.mark.asyncio
    async def test_items_below_min_severity_returned_unchanged(self):
        items = [
            _make_item(severity=5, url="https://example.com/low"),
            _make_item(severity=6, url="https://example.com/medium"),
        ]
        with patch("config.DEEP_DIVE_MIN_SEVERITY", 8), patch("config.DEEP_DIVE_MAX_PER_CYCLE", 3):
            result = await deep_dive(items)

        assert result == items
        assert all("deep_dive" not in item for item in result)

    @pytest.mark.asyncio
    async def test_adds_deep_dive_fields_to_qualifying_items(self):
        item = _make_item(severity=9)
        analysis = _make_analysis()

        with (
            patch("config.DEEP_DIVE_MIN_SEVERITY", 8),
            patch("config.DEEP_DIVE_MAX_PER_CYCLE", 3),
            patch("deep_diver._fetch_content", new=AsyncMock(return_value="Full article text here.")),
            patch("deep_diver._call_claude", return_value=analysis),
        ):
            result = await deep_dive([item])

        assert len(result) == 1
        assert result[0]["deep_dive"] is True
        assert result[0]["deep_summary"] == analysis["deep_summary"]
        assert result[0]["iocs"] == analysis["iocs"]
        assert result[0]["affected_products"] == analysis["affected_products"]
        assert result[0]["cve_ids"] == analysis["cve_ids"]
        assert result[0]["threat_actor"] == analysis["threat_actor"]
        assert result[0]["mitigations"] == analysis["mitigations"]

    @pytest.mark.asyncio
    async def test_original_fields_preserved_after_deep_dive(self):
        item = _make_item(severity=9)

        with (
            patch("config.DEEP_DIVE_MIN_SEVERITY", 8),
            patch("config.DEEP_DIVE_MAX_PER_CYCLE", 3),
            patch("deep_diver._fetch_content", new=AsyncMock(return_value="Full text...")),
            patch("deep_diver._call_claude", return_value=_make_analysis()),
        ):
            result = await deep_dive([item])

        assert result[0]["id"] == item["id"]
        assert result[0]["title"] == item["title"]
        assert result[0]["severity"] == item["severity"]

    @pytest.mark.asyncio
    async def test_returns_item_unchanged_when_fetch_returns_none(self):
        item = _make_item(severity=9)

        with (
            patch("config.DEEP_DIVE_MIN_SEVERITY", 8),
            patch("config.DEEP_DIVE_MAX_PER_CYCLE", 3),
            patch("deep_diver._fetch_content", new=AsyncMock(return_value=None)),
        ):
            result = await deep_dive([item])

        assert result == [item]
        assert "deep_dive" not in result[0]

    @pytest.mark.asyncio
    async def test_returns_item_unchanged_when_claude_returns_none(self):
        item = _make_item(severity=9)

        with (
            patch("config.DEEP_DIVE_MIN_SEVERITY", 8),
            patch("config.DEEP_DIVE_MAX_PER_CYCLE", 3),
            patch("deep_diver._fetch_content", new=AsyncMock(return_value="Full article...")),
            patch("deep_diver._call_claude", return_value=None),
        ):
            result = await deep_dive([item])

        assert result == [item]

    @pytest.mark.asyncio
    async def test_caps_deep_dives_at_max_per_cycle(self):
        items = [_make_item(severity=9, url=f"https://example.com/{i}") for i in range(5)]

        async def mock_fetch(url):
            return "Article text..."

        with (
            patch("config.DEEP_DIVE_MIN_SEVERITY", 8),
            patch("config.DEEP_DIVE_MAX_PER_CYCLE", 2),
            patch("deep_diver._fetch_content", new=mock_fetch),
            patch("deep_diver._call_claude", return_value=_make_analysis()),
        ):
            result = await deep_dive(items)

        deep_count = sum(1 for item in result if item.get("deep_dive"))
        assert deep_count == 2

    @pytest.mark.asyncio
    async def test_prioritises_highest_severity_items_for_deep_dive(self):
        items = [
            _make_item(severity=8,  url="https://example.com/low"),
            _make_item(severity=10, url="https://example.com/high"),
            _make_item(severity=9,  url="https://example.com/mid"),
        ]
        fetched_urls: list[str] = []

        async def mock_fetch(url):
            fetched_urls.append(url)
            return "Article text..."

        with (
            patch("config.DEEP_DIVE_MIN_SEVERITY", 8),
            patch("config.DEEP_DIVE_MAX_PER_CYCLE", 2),
            patch("deep_diver._fetch_content", new=mock_fetch),
            patch("deep_diver._call_claude", return_value=_make_analysis()),
        ):
            await deep_dive(items)

        assert "https://example.com/high" in fetched_urls
        assert "https://example.com/mid" in fetched_urls
        assert "https://example.com/low" not in fetched_urls

    @pytest.mark.asyncio
    async def test_non_candidates_passed_through_unchanged(self):
        low_item  = _make_item(severity=4, url="https://example.com/low")
        high_item = _make_item(severity=9, url="https://example.com/high")

        with (
            patch("config.DEEP_DIVE_MIN_SEVERITY", 8),
            patch("config.DEEP_DIVE_MAX_PER_CYCLE", 3),
            patch("deep_diver._fetch_content", new=AsyncMock(return_value="Text...")),
            patch("deep_diver._call_claude", return_value=_make_analysis()),
        ):
            result = await deep_dive([low_item, high_item])

        # low item should come through unchanged
        low_result = next(r for r in result if r["url"] == "https://example.com/low")
        assert "deep_dive" not in low_result

        # high item should have deep dive fields
        high_result = next(r for r in result if r["url"] == "https://example.com/high")
        assert high_result.get("deep_dive") is True
