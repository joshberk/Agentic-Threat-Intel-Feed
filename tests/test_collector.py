"""
Tests for collector.py — RSS, NVD, CISA, and Reddit data collection.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from collector import (
    _normalize_rss,
    _nvd_cvss_score,
    fetch_rss_feeds,
    fetch_nvd_cves,
    fetch_cisa_kev,
    fetch_reddit,
    collect_all,
    RSS_FEEDS,
    RSS_ITEMS_PER_FEED,
)


# ── _normalize_rss ─────────────────────────────────────────────────────────────

class TestNormalizeRss:
    def test_extracts_all_basic_fields(self):
        entry = {
            "link": "https://example.com/article",
            "title": "Security Alert",
            "published": "2024-01-15",
            "summary": "Article summary here.",
        }
        result = _normalize_rss(entry, "TestSource")

        assert result["id"] == "https://example.com/article"
        assert result["title"] == "Security Alert"
        assert result["url"] == "https://example.com/article"
        assert result["source"] == "TestSource"
        assert result["published"] == "2024-01-15"
        assert result["content"] == "Article summary here."

    def test_falls_back_to_entry_id_when_no_link(self):
        entry = {"id": "entry-id-123", "title": "No Link Article"}
        result = _normalize_rss(entry, "Source")
        assert result["id"] == "entry-id-123"

    def test_uses_description_when_no_summary(self):
        entry = {
            "link": "https://example.com/article",
            "title": "Test",
            "description": "Description text",
        }
        result = _normalize_rss(entry, "Source")
        assert result["content"] == "Description text"

    def test_defaults_title_to_no_title_when_missing(self):
        entry = {"link": "https://example.com/article"}
        result = _normalize_rss(entry, "Source")
        assert result["title"] == "No title"

    def test_empty_string_when_no_id_or_link(self):
        entry = {"title": "No URL at all"}
        result = _normalize_rss(entry, "Source")
        assert result["id"] == ""
        assert result["url"] == ""


# ── _nvd_cvss_score ────────────────────────────────────────────────────────────

class TestNvdCvssScore:
    def test_extracts_v31_score(self):
        cve = {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}
        assert _nvd_cvss_score(cve) == 9.8

    def test_extracts_v30_score_when_no_v31(self):
        cve = {"metrics": {"cvssMetricV30": [{"cvssData": {"baseScore": 7.5}}]}}
        assert _nvd_cvss_score(cve) == 7.5

    def test_extracts_v2_score_as_last_resort(self):
        cve = {"metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]}}
        assert _nvd_cvss_score(cve) == 5.0

    def test_prefers_v31_over_v30_and_v2(self):
        cve = {
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}],
                "cvssMetricV30": [{"cvssData": {"baseScore": 7.5}}],
                "cvssMetricV2":  [{"cvssData": {"baseScore": 5.0}}],
            }
        }
        assert _nvd_cvss_score(cve) == 9.8

    def test_returns_none_when_no_metrics(self):
        assert _nvd_cvss_score({"metrics": {}}) is None

    def test_returns_none_for_empty_cve(self):
        assert _nvd_cvss_score({}) is None


# ── fetch_rss_feeds ────────────────────────────────────────────────────────────

class TestFetchRssFeeds:
    def _make_mock_entry(self, link="https://example.com/art", title="Security Alert"):
        entry = MagicMock()
        entry.get = lambda k, d="": {
            "link": link,
            "title": title,
            "published": "2024-01-15",
            "summary": "Summary here.",
        }.get(k, d)
        return entry

    @pytest.mark.asyncio
    async def test_returns_normalized_items_from_all_feeds(self):
        mock_parsed = MagicMock()
        mock_parsed.entries = [self._make_mock_entry()] * 2

        mock_response = MagicMock()
        mock_response.text = "<rss/>"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("feedparser.parse", return_value=mock_parsed):
            items = await fetch_rss_feeds(mock_client)

        # 6 feeds × 2 entries each
        assert len(items) == len(RSS_FEEDS) * 2
        assert all("source" in item for item in items)
        assert all("title" in item for item in items)

    @pytest.mark.asyncio
    async def test_caps_items_per_feed_at_rss_items_per_feed(self):
        mock_parsed = MagicMock()
        mock_parsed.entries = [self._make_mock_entry()] * 20  # exceeds cap

        mock_response = MagicMock()
        mock_response.text = "<rss/>"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("feedparser.parse", return_value=mock_parsed):
            items = await fetch_rss_feeds(mock_client)

        assert len(items) <= RSS_ITEMS_PER_FEED * len(RSS_FEEDS)

    @pytest.mark.asyncio
    async def test_continues_on_feed_http_error(self):
        """A failing feed should not abort fetching from other feeds."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("Connection refused"))

        items = await fetch_rss_feeds(mock_client)
        assert items == []

    @pytest.mark.asyncio
    async def test_attaches_correct_source_name(self):
        mock_parsed = MagicMock()
        mock_parsed.entries = [self._make_mock_entry()]

        mock_response = MagicMock()
        mock_response.text = "<rss/>"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("feedparser.parse", return_value=mock_parsed):
            items = await fetch_rss_feeds(mock_client)

        expected_sources = {feed["name"] for feed in RSS_FEEDS}
        actual_sources = {item["source"] for item in items}
        assert actual_sources.issubset(expected_sources)


# ── fetch_nvd_cves ─────────────────────────────────────────────────────────────

class TestFetchNvdCves:
    def _nvd_response(self, n: int = 1, base_score: float = 9.8) -> MagicMock:
        vulns = [
            {
                "cve": {
                    "id": f"CVE-2024-{i:04d}",
                    "descriptions": [{"lang": "en", "value": f"A critical vulnerability {i}."}],
                    "published": "2024-01-15T00:00:00.000",
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": base_score}}]
                    },
                }
            }
            for i in range(n)
        ]
        mock_response = MagicMock()
        mock_response.json.return_value = {"vulnerabilities": vulns}
        return mock_response

    @pytest.mark.asyncio
    async def test_parses_cve_id_and_source(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=self._nvd_response(1))

        items = await fetch_nvd_cves(mock_client)

        assert len(items) == 1
        assert items[0]["source"] == "NVD"
        assert "CVE-2024-0000" in items[0]["title"]

    @pytest.mark.asyncio
    async def test_extracts_cvss_score(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=self._nvd_response(1, base_score=9.8))

        items = await fetch_nvd_cves(mock_client)

        assert items[0]["cvss_score"] == 9.8

    @pytest.mark.asyncio
    async def test_limits_results_to_20(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=self._nvd_response(30))

        items = await fetch_nvd_cves(mock_client)

        assert len(items) == 20

    @pytest.mark.asyncio
    async def test_detail_url_contains_cve_id(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=self._nvd_response(1))

        items = await fetch_nvd_cves(mock_client)

        assert "CVE-2024-0000" in items[0]["url"]
        assert "nvd.nist.gov" in items[0]["url"]

    @pytest.mark.asyncio
    async def test_includes_api_key_header_when_configured(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {"vulnerabilities": []}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("config.NVD_API_KEY", "test-nvd-key"):
            await fetch_nvd_cves(mock_client)

        call_kwargs = mock_client.get.call_args
        assert call_kwargs.kwargs["headers"].get("apiKey") == "test-nvd-key"

    @pytest.mark.asyncio
    async def test_returns_empty_list_on_http_error(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("Timeout"))

        items = await fetch_nvd_cves(mock_client)
        assert items == []

    @pytest.mark.asyncio
    async def test_truncates_long_descriptions_in_title(self):
        long_desc = "A" * 200
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-0001",
                    "descriptions": [{"lang": "en", "value": long_desc}],
                    "published": "2024-01-15T00:00:00.000",
                    "metrics": {},
                }
            }]
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        items = await fetch_nvd_cves(mock_client)

        # Title should be truncated to 120 chars of description + prefix
        assert "..." in items[0]["title"]


# ── fetch_cisa_kev ─────────────────────────────────────────────────────────────

class TestFetchCisaKev:
    def _kev_response(self, n: int = 1) -> MagicMock:
        vulns = [
            {
                "cveID": f"CVE-2024-{i:04d}",
                "vulnerabilityName": f"Vuln {i}",
                "dateAdded": f"2024-01-{i+1:02d}",
                "shortDescription": f"Short desc {i}.",
                "product": f"Product {i}",
                "vendorProject": f"Vendor {i}",
                "requiredAction": "Patch immediately.",
            }
            for i in range(n)
        ]
        mock_response = MagicMock()
        mock_response.json.return_value = {"vulnerabilities": vulns}
        return mock_response

    @pytest.mark.asyncio
    async def test_parses_cve_id_vulnerability_name_and_source(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=self._kev_response(1))

        items = await fetch_cisa_kev(mock_client)

        assert len(items) == 1
        assert items[0]["source"] == "CISA KEV"
        assert "CVE-2024-0000" in items[0]["title"]
        assert "Vuln 0" in items[0]["title"]

    @pytest.mark.asyncio
    async def test_limits_results_to_20_most_recent(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=self._kev_response(30))

        items = await fetch_cisa_kev(mock_client)

        assert len(items) == 20

    @pytest.mark.asyncio
    async def test_content_includes_description_and_required_action(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=self._kev_response(1))

        items = await fetch_cisa_kev(mock_client)

        assert "Short desc 0." in items[0]["content"]
        assert "Patch immediately." in items[0]["content"]
        assert "Product 0" in items[0]["content"]

    @pytest.mark.asyncio
    async def test_returns_empty_list_on_http_error(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("Connection error"))

        items = await fetch_cisa_kev(mock_client)
        assert items == []


# ── fetch_reddit ───────────────────────────────────────────────────────────────

class TestFetchReddit:
    @pytest.mark.asyncio
    async def test_returns_empty_list_stub(self):
        mock_client = AsyncMock()
        items = await fetch_reddit(mock_client)
        assert items == []


# ── collect_all ────────────────────────────────────────────────────────────────

class TestCollectAll:
    @pytest.mark.asyncio
    async def test_combines_items_from_all_sources(self):
        rss_item   = {"id": "rss-1",  "source": "RSS",      "title": "RSS",  "url": "u1", "published": "", "content": ""}
        nvd_item   = {"id": "nvd-1",  "source": "NVD",      "title": "NVD",  "url": "u2", "published": "", "content": ""}
        cisa_item  = {"id": "cisa-1", "source": "CISA KEV", "title": "CISA", "url": "u3", "published": "", "content": ""}

        with (
            patch("collector.fetch_rss_feeds",  new=AsyncMock(return_value=[rss_item])),
            patch("collector.fetch_nvd_cves",   new=AsyncMock(return_value=[nvd_item])),
            patch("collector.fetch_cisa_kev",   new=AsyncMock(return_value=[cisa_item])),
            patch("collector.fetch_reddit",     new=AsyncMock(return_value=[])),
        ):
            items = await collect_all()

        assert len(items) == 3
        sources = {item["source"] for item in items}
        assert sources == {"RSS", "NVD", "CISA KEV"}

    @pytest.mark.asyncio
    async def test_returns_empty_when_all_sources_fail(self):
        with (
            patch("collector.fetch_rss_feeds",  new=AsyncMock(return_value=[])),
            patch("collector.fetch_nvd_cves",   new=AsyncMock(return_value=[])),
            patch("collector.fetch_cisa_kev",   new=AsyncMock(return_value=[])),
            patch("collector.fetch_reddit",     new=AsyncMock(return_value=[])),
        ):
            items = await collect_all()

        assert items == []
