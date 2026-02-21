"""
Tests for notifier.py — Slack webhook and email digest delivery.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from notifier import (
    _severity_label,
    _severity_emoji,
    _slack_payload,
    _email_html,
    send_slack,
    send_email,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_item(severity: int = 7, deep_dive: bool = False) -> dict:
    item = {
        "id": "https://example.com/article",
        "title": "Security Alert: Critical Vulnerability",
        "url": "https://example.com/article",
        "source": "TheHackerNews",
        "published": "2024-01-15",
        "content": "Full article content.",
        "summary": "A critical vulnerability was discovered.",
        "severity": severity,
        "topics": ["CVE", "exploit"],
    }
    if deep_dive:
        item.update({
            "deep_dive": True,
            "deep_summary": "Detailed deep dive analysis of the vulnerability.",
            "iocs": ["1.2.3.4", "evil.com"],
            "affected_products": ["Windows 11 22H2"],
            "cve_ids": ["CVE-2024-1234"],
            "threat_actor": "APT41",
            "mitigations": ["Apply patch KB5034441", "Block IP 1.2.3.4"],
        })
    return item


# ── _severity_label ────────────────────────────────────────────────────────────

class TestSeverityLabel:
    @pytest.mark.parametrize("score,expected", [
        (10, "CRITICAL"),
        (9,  "CRITICAL"),
        (8,  "HIGH"),
        (7,  "HIGH"),
        (6,  "MEDIUM"),
        (5,  "MEDIUM"),
        (4,  "LOW"),
        (1,  "LOW"),
        (0,  "UNSCORED"),
    ])
    def test_correct_label_for_score(self, score, expected):
        assert _severity_label(score) == expected


# ── _severity_emoji ────────────────────────────────────────────────────────────

class TestSeverityEmoji:
    def test_critical_returns_red_circle(self):
        assert _severity_emoji(9) == "🔴"

    def test_high_returns_orange_circle(self):
        assert _severity_emoji(8) == "🟠"

    def test_medium_returns_yellow_circle(self):
        assert _severity_emoji(6) == "🟡"

    def test_low_returns_green_circle(self):
        assert _severity_emoji(3) == "🟢"

    def test_unscored_returns_white_circle(self):
        assert _severity_emoji(0) == "⚪"


# ── _slack_payload ─────────────────────────────────────────────────────────────

class TestSlackPayload:
    def test_payload_contains_blocks_key(self):
        payload = _slack_payload(_make_item())
        assert "blocks" in payload

    def test_title_appears_in_section_block(self):
        item = _make_item(severity=8)
        payload = _slack_payload(item)
        section_text = " ".join(
            b["text"]["text"] for b in payload["blocks"] if b["type"] == "section"
        )
        assert "Security Alert: Critical Vulnerability" in section_text

    def test_url_appears_in_section_block(self):
        item = _make_item()
        payload = _slack_payload(item)
        section_text = " ".join(
            b["text"]["text"] for b in payload["blocks"] if b["type"] == "section"
        )
        assert "https://example.com/article" in section_text

    def test_correct_severity_label_in_section(self):
        item = _make_item(severity=9)
        payload = _slack_payload(item)
        section_text = " ".join(
            b["text"]["text"] for b in payload["blocks"] if b["type"] == "section"
        )
        assert "CRITICAL" in section_text

    def test_score_shown_in_context_block(self):
        item = _make_item(severity=7)
        payload = _slack_payload(item)
        context_text = " ".join(
            str(b) for b in payload["blocks"] if b["type"] == "context"
        )
        assert "7/10" in context_text

    def test_deep_dive_badge_shown_in_section(self):
        item = _make_item(severity=9, deep_dive=True)
        payload = _slack_payload(item)
        section_text = " ".join(
            b["text"]["text"] for b in payload["blocks"] if b["type"] == "section"
        )
        assert "Deep Dive" in section_text

    def test_deep_dive_fields_present_when_deep_dive(self):
        item = _make_item(severity=9, deep_dive=True)
        payload = _slack_payload(item)
        all_text = str(payload)
        assert "APT41" in all_text
        assert "CVE-2024-1234" in all_text
        assert "1.2.3.4" in all_text

    def test_no_deep_dive_fields_for_standard_item(self):
        item = _make_item(severity=7, deep_dive=False)
        payload = _slack_payload(item)
        all_text = str(payload)
        assert "Actor:" not in all_text
        assert "IOCs:" not in all_text

    def test_deep_summary_used_instead_of_summary_when_available(self):
        item = _make_item(severity=9, deep_dive=True)
        payload = _slack_payload(item)
        section_text = " ".join(
            b["text"]["text"] for b in payload["blocks"] if b["type"] == "section"
        )
        assert "Detailed deep dive analysis" in section_text

    def test_topics_joined_in_context_block(self):
        item = _make_item()
        payload = _slack_payload(item)
        context_text = str([b for b in payload["blocks"] if b["type"] == "context"])
        assert "CVE" in context_text

    def test_no_topics_shows_general(self):
        item = _make_item()
        item["topics"] = []
        payload = _slack_payload(item)
        context_text = str([b for b in payload["blocks"] if b["type"] == "context"])
        assert "general" in context_text


# ── send_slack ─────────────────────────────────────────────────────────────────

class TestSendSlack:
    @pytest.mark.asyncio
    async def test_stub_mode_prints_when_no_webhook_configured(self, capsys):
        item = _make_item(severity=8)
        with patch("config.SLACK_WEBHOOK_URL", ""):
            await send_slack(item)
        captured = capsys.readouterr()
        assert "STUB" in captured.out

    @pytest.mark.asyncio
    async def test_stub_mode_includes_severity_score(self, capsys):
        item = _make_item(severity=9)
        with patch("config.SLACK_WEBHOOK_URL", ""):
            await send_slack(item)
        captured = capsys.readouterr()
        assert "9" in captured.out

    @pytest.mark.asyncio
    async def test_posts_json_to_webhook_url(self):
        item = _make_item(severity=8)
        mock_response = MagicMock()
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = AsyncMock(return_value=mock_response)

        with (
            patch("config.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"),
            patch("httpx.AsyncClient", return_value=mock_client),
        ):
            await send_slack(item)

        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        assert call_args.args[0] == "https://hooks.slack.com/test"
        assert "json" in call_args.kwargs

    @pytest.mark.asyncio
    async def test_logs_error_on_non_200_response(self, capsys):
        item = _make_item()
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Bad Request"

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = AsyncMock(return_value=mock_response)

        with (
            patch("config.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"),
            patch("httpx.AsyncClient", return_value=mock_client),
        ):
            await send_slack(item)  # must not raise

        captured = capsys.readouterr()
        assert "400" in captured.out

    @pytest.mark.asyncio
    async def test_handles_network_exception_gracefully(self, capsys):
        item = _make_item()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = AsyncMock(side_effect=Exception("Network error"))

        with (
            patch("config.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"),
            patch("httpx.AsyncClient", return_value=mock_client),
        ):
            await send_slack(item)  # must not raise

        captured = capsys.readouterr()
        assert "Error" in captured.out


# ── send_email ─────────────────────────────────────────────────────────────────

class TestSendEmail:
    def test_stub_mode_prints_when_no_smtp_configured(self, capsys):
        items = [_make_item()]
        with patch("config.SMTP_HOST", ""):
            send_email(items)
        captured = capsys.readouterr()
        assert "STUB" in captured.out

    def test_stub_mode_reports_correct_item_count(self, capsys):
        items = [_make_item(), _make_item(severity=9)]
        with patch("config.SMTP_HOST", ""):
            send_email(items)
        captured = capsys.readouterr()
        assert "2" in captured.out

    def test_sends_via_smtp_when_configured(self):
        items = [_make_item()]
        mock_smtp = MagicMock()
        mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp.__exit__ = MagicMock(return_value=None)

        with (
            patch("config.SMTP_HOST", "smtp.example.com"),
            patch("config.SMTP_PORT", 587),
            patch("config.SMTP_USER", "user@example.com"),
            patch("config.SMTP_PASS", "password"),
            patch("config.EMAIL_FROM", "from@example.com"),
            patch("config.EMAIL_TO", "to@example.com"),
            patch("smtplib.SMTP", return_value=mock_smtp),
            patch("ssl.create_default_context"),
        ):
            send_email(items)

        mock_smtp.starttls.assert_called_once()
        mock_smtp.login.assert_called_once_with("user@example.com", "password")
        mock_smtp.sendmail.assert_called_once()

    def test_sendmail_uses_correct_from_and_to(self):
        items = [_make_item()]
        mock_smtp = MagicMock()
        mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp.__exit__ = MagicMock(return_value=None)

        with (
            patch("config.SMTP_HOST", "smtp.example.com"),
            patch("config.SMTP_PORT", 587),
            patch("config.SMTP_USER", "user@example.com"),
            patch("config.SMTP_PASS", "password"),
            patch("config.EMAIL_FROM", "alerts@mycompany.com"),
            patch("config.EMAIL_TO", "security-team@mycompany.com"),
            patch("smtplib.SMTP", return_value=mock_smtp),
            patch("ssl.create_default_context"),
        ):
            send_email(items)

        call_args = mock_smtp.sendmail.call_args.args
        assert call_args[0] == "alerts@mycompany.com"
        assert call_args[1] == "security-team@mycompany.com"

    def test_handles_smtp_exception_gracefully(self, capsys):
        items = [_make_item()]
        mock_smtp = MagicMock()
        mock_smtp.__enter__ = MagicMock(side_effect=Exception("SMTP connection failed"))
        mock_smtp.__exit__ = MagicMock(return_value=None)

        with (
            patch("config.SMTP_HOST", "smtp.example.com"),
            patch("config.SMTP_PORT", 587),
            patch("config.SMTP_USER", "user"),
            patch("config.SMTP_PASS", "pass"),
            patch("config.EMAIL_FROM", "from@example.com"),
            patch("config.EMAIL_TO", "to@example.com"),
            patch("smtplib.SMTP", return_value=mock_smtp),
            patch("ssl.create_default_context"),
        ):
            send_email(items)  # must not raise

        captured = capsys.readouterr()
        assert "Error" in captured.out


# ── _email_html ────────────────────────────────────────────────────────────────

class TestEmailHtml:
    def test_html_contains_item_count(self):
        items = [_make_item(), _make_item(severity=9)]
        html = _email_html(items)
        assert "2 new item(s)" in html

    def test_html_contains_item_title(self):
        items = [_make_item()]
        html = _email_html(items)
        assert "Security Alert: Critical Vulnerability" in html

    def test_html_contains_item_url(self):
        items = [_make_item()]
        html = _email_html(items)
        assert "https://example.com/article" in html

    def test_critical_severity_uses_red_color(self):
        items = [_make_item(severity=9)]
        html = _email_html(items)
        assert "#dc2626" in html

    def test_high_severity_uses_orange_color(self):
        items = [_make_item(severity=8)]
        html = _email_html(items)
        assert "#ea580c" in html

    def test_medium_severity_uses_yellow_color(self):
        items = [_make_item(severity=6)]
        html = _email_html(items)
        assert "#ca8a04" in html

    def test_summary_included_in_html(self):
        items = [_make_item()]
        html = _email_html(items)
        assert "A critical vulnerability was discovered." in html

    def test_topics_joined_in_html(self):
        items = [_make_item()]
        html = _email_html(items)
        assert "CVE" in html
        assert "exploit" in html
