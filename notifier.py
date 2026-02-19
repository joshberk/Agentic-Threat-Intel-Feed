"""
notifier.py — Delivers enriched items to Slack and/or Email.

Security hardening:
  • html.escape() on all external fields rendered into email HTML
  • _safe_url() rejects javascript: and data: URI schemes
  • Credentials never logged — Slack webhook URL excluded from error messages

Both channels are stub-safe: if the relevant credential is not configured the
function logs what *would* be sent and returns without error. Wire in the
real credentials via .env when ready.
"""

import html
import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import urlparse

import httpx

import config

log = logging.getLogger(__name__)

# ── URL sanitisation ──────────────────────────────────────────────────────────

def _safe_url(url: str) -> str:
    """Return url only if it uses http/https; otherwise return '#' to prevent XSS."""
    parsed = urlparse(url)
    if parsed.scheme in ("http", "https"):
        return url
    return "#"


# ── Severity labels ───────────────────────────────────────────────────────────
def _severity_label(score: int) -> str:
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    if score >= 1:
        return "LOW"
    return "UNSCORED"


def _severity_emoji(score: int) -> str:
    return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "UNSCORED": "⚪"}[
        _severity_label(score)
    ]


# ── Slack ─────────────────────────────────────────────────────────────────────
def _slack_payload(item: dict) -> dict:
    score  = item.get("severity", 0)
    label  = _severity_label(score)
    emoji  = _severity_emoji(score)
    topics = ", ".join(item.get("topics", [])) or "general"
    is_deep = item.get("deep_dive", False)

    blocks = [
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"{emoji} *{label}* | _{item['source']}_"
                    f"{' | 🔬 _Deep Dive_' if is_deep else ''}\n"
                    f"*<{_safe_url(item['url'])}|{item['title']}>*\n"
                    f"{item.get('deep_summary') or item.get('summary', '')}"
                ),
            },
        },
    ]

    # Deep dive extra fields
    if is_deep:
        details: list[str] = []
        if item.get("affected_products"):
            details.append("*Affected:* " + ", ".join(item["affected_products"][:5]))
        if item.get("cve_ids"):
            details.append("*CVEs:* " + ", ".join(item["cve_ids"]))
        if item.get("threat_actor"):
            details.append(f"*Actor:* {item['threat_actor']}")
        if item.get("mitigations"):
            mits = "\n".join(f"• {m}" for m in item["mitigations"][:4])
            details.append(f"*Mitigations:*\n{mits}")
        if item.get("iocs"):
            details.append("*IOCs:* " + ", ".join(item["iocs"][:6]))

        if details:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "\n".join(details)},
            })

    blocks.append({
        "type": "context",
        "elements": [
            {
                "type": "mrkdwn",
                "text": f"Topics: {topics}  |  Score: {score}/10",
            }
        ],
    })

    return {"blocks": blocks}


async def send_slack(item: dict) -> None:
    """Post a single item to the configured Slack webhook."""
    if not config.SLACK_WEBHOOK_URL:
        score = item.get("severity", "?")
        log.info(
            "Slack STUB — [%s/10] %s | %s | %s",
            score, _severity_label(int(score or 0)), item["source"], item["title"],
        )
        return

    payload = _slack_payload(item)
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(config.SLACK_WEBHOOK_URL, json=payload)
            if resp.status_code != 200:
                # Log status only — never log the webhook URL
                log.error("Slack webhook returned HTTP %s", resp.status_code)
    except httpx.TimeoutException:
        log.error("Slack webhook timed out")
    except Exception as exc:
        log.error("Slack webhook error: %s", type(exc).__name__)


# ── Email ─────────────────────────────────────────────────────────────────────
_EMAIL_ROW_TEMPLATE = """
<tr>
  <td style="padding:14px 8px;border-bottom:1px solid #e5e7eb;font-family:sans-serif;">
    <span style="font-size:12px;font-weight:bold;color:{color};">{emoji} {label}</span>
    &nbsp;·&nbsp;
    <span style="font-size:12px;color:#6b7280;">{source}</span><br>
    <a href="{url}" style="font-size:15px;font-weight:bold;color:#1d4ed8;text-decoration:none;">
      {title}
    </a><br>
    <p style="margin:6px 0 4px;font-size:13px;color:#374151;">{summary}</p>
    <span style="font-size:11px;color:#9ca3af;">Topics: {topics} &nbsp;|&nbsp; Score: {score}/10</span>
  </td>
</tr>
"""

_SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#ca8a04",
    "LOW":      "#16a34a",
    "UNSCORED": "#6b7280",
}


def _email_html(items: list[dict]) -> str:
    rows = ""
    for item in items:
        score  = item.get("severity", 0)
        label  = _severity_label(score)
        rows  += _EMAIL_ROW_TEMPLATE.format(
            color   = _SEVERITY_COLORS[label],
            emoji   = _severity_emoji(score),
            label   = html.escape(label),
            source  = html.escape(item["source"]),
            url     = _safe_url(item["url"]),
            title   = html.escape(item["title"]),
            summary = html.escape(item.get("summary", "")),
            topics  = html.escape(", ".join(item.get("topics", [])) or "general"),
            score   = score,
        )

    return f"""
<!DOCTYPE html>
<html>
<body style="margin:0;padding:20px;background:#f9fafb;">
  <table cellpadding="0" cellspacing="0"
         style="max-width:680px;margin:0 auto;background:#fff;border-radius:8px;
                border:1px solid #e5e7eb;overflow:hidden;">
    <tr>
      <td style="padding:20px 16px;background:#1e293b;">
        <h2 style="margin:0;color:#fff;font-family:sans-serif;font-size:18px;">
          🛡️ Agentic Threat Intel Feed
        </h2>
        <p style="margin:4px 0 0;color:#94a3b8;font-family:sans-serif;font-size:13px;">
          {len(items)} new item(s) above severity threshold
        </p>
      </td>
    </tr>
    {rows}
    <tr>
      <td style="padding:12px 16px;font-family:sans-serif;font-size:11px;color:#9ca3af;">
        Powered by Claude · Agentic Threat Intel Feed
      </td>
    </tr>
  </table>
</body>
</html>"""


def send_email(items: list[dict]) -> None:
    """Send a digest email containing all notifiable items."""
    if not config.SMTP_HOST:
        log.info("Email STUB — would send digest of %d item(s)", len(items))
        return

    try:
        msg             = MIMEMultipart("alternative")
        msg["Subject"]  = f"[Agentic Threat Intel] {len(items)} new threat intel item(s)"
        msg["From"]     = config.EMAIL_FROM
        msg["To"]       = config.EMAIL_TO
        msg.attach(MIMEText(_email_html(items), "html"))

        ctx = ssl.create_default_context()
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT) as server:
            server.starttls(context=ctx)
            server.login(config.SMTP_USER, config.SMTP_PASS)
            server.sendmail(config.EMAIL_FROM, config.EMAIL_TO, msg.as_string())

        log.info("Email digest sent (%d items)", len(items))
    except Exception as exc:
        log.error("Email send error: %s", type(exc).__name__)
