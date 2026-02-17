import os
from dotenv import load_dotenv

load_dotenv()

# ── Anthropic ─────────────────────────────────────────────────────────────────
ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")

# ── Slack (fill in after MVP) ─────────────────────────────────────────────────
SLACK_WEBHOOK_URL: str = os.getenv("SLACK_WEBHOOK_URL", "")

# ── Email / SMTP (fill in after MVP) ─────────────────────────────────────────
SMTP_HOST: str = os.getenv("SMTP_HOST", "")
SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER: str = os.getenv("SMTP_USER", "")
SMTP_PASS: str = os.getenv("SMTP_PASS", "")
EMAIL_FROM: str = os.getenv("EMAIL_FROM", "")
EMAIL_TO: str = os.getenv("EMAIL_TO", "")

# ── Reddit (fill in after MVP) ───────────────────────────────────────────────
REDDIT_CLIENT_ID: str = os.getenv("REDDIT_CLIENT_ID", "")
REDDIT_CLIENT_SECRET: str = os.getenv("REDDIT_CLIENT_SECRET", "")
REDDIT_USER_AGENT: str = os.getenv("REDDIT_USER_AGENT", "cybersec-agent/1.0")

# ── Agent behaviour ───────────────────────────────────────────────────────────
# How often to poll all sources (seconds). Default = 5 minutes.
POLL_INTERVAL_SECONDS: int = int(os.getenv("POLL_INTERVAL_SECONDS", "300"))

# Minimum Claude severity score (1–10) required before a notification is sent.
SEVERITY_THRESHOLD: int = int(os.getenv("SEVERITY_THRESHOLD", "6"))

# Path to the SQLite deduplication database.
DB_PATH: str = os.getenv("DB_PATH", "data/seen_items.db")

# Topics Claude uses to judge relevance and to tag each item.
TOPICS: list[str] = [
    "vulnerabilities", "CVE", "zero-day", "exploit",
    "ransomware", "malware", "spyware", "botnet",
    "APT", "nation-state", "threat actor", "attribution",
    "cloud security", "AWS", "GCP", "Azure", "SaaS",
    "detection engineering", "SIEM", "EDR", "threat hunting",
    "OWASP", "web security", "injection", "XSS", "supply chain",
    "hacking", "breach", "data leak", "phishing",
]
