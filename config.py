import os
from dotenv import load_dotenv

load_dotenv()


def _clamp(value: int, lo: int, hi: int, name: str) -> int:
    """Clamp an integer config value to [lo, hi] and warn if it was out of range."""
    if value < lo:
        print(f"[config] WARNING: {name}={value} below minimum {lo}, clamping to {lo}")
        return lo
    if value > hi:
        print(f"[config] WARNING: {name}={value} above maximum {hi}, clamping to {hi}")
        return hi
    return value


# ── Anthropic ─────────────────────────────────────────────────────────────────
ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL: str = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-5-20250929")

# ── Slack (fill in after MVP) ─────────────────────────────────────────────────
SLACK_WEBHOOK_URL: str = os.getenv("SLACK_WEBHOOK_URL", "")

# ── Email / SMTP (fill in after MVP) ─────────────────────────────────────────
SMTP_HOST: str = os.getenv("SMTP_HOST", "")
SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER: str = os.getenv("SMTP_USER", "")
SMTP_PASS: str = os.getenv("SMTP_PASS", "")
EMAIL_FROM: str = os.getenv("EMAIL_FROM", "")
EMAIL_TO: str = os.getenv("EMAIL_TO", "")

# ── NVD ─────────────────────────────────────────────────────────────────────
NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")

# ── Reddit (fill in after MVP) ───────────────────────────────────────────────
REDDIT_CLIENT_ID: str = os.getenv("REDDIT_CLIENT_ID", "")
REDDIT_CLIENT_SECRET: str = os.getenv("REDDIT_CLIENT_SECRET", "")
REDDIT_USER_AGENT: str = os.getenv("REDDIT_USER_AGENT", "cybersec-agent/1.0")

# ── Agent behaviour ───────────────────────────────────────────────────────────
# How often to poll all sources (seconds). Default = 5 minutes.
POLL_INTERVAL_SECONDS: int = max(
    60, int(os.getenv("POLL_INTERVAL_SECONDS", "300"))
)

# Minimum Claude severity score (1–10) required before a notification is sent.
SEVERITY_THRESHOLD: int = _clamp(
    int(os.getenv("SEVERITY_THRESHOLD", "6")), 1, 10, "SEVERITY_THRESHOLD"
)

# Maximum daily spend on Claude API calls (USD). Agent skips enrichment once hit.
DAILY_COST_LIMIT_USD: str = os.getenv("DAILY_COST_LIMIT_USD", "1.00")

# Path to the SQLite deduplication database.
DB_PATH: str = os.getenv("DB_PATH", "data/seen_items.db")

# ── Deep dive ─────────────────────────────────────────────────────────────────
# Minimum severity score to trigger an autonomous deep dive.
DEEP_DIVE_MIN_SEVERITY: int = _clamp(
    int(os.getenv("DEEP_DIVE_MIN_SEVERITY", "8")), 1, 10, "DEEP_DIVE_MIN_SEVERITY"
)
# Max number of deep dives per cycle (highest severity first).
DEEP_DIVE_MAX_PER_CYCLE: int = max(
    1, int(os.getenv("DEEP_DIVE_MAX_PER_CYCLE", "3"))
)

# ── Adaptive polling ───────────────────────────────────────────────────────────
# Number of high-severity items in a cycle that triggers spike mode.
SPIKE_TRIGGER_COUNT: int = max(
    1, int(os.getenv("SPIKE_TRIGGER_COUNT", "3"))
)
# Minimum severity score that counts toward the spike trigger.
SPIKE_SEVERITY_MIN: int = _clamp(
    int(os.getenv("SPIKE_SEVERITY_MIN", "8")), 1, 10, "SPIKE_SEVERITY_MIN"
)
# Poll interval (seconds) during a spike (default: 1 minute).
SPIKE_POLL_SECONDS: int = max(
    30, int(os.getenv("SPIKE_POLL_SECONDS", "60"))
)
# How long (seconds) to stay in spike mode after a spike is detected (default: 2 hours).
SPIKE_DURATION_SECONDS: int = max(
    60, int(os.getenv("SPIKE_DURATION_SECONDS", "7200"))
)

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
