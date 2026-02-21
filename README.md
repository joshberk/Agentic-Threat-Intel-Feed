# Agentic Threat Intel Feed

An automated agent that continuously monitors cybersecurity news sources, uses Claude AI to triage and score threats, and delivers real-time alerts to Slack and email.

## Architecture

```
RSS / NVD / CISA
        |
    collector.py        Fetches raw items from all sources in parallel
        |
    deduplicator.py     SQLite-backed filter — skips already-seen items
        |
    enricher.py         Claude AI triage — relevance, summary, severity (1-10), topic tags
        |
    severity filter     Only items >= threshold pass through
        |
    notifier.py         Slack webhook (per-item) + Email digest (batched)
```

Orchestrated by `agent.py` which runs the pipeline in an async loop (locally) or as a single cycle via `--once` (GitHub Actions).

## Data Sources

| Source | What it collects |
|---|---|
| **RSS Feeds** | TheHackerNews, BleepingComputer, KrebsOnSecurity, DarkReading, Threatpost, SANS ISC |
| **NVD CVE API** | CVEs published in the last 2 hours (with CVSS scores) |
| **CISA KEV** | Known Exploited Vulnerabilities catalog (most recent 20) |

## Setup

### Prerequisites

- Python 3.10+
- [Anthropic API key](https://console.anthropic.com)
- Slack Incoming Webhook URL (optional but recommended)

### Install

```bash
git clone <your-repo-url>
cd Agentic-Threat-Intel-Feed

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY and SLACK_WEBHOOK_URL
```

### Run locally

```bash
# Continuous polling (default: every 5 minutes)
python agent.py

# Single cycle (for cron/CI)
python agent.py --once
```

## Configuration

All settings are configured via environment variables (`.env` file locally, GitHub Secrets for Actions).

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | *(required)* | Claude API key |
| `SLACK_WEBHOOK_URL` | *(empty)* | Slack Incoming Webhook URL |
| `SMTP_HOST` | *(empty)* | SMTP server for email digest |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` / `SMTP_PASS` | *(empty)* | SMTP credentials |
| `EMAIL_FROM` / `EMAIL_TO` | *(empty)* | Email sender and recipient |
| `POLL_INTERVAL_SECONDS` | `300` | Polling interval for local mode (seconds) |
| `SEVERITY_THRESHOLD` | `6` | Minimum severity score (1-10) to trigger notifications |
| `DAILY_COST_LIMIT_USD` | `1.00` | Daily Claude API spend cap (USD) |
| `DB_PATH` | `data/seen_items.db` | Path to SQLite deduplication database |

Both Slack and email notifiers are **stub-safe** — they print what would be sent if credentials are not configured.

## GitHub Actions Deployment

The agent runs automatically via GitHub Actions on a cron schedule (every 30 minutes, 6am-10pm UTC).

### Setup

1. Push the repo to GitHub
2. Go to **Settings** > **Secrets and variables** > **Actions**
3. Add repository secrets:
   - `ANTHROPIC_API_KEY`
   - `SLACK_WEBHOOK_URL`
4. The workflow starts automatically on the cron schedule

To trigger manually: **Actions** tab > **Threat Intelligence Agent** > **Run workflow**

The dedup database is persisted between runs via GitHub Actions cache.

## Cost Management

- **Model**: Claude Sonnet 4.5 (~$1-2/week under normal usage)
- **Daily cap**: Built-in `DAILY_COST_LIMIT_USD` stops API calls once the daily budget is reached
- **Deduplication**: SQLite DB prevents re-processing items across cycles
- **Recommendation**: Set a monthly spend limit on the [Anthropic Console](https://console.anthropic.com) as an additional safeguard

## Project Structure

```
.
├── agent.py              # Orchestrator — async loop or single cycle (--once)
├── collector.py          # Data source fetchers (RSS, NVD, CISA, Reddit)
├── config.py             # Centralized configuration from .env
├── deduplicator.py       # SQLite-backed dedup (SHA-256 fingerprinting)
├── enricher.py           # Claude AI triage with cost tracking
├── deep_diver.py         # Autonomous deep-dive analysis for high-severity items
├── notifier.py           # Slack webhook + email digest delivery
├── requirements.txt      # Python dependencies
├── .env.example          # Template for environment variables
├── .gitignore            # Excludes .env, data/, venv/, etc.
└── .github/
    └── workflows/
        └── threat-intel.yml  # GitHub Actions cron workflow
```

## Security

- Credentials are stored in `.env` (excluded from git via `.gitignore`)
- The enricher includes prompt injection defense — external content is treated as data, not instructions
- GitHub Actions secrets are used for CI/CD deployment
