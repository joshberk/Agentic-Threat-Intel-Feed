"""
agent.py — Agentic Threat Intel Feed

Orchestration loop:
  collect → deduplicate → enrich (Claude) → notify (Slack + Email)

Run:
  python agent.py

Credentials are loaded from .env  (see .env.example).
Slack and Email notifiers log stubs when credentials are not yet configured.
"""

import asyncio
import logging
import logging.handlers
import re
import sys
from datetime import datetime, timezone

import config
from collector import collect_all
from deduplicator import filter_new, mark_seen
from deep_diver import deep_dive
from enricher import enrich
from notifier import send_email, send_slack


# ── Logging setup ─────────────────────────────────────────────────────────────

_URL_RE = re.compile(
    r"https?://[^\s\"'<>]+"
    r"|hooks\.slack\.com/[^\s\"'<>]+"
    r"|sk-ant-[A-Za-z0-9\-]+"
)


class _RedactingFormatter(logging.Formatter):
    """Strip URLs and API keys from log records before emitting."""

    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        return _URL_RE.sub("<redacted>", original)


def _configure_logging() -> None:
    fmt = _RedactingFormatter(
        fmt="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    # Avoid duplicate handlers if called more than once (e.g. in tests)
    if not root.handlers:
        root.addHandler(handler)


log = logging.getLogger(__name__)


# ── Banner ────────────────────────────────────────────────────────────────────

def _banner() -> None:
    print("=" * 60)
    print("  🛡️  Agentic Threat Intel Feed")
    print("=" * 60)
    print(f"  Poll interval : {config.POLL_INTERVAL_SECONDS}s")
    print(f"  Sev threshold : {config.SEVERITY_THRESHOLD}/10")
    print(f"  Slack         : {'configured' if config.SLACK_WEBHOOK_URL else 'STUB (not configured)'}")
    print(f"  Email         : {'configured' if config.SMTP_HOST else 'STUB (not configured)'}")
    print(f"  Reddit        : {'configured' if config.REDDIT_CLIENT_ID else 'STUB (not configured)'}")
    print("=" * 60)
    print()


async def run_cycle() -> int:
    """
    Run one collect→deduplicate→enrich→notify cycle.
    Returns the number of high-severity items found (used for adaptive polling).
    """
    ts = datetime.now().strftime("%H:%M:%S")
    log.info("── Cycle start ──────────────────────────────────────")

    # 1. Collect
    raw = await collect_all()
    log.info("Collected   : %d raw items", len(raw))

    # 2. Deduplicate
    new_items = filter_new(raw)
    log.info("New (unseen): %d items", len(new_items))

    if not new_items:
        log.info("Nothing new — sleeping until next cycle.")
        return 0

    # 3. Enrich via Claude
    enriched = enrich(new_items)
    log.info("Relevant    : %d items after Claude triage", len(enriched))

    # Mark everything collected as seen now, regardless of relevance,
    # so we never re-send the same raw item.
    mark_seen(new_items)

    # 4. Apply severity threshold
    to_notify = [i for i in enriched if i.get("severity", 0) >= config.SEVERITY_THRESHOLD]
    log.info(
        "To notify   : %d items at or above threshold %d/10",
        len(to_notify), config.SEVERITY_THRESHOLD,
    )

    if not to_notify:
        log.info("No items above threshold — sleeping until next cycle.")
        return 0

    # 5. Autonomous deep dive on high-severity items
    to_notify = await deep_dive(to_notify)
    deep_count = sum(1 for i in to_notify if i.get("deep_dive"))
    if deep_count:
        log.info("Deep dives  : %d item(s) analysed in depth", deep_count)

    # 6. Send to Slack (one message per item for real-time feel)
    await asyncio.gather(*[send_slack(item) for item in to_notify])

    # 7. Send email digest (batched)
    send_email(to_notify)

    log.info("Cycle complete — %d notification(s) sent.", len(to_notify))

    # Return count of high-severity items for adaptive polling
    return sum(1 for i in to_notify if i.get("severity", 0) >= config.SPIKE_SEVERITY_MIN)


async def main(once: bool = False) -> None:
    _configure_logging()
    _banner()

    if not config.ANTHROPIC_API_KEY:
        log.error("ANTHROPIC_API_KEY is not set. Add it to your .env file.")
        return

    if once:
        # Single cycle mode (for GitHub Actions / cron)
        await run_cycle()
        log.info("Single cycle complete.")
        return

    spike_until: datetime | None = None  # when spike mode expires

    while True:
        try:
            high_sev_count = await run_cycle()
        except KeyboardInterrupt:
            log.info("Interrupted — shutting down.")
            break
        except Exception as exc:
            log.error("Unhandled cycle error: %s", type(exc).__name__)
            high_sev_count = 0

        now = datetime.now(timezone.utc)

        # Activate spike mode if enough high-severity items were found
        if high_sev_count >= config.SPIKE_TRIGGER_COUNT:
            spike_until = datetime.fromtimestamp(
                now.timestamp() + config.SPIKE_DURATION_SECONDS, tz=timezone.utc
            )
            log.info(
                "⚡ SPIKE MODE — %d high-severity items detected. "
                "Polling every %ds for %d min.",
                high_sev_count, config.SPIKE_POLL_SECONDS,
                config.SPIKE_DURATION_SECONDS // 60,
            )

        # Determine sleep interval
        if spike_until and now < spike_until:
            sleep_for = config.SPIKE_POLL_SECONDS
            remaining = int((spike_until.timestamp() - now.timestamp()) / 60)
            log.info("Spike mode active (%d min remaining) — sleeping %ds …", remaining, sleep_for)
        else:
            if spike_until and now >= spike_until:
                log.info("Spike mode expired — returning to normal polling.")
                spike_until = None
            sleep_for = config.POLL_INTERVAL_SECONDS
            log.info("Sleeping %ds …", sleep_for)

        await asyncio.sleep(sleep_for)


if __name__ == "__main__":
    once = "--once" in sys.argv
    try:
        asyncio.run(main(once=once))
    except KeyboardInterrupt:
        print("\n[agent] Goodbye.")
