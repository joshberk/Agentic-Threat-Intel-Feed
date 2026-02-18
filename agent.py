"""
agent.py — Agentic Threat Intel Feed

Orchestration loop:
  collect → deduplicate → enrich (Claude) → notify (Slack + Email)

Run:
  python agent.py

Credentials are loaded from .env  (see .env.example).
Slack and Email notifiers print stubs when credentials are not yet configured.
"""

import asyncio
import sys
from datetime import datetime

import config
from collector import collect_all
from deduplicator import filter_new, mark_seen
from enricher import enrich
from notifier import send_email, send_slack


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


async def run_cycle() -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] ── Cycle start ──────────────────────────────────────")

    # 1. Collect
    raw = await collect_all()
    print(f"[{ts}] Collected   : {len(raw)} raw items")

    # 2. Deduplicate
    new_items = filter_new(raw)
    print(f"[{ts}] New (unseen): {len(new_items)} items")

    if not new_items:
        print(f"[{ts}] Nothing new — sleeping until next cycle.\n")
        return

    # 3. Enrich via Claude
    enriched = enrich(new_items)
    print(f"[{ts}] Relevant    : {len(enriched)} items after Claude triage")

    # Mark everything collected as seen now, regardless of relevance,
    # so we never re-send the same raw item.
    mark_seen(new_items)

    # 4. Apply severity threshold
    to_notify = [i for i in enriched if i.get("severity", 0) >= config.SEVERITY_THRESHOLD]
    print(f"[{ts}] To notify   : {len(to_notify)} items at or above threshold {config.SEVERITY_THRESHOLD}/10")

    if not to_notify:
        print(f"[{ts}] No items above threshold — sleeping until next cycle.\n")
        return

    # 5. Send to Slack (one message per item for real-time feel)
    await asyncio.gather(*[send_slack(item) for item in to_notify])

    # 6. Send email digest (batched)
    send_email(to_notify)

    print(f"[{ts}] Cycle complete — {len(to_notify)} notification(s) sent.\n")


async def main(once: bool = False) -> None:
    _banner()

    if not config.ANTHROPIC_API_KEY:
        print("[agent] ERROR: ANTHROPIC_API_KEY is not set. Add it to your .env file.")
        return

    if once:
        # Single cycle mode (for GitHub Actions / cron)
        await run_cycle()
        print("[agent] Single cycle complete.")
        return

    while True:
        try:
            await run_cycle()
        except KeyboardInterrupt:
            print("\n[agent] Interrupted — shutting down.")
            break
        except Exception as exc:
            print(f"[agent] Unhandled cycle error: {exc}")

        print(f"[agent] Sleeping {config.POLL_INTERVAL_SECONDS}s …")
        await asyncio.sleep(config.POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    once = "--once" in sys.argv
    try:
        asyncio.run(main(once=once))
    except KeyboardInterrupt:
        print("\n[agent] Goodbye.")
