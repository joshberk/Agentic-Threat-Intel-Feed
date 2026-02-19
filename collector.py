"""
collector.py — Fetches raw news items from all configured sources.

Security hardening:
  • follow_redirects=False — prevents TLS-downgrade redirect attacks
  • Sequential RSS fetching with 500 ms delay — basic rate limiting
  • Typed exception handling — avoids swallowing unexpected errors silently

Sources (MVP):
  • RSS feeds  — TheHackerNews, BleepingComputer, KrebsOnSecurity,
                  DarkReading, Threatpost, SANS ISC
  • NVD CVE API — CVEs published in the last 2 hours
  • CISA KEV    — Known Exploited Vulnerabilities catalog (most recent 20)

Reddit is stubbed; it will be wired in once credentials are available.
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta

import feedparser
import httpx

import config

log = logging.getLogger(__name__)

# ── RSS sources ───────────────────────────────────────────────────────────────
RSS_FEEDS: list[dict] = [
    {"name": "TheHackerNews",   "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "BleepingComputer","url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "KrebsOnSecurity", "url": "https://krebsonsecurity.com/feed/"},
    {"name": "DarkReading",     "url": "https://www.darkreading.com/rss.xml"},
    {"name": "Threatpost",      "url": "https://threatpost.com/feed/"},
    {"name": "SANS ISC",        "url": "https://isc.sans.edu/rssfeed_full.xml"},
]

# Cap items taken per RSS feed per cycle to avoid overwhelming the enricher.
RSS_ITEMS_PER_FEED = 10


# ── Helpers ───────────────────────────────────────────────────────────────────
def _normalize_rss(entry: dict, source: str) -> dict:
    return {
        "id":        entry.get("link") or entry.get("id", ""),
        "title":     entry.get("title", "No title"),
        "url":       entry.get("link", ""),
        "source":    source,
        "published": entry.get("published", ""),
        "content":   entry.get("summary", "") or entry.get("description", ""),
    }


def _nvd_cvss_score(cve: dict) -> float | None:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            return entries[0].get("cvssData", {}).get("baseScore")
    return None


# ── Fetchers ──────────────────────────────────────────────────────────────────
async def _get_with_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    source: str = "",
    max_retries: int = 2,
    **kwargs,
) -> httpx.Response | None:
    """
    GET with exponential backoff on 429 / 5xx responses (OWASP A09).
    Returns None if all retries are exhausted.
    """
    for attempt in range(max_retries + 1):
        try:
            resp = await client.get(url, **kwargs)
            if resp.status_code in (429, 500, 503) and attempt < max_retries:
                wait = 2 ** attempt * 2  # 2s, 4s
                log.warning(
                    "HTTP %s from %s — retrying in %ds (attempt %d/%d)",
                    resp.status_code, source or "<redacted>", wait, attempt + 1, max_retries + 1,
                )
                await asyncio.sleep(wait)
                continue
            return resp
        except httpx.TimeoutException:
            if attempt < max_retries:
                wait = 2 ** attempt * 2
                log.warning("Timeout fetching %s — retrying in %ds", source, wait)
                await asyncio.sleep(wait)
            else:
                raise
    return None


async def fetch_rss_feeds(client: httpx.AsyncClient) -> list[dict]:
    """Fetch RSS feeds sequentially with a short delay to avoid hammering sources."""
    items: list[dict] = []
    for feed in RSS_FEEDS:
        try:
            resp = await _get_with_retry(client, feed["url"], source=feed["name"], timeout=15)
            if resp is None:
                continue
            resp.raise_for_status()
            parsed = feedparser.parse(resp.text)
            for entry in parsed.entries[:RSS_ITEMS_PER_FEED]:
                items.append(_normalize_rss(entry, feed["name"]))
        except httpx.TimeoutException:
            log.warning("RSS timeout [%s]", feed["name"])
        except httpx.HTTPStatusError as exc:
            log.warning("RSS HTTP %s [%s]", exc.response.status_code, feed["name"])
        except Exception as exc:
            log.error("RSS unexpected error [%s]: %s", feed["name"], type(exc).__name__)
        # Polite delay between feeds — basic rate limiting
        await asyncio.sleep(0.5)
    return items


async def fetch_nvd_cves(client: httpx.AsyncClient) -> list[dict]:
    """CVEs published in the last 2 hours via NVD REST API v2."""
    items: list[dict] = []
    now   = datetime.now(timezone.utc)
    start = now - timedelta(hours=2)
    fmt   = "%Y-%m-%dT%H:%M:%S.000"

    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?pubStartDate={start.strftime(fmt)}&pubEndDate={now.strftime(fmt)}"
    )
    headers = {}
    if config.NVD_API_KEY:
        headers["apiKey"] = config.NVD_API_KEY
    try:
        resp = await _get_with_retry(client, url, source="NVD", headers=headers, timeout=20)
        if resp is None:
            return items
        resp.raise_for_status()
        data = resp.json()
        for vuln in data.get("vulnerabilities", [])[:20]:
            cve    = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            descs  = cve.get("descriptions", [])
            desc   = next((d["value"] for d in descs if d["lang"] == "en"), "")
            score  = _nvd_cvss_score(cve)

            title = f"{cve_id}: {desc[:120]}{'...' if len(desc) > 120 else ''}"
            detail_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

            items.append({
                "id":         detail_url,
                "title":      title,
                "url":        detail_url,
                "source":     "NVD",
                "published":  cve.get("published", ""),
                "content":    desc,
                "cvss_score": score,
            })
    except httpx.TimeoutException:
        log.warning("NVD fetch timed out")
    except httpx.HTTPStatusError as exc:
        log.warning("NVD HTTP %s", exc.response.status_code)
    except Exception as exc:
        log.error("NVD unexpected error: %s", type(exc).__name__)
    return items


async def fetch_cisa_kev(client: httpx.AsyncClient) -> list[dict]:
    """Most-recently added entries from CISA's Known Exploited Vulnerabilities catalog."""
    items: list[dict] = []
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        resp = await _get_with_retry(client, url, source="CISA KEV", timeout=20)
        if resp is None:
            return items
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        # Most recently added first
        vulns = sorted(vulns, key=lambda v: v.get("dateAdded", ""), reverse=True)[:20]
        for v in vulns:
            cve_id     = v.get("cveID", "")
            detail_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            content    = (
                f"{v.get('shortDescription', '')} "
                f"Affected: {v.get('product', '')} by {v.get('vendorProject', '')}. "
                f"Required action: {v.get('requiredAction', '')}"
            )
            items.append({
                "id":        detail_url,
                "title":     f"[CISA KEV] {cve_id}: {v.get('vulnerabilityName', '')}",
                "url":       detail_url,
                "source":    "CISA KEV",
                "published": v.get("dateAdded", ""),
                "content":   content,
            })
    except httpx.TimeoutException:
        log.warning("CISA KEV fetch timed out")
    except httpx.HTTPStatusError as exc:
        log.warning("CISA KEV HTTP %s", exc.response.status_code)
    except Exception as exc:
        log.error("CISA KEV unexpected error: %s", type(exc).__name__)
    return items


async def fetch_reddit(client: httpx.AsyncClient) -> list[dict]:
    """
    Reddit collector — stubbed until credentials are configured.
    Subreddits: r/netsec, r/cybersecurity, r/hacking
    """
    # TODO: implement once REDDIT_CLIENT_ID / REDDIT_CLIENT_SECRET are set.
    log.debug("Reddit: skipped (credentials not configured)")
    return []


# ── Public API ────────────────────────────────────────────────────────────────
async def collect_all() -> list[dict]:
    """
    Run collectors and return a flat list of raw items.

    RSS feeds are fetched sequentially (with polite delays) using a shared client.
    NVD and CISA are fetched concurrently after RSS completes.
    follow_redirects=False prevents TLS-downgrade redirect attacks.
    """
    async with httpx.AsyncClient(follow_redirects=False) as client:
        # RSS is sequential to rate-limit; NVD + CISA run in parallel
        rss = await fetch_rss_feeds(client)
        nvd, cisa, reddit = await asyncio.gather(
            fetch_nvd_cves(client),
            fetch_cisa_kev(client),
            fetch_reddit(client),
        )
    return rss + nvd + cisa + reddit
