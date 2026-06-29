"""Aggregates free, no-API-key security news RSS feeds into one "what's
happening today" list. Sources picked for being free, stable, and not
requiring a key - not an exhaustive threat-intel feed, just a daily
relevance news corner.

Image handling: most security blogs don't embed an image in their RSS/
Atom XML at all (verified empirically - Krebs, BleepingComputer, SANS ISC,
Dark Reading, and Schneier all carry none). Only Hacker News and The
Record include a real enclosure image. Rather than scraping each
article's full HTML page for an og:image tag (slower, fragile, and not
great behavior for something that auto-refreshes), entries without a real
feed-provided image just go without one - the frontend shows a plain
source-name badge instead.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from datetime import datetime, timezone

import feedparser

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 30 * 60
_cache: dict[str, tuple[float, list[dict]]] = {}

FEED_SOURCES: dict[str, str] = {
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "SANS Internet Storm Center": "https://isc.sans.edu/rssfeed_full.xml",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
    "Schneier on Security": "https://www.schneier.com/feed/atom/",
    "The Record": "https://therecord.media/feed/",
}

MAX_ENTRIES_PER_SOURCE = 5
FETCH_TIMEOUT_SECONDS = 10

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _extract_image(entry) -> str | None:
    for enclosure in entry.get("enclosures", []):
        enc_type = enclosure.get("type", "")
        href = enclosure.get("href")
        if href and enc_type.startswith("image/"):
            return href
    return None


def _extract_cve_ids(title: str) -> list[str]:
    return sorted({m.upper() for m in CVE_PATTERN.findall(title)})


def _fetch_one_sync(source_name: str, url: str) -> dict:
    try:
        parsed = feedparser.parse(url)
    except Exception as exc:
        logger.warning("Feed fetch failed for %s: %s", source_name, exc)
        return {"source": source_name, "status": "error", "entries": []}

    if not parsed.entries:
        return {"source": source_name, "status": "error", "entries": []}

    entries = []
    for e in parsed.entries[:MAX_ENTRIES_PER_SOURCE]:
        title = e.get("title", "(no title)")
        published_parsed = e.get("published_parsed")
        published_iso = (
            datetime(*published_parsed[:6], tzinfo=timezone.utc).isoformat() if published_parsed else None
        )
        entries.append({
            "title": title,
            "link": e.get("link", ""),
            "published": e.get("published", ""),
            "published_iso": published_iso,
            "image": _extract_image(e),
            "cve_ids": _extract_cve_ids(title),
        })
    return {"source": source_name, "status": "ok", "entries": entries}


async def fetch_all_feeds(use_cache: bool = True) -> list[dict]:
    if use_cache:
        cached_at, cached_value = _cache.get("all", (0, None))
        if cached_value is not None and time.time() - cached_at < CACHE_TTL_SECONDS:
            return cached_value

    async def _fetch_with_timeout(name: str, url: str) -> dict:
        try:
            return await asyncio.wait_for(asyncio.to_thread(_fetch_one_sync, name, url), timeout=FETCH_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            logger.warning("Feed fetch timed out for %s", name)
            return {"source": name, "status": "error", "entries": []}

    results = list(await asyncio.gather(*(_fetch_with_timeout(name, url) for name, url in FEED_SOURCES.items())))
    _cache["all"] = (time.time(), results)
    return results


def merge_latest(results: list[dict], limit: int = 12) -> list[dict]:
    """Flattens every source's entries into one list sorted by recency -
    entries with no parseable date sort last rather than crashing the sort."""
    merged = []
    for result in results:
        for entry in result.get("entries", []):
            merged.append({**entry, "source": result["source"]})
    merged.sort(key=lambda e: e["published_iso"] or "", reverse=True)
    return merged[:limit]
