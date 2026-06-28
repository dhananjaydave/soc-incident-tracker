"""Aggregates a handful of free, no-API-key security news RSS feeds into
one "what's happening today" list. Sources picked for being free,
stable, and not requiring a key - not an exhaustive threat-intel feed,
just a daily-relevance news corner.
"""

from __future__ import annotations

import asyncio
import logging
import time

import feedparser

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 30 * 60
_cache: dict[str, tuple[float, list[dict]]] = {}

FEED_SOURCES: dict[str, str] = {
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "SANS Internet Storm Center": "https://isc.sans.edu/rssfeed_full.xml",
}

MAX_ENTRIES_PER_SOURCE = 5
FETCH_TIMEOUT_SECONDS = 10


def _fetch_one_sync(source_name: str, url: str) -> dict:
    try:
        parsed = feedparser.parse(url)
    except Exception as exc:
        logger.warning("Feed fetch failed for %s: %s", source_name, exc)
        return {"source": source_name, "status": "error", "entries": []}

    if not parsed.entries:
        return {"source": source_name, "status": "error", "entries": []}

    entries = [
        {"title": e.get("title", "(no title)"), "link": e.get("link", ""), "published": e.get("published", "")}
        for e in parsed.entries[:MAX_ENTRIES_PER_SOURCE]
    ]
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
