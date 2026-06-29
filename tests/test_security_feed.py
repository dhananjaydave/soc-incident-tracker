from unittest.mock import MagicMock, patch

from tracker import security_feed


class _FakeEntry(dict):
    def get(self, key, default=None):
        return dict.get(self, key, default)


def _fake_parsed(entries):
    fake = MagicMock()
    fake.entries = entries
    return fake


async def test_fetch_all_feeds_returns_one_entry_per_source(monkeypatch):
    monkeypatch.setattr(security_feed, "_cache", {})

    def fake_parse(url):
        return _fake_parsed([_FakeEntry(title="Test Article", link="https://example.com/a", published="2026-01-01")])

    with patch("tracker.security_feed.feedparser.parse", side_effect=fake_parse):
        results = await security_feed.fetch_all_feeds(use_cache=False)

    assert len(results) == len(security_feed.FEED_SOURCES)
    assert all(r["status"] == "ok" for r in results)
    assert all(r["entries"][0]["title"] == "Test Article" for r in results)


async def test_fetch_all_feeds_degrades_gracefully_on_empty_feed(monkeypatch):
    monkeypatch.setattr(security_feed, "_cache", {})

    with patch("tracker.security_feed.feedparser.parse", return_value=_fake_parsed([])):
        results = await security_feed.fetch_all_feeds(use_cache=False)

    assert all(r["status"] == "error" for r in results)
    assert all(r["entries"] == [] for r in results)


async def test_fetch_all_feeds_degrades_gracefully_on_exception(monkeypatch):
    monkeypatch.setattr(security_feed, "_cache", {})

    with patch("tracker.security_feed.feedparser.parse", side_effect=RuntimeError("network down")):
        results = await security_feed.fetch_all_feeds(use_cache=False)

    assert all(r["status"] == "error" for r in results)


async def test_fetch_all_feeds_caps_entries_per_source(monkeypatch):
    monkeypatch.setattr(security_feed, "_cache", {})
    many_entries = [_FakeEntry(title=f"Article {i}", link="x", published="") for i in range(20)]

    with patch("tracker.security_feed.feedparser.parse", return_value=_fake_parsed(many_entries)):
        results = await security_feed.fetch_all_feeds(use_cache=False)

    assert all(len(r["entries"]) <= security_feed.MAX_ENTRIES_PER_SOURCE for r in results)


async def test_fetch_all_feeds_uses_cache_on_second_call(monkeypatch):
    monkeypatch.setattr(security_feed, "_cache", {})
    call_count = {"n": 0}

    def fake_parse(url):
        call_count["n"] += 1
        return _fake_parsed([_FakeEntry(title="Cached?", link="x", published="")])

    with patch("tracker.security_feed.feedparser.parse", side_effect=fake_parse):
        await security_feed.fetch_all_feeds(use_cache=True)
        await security_feed.fetch_all_feeds(use_cache=True)

    assert call_count["n"] == len(security_feed.FEED_SOURCES)  # only fetched once, not twice


async def test_fetch_all_feeds_bypasses_cache_when_disabled(monkeypatch):
    monkeypatch.setattr(security_feed, "_cache", {})
    call_count = {"n": 0}

    def fake_parse(url):
        call_count["n"] += 1
        return _fake_parsed([_FakeEntry(title="Fresh", link="x", published="")])

    with patch("tracker.security_feed.feedparser.parse", side_effect=fake_parse):
        await security_feed.fetch_all_feeds(use_cache=False)
        await security_feed.fetch_all_feeds(use_cache=False)

    assert call_count["n"] == len(security_feed.FEED_SOURCES) * 2


def test_extract_image_from_enclosure():
    entry = _FakeEntry(enclosures=[{"type": "image/jpeg", "href": "https://example.com/pic.jpg"}])
    assert security_feed._extract_image(entry) == "https://example.com/pic.jpg"


def test_extract_image_returns_none_when_no_image_enclosure():
    entry = _FakeEntry(enclosures=[{"type": "application/pdf", "href": "https://example.com/doc.pdf"}])
    assert security_feed._extract_image(entry) is None


def test_extract_image_returns_none_when_no_enclosures():
    assert security_feed._extract_image(_FakeEntry()) is None


def test_extract_cve_ids_finds_single_cve():
    assert security_feed._extract_cve_ids("Critical RCE in Widget (CVE-2026-12345)") == ["CVE-2026-12345"]


def test_extract_cve_ids_finds_multiple_and_dedupes():
    title = "CVE-2026-1111 and cve-2026-1111 both patched, plus CVE-2025-9999"
    assert security_feed._extract_cve_ids(title) == ["CVE-2025-9999", "CVE-2026-1111"]


def test_extract_cve_ids_empty_when_none_present():
    assert security_feed._extract_cve_ids("No vulnerabilities mentioned here") == []


def test_merge_latest_sorts_by_recency_across_sources():
    results = [
        {"source": "A", "entries": [{"title": "Older", "published_iso": "2026-01-01T00:00:00+00:00"}]},
        {"source": "B", "entries": [{"title": "Newer", "published_iso": "2026-06-01T00:00:00+00:00"}]},
    ]
    merged = security_feed.merge_latest(results)
    assert merged[0]["title"] == "Newer"
    assert merged[1]["title"] == "Older"


def test_merge_latest_respects_limit():
    results = [{"source": "A", "entries": [{"title": f"Item {i}", "published_iso": "2026-01-01T00:00:00+00:00"} for i in range(20)]}]
    merged = security_feed.merge_latest(results, limit=5)
    assert len(merged) == 5


def test_merge_latest_entries_with_no_date_sort_last():
    results = [
        {"source": "A", "entries": [{"title": "No date", "published_iso": None}]},
        {"source": "B", "entries": [{"title": "Has date", "published_iso": "2026-01-01T00:00:00+00:00"}]},
    ]
    merged = security_feed.merge_latest(results)
    assert merged[0]["title"] == "Has date"
    assert merged[1]["title"] == "No date"
