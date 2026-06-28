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
