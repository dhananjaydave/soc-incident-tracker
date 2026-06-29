import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from tracker.daily_digest import build_daily_digest
from tracker.db import TrackerDB


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        yield TrackerDB(db_path=str(Path(tmp) / "test.db"))


async def test_digest_with_no_activity(db):
    with patch("tracker.daily_digest.cve_monitor._fetch_recent_high_severity_cves", new_callable=AsyncMock, return_value=[]):
        digest = await build_daily_digest(db)
    assert "Incidents: 0 total" in digest
    assert "New critical CVEs (CVSS>=9.0): 0" in digest


async def test_digest_includes_incident_counts(db):
    await db.create_incident("Phishing", "test")
    escalated = await db.create_incident("System Compromise", "test")
    await db.update_status(escalated["id"], "escalated")

    with patch("tracker.daily_digest.cve_monitor._fetch_recent_high_severity_cves", new_callable=AsyncMock, return_value=[]):
        digest = await build_daily_digest(db)

    assert "Incidents: 2 total" in digest
    assert "open: 1" in digest
    assert "escalated: 1" in digest


async def test_digest_includes_stale_count(db):
    import sqlite3
    from datetime import datetime, timedelta, timezone
    incident = await db.create_incident("Phishing", "old ticket")
    old_time = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    conn = sqlite3.connect(db.db_path)
    conn.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (old_time, incident["id"]))
    conn.commit()
    conn.close()

    with patch("tracker.daily_digest.cve_monitor._fetch_recent_high_severity_cves", new_callable=AsyncMock, return_value=[]):
        digest = await build_daily_digest(db)

    assert "Stale (no update in 24h+): 1" in digest


async def test_digest_includes_cve_findings(db):
    fake_cve = {"id": "CVE-2026-0001", "cvss": 9.8, "description": "x", "link": "https://example.com"}
    with patch("tracker.daily_digest.cve_monitor._fetch_recent_high_severity_cves", new_callable=AsyncMock, return_value=[fake_cve]) as mock_fetch:
        digest = await build_daily_digest(db)

    mock_fetch.assert_called_once_with(min_cvss=9.0)
    assert "New critical CVEs (CVSS>=9.0): 1" in digest
    assert "CVE-2026-0001" in digest


async def test_digest_caps_shown_cves_and_notes_remainder(db):
    fake_cves = [{"id": f"CVE-2026-{i:04d}", "cvss": 9.0 + i * 0.1, "description": "x", "link": "x"} for i in range(8)]
    with patch("tracker.daily_digest.cve_monitor._fetch_recent_high_severity_cves", new_callable=AsyncMock, return_value=fake_cves):
        digest = await build_daily_digest(db)

    assert "New critical CVEs (CVSS>=9.0): 8" in digest
    assert "...and 3 more" in digest


async def test_digest_shows_top_cves_by_score_not_arbitrary_order(db):
    fake_cves = [
        {"id": "CVE-LOW", "cvss": 9.1, "description": "x", "link": "x"},
        {"id": "CVE-HIGH", "cvss": 9.9, "description": "x", "link": "x"},
    ]
    with patch("tracker.daily_digest.cve_monitor._fetch_recent_high_severity_cves", new_callable=AsyncMock, return_value=fake_cves):
        digest = await build_daily_digest(db)

    assert digest.index("CVE-HIGH") < digest.index("CVE-LOW")


async def test_digest_degrades_gracefully_if_cve_lookup_fails(db):
    with patch("tracker.daily_digest.cve_monitor._fetch_recent_high_severity_cves", new_callable=AsyncMock, side_effect=ConnectionError("down")):
        digest = await build_daily_digest(db)

    assert "New critical CVEs (CVSS>=9.0): 0" in digest
