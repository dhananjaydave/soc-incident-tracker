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
    assert "New high-severity CVEs (CVSS>=7): 0" in digest


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
    with patch("tracker.daily_digest.cve_monitor._fetch_recent_high_severity_cves", new_callable=AsyncMock, return_value=[fake_cve]):
        digest = await build_daily_digest(db)

    assert "New high-severity CVEs (CVSS>=7): 1" in digest
    assert "CVE-2026-0001" in digest


async def test_digest_degrades_gracefully_if_cve_lookup_fails(db):
    with patch("tracker.daily_digest.cve_monitor._fetch_recent_high_severity_cves", new_callable=AsyncMock, side_effect=ConnectionError("down")):
        digest = await build_daily_digest(db)

    assert "New high-severity CVEs (CVSS>=7): 0" in digest
