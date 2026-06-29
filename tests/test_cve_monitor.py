import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tracker import cve_monitor
from tracker.db import TrackerDB


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        yield TrackerDB(db_path=str(Path(tmp) / "test.db"))


def _nvd_response(cves: list[dict]) -> dict:
    return {"vulnerabilities": [{"cve": cve} for cve in cves]}


def _make_cve(cve_id: str, score: float | None, description: str = "Test vulnerability description") -> dict:
    cve = {"id": cve_id, "descriptions": [{"lang": "en", "value": description}]}
    if score is not None:
        cve["metrics"] = {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]}
    else:
        cve["metrics"] = {}
    return cve


def _mock_httpx_response(json_data):
    resp = MagicMock()
    resp.json.return_value = json_data
    resp.raise_for_status = MagicMock()
    return resp


def _mock_async_client(response):
    mock_client = AsyncMock()
    mock_client.get.return_value = response
    mock_client.__aenter__.return_value = mock_client
    return mock_client


async def test_check_for_new_cves_filters_by_severity(db):
    data = _nvd_response([_make_cve("CVE-2026-0001", 9.8), _make_cve("CVE-2026-0002", 3.1)])
    with patch("tracker.cve_monitor.httpx.AsyncClient", return_value=_mock_async_client(_mock_httpx_response(data))):
        results = await cve_monitor.check_for_new_cves(db)

    assert len(results) == 1
    assert results[0]["id"] == "CVE-2026-0001"


async def test_check_for_new_cves_excludes_unscored(db):
    data = _nvd_response([_make_cve("CVE-2026-0003", None)])
    with patch("tracker.cve_monitor.httpx.AsyncClient", return_value=_mock_async_client(_mock_httpx_response(data))):
        results = await cve_monitor.check_for_new_cves(db)

    assert results == []


async def test_check_for_new_cves_does_not_renotify_same_id(db):
    data = _nvd_response([_make_cve("CVE-2026-0004", 9.0)])
    with patch("tracker.cve_monitor.httpx.AsyncClient", return_value=_mock_async_client(_mock_httpx_response(data))):
        first = await cve_monitor.check_for_new_cves(db)
        second = await cve_monitor.check_for_new_cves(db)

    assert len(first) == 1
    assert second == []


async def test_check_for_new_cves_degrades_gracefully_on_failure(db):
    mock_client = AsyncMock()
    mock_client.get.side_effect = ConnectionError("NVD unreachable")
    mock_client.__aenter__.return_value = mock_client
    with patch("tracker.cve_monitor.httpx.AsyncClient", return_value=mock_client):
        results = await cve_monitor.check_for_new_cves(db)

    assert results == []


async def test_check_for_new_kev_entries_first_run_seeds_without_notifying(db):
    catalog = {"vulnerabilities": [{"cveID": "CVE-2020-0001", "vulnerabilityName": "Old one", "dateAdded": "2020-01-01"}]}
    with patch("tracker.cve_monitor.httpx.AsyncClient", return_value=_mock_async_client(_mock_httpx_response(catalog))):
        results = await cve_monitor.check_for_new_kev_entries(db)

    assert results == []
    seeded = await db.get_setting(cve_monitor.NOTIFIED_KEV_IDS_KEY)
    assert "CVE-2020-0001" in json.loads(seeded)


async def test_check_for_new_kev_entries_notifies_on_genuinely_new_entry(db):
    catalog_v1 = {"vulnerabilities": [{"cveID": "CVE-2020-0001", "vulnerabilityName": "Old one", "dateAdded": "2020-01-01"}]}
    with patch("tracker.cve_monitor.httpx.AsyncClient", return_value=_mock_async_client(_mock_httpx_response(catalog_v1))):
        await cve_monitor.check_for_new_kev_entries(db)

    catalog_v2 = {"vulnerabilities": [
        {"cveID": "CVE-2020-0001", "vulnerabilityName": "Old one", "dateAdded": "2020-01-01"},
        {"cveID": "CVE-2026-9999", "vulnerabilityName": "New exploited vuln", "dateAdded": "2026-06-29"},
    ]}
    with patch("tracker.cve_monitor.httpx.AsyncClient", return_value=_mock_async_client(_mock_httpx_response(catalog_v2))):
        results = await cve_monitor.check_for_new_kev_entries(db)

    assert len(results) == 1
    assert results[0]["id"] == "CVE-2026-9999"


async def test_check_for_new_kev_entries_degrades_gracefully_on_failure(db):
    mock_client = AsyncMock()
    mock_client.get.side_effect = ConnectionError("CISA unreachable")
    mock_client.__aenter__.return_value = mock_client
    with patch("tracker.cve_monitor.httpx.AsyncClient", return_value=mock_client):
        results = await cve_monitor.check_for_new_kev_entries(db)

    assert results == []
