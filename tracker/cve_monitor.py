"""Checks two free, no-key public sources for things worth paging the
analyst about: NVD's real CVE REST API (high/critical severity only -
NVD publishes ~30-50 CVEs/day, far too many to notify on every one) and
CISA's Known Exploited Vulnerabilities catalog (every entry on it is, by
definition, already being exploited in the wild - more actionable than a
bare CVSS score). Both verified live and working before this was built.

Dedup is by CVE ID against a small "already notified" list persisted in
the settings table (capped so it can't grow unbounded), not by a simple
date marker - NVD's lastModified field means the same CVE can legitimately
reappear in a later query window (re-scored, description corrected), and
a pure date cutoff would either miss that or re-notify on every check.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

import httpx

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

MIN_CVSS_SCORE = 7.0
CVE_LOOKBACK_HOURS = 24
MAX_NOTIFIED_IDS_KEPT = 300
REQUEST_TIMEOUT_SECONDS = 20

NOTIFIED_CVE_IDS_KEY = "cve_monitor_notified_cve_ids"
NOTIFIED_KEV_IDS_KEY = "cve_monitor_notified_kev_ids"


def _extract_cvss_score(cve: dict) -> float | None:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            return metrics[key][0]["cvssData"]["baseScore"]
    return None


def _extract_description(cve: dict) -> str:
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


async def _fetch_recent_high_severity_cves() -> list[dict]:
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=CVE_LOOKBACK_HOURS)
    params = {
        "lastModStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 200,
    }
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
        resp = await client.get(NVD_API_URL, params=params, headers={"User-Agent": "soc-incident-tracker"})
        resp.raise_for_status()
        data = resp.json()

    found = []
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        score = _extract_cvss_score(cve)
        if score is not None and score >= MIN_CVSS_SCORE:
            found.append({
                "id": cve["id"], "cvss": score, "description": _extract_description(cve)[:300],
                "link": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
            })
    return found


async def _fetch_kev_catalog() -> list[dict]:
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
        resp = await client.get(KEV_CATALOG_URL, headers={"User-Agent": "soc-incident-tracker"})
        resp.raise_for_status()
        data = resp.json()
    return data.get("vulnerabilities", [])


async def check_for_new_cves(db) -> list[dict]:
    try:
        candidates = await _fetch_recent_high_severity_cves()
    except Exception as exc:
        logger.warning("NVD CVE check failed: %s", exc)
        return []

    raw = await db.get_setting(NOTIFIED_CVE_IDS_KEY)
    already_notified = set(json.loads(raw)) if raw else set()

    new_ones = [c for c in candidates if c["id"] not in already_notified]
    if new_ones:
        updated = list(already_notified | {c["id"] for c in new_ones})[-MAX_NOTIFIED_IDS_KEPT:]
        await db.set_setting(NOTIFIED_CVE_IDS_KEY, json.dumps(updated))
    return new_ones


async def check_for_new_kev_entries(db) -> list[dict]:
    try:
        catalog = await _fetch_kev_catalog()
    except Exception as exc:
        logger.warning("CISA KEV check failed: %s", exc)
        return []

    raw = await db.get_setting(NOTIFIED_KEV_IDS_KEY)
    already_notified = set(json.loads(raw)) if raw else None

    if already_notified is None:
        # First run ever - seed with the full existing catalog rather than
        # notifying on 1000+ historical entries all at once.
        await db.set_setting(NOTIFIED_KEV_IDS_KEY, json.dumps([v["cveID"] for v in catalog][-MAX_NOTIFIED_IDS_KEPT:]))
        return []

    new_entries = [v for v in catalog if v.get("cveID") not in already_notified]
    if new_entries:
        updated = list(already_notified | {v["cveID"] for v in new_entries})[-MAX_NOTIFIED_IDS_KEPT:]
        await db.set_setting(NOTIFIED_KEV_IDS_KEY, json.dumps(updated))
    return [
        {"id": v.get("cveID"), "name": v.get("vulnerabilityName", ""), "date_added": v.get("dateAdded", ""),
         "link": f"https://nvd.nist.gov/vuln/detail/{v.get('cveID')}"}
        for v in new_entries
    ]
