"""Calls the other three SOC Lab tools (IOC Enrichment, Phishing Triage,
File Analyser) over localhost HTTP, internally - they keep running as
their own separate, already-tested services (not public anymore), and
the tracker is just another internal caller of them, the same way
file-analyser already calls ioc-enrichment-api today. This is what lets
an analyst investigate an indicator/email/file without leaving the
tracker - "everything in one place" without rewriting any of that logic.
"""

from __future__ import annotations

import os

import httpx

IOC_API_URL = os.environ.get("IOC_ENRICHMENT_API_URL", "http://localhost:8001")
IOC_API_KEY = os.environ.get("IOC_ENRICHMENT_API_KEY")

PHISHING_API_URL = os.environ.get("PHISHING_TRIAGE_API_URL", "http://localhost:8002")

FILE_ANALYSER_API_URL = os.environ.get("FILE_ANALYSER_API_URL", "http://localhost:8004")
FILE_ANALYSER_API_KEY = os.environ.get("FILE_ANALYSER_API_KEY")

TIMEOUT_SECONDS = 30.0


async def lookup_ioc(indicator: str, checks: str = "all") -> dict:
    headers = {"X-API-Key": IOC_API_KEY} if IOC_API_KEY else {}
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
        resp = await client.get(
            f"{IOC_API_URL}/enrich", params={"indicator": indicator, "checks": checks}, headers=headers,
        )
        resp.raise_for_status()
        return resp.json()


async def analyze_phishing(raw_text: str | None = None, file_bytes: bytes | None = None,
                            filename: str | None = None) -> dict:
    data = {"raw_text": raw_text} if raw_text else {}
    files = {"file": (filename or "email.eml", file_bytes)} if file_bytes else {}
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
        resp = await client.post(f"{PHISHING_API_URL}/demo/analyze", data=data, files=files)
        resp.raise_for_status()
        return resp.json()


async def analyze_file(file_bytes: bytes, filename: str) -> dict:
    headers = {"X-API-Key": FILE_ANALYSER_API_KEY} if FILE_ANALYSER_API_KEY else {}
    files = {"file": (filename, file_bytes)}
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
        resp = await client.post(f"{FILE_ANALYSER_API_URL}/analyze", files=files, headers=headers)
        resp.raise_for_status()
        return resp.json()
