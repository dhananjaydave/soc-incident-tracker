"""Checks whether the three internal tools the Investigate tab depends on
(IOC Enrichment, Phishing Triage, File Analyser) are actually reachable.
They're no longer publicly hosted, so nothing else would ever surface it
if one of them silently died - the analyst would just get a confusing
502 the next time they tried to use that tab mid-investigation.
"""

from __future__ import annotations

import httpx

from . import integrations

REQUEST_TIMEOUT_SECONDS = 5.0

_TARGETS = {
    "IOC Enrichment": integrations.IOC_API_URL,
    "Phishing Triage": integrations.PHISHING_API_URL,
    "File Analyser": integrations.FILE_ANALYSER_API_URL,
}


async def _is_reachable(base_url: str) -> bool:
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            resp = await client.get(f"{base_url}/health")
            return resp.status_code == 200
    except Exception:
        return False


async def check_internal_tools() -> list[str]:
    """Returns the names of any tool that's currently unreachable."""
    down = []
    for name, url in _TARGETS.items():
        if not await _is_reachable(url):
            down.append(name)
    return down
