"""Generic, industry-standard SOPs for common alert types - seeded so the
tracker is useful immediately, not blocked on waiting for the user's real
SOPs. upsert_sop() only OVERWRITES, never deletes, so once the user's
real SOPs are added these are simply replaced for that alert type.
"""

from __future__ import annotations

from .db import TrackerDB

DEFAULT_SOPS: dict[str, str] = {
    "System Compromise": (
        "1. Confirm the indicator (process/hash/connection) is actually present on the host - don't isolate on a single unconfirmed alert.\n"
        "2. Preserve evidence first: snapshot running processes, network connections, and relevant logs before taking containment action.\n"
        "3. Isolate the host from the network (EDR containment or network team) once evidence is captured.\n"
        "4. Identify scope - check for the same indicator/hash on other hosts before assuming this is isolated.\n"
        "5. Reset credentials for any accounts active on the host at the time of compromise.\n"
        "6. Escalate to IR if data access/exfiltration is plausible, or if scope extends beyond one host.\n"
        "7. Document everything in the ticket as you go - don't reconstruct the timeline afterward from memory."
    ),
    "Phishing": (
        "1. Confirm whether the email was opened/link clicked/attachment executed - this determines urgency.\n"
        "2. Extract and enrich all IOCs (sender domain, links, attachment hash) - the Phishing Triage Bot/IOC Enrichment API in this same SOC Lab handles this directly.\n"
        "3. If credentials were entered on a phishing page, treat as a confirmed compromise - reset credentials and force MFA re-registration immediately.\n"
        "4. Check if the same sender/subject/link was sent to other users - this is rarely a single-target attempt.\n"
        "5. Block the sender domain/URL at the email gateway and proxy if not already blocked.\n"
        "6. Notify the affected user and their manager with plain-language guidance, not just a closure note."
    ),
    "Brute Force": (
        "1. Confirm whether any of the attempted logins actually succeeded - this is the single most important fact.\n"
        "2. If none succeeded: check if the account should be temporarily locked and whether the source is already on a watchlist.\n"
        "3. If one succeeded: treat as a confirmed compromise, not a brute-force alert - follow the System Compromise SOP instead.\n"
        "4. Check source IP reputation and whether it's part of a known credential-stuffing campaign.\n"
        "5. Consider blocking the source IP/range at the perimeter if volume is high.\n"
        "6. If the account is privileged, escalate regardless of success/failure - the attempt itself is meaningful."
    ),
    "Malware Detection": (
        "1. Confirm the file/process was actually executed, not just written to disk or quarantined on arrival.\n"
        "2. Check the file hash against reputation sources (the IOC Enrichment API in this same SOC Lab) before assuming severity.\n"
        "3. If executed: follow the System Compromise SOP for containment and scoping.\n"
        "4. If quarantined/blocked before execution: confirm the block was effective and check for related artifacts (dropped files, persistence) anyway.\n"
        "5. Identify delivery vector (email, download, removable media, lateral movement) - this determines what else needs checking."
    ),
    "Data Exfiltration": (
        "1. Confirm the destination is not an authorized business service (cloud storage, backup target) before treating as malicious.\n"
        "2. Quantify volume and what data classification was involved - this determines escalation urgency.\n"
        "3. Block the destination if external and unauthorized.\n"
        "4. Escalate to IR immediately if confirmed - this typically has legal/compliance notification implications.\n"
        "5. Preserve network logs covering the full transfer window before they age out of retention."
    ),
    "Unauthorized Access": (
        "1. Confirm whether access was to resources outside the user's normal role/permissions.\n"
        "2. Check for impossible-travel or unusual-location indicators on the session.\n"
        "3. If the account is shared/service account, identify who/what was actually using it at the time.\n"
        "4. Revoke active sessions and force re-authentication if compromise is plausible.\n"
        "5. Review what the access was actually used for (data viewed, changes made) before closing - access alone isn't the full picture."
    ),
}


async def seed_default_sops(db: TrackerDB) -> None:
    existing = {s["alert_type"] for s in await db.list_sops()}
    for alert_type, steps in DEFAULT_SOPS.items():
        if alert_type not in existing:
            await db.upsert_sop(alert_type, steps)
