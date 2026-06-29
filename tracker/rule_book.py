"""The Rule Book: real, named detection rules grouped under SOP categories,
each with the full structured guidance (investigation steps, required
fields, Splunk query hints, containment/closure checklists) that should
appear automatically the moment that rule is selected for a new ticket.

Seeded the same way as seed_sops.py - upsert_sop() only overwrites, so
editing a rule later (via the API) is never undone by a restart, and
adding a new rule here later never deletes one a user already customized.
"""

from __future__ import annotations

from .db import TrackerDB

SOP_CATEGORIES: list[dict[str, str]] = [
    {"id": "SOP-01", "name": "VPN / Authentication / Password Spraying"},
    {"id": "SOP-02", "name": "MFA Abuse / MFA Bypass"},
    {"id": "SOP-03", "name": "Risky Sign-in / Identity Compromise"},
    {"id": "SOP-04", "name": "Microsoft Defender Investigation"},
    {"id": "SOP-05", "name": "CrowdStrike / Endpoint Investigation"},
    {"id": "SOP-06", "name": "Phishing / Email Investigation"},
]

RULE_BOOK: dict[str, dict] = {
    "GP-VPN Brute Force Attempts": {
        "category": "SOP-01: VPN / Authentication / Password Spraying",
        "common_titles": [
            "Multiple failed VPN login attempts detected",
            "VPN brute force from single source IP",
            "Failed VPN authentication spike",
        ],
        "mitre_techniques": ["T1110", "T1133"],
        "description": (
            "Repeated failed VPN logins against one or more accounts from the same source. "
            "Business impact: a successful brute force gives an external actor a foothold "
            "directly on the internal network, bypassing perimeter controls entirely."
        ),
        "steps": (
            "1. Pull the full list of attempted usernames and the source IP/ASN.\n"
            "2. Check whether any attempt succeeded - if so, treat as confirmed compromise, not brute force.\n"
            "3. Check source IP reputation and whether it recurs across other tenants/logs.\n"
            "4. Check if targeted accounts are real, privileged, or stale/disabled accounts.\n"
            "5. Block the source IP/range at the VPN gateway if volume or reputation warrants it.\n"
            "6. Document attempt count, time window, and accounts targeted in the ticket."
        ),
        "structured": {
            "investigation_steps": [
                "Pull the full list of attempted usernames and the source IP/ASN.",
                "Check whether any attempt succeeded - if so, treat as confirmed compromise, not brute force.",
                "Check source IP reputation (use the IOC lookup) and whether it recurs across other logs.",
                "Check if targeted accounts are real, privileged, or stale/disabled accounts.",
                "Check for a pattern consistent with a known credential-stuffing list (sequential/dictionary usernames).",
            ],
            "required_fields": ["Source IP", "Targeted username(s)", "Attempt count", "Time window", "VPN gateway/site"],
            "escalation_criteria": "Any successful authentication, OR a privileged account was targeted, OR more than 50 attempts in a 10-minute window.",
            "splunk_query_hint": "index=vpn action=failure | stats count by src_ip, user | where count > 10",
            "containment_actions": [
                "Block source IP/range at the VPN gateway or firewall.",
                "Temporarily lock or require password reset for targeted accounts if attempts are ongoing.",
                "Notify the network/infra team if the source is internal.",
            ],
            "closure_checklist": [
                "Source IP and attempt count documented.",
                "Confirmed no successful authentication (or escalated if there was one).",
                "Block action taken and verified, if applicable.",
                "Disposition reason recorded.",
            ],
            "false_positive_indicators": [
                "Source IP belongs to a known scheduled job, monitoring tool, or misconfigured client retrying.",
                "Single account, single attempt, immediately followed by a successful login from the same IP (user mistyped password).",
            ],
        },
    },
    "Password Spraying Attempts": {
        "category": "SOP-01: VPN / Authentication / Password Spraying",
        "common_titles": [
            "Password spray detected across multiple accounts",
            "Low-volume credential spray attempt",
            "Spray attack against multiple users from one source",
        ],
        "mitre_techniques": ["T1110"],
        "description": (
            "Low-and-slow login attempts against MANY accounts using a small set of common "
            "passwords, designed to stay under per-account lockout thresholds. Business "
            "impact: a single hit across a large user base is often enough to gain initial access."
        ),
        "steps": (
            "1. Identify the full set of targeted accounts and confirm this is many-accounts/few-passwords (not the reverse, which is brute force).\n"
            "2. Check whether ANY targeted account had a successful login in the same window.\n"
            "3. Check source IP/ASN reputation and geography against normal user populations.\n"
            "4. Cross-reference targeted usernames against any recent breach/leak data if available.\n"
            "5. Recommend org-wide password reset only if a hit is confirmed or the spray is unusually broad.\n"
            "6. Document scope (number of accounts targeted) - this is the key severity signal for spraying, not per-account attempt count."
        ),
        "structured": {
            "investigation_steps": [
                "Confirm the pattern is many-accounts/few-passwords - distinguishes spraying from simple brute force.",
                "Check whether ANY targeted account had a successful login in the same window.",
                "Check source IP/ASN reputation and geography against normal user populations.",
                "Cross-reference targeted usernames against known breach/leak data if available.",
                "Check whether the same source has targeted other tenants/customers (common with commodity spray tools).",
            ],
            "required_fields": ["Source IP/ASN", "Number of accounts targeted", "Passwords attempted (if known)", "Time window"],
            "escalation_criteria": "Any successful login among targeted accounts, OR more than 20 accounts targeted in under an hour.",
            "splunk_query_hint": "index=auth action=failure | stats dc(user) as accounts_targeted by src_ip | where accounts_targeted > 10",
            "containment_actions": [
                "Block source IP/ASN at the identity provider or perimeter.",
                "Force password reset for any account with a successful login from the source.",
                "Enable/verify smart lockout or sign-in risk policies are active for the targeted tenant.",
            ],
            "closure_checklist": [
                "Total accounts targeted documented.",
                "Confirmed presence/absence of a successful login.",
                "Source blocked or risk policy confirmed active.",
                "Disposition reason recorded.",
            ],
            "false_positive_indicators": [
                "Source IP is a known internal vulnerability scanner or pentest engagement (check the authorized-testing calendar).",
            ],
        },
    },
    "Azure Risky Sign-in": {
        "category": "SOP-03: Risky Sign-in / Identity Compromise",
        "common_titles": [
            "Impossible travel sign-in detected",
            "Sign-in from anonymous IP",
            "Leaked credentials risk sign-in",
            "Unfamiliar sign-in properties flagged",
        ],
        "mitre_techniques": ["T1078", "T1114"],
        "description": (
            "Azure AD/Entra ID flagged a sign-in as risky (impossible travel, anonymous IP, "
            "unfamiliar sign-in properties, leaked credentials, etc). Business impact: this is "
            "Microsoft's own ML-based signal that the account may already be in an attacker's hands."
        ),
        "steps": (
            "1. Open the sign-in in Entra ID and read the specific risk detection type(s) - they change the investigation, not just the IP.\n"
            "2. Check sign-in location/device against the user's normal pattern and check with the user directly if reachable.\n"
            "3. Review what the session actually did after sign-in (mailbox rules added, OAuth app consent granted, files accessed).\n"
            "4. Check for new mail forwarding rules or inbox rules - a very common post-compromise persistence step.\n"
            "5. Revoke all active sessions and require re-authentication with MFA if compromise is plausible.\n"
            "6. Confirm with the user via a channel OTHER than email (Teams/phone) since email itself may be compromised."
        ),
        "structured": {
            "investigation_steps": [
                "Read the specific Entra ID risk detection type(s) (impossible travel, anonymous IP, leaked credentials, etc).",
                "Check sign-in location/device/browser against the user's normal pattern.",
                "Review post-sign-in activity: new mailbox rules, OAuth app consents, mass file downloads.",
                "Check for new mail forwarding or inbox rules - common persistence mechanism.",
                "Contact the user via Teams/phone (not email) to confirm or deny the sign-in.",
            ],
            "required_fields": ["User", "Risk detection type", "Source IP/location", "Device/browser", "Sign-in timestamp"],
            "escalation_criteria": "User denies the sign-in, OR new mailbox/forwarding rules found, OR account is privileged (admin role).",
            "splunk_query_hint": "Use Entra ID risky sign-ins report; cross-check with index=o365 eventtype=mailitemsaccessed for the same user/timeframe.",
            "containment_actions": [
                "Revoke all active sessions for the account.",
                "Force password reset and MFA re-registration.",
                "Remove any unauthorized inbox/forwarding rules or OAuth app grants found.",
            ],
            "closure_checklist": [
                "Risk detection type documented.",
                "User contacted and response recorded.",
                "Mailbox rules/OAuth grants checked and cleaned up if needed.",
                "Disposition reason recorded.",
            ],
            "false_positive_indicators": [
                "User confirmed travel matches the location (legitimate impossible-travel false positive from VPN/corporate proxy egress changes).",
                "Known corporate VPN exit node flagged as an anonymous IP.",
            ],
        },
    },
    "PingID MFA Spamming": {
        "category": "SOP-02: MFA Abuse / MFA Bypass",
        "common_titles": [
            "Unusual volume of MFA push prompts",
            "Suspected MFA fatigue attack",
            "Repeated MFA push notifications to user",
        ],
        "mitre_techniques": ["T1621", "T1111"],
        "description": (
            "A user is receiving an unusual volume of MFA push prompts they did not initiate "
            "('MFA fatigue' / 'MFA bombing'). Business impact: the attacker already has valid "
            "credentials and is trying to get the user to approve out of annoyance or confusion."
        ),
        "steps": (
            "1. Confirm with the user directly whether they approved any of the prompts.\n"
            "2. Treat ANY approval as a confirmed compromise - move straight to account containment.\n"
            "3. Identify the source IP/device generating the push requests.\n"
            "4. Check how the attacker obtained valid credentials in the first place (often a prior unreported phish).\n"
            "5. Reset the password regardless of approval status - the credential is known to be compromised.\n"
            "6. Educate the user on MFA fatigue attacks as part of closure, not just resetting and moving on."
        ),
        "structured": {
            "investigation_steps": [
                "Confirm with the user directly whether they approved any push prompt.",
                "Identify source IP/device generating the requests.",
                "Check authentication logs for the originating credential-entry event that triggered the pushes.",
                "Check if the same source IP appears against other accounts (often part of a wider campaign).",
            ],
            "required_fields": ["User", "Number of push prompts", "Time window", "Source IP (if available)", "User's response"],
            "escalation_criteria": "User approved any prompt, OR the account is privileged, OR the source IP matches a known-bad indicator.",
            "splunk_query_hint": "index=pingid eventtype=push | stats count by user | where count > 5",
            "containment_actions": [
                "Force password reset immediately, regardless of approval status.",
                "Revoke active sessions and re-register MFA device.",
                "Block source IP if identifiable.",
            ],
            "closure_checklist": [
                "Confirmed approval/denial status with the user.",
                "Password reset completed.",
                "User briefed on MFA fatigue tactics.",
                "Disposition reason recorded.",
            ],
            "false_positive_indicators": [
                "User has multiple devices/sessions auto-retrying a single legitimate login (e.g. laptop + phone both prompting for one sign-in).",
            ],
        },
    },
    "CrowdStrike High Alert": {
        "category": "SOP-05: CrowdStrike / Endpoint Investigation",
        "common_titles": [
            "CrowdStrike high-severity detection",
            "Suspicious process behavior flagged by Falcon",
            "Potential malware execution detected",
        ],
        "mitre_techniques": ["T1055", "T1059", "T1027"],
        "description": (
            "CrowdStrike Falcon flagged a high-severity detection on an endpoint (process "
            "injection, credential access, ransomware behavior, etc). Business impact varies "
            "by detection technique - this is an EDR signal, not yet a confirmed incident."
        ),
        "steps": (
            "1. Open the detection in the Falcon console and read the full process tree, not just the headline.\n"
            "2. Check the MITRE ATT&CK technique CrowdStrike mapped this to - use it to anticipate next attacker steps.\n"
            "3. Check if Falcon already blocked/killed the process, or only alerted.\n"
            "4. Pull the parent process and command line - confirm whether this is a legitimate admin tool (LOLBin) being abused.\n"
            "5. Network-contain the host in Falcon if the process is still active and not yet blocked.\n"
            "6. Check for the same hash/indicator on other hosts via Falcon's fleet-wide search before closing."
        ),
        "structured": {
            "investigation_steps": [
                "Open the detection in Falcon, review the full process tree and command line.",
                "Note the MITRE ATT&CK technique CrowdStrike mapped this to.",
                "Confirm whether Falcon auto-blocked/killed the process or only alerted.",
                "Check whether the binary is a legitimate signed tool being abused (LOLBin) vs unknown/unsigned.",
                "Search Falcon fleet-wide for the same hash/indicator on other hosts.",
            ],
            "required_fields": ["Hostname", "Detected process/hash", "MITRE technique", "Falcon severity", "Action taken by Falcon"],
            "escalation_criteria": "Process was not auto-blocked AND is still active, OR the same indicator appears on more than one host, OR detection involves credential access/ransomware behavior.",
            "splunk_query_hint": "index=crowdstrike event_simpleName=ProcessRollup2 OR event_simpleName=*Detect* | search ComputerName=<host>",
            "containment_actions": [
                "Network-contain the host via Falcon if the threat is still active.",
                "Kill the malicious process if not already auto-remediated.",
                "Isolate and image the host if ransomware/lateral-movement behavior is confirmed.",
            ],
            "closure_checklist": [
                "Process tree and MITRE technique documented.",
                "Confirmed scope (single host vs multiple).",
                "Containment action taken and verified.",
                "Disposition reason recorded.",
            ],
            "false_positive_indicators": [
                "Known, approved admin/IT tool running a flagged-but-benign command line (verify against the approved-tools list).",
                "Detection on a sanctioned vulnerability scanner or EDR test/canary file.",
            ],
        },
    },
    "Defender High Alert": {
        "category": "SOP-04: Microsoft Defender Investigation",
        "common_titles": [
            "Microsoft Defender high-severity alert",
            "Suspicious activity flagged by Defender for Endpoint",
            "Defender for O365 high alert",
        ],
        "mitre_techniques": ["T1059", "T1078", "T1566"],
        "description": (
            "Microsoft Defender (for Endpoint/Office 365/Identity) raised a high-severity "
            "alert. Business impact depends on the Defender product and technique involved - "
            "treat the linked incident graph as the source of truth, not just the alert title."
        ),
        "steps": (
            "1. Open the alert in the Defender portal and review the full incident graph (related alerts, entities, timeline).\n"
            "2. Identify which Defender product raised it (Endpoint, Identity, O365, Cloud Apps) - this changes the next steps.\n"
            "3. Check Defender's own automated investigation/remediation status before duplicating manual work.\n"
            "4. Pivot to the affected user/device's full alert history - high alerts rarely arrive alone.\n"
            "5. Take manual remediation action only for what Defender's automation did NOT already handle.\n"
            "6. Cross-check any file/IP/domain involved against the IOC enrichment tool before treating as confirmed-bad."
        ),
        "structured": {
            "investigation_steps": [
                "Open the alert in the Defender portal, review the full incident graph and timeline.",
                "Identify which Defender product raised it (Endpoint, Identity, O365, Cloud Apps).",
                "Check Defender's automated investigation/remediation status first.",
                "Review the affected user/device's full recent alert history for related activity.",
                "Cross-check any file/IP/domain via IOC enrichment before treating as confirmed malicious.",
            ],
            "required_fields": ["Affected user/device", "Defender product", "Alert category/technique", "Automated remediation status"],
            "escalation_criteria": "Automated remediation failed or is pending AND the entity is still active, OR alert correlates with other recent alerts on the same user/device, OR a privileged identity is involved.",
            "splunk_query_hint": "index=defender_atp | search DeviceName=<host> OR AccountName=<user> | sort -_time",
            "containment_actions": [
                "Manually isolate the device/disable the account if automated remediation did not.",
                "Revoke sessions and tokens for the affected identity if an identity-based alert.",
                "Block any confirmed-malicious file/IP/domain at the relevant control point.",
            ],
            "closure_checklist": [
                "Incident graph reviewed and summarized in the ticket.",
                "Automated remediation status confirmed.",
                "Any manual containment action documented.",
                "Disposition reason recorded.",
            ],
            "false_positive_indicators": [
                "Alert matches a known, recently-whitelisted application behavior change.",
                "Defender's own automated investigation already classified it as no threat found.",
            ],
        },
    },
    "O365 Phishing Alert": {
        "category": "SOP-06: Phishing / Email Investigation",
        "common_titles": [
            "User-reported phishing email",
            "Suspicious email with credential harvesting link",
            "Bulk phishing campaign detected in O365",
        ],
        "mitre_techniques": ["T1566", "T1204"],
        "description": (
            "A phishing email was reported or auto-flagged in Office 365 (via user report, "
            "Defender for O365, or mail flow rules). Business impact depends entirely on "
            "whether it was opened/clicked/credentials entered, and how widely it was sent."
        ),
        "steps": (
            "1. Pull the message headers and confirm sender authenticity (SPF/DKIM/DMARC results) - this alone often confirms spoofing.\n"
            "2. Extract and enrich all IOCs (sender domain, embedded links, attachment hash) using the IOC enrichment tool.\n"
            "3. Use the O365 Threat Explorer to find every other recipient of the same campaign - this is almost never a single-target email.\n"
            "4. If a link was clicked or credentials entered, treat as confirmed compromise: reset credentials and re-register MFA immediately.\n"
            "5. Purge the message from all mailboxes it reached, not just the reporting user's.\n"
            "6. Block the sender domain/URL at the mail gateway and proxy, and notify all affected users in plain language."
        ),
        "structured": {
            "investigation_steps": [
                "Pull message headers, check SPF/DKIM/DMARC results for sender spoofing.",
                "Extract and enrich all IOCs (sender domain, links, attachment hash) via the IOC enrichment tool.",
                "Use O365 Threat Explorer to find every other recipient of the same campaign.",
                "Check Defender for O365's Safe Links/Safe Attachments verdict if available.",
                "Confirm whether any recipient clicked the link or entered credentials (URL click tracking).",
            ],
            "required_fields": ["Sender address/domain", "Subject", "Number of recipients", "Link/attachment IOC", "Click/credential-entry status"],
            "escalation_criteria": "Any confirmed credential entry, OR more than 5 recipients, OR the sender domain impersonates an internal/partner brand.",
            "splunk_query_hint": "index=o365 eventtype=email | search subject=\"<subject>\" OR sender=\"<sender>\"",
            "containment_actions": [
                "Purge the message from all reached mailboxes (not just the reporter's).",
                "Block sender domain/URL at the mail gateway and web proxy.",
                "Force password reset and MFA re-registration for anyone who entered credentials.",
            ],
            "closure_checklist": [
                "Full recipient list identified and documented.",
                "Message purged from all mailboxes.",
                "Sender/URL blocked at the gateway.",
                "Affected users notified in plain language.",
                "Disposition reason recorded.",
            ],
            "false_positive_indicators": [
                "Legitimate marketing/newsletter email incorrectly reported by a user.",
                "Internal phishing simulation/awareness-training campaign (check the training calendar first).",
            ],
        },
    },
}


def all_mapped_mitre_technique_ids() -> set[str]:
    """Every MITRE technique ID referenced anywhere in the Rule Book -
    the basis for the Detection Gap Analyzer (which of the 55 curated
    techniques have NO rule covering them yet)."""
    ids: set[str] = set()
    for rule in RULE_BOOK.values():
        ids.update(rule.get("mitre_techniques", []))
    return ids


async def seed_rule_book(db: TrackerDB) -> None:
    existing = {s["alert_type"] for s in await db.list_sops()}
    for alert_type, rule in RULE_BOOK.items():
        if alert_type not in existing:
            structured = {
                **rule["structured"],
                "common_titles": rule.get("common_titles", []),
                "mitre_techniques": rule.get("mitre_techniques", []),
            }
            await db.upsert_sop(alert_type, rule["steps"], category=rule["category"], structured=structured)
