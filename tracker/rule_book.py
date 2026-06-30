"""The Rule Book: real, named detection rules grouped under SOP categories,
each with the full structured guidance (investigation steps, required
fields, Splunk queries, containment/closure checklists, and a
customer-facing description template) that should appear automatically
the moment that rule is selected for a new ticket.

The description template follows the structure the user chose after
reviewing real SOC report formats: Executive Summary, Alert Description,
Detection Engineering, Investigation Performed, Findings, Impact
Assessment, Actions Taken, Recommendations, Closure Reason. Several of
those sections map onto fields that already existed for other reasons
(Investigation Performed = investigation_steps, Actions Taken (response)
= containment_actions, Closure Reason = the incident's own
disposition_reason) - only the genuinely new sections get their own
field here, to avoid duplicating the same content twice under two names.

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
    {"id": "SOP-07", "name": "DDoS / Availability"},
    {"id": "SOP-08", "name": "Major Incident / Crisis Response"},
]

# Universal reference, not tied to one rule - how confidence percentages
# map to a verdict, for whichever rule's description includes one.
CONFIDENCE_SCALE: list[dict[str, str]] = [
    {"range": "90-100%", "meaning": "Highly malicious"},
    {"range": "70-89%", "meaning": "Likely suspicious"},
    {"range": "50-69%", "meaning": "Requires investigation"},
    {"range": "Below 50%", "meaning": "Possible false positive"},
]

# The disposition_verdict enum's full definitions (db.py:VALID_DISPOSITION_VERDICTS
# holds just the 5 values for validation; the prose definitions live here
# since they're reference/display content, not a validation concern) -
# verbatim from the team's real Tines case-note template.
DISPOSITION_DEFINITIONS: dict[str, str] = {
    "Malicious": "Adversarial intent confirmed or strongly indicated.",
    "Unresolved-suspicious": "Risk indicators present. Intent unestablished. Treated defensively.",
    "Policy violation": "Legitimate actor, real activity, breaks policy. No approval on file.",
    "Authorized": "Legitimate activity with durable evidence of pre-approval. Requires Evidence Reference.",
    "Benign-other": "Legitimate. No approval needed. Normal business, source misconfiguration, or non-security testing.",
}

# A cross-cutting reference for assessing ANY IP encountered during
# triage, regardless of which rule fired - the worked "Suspicious IP"
# example the user gave, generalized. Alert-specific rules below also
# have their own narrower ip_check_guide for what's specifically
# relevant to THAT alert type.
SUSPICIOUS_IP_GUIDE: dict = {
    "title": "How to check a suspicious IP (any alert type)",
    "steps": [
        "Look it up in the Investigate tab's IOC lookup - this pulls AbuseIPDB's abuse score and report count, plus VirusTotal's detection ratio, in one call.",
        "Check ASN and geolocation - does it belong to a hosting/VPS provider (common for attack infrastructure) or a residential/business ISP consistent with where your real users connect from?",
        "Search your own logs for the IP's history - has it ever been associated with a legitimate session for this org? First-seen-today + high abuse score is a strong combined signal.",
        "Check whether the same IP appears against other unrelated alerts/accounts - recurrence across multiple unrelated targets points to scanning/attack infrastructure rather than a one-off.",
        "Cross-reference any threat intel your org subscribes to, if available, for a known campaign/actor match.",
    ],
    "findings_example": "The IP has been associated with suspicious activity (elevated AbuseIPDB score, no history of legitimate access from this organization).",
    "recommendation_example": "Block the IP at the relevant control point and continue monitoring for recurrence.",
}

RULE_BOOK: dict[str, dict] = {
    "GP-VPN Brute Force Attempts": {
        "category": "SOP-01: VPN / Authentication / Password Spraying",
        "common_titles": [
            "Multiple failed VPN login attempts detected",
            "VPN brute force from single source IP",
            "Failed VPN authentication spike",
        ],
        "mitre_techniques": ["T1110", "T1133"],
        "default_priority": "medium",
        "description_template": {
            "who": "Targeted account(s) - list every username attempted, not just one",
            "what": "Number of failed attempts and whether any attempt succeeded",
            "when": "Start/end time of the attempt window",
            "where": "Source IP/ASN and which VPN gateway/site was targeted",
            "why": "Verdict - e.g. 'No successful auth, source IP blocked, closed as contained' or 'Successful auth on attempt N - escalated as confirmed compromise'",
        },
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
        "detection_engineering": {
            "name": "VPN Brute Force",
            "type": "Threshold / Correlation Rule",
            "data_sources": ["VPN logs", "Identity provider logs"],
            "logic": "10+ failed authentications against the same account(s) from one source IP within a short window.",
            "confidence_guidance": "High account-attempt-count + zero successes from a low-reputation IP = high confidence true positive. A single account with one or two failures is usually just a mistyped password.",
        },
        "splunk_queries": [
            {"name": "Find the brute-force pattern", "query": "index=vpn action=failure | stats count by src_ip, user | where count > 10"},
            {"name": "Check if any attempt succeeded", "query": "index=vpn src_ip=<ip> | stats count by action"},
            {"name": "Check a specific user's login history", "query": "index=vpn user=<username> | sort -_time | table _time, action, src_ip"},
        ],
        "ip_check_guide": (
            "Pull the source IP's reputation via the Investigate tab (AbuseIPDB score, VirusTotal detections, ASN). "
            "A hosting/VPS-range IP with no prior legitimate session history for this org and a non-trivial abuse "
            "score is confidently the attacker; a known corporate VPN exit node or partner IP is very likely benign."
        ),
        "description_sections": {
            "executive_summary": "The SOC detected multiple failed VPN authentication attempts originating from an external IP address targeting one or more user accounts. The activity was investigated to determine whether unauthorized access occurred.",
            "findings": [
                "No successful authentication was identified.",
                "The source IP showed no history of legitimate access from this organization.",
                "No additional indicators of compromise were identified.",
            ],
            "impact_assessment": "At the time of investigation, no evidence of account compromise or unauthorized access was identified.",
            "actions_taken": [
                "Reviewed VPN authentication logs for the targeted account(s).",
                "Validated whether any attempt succeeded.",
                "Checked the source IP's reputation and history.",
                "Reviewed related alerts for the same source IP.",
            ],
            "recommendations": [
                "Continue monitoring the source IP.",
                "Block the IP at the VPN gateway if further activity is observed.",
                "Consider enabling additional MFA controls for the targeted account(s).",
            ],
        },
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
        "default_priority": "medium",
        "description_template": {
            "who": "All targeted accounts - the spray's BREADTH (account count) is the key fact, not any single account",
            "what": "Number of accounts targeted and the passwords/pattern observed, if known",
            "when": "Start/end time of the spray window",
            "where": "Source IP/ASN and geography",
            "why": "Verdict - e.g. 'No successful logins across N accounts, source blocked' or 'Hit confirmed on <user> - escalated, org-wide reset recommended'",
        },
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
        "detection_engineering": {
            "name": "VPN/Identity Password Spraying",
            "type": "Correlation Rule",
            "data_sources": ["VPN logs", "Active Directory", "Identity provider logs"],
            "logic": "5+ failed logins across 3+ different user accounts from the same source IP within a 10-minute window.",
            "confidence_guidance": "85% typical confidence when the account-diversity and IP-singularity conditions both hold cleanly with no successful login mixed in.",
        },
        "splunk_queries": [
            {"name": "Find the spray pattern", "query": "index=auth action=failure | stats dc(user) as accounts_targeted by src_ip | where accounts_targeted > 3"},
            {"name": "Check if any login succeeded", "query": "index=auth src_ip=<ip> | stats count by action, user"},
            {"name": "Check a specific user's login history", "query": "index=auth user=<username> | sort -_time | table _time, action, src_ip"},
        ],
        "ip_check_guide": (
            "Same approach as brute force, but cross-check the IP against OTHER tenants/customers if your "
            "platform serves multiple - commodity spray tools reuse the same source against many targets in sequence."
        ),
        "description_sections": {
            "executive_summary": "The SOC detected repeated authentication attempts against multiple accounts from a single source IP address, consistent with a password spraying attack. The activity was investigated to determine whether unauthorized access occurred.",
            "findings": [
                "No successful authentication was identified.",
                "The user account(s) remained uncompromised.",
                "The source IP appears suspicious based on its targeting pattern.",
            ],
            "impact_assessment": "At the time of investigation, no evidence of account compromise or unauthorized access was identified.",
            "actions_taken": [
                "Reviewed authentication logs across the targeted accounts.",
                "Validated whether any login attempt succeeded.",
                "Investigated the source IP's reputation.",
                "Reviewed related alerts for the same source.",
            ],
            "recommendations": [
                "Continue monitoring.",
                "Reset credentials if a hit is later confirmed.",
                "Block the source IP if confirmed malicious.",
                "Enable additional MFA controls.",
            ],
        },
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
        "default_priority": "high",
        "description_template": {
            "who": "The account that triggered the risk detection",
            "what": "The specific risk detection type(s) Entra ID flagged (impossible travel, anonymous IP, leaked credentials, etc.)",
            "when": "Sign-in timestamp",
            "where": "Source IP/location/device vs the user's normal pattern",
            "why": "Verdict - e.g. 'User confirmed travel, false positive' or 'User denies sign-in, mailbox rule found - confirmed compromise, sessions revoked'",
        },
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
        "detection_engineering": {
            "name": "Entra ID Risky Sign-in",
            "type": "ML / Anomaly Detection (Microsoft-native)",
            "data_sources": ["Entra ID sign-in logs", "Identity Protection risk detections"],
            "logic": "Microsoft's own risk engine - impossible travel, anonymous IP/Tor, unfamiliar sign-in properties, or a credential found in a leak corpus.",
            "confidence_guidance": "Treat Microsoft's own risk LEVEL (low/medium/high) as a starting confidence, then adjust down if the user confirms legitimate travel/VPN use.",
        },
        "splunk_queries": [
            {"name": "Cross-check mailbox access after sign-in", "query": "index=o365 eventtype=mailitemsaccessed user=<user> earliest=<signin_time>"},
            {"name": "Check for new inbox/forwarding rules", "query": "index=o365 Operation=\"New-InboxRule\" OR Operation=\"Set-Mailbox\" user=<user>"},
            {"name": "Check the user's recent sign-in history", "query": "index=o365 eventtype=signin user=<user> | sort -_time | table _time, src_ip, location, risk_level"},
        ],
        "ip_check_guide": (
            "Check the sign-in IP's reputation and geolocation via the Investigate tab. Compare against the "
            "user's normal egress (corporate VPN/proxy ranges) - a known corporate exit node flagged as "
            "'anonymous' is a common benign cause; an unfamiliar residential/hosting IP in a country the user has never traveled to is not."
        ),
        "description_sections": {
            "executive_summary": "The SOC detected a sign-in flagged as risky by the identity provider's risk engine, potentially indicating account compromise. The activity was investigated to determine whether the account was accessed by an unauthorized party.",
            "findings": [
                "The specific risk detection type was reviewed.",
                "No unauthorized mailbox rules or OAuth grants were identified.",
                "The user's response to the sign-in was recorded.",
            ],
            "impact_assessment": "At the time of investigation, no evidence of unauthorized access or data exposure was identified.",
            "actions_taken": [
                "Reviewed the specific risk detection type.",
                "Compared sign-in location/device against the user's normal pattern.",
                "Reviewed post-sign-in mailbox and application activity.",
                "Contacted the user via a separate channel to confirm the sign-in.",
            ],
            "recommendations": [
                "Continue monitoring the account.",
                "Reset credentials and re-register MFA if compromise is confirmed.",
                "Educate the user on recognizing risky sign-in prompts.",
            ],
        },
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
        "default_priority": "high",
        "description_template": {
            "who": "The user receiving the push prompts",
            "what": "Number of push prompts and whether the user approved any of them",
            "when": "Start/end time of the prompt burst",
            "where": "Source IP/device generating the requests, if identifiable",
            "why": "Verdict - e.g. 'User denied all prompts, password reset as precaution' or 'User approved a prompt - confirmed compromise, account reset and re-registered'",
        },
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
        "detection_engineering": {
            "name": "MFA Push Fatigue / Bombing",
            "type": "Threshold Detection",
            "data_sources": ["PingID logs", "Identity provider authentication logs"],
            "logic": "5+ MFA push notifications to the same user within a short window without a corresponding single legitimate login attempt.",
            "confidence_guidance": "Confidence rises sharply with prompt count and falls if multiple legitimate devices/sessions explain the volume (check device count first).",
        },
        "splunk_queries": [
            {"name": "Find the push-spam pattern", "query": "index=pingid eventtype=push | stats count by user | where count > 5"},
            {"name": "Check the originating credential-entry event", "query": "index=auth user=<user> earliest=-1h | sort -_time"},
            {"name": "Check if the same source IP hit other accounts", "query": "index=pingid src_ip=<ip> | stats dc(user) by src_ip"},
        ],
        "ip_check_guide": (
            "Check the source IP generating the pushes via the Investigate tab. If it also appears against other "
            "accounts in the same window, this is part of a wider credential-stuffing campaign, not an isolated incident."
        ),
        "description_sections": {
            "executive_summary": "The SOC detected an unusual volume of MFA push notifications sent to a user who did not initiate them, consistent with an MFA fatigue attack. The activity was investigated to determine whether the user approved any prompt.",
            "findings": [
                "The user's response to each prompt was confirmed.",
                "The source generating the requests was identified where possible.",
                "Password reset was performed regardless of outcome, since the underlying credential is known to be compromised.",
            ],
            "impact_assessment": "Impact depends entirely on approval status - no compromise if all prompts were denied; confirmed compromise if any prompt was approved.",
            "actions_taken": [
                "Contacted the user to confirm approval/denial status.",
                "Identified the source IP/device generating the requests.",
                "Reviewed authentication logs for the originating credential-entry event.",
                "Reset the account password as a precaution.",
            ],
            "recommendations": [
                "Brief the user on MFA fatigue tactics.",
                "Continue monitoring the account.",
                "Consider number-matching or risk-based MFA policies to reduce future fatigue-attack surface.",
            ],
        },
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
        "default_priority": "high",
        "description_template": {
            "who": "Affected host(s) - and the logged-in user(s) on those hosts at the time",
            "what": "The detected process/technique and whether Falcon auto-blocked it",
            "when": "Detection timestamp",
            "where": "Hostname(s) - and whether the same hash/indicator was found on others",
            "why": "Verdict - e.g. 'Known approved tool, false positive' or 'Confirmed malicious, host isolated, scope limited to one host'",
        },
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
        "detection_engineering": {
            "name": "Falcon High-Severity Endpoint Detection",
            "type": "Behavioral / ML Detection (CrowdStrike-native)",
            "data_sources": ["CrowdStrike Falcon sensor telemetry", "Process execution logs"],
            "logic": "Falcon's own behavioral/ML model flags the process tree and technique; severity and MITRE mapping are provided directly by the platform.",
            "confidence_guidance": "Trust Falcon's own severity score as the starting point; lower confidence only if the binary matches a known, approved internal tool.",
        },
        "splunk_queries": [
            {"name": "Pull the full detection event", "query": "index=crowdstrike event_simpleName=ProcessRollup2 OR event_simpleName=*Detect* ComputerName=<host>"},
            {"name": "Check for the same hash fleet-wide", "query": "index=crowdstrike SHA256HashData=<hash> | stats dc(ComputerName) by SHA256HashData"},
            {"name": "Check the host's recent process history", "query": "index=crowdstrike ComputerName=<host> | sort -_time | table _time, FileName, CommandLine, ParentBaseFileName"},
        ],
        "ip_check_guide": (
            "If the detection involves a network connection (C2 beacon, download), check that destination IP/domain "
            "via the Investigate tab the same way as any other alert - reputation, ASN, and whether other hosts have called out to it."
        ),
        "description_sections": {
            "executive_summary": "The SOC detected a high-severity endpoint alert from CrowdStrike Falcon involving a flagged process on a host. The activity was investigated to determine whether the host was compromised.",
            "findings": [
                "The full process tree and command line were reviewed.",
                "Falcon's auto-remediation status was confirmed.",
                "Scope was checked across the fleet for the same indicator.",
            ],
            "impact_assessment": "Impact depends on whether the process executed successfully and whether it spread beyond the originating host.",
            "actions_taken": [
                "Reviewed the detection's process tree and command line in the Falcon console.",
                "Confirmed whether Falcon auto-blocked the process.",
                "Checked the binary's signature/reputation.",
                "Searched fleet-wide for the same hash/indicator.",
            ],
            "recommendations": [
                "Continue monitoring the host.",
                "Isolate and image the host if ransomware/lateral-movement behavior is confirmed.",
                "Add the indicator to the blocklist if confirmed malicious.",
            ],
        },
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
        "default_priority": "high",
        "description_template": {
            "who": "Affected user/device",
            "what": "Which Defender product raised it and the alert category/technique",
            "when": "Alert timestamp",
            "where": "Device/identity involved, and whether it correlates with other recent alerts",
            "why": "Verdict - e.g. 'Automated remediation succeeded, no further action' or 'Remediation failed, manually contained, escalated'",
        },
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
        "detection_engineering": {
            "name": "Defender High-Severity Alert",
            "type": "Behavioral / ML Detection (Microsoft-native)",
            "data_sources": ["Microsoft Defender for Endpoint", "Defender for O365", "Defender for Identity"],
            "logic": "Defender's own incident-graph correlation across entities (device, user, file, mailbox) - severity and category are platform-assigned.",
            "confidence_guidance": "If Defender's automated investigation already classified it as a threat with high confidence, treat that as your starting point; downgrade only with a specific contrary finding.",
        },
        "splunk_queries": [
            {"name": "Pull the device/user's alert history", "query": "index=defender_atp | search DeviceName=<host> OR AccountName=<user> | sort -_time"},
            {"name": "Check automated remediation status", "query": "index=defender_atp ActionType=*Remediat* DeviceName=<host>"},
            {"name": "Check related alerts in the same incident graph", "query": "index=defender_atp IncidentId=<id> | table _time, AlertTitle, Severity, EntityType"},
        ],
        "ip_check_guide": (
            "If the alert involves a network indicator, check it the same way as any other alert via the Investigate "
            "tab - Defender's own threat intel context plus the IOC lookup together usually settle the verdict quickly."
        ),
        "description_sections": {
            "executive_summary": "The SOC detected a high-severity alert from Microsoft Defender involving a flagged device, user, or mailbox. The activity was investigated to determine its scope and impact.",
            "findings": [
                "The Defender incident graph and timeline were reviewed.",
                "Automated remediation status was confirmed.",
                "Related alerts on the same entity were reviewed.",
            ],
            "impact_assessment": "Impact depends on whether Defender's automated remediation succeeded and whether the entity correlates with other active alerts.",
            "actions_taken": [
                "Reviewed the Defender incident graph and timeline.",
                "Identified which Defender product raised the alert.",
                "Confirmed automated remediation status.",
                "Cross-checked any file/IP/domain via IOC enrichment.",
            ],
            "recommendations": [
                "Continue monitoring the entity.",
                "Manually contain if automated remediation did not fully resolve it.",
                "Review for related alerts on the same user/device going forward.",
            ],
        },
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
        "default_priority": "medium",
        "description_template": {
            "who": "Recipient(s) - check Threat Explorer for the FULL campaign, rarely just one person",
            "what": "Sender domain, subject, and whether a link was clicked or credentials entered",
            "when": "Delivery timestamp",
            "where": "Number of recipients across the org",
            "why": "Verdict - e.g. 'No clicks, message purged org-wide' or 'Credentials entered - confirmed compromise, reset + MFA re-registration done'",
        },
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
        "detection_engineering": {
            "name": "O365 Phishing Detection",
            "type": "Signature / Heuristic Detection",
            "data_sources": ["Microsoft 365 mail flow logs", "Defender for O365 (Safe Links/Safe Attachments)", "User reports"],
            "logic": "Sender authentication failure (SPF/DKIM/DMARC), known phishing-kit URL/attachment signature, or a user report matched against Threat Explorer's campaign clustering.",
            "confidence_guidance": "A failed sender-authentication check plus a credential-harvesting page signature together push confidence well above 90%; a user report alone with clean authentication is often a false positive.",
        },
        "splunk_queries": [
            {"name": "Find the full campaign by subject/sender", "query": "index=o365 eventtype=email | search subject=\"<subject>\" OR sender=\"<sender>\""},
            {"name": "Check a specific recipient's click activity", "query": "index=o365 eventtype=url_click user=<user> earliest=<delivery_time>"},
            {"name": "Check sender authentication results", "query": "index=o365 eventtype=email sender=\"<sender>\" | table _time, spf_result, dkim_result, dmarc_result"},
        ],
        "ip_check_guide": (
            "Check the sending IP and any embedded link's hosting IP via the Investigate tab. A sending IP with no "
            "prior mail history for this org plus a low-reputation/newly-registered hosting IP for the link strongly supports a true positive."
        ),
        "description_sections": {
            "executive_summary": "The SOC detected a phishing email reported by a user or flagged by automated detection, potentially exposing the organization to credential theft. The activity was investigated to determine its reach and impact.",
            "findings": [
                "The full recipient list for the campaign was identified.",
                "Sender authentication (SPF/DKIM/DMARC) results were reviewed.",
                "Click/credential-entry status was confirmed across all recipients.",
            ],
            "impact_assessment": "Impact depends entirely on whether any recipient entered credentials - no compromise if none did; confirmed compromise otherwise.",
            "actions_taken": [
                "Reviewed message headers and sender authentication results.",
                "Extracted and enriched all IOCs (sender domain, links, attachments).",
                "Used Threat Explorer to identify the full recipient list.",
                "Purged the message from all reached mailboxes.",
            ],
            "recommendations": [
                "Block the sender domain/URL at the gateway.",
                "Notify all affected users in plain language.",
                "Reset credentials for anyone who entered them.",
            ],
        },
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
    "DDoS Attack Detected": {
        "category": "SOP-07: DDoS / Availability",
        "common_titles": [
            "Volumetric DDoS attack detected",
            "Service degradation due to traffic spike",
            "Application-layer DDoS against web service",
        ],
        "mitre_techniques": ["T1499"],
        "default_priority": "high",
        "description_template": {
            "who": "Affected service(s)/system(s) - this alert type targets infrastructure, not a user account",
            "what": "Attack type (volumetric/protocol/application-layer) and peak traffic volume observed",
            "when": "Start time and duration of the attack",
            "where": "Target IP/service, plus top source IP/ASN/country distribution",
            "why": "Verdict - e.g. 'Confirmed legitimate traffic spike, no action needed' or 'Confirmed attack, mitigated via rate limiting, service availability restored'",
        },
        "description": (
            "An attacker (or botnet) is overwhelming a service or network with traffic to make "
            "it unavailable to legitimate users. Business impact: direct service outage/degradation, "
            "and a common smokescreen for a simultaneous, less-noisy attack elsewhere."
        ),
        "steps": (
            "1. Confirm the attack is real - check whether the volume correlates with a known legitimate event (product launch, marketing campaign, viral content) before treating as malicious.\n"
            "2. Identify the attack type: volumetric (raw bandwidth), protocol (e.g. SYN flood), or application-layer (e.g. HTTP flood).\n"
            "3. Check which services are actually degraded vs still healthy - scope matters for response urgency.\n"
            "4. Identify the top source IPs/ASNs/countries by volume - these are your mitigation targets.\n"
            "5. Apply mitigation appropriate to the attack type: rate limiting, ACLs, geo-fencing, malicious user-agent blocking, or engaging a CDN/scrubbing provider/ISP for large volumetric attacks.\n"
            "6. Document peak volume, duration, and mitigation effectiveness for the write-up."
        ),
        "detection_engineering": {
            "name": "DDoS / Volumetric Traffic Anomaly",
            "type": "Threshold / Anomaly Detection",
            "data_sources": ["Firewall/edge logs", "CDN/WAF logs", "NetFlow/traffic baseline"],
            "logic": "Traffic volume or connection rate to a service exceeds its established baseline by a large multiple, sustained beyond a short threshold window.",
            "confidence_guidance": "High confidence when volume is both abnormal AND has no corresponding legitimate business event; check the business calendar before escalating on volume alone.",
        },
        "splunk_queries": [
            {"name": "Find top source IPs by volume", "query": "index=network dest=<service_ip> | stats sum(bytes) as total_bytes by src_ip | sort -total_bytes | head 20"},
            {"name": "Check traffic by source country/ASN", "query": "index=network dest=<service_ip> | iplocation src_ip | stats count by Country, src_ip"},
            {"name": "Check service availability during the window", "query": "index=web_logs dest=<service_ip> | timechart span=1m count by status"},
        ],
        "ip_check_guide": (
            "For each top-volume source IP, check reputation/ASN via the Investigate tab. A spread across many "
            "unrelated hosting-provider IPs with no legitimate history is classic botnet traffic; a concentrated "
            "spike from a small number of IPs with real history may be a misbehaving legitimate client instead."
        ),
        "description_sections": {
            "executive_summary": "The SOC detected an unusually high volume of traffic directed toward a public-facing service, potentially indicating denial-of-service activity. The activity was investigated to determine impact and whether mitigation was required.",
            "findings": [
                "No service outage was identified.",
                "Traffic originated from a wide distribution of source IPs consistent with a botnet.",
                "No legitimate business event explained the volume.",
            ],
            "impact_assessment": "Service remained available throughout the event; degradation, if any, was limited to elevated latency.",
            "actions_taken": [
                "Reviewed firewall/edge logs for the affected service.",
                "Identified top source IPs by traffic volume.",
                "Validated service availability throughout the window.",
                "Reviewed bandwidth utilization against baseline.",
            ],
            "recommendations": [
                "Continue monitoring.",
                "Consider rate limiting or geo-fencing for the top offending sources.",
                "Engage the CDN/scrubbing provider if volume exceeds on-prem mitigation capacity.",
            ],
        },
        "structured": {
            "investigation_steps": [
                "Confirm the attack is real - rule out a legitimate traffic spike (check the business calendar) first.",
                "Identify attack type: volumetric, protocol, or application-layer.",
                "Check which services are actually degraded vs still healthy.",
                "Identify top source IPs/ASNs/countries by volume.",
                "Check whether mitigation already engaged (CDN/WAF auto-mitigation) and its effectiveness.",
            ],
            "required_fields": ["Affected service/IP", "Attack type", "Peak traffic volume", "Source IP/ASN/country distribution", "Duration"],
            "escalation_criteria": "Any customer-facing service outage, OR the attack is sustained beyond 30 minutes without mitigation effect, OR volume exceeds normal baseline by 10x or more.",
            "splunk_query_hint": "index=network dest=<service_ip> | stats sum(bytes) as total_bytes by src_ip | sort -total_bytes | head 20",
            "containment_actions": [
                "Enable or tighten rate limiting at the edge/WAF.",
                "Apply geo-fencing or ASN-based ACLs for the worst offending sources.",
                "Block malicious user-agents if the attack is application-layer.",
                "Engage the CDN/scrubbing provider or ISP if volumetric and beyond on-prem capacity.",
            ],
            "closure_checklist": [
                "Attack type and peak volume documented.",
                "Mitigation action confirmed effective.",
                "Affected service availability restored and verified.",
                "Disposition reason recorded.",
            ],
            "false_positive_indicators": [
                "Legitimate traffic spike from a marketing campaign, viral content, or a scheduled batch job - check the business calendar before treating as an attack.",
            ],
        },
    },
    "Major Incident": {
        # Created by the Emergency button - deliberately NOT tied to one
        # MITRE technique, since it's a severity escalation classification
        # that can apply to any underlying incident type (ransomware, mass
        # account compromise, data breach, etc), not a specific detection.
        "category": "SOP-08: Major Incident / Crisis Response",
        "common_titles": [
            "Active ransomware spreading",
            "Confirmed data breach in progress",
            "Mass account compromise",
            "Critical service outage with security implications",
        ],
        "mitre_techniques": [],
        "default_priority": "high",
        "description_template": {
            "who": "Affected systems/users - scope is often still unknown at creation, update as it's learned",
            "what": "What's known right now, even if incomplete - this ticket exists because waiting for full categorization wasn't an option",
            "when": "When you first became aware vs when the activity actually started, if different",
            "where": "Every affected system/network segment identified so far",
            "why": "Verdict - this field will evolve fastest of any ticket type as the incident is worked",
        },
        "description": (
            "Created via the Emergency button when something is severe enough to need a ticket and "
            "escalation immediately, before there's time to identify which specific alert type applies. "
            "Business impact: by definition, high - this bypasses normal triage specifically because waiting wasn't safe."
        ),
        "steps": (
            "1. Assess scope immediately - what's confirmed affected vs suspected, don't wait for full certainty to start containing.\n"
            "2. Contain first, investigate in parallel - for a true major incident, speed matters more than process polish.\n"
            "3. Notify stakeholders/management per your major-incident communication plan - this should already be in flight, not blocked on this ticket.\n"
            "4. Assign clear ownership - who is the incident commander for this one.\n"
            "5. Update this ticket regularly as the picture develops - treat it as the running log, not a write-once report.\n"
            "6. Once contained, identify which specific alert type(s)/technique(s) this actually was, for the post-incident record."
        ),
        "detection_engineering": {
            "name": "Manual Escalation (Emergency Button)",
            "type": "Analyst-initiated, not an automated detection",
            "data_sources": ["Analyst judgment - this exists specifically to bypass waiting on automated categorization"],
            "logic": "No threshold/correlation logic - created directly when an analyst judges something needs immediate ticket creation and escalation.",
            "confidence_guidance": "By definition the analyst already believes this is real and severe enough to escalate immediately - confidence starts high and is revised down only if early findings contradict it.",
        },
        "splunk_queries": [
            {"name": "Recent activity for an affected host", "query": "index=* host=<host> earliest=-2h | sort -_time"},
            {"name": "Recent activity for an affected user", "query": "index=* user=<user> earliest=-2h | sort -_time"},
        ],
        "ip_check_guide": (
            "Use the universal Suspicious IP guide (Investigate tab) the same way as any other alert - "
            "scope and containment speed matter more here than a perfectly thorough IP writeup at this stage."
        ),
        "description_sections": {
            "executive_summary": "The SOC identified an incident assessed as severe enough to require immediate escalation, ahead of full categorization. Containment actions were initiated immediately; investigation continues in parallel.",
            "findings": ["(update as the investigation develops - this section evolves fastest of any major incident)"],
            "impact_assessment": "Impact assessment is in progress - update this section as scope is confirmed.",
            "actions_taken": [
                "Escalated immediately via the Emergency workflow.",
                "Began scope assessment.",
                "Notified relevant stakeholders per the major-incident communication plan.",
            ],
            "recommendations": [
                "Continue containment and scope assessment.",
                "Schedule a post-incident review once resolved.",
                "Reclassify under the specific alert type/technique once identified, for the historical record.",
            ],
        },
        "structured": {
            "investigation_steps": [
                "Assess scope immediately - confirmed vs suspected, don't wait for certainty to start containing.",
                "Contain first, investigate in parallel.",
                "Confirm stakeholder/management notification is in flight.",
                "Assign clear incident-commander ownership.",
                "Update the ticket regularly as the picture develops.",
            ],
            "required_fields": ["Affected systems/users (best current estimate)", "Containment actions taken", "Incident commander", "Stakeholder notification status"],
            "escalation_criteria": "Already escalated by definition - this section instead tracks whether it needs to go BEYOND the SOC (legal, executive, external IR firm, law enforcement).",
            "splunk_query_hint": "index=* host=<host> OR user=<user> earliest=-2h | sort -_time",
            "containment_actions": [
                "Isolate/contain affected systems immediately, even with incomplete information.",
                "Disable/reset credentials for any confirmed-compromised accounts.",
                "Engage your incident response plan's next steps (legal, comms, executive notification) as applicable.",
            ],
            "closure_checklist": [
                "Final scope documented.",
                "All stakeholders notified of resolution.",
                "Reclassified under the specific alert type/technique for the historical record, if applicable.",
                "Disposition reason recorded.",
                "Post-incident review scheduled.",
            ],
            "false_positive_indicators": [
                "Extremely rare for this category by design - if it turns out not to be major, document why and consider whether the Emergency button was the right call for next time.",
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
                "default_priority": rule.get("default_priority", "medium"),
                "description_template": rule.get("description_template", {}),
                "detection_engineering": rule.get("detection_engineering", {}),
                "splunk_queries": rule.get("splunk_queries", []),
                "ip_check_guide": rule.get("ip_check_guide", ""),
                "description_sections": rule.get("description_sections", {}),
                "alert_description": rule.get("description", ""),
            }
            await db.upsert_sop(alert_type, rule["steps"], category=rule["category"], structured=structured)
