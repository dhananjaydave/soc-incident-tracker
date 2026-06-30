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

upsert_sop() only overwrites, so editing a rule later (via the API) is
never undone by a restart, and adding a new rule here later never
deletes one a user already customized. (An earlier, generic placeholder
seed_sops.py - 6 alert types with no structured data, e.g. bare
"Phishing"/"Brute Force" - was retired once this Rule Book covered the
same ground with real structured content; its alert_type strings never
matched these ones exactly so it was silently coexisting as dead weight
in the dropdown rather than being overwritten as originally intended.)
"""

from __future__ import annotations

from .db import TrackerDB

# IDs deliberately use an "RB-" (Rule Book) prefix, not "SOP-" - these were
# built early in the project, before any real SOP document existed, as
# placeholder categories for the 9 hand-written playbooks below. Once the
# user started sharing the team's REAL SOP documents (see
# real_sop_reference.py), it turned out RB-01 through RB-06 happen to line
# up conceptually with the real SOP-01..SOP-06, but RB-07 ("DDoS") and
# RB-08 ("Major Incident") do NOT correspond to anything in the real
# numbering (real SOP-07 is "Cloud Malware", SOP-08 is "Data Protection/
# DLP") - these were previously labeled "SOP-07"/"SOP-08" and collided
# with the real ones, showing contradictory info depending which feature
# you looked at. Renamed to RB-* across the board so the two systems can
# never collide as more real SOPs (up to SOP-13) are added.
SOP_CATEGORIES: list[dict[str, str]] = [
    {"id": "RB-01", "name": "VPN / Authentication / Password Spraying"},
    {"id": "RB-02", "name": "MFA Abuse / MFA Bypass"},
    {"id": "RB-03", "name": "Risky Sign-in / Identity Compromise"},
    {"id": "RB-04", "name": "Microsoft Defender Investigation"},
    {"id": "RB-05", "name": "CrowdStrike / Endpoint Investigation"},
    {"id": "RB-06", "name": "Phishing / Email Investigation"},
    {"id": "RB-07", "name": "DDoS / Availability"},
    {"id": "RB-08", "name": "Major Incident / Crisis Response"},
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
        "category": "RB-01: VPN / Authentication / Password Spraying",
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
        # Adapted from the team's real SOP-01 (VPN/Auth/Brute Force/Password
        # Spraying) document, trimmed from the SOP's full eval/coalesce
        # chains to the core pattern - index/field names are authentic,
        # not invented.
        "splunk_queries": [
            {"name": "Confirm the notable (SOP-01 L1)", "query": (
                "index=notable earliest=-30d@d latest=now\n"
                "| search search_name=\"<rule_name>\" OR correlation_search_name=\"<rule_name>\"\n"
                "| eval alert_id_reference_id=coalesce(alert_id, reference_id, notable_id, event_id, orig_rid, sid, _cd)\n"
                "| table _time search_name severity urgency status user src_ip dest_ip host alert_id_reference_id owner\n"
                "| sort - _time"
            )},
            {"name": "Duplicate / related alert check (SOP-01 L1)", "query": (
                "index=notable earliest=-7d@d latest=now\n"
                "| search src_ip=\"<ip>\" OR src=\"<ip>\" OR source_ip=\"<ip>\" OR user=\"<username>\" OR username=\"<username>\"\n"
                "| table _time search_name severity urgency status user src_ip host owner\n"
                "| sort - _time"
            )},
            {"name": "Failed-authentication pattern by source IP (SOP-01 L1)", "query": (
                "(index=pan_system OR index=office365 OR index=azure_security) earliest=-24h latest=now\n"
                "(src_ip=\"<ip>\" OR src=\"<ip>\" OR user=\"<username>\" OR username=\"<username>\")\n"
                "(action=failure OR action=failed OR result=failure OR authentication_result=failure)\n"
                "| eval normalized_user=coalesce(user, username, src_user, account_name)\n"
                "| eval normalized_src_ip=coalesce(src_ip, src, source_ip, client_ip)\n"
                "| stats count as failure_count dc(normalized_user) as unique_users values(normalized_user) as users by normalized_src_ip\n"
                "| sort - failure_count"
            )},
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
        "category": "RB-01: VPN / Authentication / Password Spraying",
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
        # Same source SOP-01 as GP-VPN Brute Force Attempts (spraying is
        # SOP-01's "many accounts, few attempts" pattern, brute force is
        # "one account, many attempts") - same notable/duplicate queries,
        # plus the spray-specific account-diversity pattern.
        "splunk_queries": [
            {"name": "Find the spray pattern - many accounts, one source (SOP-01 L2)", "query": (
                "(index=pan_system OR index=office365 OR index=azure_security) earliest=-24h latest=now\n"
                "(action=failure OR action=failed OR result=failure OR authentication_result=failure)\n"
                "| eval normalized_user=coalesce(user, username, src_user, account_name)\n"
                "| eval normalized_src_ip=coalesce(src_ip, src, source_ip, client_ip)\n"
                "| stats count as failure_count dc(normalized_user) as accounts_targeted values(normalized_user) as users by normalized_src_ip\n"
                "| where accounts_targeted > 3\n"
                "| sort - accounts_targeted"
            )},
            {"name": "Check whether any targeted account succeeded after failures (SOP-01 L2)", "query": (
                "(index=pan_system OR index=office365 OR index=azure_security) earliest=-24h latest=now\n"
                "(src_ip=\"<ip>\" OR user=\"<username>\")\n"
                "(action=success OR result=success OR authentication_result=success)\n"
                "| eval normalized_user=coalesce(user, username, src_user, account_name)\n"
                "| table _time normalized_user src_ip dest action result"
            )},
            {"name": "Confirm the notable (SOP-01 L1)", "query": (
                "index=notable earliest=-30d@d latest=now\n"
                "| search search_name=\"<rule_name>\" OR correlation_search_name=\"<rule_name>\"\n"
                "| table _time search_name severity urgency status user src_ip dest_ip host owner\n"
                "| sort - _time"
            )},
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
        "category": "RB-03: Risky Sign-in / Identity Compromise",
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
        # First two adapted from the team's real SOP-03 (Risky Sign-in/
        # Identity Risk) document, authentic index/field names; the
        # remaining three are this app's own downstream-access checks
        # (mailbox/inbox-rule abuse after a successful risky sign-in),
        # which the real SOP covers more generally - kept since they're
        # specific and not redundant with the SOP-03 queries below.
        "splunk_queries": [
            {"name": "Confirm the notable (SOP-03 L1)", "query": (
                "index=notable earliest=-30d@d latest=now\n"
                "| search search_name=\"<rule_name>\" OR correlation_search_name=\"<rule_name>\" OR user=\"<user>\"\n"
                "| table _time search_name severity urgency status user src_ip country asn risk_level risk_reason sign_in_result app device host owner\n"
                "| sort - _time"
            )},
            {"name": "User baseline - last 30 days (SOP-03 L1)", "query": (
                "(index=azure_security OR index=office365 OR index=cia-sso-prod) earliest=-30d@d latest=now\n"
                "(user=\"<user>\" OR username=\"<user>\" OR UserId=\"<user>\")\n"
                "| eval normalized_src_ip=coalesce(src_ip, src, source_ip, client_ip, ClientIP)\n"
                "| stats count as event_count earliest(_time) as first_seen latest(_time) as last_seen values(normalized_src_ip) as source_ips values(country) as countries values(asn) as asns by user\n"
                "| convert ctime(first_seen) ctime(last_seen)"
            )},
            {"name": "Cross-check mailbox access after sign-in", "query": "index=o365 eventtype=mailitemsaccessed user=<user> earliest=<signin_time>"},
            {"name": "Check for new inbox/forwarding rules", "query": "index=o365 Operation=\"New-InboxRule\" OR Operation=\"Set-Mailbox\" user=<user>"},
            {"name": "Check the user's recent sign-in history", "query": "index=o365 eventtype=signin user=<user> | sort -_time | table _time, src_ip, location, risk_level"},
        ],
        "ip_check_guide": (
            "Check the sign-in IP's reputation and geolocation via the Investigate tab. Compare against the "
            "user's normal egress (corporate VPN/proxy ranges) - a known corporate exit node flagged as "
            "'anonymous' is a common benign cause; an unfamiliar residential/hosting IP in a country the user has never traveled to is not."
        ),
        "reference_links": [
            {"label": "Microsoft: Investigate risk with Entra ID Protection",
             "url": "https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-investigate-risk"},
        ],
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
        "category": "RB-02: MFA Abuse / MFA Bypass",
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
        # Adapted from the team's real SOP-02 (MFA Abuse/Bypass/Spamming)
        # document - authentic index/field names, trimmed from the SOP's
        # full coalesce chains.
        "splunk_queries": [
            {"name": "MFA timeline for this user (SOP-02 L1)", "query": (
                "(index=cia-sso-prod OR index=office365 OR index=azure_security) earliest=-24h latest=now\n"
                "(user=\"<user>\" OR username=\"<user>\")\n"
                "(mfa_result=* OR mfa_status=* OR factor=* OR action=*mfa* OR action=*approve* OR action=*deny*)\n"
                "| eval mfa=coalesce(mfa_result, mfa_status, factor_result, authentication_result, result, status)\n"
                "| eval method=coalesce(factor, authentication_method, mfa_factor)\n"
                "| table _time user src_ip country asn app action result mfa method device\n"
                "| sort _time"
            )},
            {"name": "Approval after repeated denials - the key escalation signal (SOP-02 L1)", "query": (
                "(index=cia-sso-prod OR index=office365 OR index=azure_security) earliest=-24h latest=now\n"
                "(\"PingID\" OR \"MFA\" OR \"multi-factor\" OR \"HDDT\")\n"
                "(user=\"<user>\" OR src_user=\"<user>\" OR UserPrincipalName=\"<user>\")\n"
                "| eval result_lower=lower(coalesce(mfa_result, result, status, \"\"))\n"
                "| eval mfa_final_result=case(\n"
                "    match(result_lower,\"approved|approve|success|accepted|allow\"), \"Approved\",\n"
                "    match(result_lower,\"denied|deny|rejected|declined\"), \"Denied\",\n"
                "    match(result_lower,\"fail|failed|error|timeout\"), \"Failed\",\n"
                "    true(), \"Unknown\")\n"
                "| sort 0 _time\n"
                "| streamstats count(eval(mfa_final_result=\"Denied\")) as denials_before_this_event by user\n"
                "| where mfa_final_result=\"Approved\" AND denials_before_this_event>=2"
            )},
            {"name": "Check if the same source IP hit other accounts", "query": "index=cia-sso-prod src_ip=\"<ip>\" | stats dc(user) by src_ip"},
        ],
        "ip_check_guide": (
            "Check the source IP generating the pushes via the Investigate tab. If it also appears against other "
            "accounts in the same window, this is part of a wider credential-stuffing campaign, not an isolated incident."
        ),
        "reference_links": [
            {"label": "Microsoft: Defend your users from MFA fatigue attacks",
             "url": "https://techcommunity.microsoft.com/blog/microsoft-entra-blog/defend-your-users-from-mfa-fatigue-attacks/2365677"},
        ],
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
        "category": "RB-05: CrowdStrike / Endpoint Investigation",
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
        "category": "RB-04: Microsoft Defender Investigation",
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
        "category": "RB-06: Phishing / Email Investigation",
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
        "category": "RB-07: DDoS / Availability",
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
        "category": "RB-08: Major Incident / Crisis Response",
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


# Additional investigation content merged at seed time - appended to (not
# replacing) each rule's existing structured dicts. Derived from: the
# team's own real SOP-01/02/03 documents, Microsoft's official IR
# playbooks (learn.microsoft.com/security/operations/incident-response-
# playbooks), and general SOC analyst practice.
# Language is intentionally analyst-register - specific, evidence-first,
# no AI-cliche filler phrases like "it is important to note that."
_ENRICHMENTS: dict[str, dict] = {
    "GP-VPN Brute Force Attempts": {
        "investigation_steps": [
            "Map the full attack window: pull the earliest and latest failed-auth events to bound your time filter, then search specifically for any 'interrupted' sign-in (password correct, MFA challenged) within that window — an interrupted result means the attacker holds a valid credential even if 'success' is never logged.",
            "Check Entra sign-in error codes for any accounts touched: 50072/50074 = MFA was prompted (attacker may have the password); 53003 = blocked by CA; 50055 = password expired. These codes tell you more than pass/fail alone.",
            "Check the client_app field for legacy authentication protocols (SMTP, IMAP, POP3, Exchange ActiveSync) — legacy auth bypasses MFA entirely. A legacy-auth failure is still high urgency even without a success because the attacker is explicitly trying to bypass MFA.",
            "Search the notable index for the same source IP against other alert types in the past 7 days — spray toolkits hit multiple targets in rotation. Multi-alert history from the same IP confirms an active campaign, not a one-off.",
            "Confirm with the network team whether the attacking IP is a known shared corporate egress, partner gateway, or scanner range before recommending a block — blocking a shared egress IP affects all users behind it.",
        ],
        "findings_extra": [
            "Attack window: [source IP] made [N] failed attempts against [M] account(s) from [start time] to [end time].",
            "Source IP geolocation/ASN: [Country / hosting provider] — inconsistent with any known corporate user population.",
            "No 'interrupted' sign-ins detected within the window — attacker does not appear to hold a valid credential at this time.",
            "Legacy authentication protocols: [not observed / observed via client_app field — MFA bypass risk noted].",
        ],
        "actions_extra": [
            "Block source IP at VPN gateway or perimeter firewall — confirm no corporate egress / partner IP overlap with network team before applying.",
            "Force password reset for any account where sign-in result was 'interrupted' (password correct, MFA challenged) — attacker has the credential; reset is required regardless of whether authentication completed.",
            "Enable Entra ID Smart Lockout and ADFS Extranet Lockout if not already active to limit attacker velocity on future attempts.",
            "Tag source IP in SIEM and Defender for Cloud Apps to trigger alerts on any future appearance from same IP.",
        ],
        "false_positive_indicators_extra": [
            "Automated provisioning tool or service account retrying with stale/rotated credentials — check the client user-agent string and whether the source IP matches known internal tooling.",
            "VPN client auto-reconnect after token expiry: single account, failures at regular intervals, immediately followed by a success from the same IP. Benign pattern if the source is the corporate egress.",
        ],
    },
    "Password Spraying Attempts": {
        "investigation_steps": [
            "Confirm the many-accounts/few-attempts pattern (spray) vs. many-attempts/one-account (brute force) — the distinction changes the scope query entirely. For spray, the key number is unique_users targeted; for brute force, it's attempt_count per user.",
            "Search for any 'interrupted' sign-in (password correct, MFA challenged) across ALL targeted accounts in the spray window — even one interrupted sign-in on one account means the attacker found a valid password and requires immediate escalation.",
            "Check sign-in error code 53003 (blocked by Conditional Access) for the targeted accounts — if CA fired, it likely stopped the attack but the accounts still had valid credentials tested. Document which accounts triggered CA.",
            "Cross-reference the spray window against any known password breach data for this domain (Have I Been Pwned Enterprise, dark-web credential reports) — credential-stuffing sprays often immediately follow a breach publication.",
            "Review the spray pattern for timing regularity — automated spray tools hit at uniform intervals (every 30s, every 60s); irregular gaps may indicate a manual or low-and-slow attempt designed to avoid lockout detection.",
        ],
        "findings_extra": [
            "Password spray pattern confirmed: [source IP] targeted [N] unique accounts with approximately [M] attempts per account over [window].",
            "No successful or interrupted authentications observed — attacker does not currently hold any confirmed valid credential.",
            "Spray timing: [regular cadence of ~Ns intervals / irregular] — [consistent with automated tooling / may indicate manual or throttled spray].",
        ],
        "actions_extra": [
            "Block source IP at perimeter if repeat spray activity expected — note that sophisticated spray campaigns rotate source IPs after detection; monitor for re-spray from new IP against the same accounts.",
            "Notify affected account owners — many spray targets are unaware their account was targeted, and a heads-up improves reporting of future suspicious activity.",
        ],
        "false_positive_indicators_extra": [
            "Pen test or red team exercise — confirm with security engineering before blocking or resetting credentials.",
            "Single-sign-on misconfiguration re-trying valid credentials against a stale ADFS endpoint — check with the SIEM team if the source is an internal ADFS proxy.",
        ],
    },
    "PingID MFA Spamming": {
        "investigation_steps": [
            "Confirm with the user directly by phone or Teams chat (NOT email — attacker may already have mailbox access) whether they approved any prompt, and whether they recall initiating any login around the alert time. A genuine user may have approved one prompt out of habit before realising something was wrong.",
            "Pull the authentication method used for any approval event — number-matching MFA approval requires the user to actively enter a displayed code and is harder to coerce than a simple push tap. A number-match approval from an unusual location is still suspicious but changes the attack-vector assessment.",
            "Identify WHERE the attacker obtained the valid password — pull this user's sign-in history for the past 30 days for any 'interrupted' events (password correct, MFA challenged), and check for any phishing email delivered to this user in the same period. MFA bombing only works with a valid credential; the credential source is a key evidence gap.",
            "Check whether the same source IP appears in notables for other users in the past 72 hours — MFA bombing campaigns target multiple accounts simultaneously; a single-user event with no other activity may indicate targeted compromise rather than broad campaign.",
            "Review the user's password last-changed date — MFA bombing attempts following a password that has not been changed in 6+ months and a recent breach disclosure affecting the organization are strongly correlated.",
        ],
        "findings_extra": [
            "[N] MFA push prompts sent to [user] within [window] from source IP [IP] ([Country] / [ASN/hosting provider]).",
            "No MFA prompt was approved [or: One prompt approved at [time] — post-authentication activity check required].",
            "Attacker holds a valid password for this account — password reset is required regardless of whether any prompt was approved.",
            "Source IP shows no prior association with legitimate sign-ins by this user.",
        ],
        "actions_extra": [
            "Reset the user's password immediately — attacker holds valid credentials and the reset closes the door on further MFA bombing or password-based attacks.",
            "If any prompt was approved: revoke all active sessions in Entra ID (Entra portal → User → Revoke sessions) and check mailbox for new inbox rules, forwarded messages, or external sharing events created after the approval timestamp.",
            "Verify whether number matching is enforced for this user's Authenticator policy — if not, recommend enabling it as an immediate improvement to MFA bombing resilience.",
        ],
        "false_positive_indicators_extra": [
            "User initiating a login from a new device while their existing session is also prompting a refresh — can produce a burst of push prompts that look like an attack but are entirely self-generated.",
            "Session token expiry after a password change causing multiple apps to simultaneously re-authenticate — produces several push prompts in quick succession that look like a bombing event.",
        ],
    },
    "Azure Risky Sign-in": {
        "investigation_steps": [
            "Pull the specific Entra ID Protection risk detection type (anonymous IP, impossible travel, leaked credentials, malicious IP, unfamiliar sign-in properties, token anomaly, etc.) — the detection type determines both urgency and what to investigate next. 'Leaked credentials' requires immediate password reset regardless of any other factor; 'impossible travel' should be verified directly with the user; 'anonymous IP' requires checking session downstream activity.",
            "Review the Conditional Access evaluation outcome for the risky session — if CA applied a 'grant with MFA-required' grant and MFA completed, the session may be active and downstream access must be scoped. If CA blocked it, the session is almost certainly terminated; confirm and close if scope is clean.",
            "Pull Entra audit logs for the 60 minutes immediately after the risky sign-in and filter specifically for: inbox rule creations (Set-InboxRule, New-InboxRule), application consent grants (Consent to application), device registrations (Add registered device), and password changes — these are the four most common post-compromise persistence actions taken within the first hour of account access.",
            "Compare the risky sign-in source IP against the user's last 10 clean, successful sign-ins for baseline deviations: new country, new ASN, new device OS/browser, new user agent — the more deviations, the lower the likelihood this is the legitimate user.",
            "Search Defender XDR for any correlated incident or linked alerts on the same user or same source IP — Defender often bundles a risky sign-in with endpoint detections or mailbox anomaly alerts into a single incident graph that gives a fuller picture than the Entra alert alone.",
        ],
        "findings_extra": [
            "Risky sign-in detected: [risk detection type] for [user] from [IP] ([Country] / [ASN]) at [time]. Authentication result: [success/failure/interrupt].",
            "Post-sign-in activity in 60-minute window: [no anomalous actions observed / inbox rules created at [time] / [N] new app consents / etc.].",
            "User risk level in Entra ID Protection: [none/low/medium/high at time of investigation]. CA evaluation: [blocked / granted / not applied].",
            "Baseline comparison: source IP/country/device [consistent with/deviates from] user's normal sign-in pattern.",
        ],
        "actions_extra": [
            "Confirm or dismiss the Entra ID Protection risk event — confirming it feeds the risk engine and triggers CA remediation policies on future sign-ins from risky sessions.",
            "Check and close any CA gaps for this user — verify that medium and high risk sign-ins are gated by MFA or blocked outright in the user's assigned policy.",
        ],
        "false_positive_indicators_extra": [
            "User confirmed travelling to the flagged country — document the travel approval or Teams confirmation as evidence reference and close as Authorized.",
            "Corporate VPN exit node in an unusual region (common for remote workers or remote-office VPN tunnels) — validate the exit IP is in the known-IPs allowlist; if it should be, create a Jira for SIEM team to add it.",
        ],
    },
    "CrowdStrike High Alert": {
        "investigation_steps": [
            "Open the detection in Falcon and pull the full process tree — review the parent AND grandparent of the flagged process, not just the alert node. Attackers use legitimate Windows binaries (wscript.exe, mshta.exe, certutil.exe, regsvr32.exe, rundll32.exe) as launchers; the alert fires on the child or grandchild process, but the entry point is higher in the tree.",
            "Note the MITRE ATT&CK technique CrowdStrike assigned to this detection and use it to direct the next check: T1059 (script execution) → look for payload drop path; T1055 (process injection) → identify which legitimate process was injected and what it did; T1543 (persistence) → look for registry key modifications or new service creation.",
            "Check the host's sensor last-seen timestamp in Falcon — a host that stopped reporting within 30–60 minutes of the detection may indicate an adversary-initiated action (sensor disablement, host isolation, network cut) rather than normal remediation activity.",
            "Search for the same SHA256 file hash across all Falcon-enrolled hosts: index=crowdstrike SHA256HashData=<hash> event_simpleName=ProcessRollup2 — if it's on more than one host, the scope is wider than an isolated endpoint event.",
            "Pull NetworkConnectIP4 events from the flagged host for the 30 minutes following the detection — C2 callbacks, data staging, and lateral movement connection attempts almost always occur within this window post-execution.",
        ],
        "findings_extra": [
            "CrowdStrike [High/Critical] detection on [host] for [detection name] — MITRE technique: [T-code / tactic]. Process: [process name] spawned by [parent process].",
            "Hash [SHA256]: [observed on this host only / observed on N additional hosts — [list]].",
            "Sensor status: [reporting normally / stopped reporting at [time] — investigate].",
            "No outbound connections from host to non-corporate IPs in 30-minute post-detection window [or: Connection to [IP:port] at [time] — requires reputation check].",
        ],
        "actions_extra": [
            "Contain the host in Falcon (network containment, not full isolation) if active malicious activity is confirmed — containment preserves forensic evidence access while cutting lateral movement paths.",
            "Collect volatile evidence before reimaging: running process list, open network connections, event logs from the 2-hour window around the detection, and a copy of any file artifacts.",
            "Route to PT-EDR Platform via ServiceNow for hash block, network containment, or Falcon platform support if containment is required.",
        ],
        "false_positive_indicators_extra": [
            "Security tool or AV scanner performing legitimate binary analysis that triggers a behavioral detection — validate by checking the parent process and the tool's installed path.",
            "IT administrator using a dual-use tool (PsExec, Mimikatz-style admin utility) for authorized maintenance — check the change management calendar and confirm with the system owner before closing.",
        ],
    },
    "Defender High Alert": {
        "investigation_steps": [
            "Open the full Defender XDR incident, not just the individual alert — Defender correlates multiple signals (email delivery → endpoint execution → identity risk) into a single incident graph; review all entities and alerts in the incident, not only the one that triggered your ticket.",
            "Check Automated Investigation and Remediation (AIR) status — Defender may have already quarantined a file, killed a process, or blocked a URL before you opened the ticket. Document what was auto-remediated so the incident report reflects it and to avoid double-action.",
            "Review the Defender device timeline for the 2 hours before the alert trigger — look for: unusual PowerShell invocations, LOLBin usage (certutil, mshta, wscript, regsvr32, rundll32), net/whoami/ipconfig /all reconnaissance commands, or file drops in temp/AppData paths.",
            "Confirm whether the affected device is a privileged endpoint (admin workstation, domain controller, CA server, jump host) — the same alert severity requires faster escalation and deeper review on privileged endpoints than on standard user workstations.",
        ],
        "findings_extra": [
            "Defender [High/Critical] alert on [device] / [user] — alert title: [alert name]. AIR status: [auto-remediated / pending manual action].",
            "Incident scope: [single alert / correlated multi-entity incident — [N] other alerts in the same Defender incident].",
            "Device role: [standard user workstation / privileged endpoint — escalation threshold adjusted accordingly].",
        ],
        "actions_extra": [
            "Isolate device in Defender portal if active threat is confirmed and host has not already been network-isolated by AIR.",
            "Submit any quarantined file samples to your threat intel sandbox or Defender's Threat Intelligence portal for full behavioral detonation before reimaging.",
        ],
        "false_positive_indicators_extra": [
            "Defender alerting on a security tool installed by IT (pen-test toolkits, AV comparative testing, SIEM agents with process injection capabilities) — validate against change management records.",
            "LOLBin activity flagged during a legitimate OS patching or imaging job — check the device management console (Intune/SCCM) for scheduled tasks active at alert time.",
        ],
    },
    "O365 Phishing Alert": {
        "investigation_steps": [
            "Confirm actual email delivery status in Exchange Admin Center or Defender's Message Trace before doing anything else — was it delivered to inbox, held in quarantine, or deleted before delivery? A quarantined message with no user click is a significantly lower urgency than a delivered-and-opened one.",
            "Extract ALL URLs from the email body (not only the one that triggered the detection) — phishing kits embed decoy legitimate links alongside the malicious one specifically to confuse automated scanners. Submit each extracted URL individually to a sandbox or URL reputation service.",
            "Check WHOIS registration age of the sender domain — domains registered within the last 30 days that pass SPF/DKIM/DMARC technical checks are almost exclusively attack infrastructure. A passing DMARC alone does not mean the sender is who they claim to be.",
            "Pull the full recipient list for this message from the email gateway or Defender's Threat Explorer — phishing campaigns are rarely single-target. Find all recipients, prioritize any who clicked, and scope the breach before closing the ticket.",
            "Check Teams workspace for the same URL or same sender domain — O365 phishing is increasingly delivered via Teams external-user messages and file sharing as email filtering has tightened. Teams links bypass most email gateway controls entirely.",
        ],
        "findings_extra": [
            "Email [delivered to inbox / quarantined / blocked] — user [did / did not] interact with the message. [URL clicked at [time] / no URL click observed in URL click logs].",
            "Sender domain [domain] registered [N] days ago — consistent with purpose-registered attack infrastructure (sub-30-day domain).",
            "Technical authentication: SPF [pass/fail], DKIM [pass/fail/none], DMARC [pass/fail/none] — technical checks [do not / do] indicate spoofed organization.",
            "Campaign scope: same message or tracked URL sent to [N] additional recipients in this tenant [or: no additional recipients confirmed].",
        ],
        "actions_extra": [
            "Purge the message from all recipient inboxes using Defender's soft-delete or Search-UnifiedAuditLog plus Remove-ComplianceSearchAction — document purge completion in the ticket.",
            "Block sender domain and all embedded URLs at the email gateway, proxy, and Defender Safe Links blocklist.",
            "For any user who clicked the malicious URL: treat as potential credential entry — pull the URL destination content to confirm if it was a credential-harvesting page; if yes, initiate immediate password reset and MFA check.",
        ],
        "false_positive_indicators_extra": [
            "Internal phishing simulation or security awareness training campaign — confirm with the security awareness team before blocking the sender or resetting credentials.",
            "Marketing email from a recently-acquired or rebranded domain that hasn't been added to the allowlist — check with the business before blocking; newer corporate domains pass all technical checks and can trigger this alert.",
        ],
    },
    "DDoS Attack Detected": {
        "investigation_steps": [
            "Classify the attack type before trying to mitigate — volumetric (bandwidth saturation), protocol (SYN/ICMP/UDP flood targeting state tables), or application-layer (HTTP flood, slow-loris targeting server thread pools). The response for each is different: volumetric requires upstream scrubbing or null-routing; protocol requires ACL or SYN-cookie tuning; application-layer requires WAF rate-limiting.",
            "Establish a traffic baseline for the targeted destination(s) over the past 7 days before calling it DDoS — a 2–3× spike should be correlated against scheduled business events (marketing campaign launch, product release, planned external scan) before engaging mitigation. A 10× spike with no business event explanation is DDoS.",
            "Determine whether the attack traffic has a discernible signature (source port, TTL, packet size, payload prefix) that enables upstream ACL filtering without null-routing — a signature-based ACL preserves partial service availability and gives you evidence to share with your upstream provider.",
            "Identify whether the attack is targeting a single IP or distributed across a subnet — a distributed attack against a /24 may require upstream provider null-routing or a network provider's scrubbing center rather than perimeter-only filtering.",
            "Check for concurrent suspicious activity (failed logins, new accounts created, admin console access attempts) during the DDoS window — DDoS is sometimes used as a distraction during a simultaneous intrusion attempt.",
        ],
        "findings_extra": [
            "Attack confirmed: [volumetric / protocol / application-layer] DDoS targeting [destination IP / service]. Peak: [N Gbps / N Mpps / N req/s].",
            "Business impact: service [degraded / fully unavailable] for [duration] since [start time]. [Service recovery confirmed at [time] / service remains impacted].",
            "Attack signature: [source port, packet size, payload pattern if identified]. Upstream provider mitigation: [engaged / not required / pending].",
            "No concurrent intrusion activity observed during attack window [or: concurrent suspicious access attempts noted — investigate separately].",
        ],
        "actions_extra": [
            "Engage upstream ISP or CDN DDoS mitigation if on-premises scrubbing is insufficient for the observed traffic volume — include attack type, peak volume, and target IP in the provider request.",
            "Apply perimeter ACL to drop signature-matching traffic — confirm with network team that the ACL pattern does not inadvertently affect legitimate traffic before applying.",
        ],
        "false_positive_indicators_extra": [
            "Legitimate high-volume traffic event (major product launch, external scan audit, media coverage spike) — confirm with the business calendar and web analytics before engaging mitigation.",
            "Monitoring tool or load-testing framework running against a pre-production environment that shares infrastructure — confirm with the dev/infra team before declaring DDoS.",
        ],
    },
    "Major Incident": {
        "investigation_steps": [
            "Do not wait for certainty before containing — in a major incident, contain first and investigate in parallel. Delaying containment to gather more evidence typically results in wider blast radius.",
            "Assign a single incident commander immediately and communicate the assignment to all responders — major incidents collapse into confusion when multiple people are making containment decisions independently without clear ownership.",
            "Every containment action and its outcome must be logged in real time — major incident timelines are always reconstructed later for legal, compliance, or board review, and real-time notes are far more reliable than post-incident recall.",
            "Scope first before public communications — determine what is confirmed vs. suspected and what data/systems are confirmed impacted before drafting any external-facing statement. Premature scope estimates in major incidents are almost always wrong and create additional reputational risk.",
        ],
        "findings_extra": [
            "Incident scope as of [time]: [confirmed affected systems / suspected affected systems / data classification involved if known].",
            "Containment status: [contained / partially contained / active spread ongoing].",
            "Business impact: [services affected, estimated revenue/operational impact if known].",
        ],
        "actions_extra": [
            "Notify legal and compliance immediately if data exfiltration is possible — breach notification timelines start from the point of discovery, not confirmation.",
            "Preserve all evidence before containment actions where operationally feasible — memory dumps, network captures, log exports — the forensic record is required for post-incident review and may be legally required.",
        ],
        "false_positive_indicators_extra": [
            "Cascading infrastructure failure (BGP mis-announcement, CDN outage, cloud provider incident) misclassified as security event — check provider status pages and network team before declaring major security incident.",
        ],
    },
}


async def seed_rule_book(db: TrackerDB) -> None:
    existing = {s["alert_type"] for s in await db.list_sops()}
    for alert_type, rule in RULE_BOOK.items():
        if alert_type not in existing:
            enrichment = _ENRICHMENTS.get(alert_type, {})
            base_sections = rule.get("description_sections", {})
            structured = {
                **rule["structured"],
                "common_titles": rule.get("common_titles", []),
                "mitre_techniques": rule.get("mitre_techniques", []),
                "default_priority": rule.get("default_priority", "medium"),
                "description_template": rule.get("description_template", {}),
                "detection_engineering": rule.get("detection_engineering", {}),
                "splunk_queries": rule.get("splunk_queries", []),
                "ip_check_guide": rule.get("ip_check_guide", ""),
                "alert_description": rule.get("description", ""),
                "reference_links": rule.get("reference_links", []),
                "investigation_steps": (
                    rule["structured"].get("investigation_steps", []) +
                    enrichment.get("investigation_steps", [])
                ),
                "containment_actions": (
                    rule["structured"].get("containment_actions", []) +
                    enrichment.get("actions_extra", [])
                ),
                "false_positive_indicators": (
                    rule["structured"].get("false_positive_indicators", []) +
                    enrichment.get("false_positive_indicators_extra", [])
                ),
                "description_sections": {
                    **base_sections,
                    "findings": (
                        base_sections.get("findings", []) +
                        enrichment.get("findings_extra", [])
                    ),
                    "actions_taken": (
                        base_sections.get("actions_taken", []) +
                        enrichment.get("actions_extra", [])
                    ),
                },
            }
            await db.upsert_sop(alert_type, rule["steps"], category=rule["category"], structured=structured)
