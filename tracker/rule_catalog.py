"""The real, fixed catalog of Splunk alert titles from GAP Cyber Defense's
13 SOPs (source: "Alert Structure Reference" doc, 2026-06-30). Unlike
rule_book.py's 9 hand-written playbooks (deep guidance for broad alert
*types*), this is the literal Splunk search_name catalog - exact strings,
one row per real detection rule, used so alert_title is a lookup into a
fixed list instead of free text. The two coexist: an analyst picks an
alert_title here (gets SOP/category/severity for free), and separately the
ticket's alert_type/Rule Book entry still drives the deeper investigation
guidance where one exists.

Transcribed verbatim from the source PDF tables. The doc's own summary
table claims 77 unique titles across 13 SOPs; the literal per-SOP tables
add up to a couple more/less depending how you count one rule
("Falcon Admin / RTR Role Assignment") that's intentionally listed under
both SOP-05 and SOP-10 because it's actioned by either playbook depending
on context - kept as two catalog rows rather than force a single SOP.
"""

from __future__ import annotations

# SOP number -> short category label, used for grouping/UI display.
SOP_CATEGORIES: dict[str, str] = {
    "SOP-01": "VPN & Authentication",
    "SOP-02": "MFA & Identity",
    "SOP-03": "Identity Risk",
    "SOP-04": "Microsoft Defender",
    "SOP-05": "CrowdStrike/Endpoint",
    "SOP-06": "Email/Phishing",
    "SOP-07": "Cloud Malware",
    "SOP-08": "Data Protection/DLP",
    "SOP-09": "Network/IOC/C2",
    "SOP-10": "Privileged/Persistence",
    "SOP-11": "Wireless",
    "SOP-12": "Risk/ATT&CK",
    "SOP-13": "Platform Health",
}

# (sop, title, default_severity) - one row per real Splunk alert title.
_CATALOG_ROWS: list[tuple[str, str, str]] = [
    ("SOP-01", "Access - Gap-GP-VPN Password Spraying Attempts - Rule", "High"),
    ("SOP-01", "Access - Gap-GP-VPN Brute Force Attempts - Rule", "High"),
    ("SOP-01", "Threat - GAP-Windows-Suspicious Failed Logon on disabled account - Rule", "Medium"),
    ("SOP-01", "Threat - Gap-O365-Office Activity Associated with Anonymous Proxy IP - Rule", "High"),
    ("SOP-01", "Network - Gap-PAN-Global Protect-VPN using unofficial GP Client - Rule", "Medium"),

    ("SOP-02", "Access - Gap-PingID-Potential MFA Spamming - Rule", "High"),
    ("SOP-02", "Threat - Gap-Ping-HDDT Performs MFA Bypass Detection - Rule", "High"),
    ("SOP-02", "Threat - Gap-Ping-HDDT performs anomalous MFA activity on a user's account - Rule", "High"),
    ("SOP-02", "Access - GAP - PingID MFA Device Added After Password Reset - Rule", "High"),
    ("SOP-02", "Threat - Gap-O365-MFA Enabled Conditional Access Policy has been modified - Rule", "Medium"),

    ("SOP-03", "Access - Gap-Azure-Risky Signin Detected - Rule", "High"),
    ("SOP-03", "Identity - GAP-Permiso-Critical Severity Alert Monitoring - Rule", "Critical"),
    ("SOP-03", "Identity - GAP-Permiso-High Severity Alert Monitoring - Rule", "High"),
    ("SOP-03", "Identity - GAP PingID - Possible Suspicious Activity from PingID Risk Logs - Rule", "Medium"),
    ("SOP-03", "Endpoint - Gap-CrowdStrike-Identity-Protection-Critical - Rule", "Critical"),
    ("SOP-03", "Endpoint - Gap-CrowdStrike-Identity-Protection-High - Rule", "High"),
    ("SOP-03", "Endpoint - Gap-CrowdStrike-Identity-Protection-Medium - Rule", "Medium"),

    ("SOP-04", "Threat - Gap-MSFT-High - Rule", "High"),
    ("SOP-04", "Threat - Gap-MSFT-Medium - Rule", "Medium"),
    ("SOP-04", "Threat - Gap-MSFT-Low - Rule", "Low"),
    ("SOP-04", "Threat - Gap-MSFT-Informational - Rule", "Info"),
    ("SOP-04", "Threat - Gap-MSFT-Low Risk Rule - Rule", "Low"),
    ("SOP-04", "Threat - Gap-MSFT-Informational Risk Rule - Rule", "Info"),

    ("SOP-05", "Endpoint - Gap-CrowdStrike-Critical - Rule", "Critical"),
    ("SOP-05", "Endpoint - Gap-CrowdStrike-High - Rule", "High"),
    ("SOP-05", "Endpoint - Gap-CrowdStrike-Medium - Rule", "Medium"),
    ("SOP-05", "Endpoint - Gap-CrowdStrike-Low - Rule", "Low"),
    ("SOP-05", "Endpoint - Gap-CrowdStrike-Informational - Rule", "Info"),
    ("SOP-05", "Endpoint - Gap-CrowdStrike-OverWatch - Rule", "Critical"),
    ("SOP-05", "Endpoint - Gap-CrowdStrike_FIM - Rule", "High"),
    ("SOP-05", "Endpoint - GAP-Crowdstrike-Suspicious npm Script Execution with Token Access - Rule", "High"),
    ("SOP-05", "Endpoint - Gap-CrowdStrike-Detection of Falcon Admin / RTR Role Assignment - Rule", "High"),
    ("SOP-05", "Threat - GAP-Windows-Audit Logs Was Cleared - Rule", "High"),
    ("SOP-05", "Threat - GAP - MSHTA Execution with Remote URL - Rule", "High"),
    ("SOP-05", "ESCU - Access LSASS Memory for Dump Creation - Rule", "High"),
    ("SOP-05", "Threat - GAP - Suspicious Disk Image Transfer Activity from KVM Engine Logs - Rule", "Medium"),
    ("SOP-05", "Threat - Gap-Nexthink-Bulk Deployment Detection - Rule", "Medium"),

    ("SOP-06", "Threat - Gap-O365-External User Added to Teams - Rule", "Medium"),
    ("SOP-06", "Threat - Gap-O365-Masquerading External Email being Added to Teams - Rule", "High"),
    ("SOP-06", "Threat - Gap-O365-Masquerading External Email being Added to Sharepoint - Rule", "High"),
    ("SOP-06", "Threat - Gap-O365-Suspected Non-Dropped Phishing Event - Rule", "High"),
    ("SOP-06", "Threat - Gap-O365-External Email Added/Removed from Teams - Rule", "Medium"),

    ("SOP-07", "Threat - Gap-O365-Malware Identified on Sharepoint/OneDrive - Rule", "High"),

    ("SOP-08", "Threat - Gap-O365-Office Mass Deletion of Files - Rule", "High"),
    ("SOP-08", "Threat - Gap-O365-Anonymous Sharing of Sensitive Files - Rule", "High"),
    ("SOP-08", "Threat - Gap-O365-DLP-PGP_PEM - Rule", "High"),
    ("SOP-08", "Threat - Gap-O365-Sensitive Keywords Found in Outbound Email - Rule", "Medium"),
    ("SOP-08", "Threat - Gap-O365-Abnormally Large Emails being sent Outbound - Rule", "Medium"),
    ("SOP-08", "Threat - Gap-O365-Copier or Scanner Sending Scan to External Email - Rule", "Low"),
    ("SOP-08", "Threat - Gap-O365 Content Shared to External Users via Commercial Email - Rule", "Medium"),

    ("SOP-09", "Network - GAP - Detect Outbound SMB Traffic - Rule", "High"),
    ("SOP-09", "Network - Gap-PAN-Large Outbound RDP - Rule", "Medium"),
    ("SOP-09", "Network - Gap-PAN-Excessive Outbound SMTP - Rule", "Medium"),
    ("SOP-09", "Threat - Gap-PAN-Allowed Inbound on Port 22 and Port 3389 - Rule", "Medium"),
    ("SOP-09", "Threat - Gap-PAN-Abnormal Access to VirusTotal - Rule", "Medium"),
    ("SOP-09", "Threat - GAP-Claroty-Malicious Internet Communication Detection - Rule", "High"),
    ("SOP-09", "Threat - GAP-Claroty-Attempted Malicious Internet Communication - Rule", "Medium"),
    ("SOP-09", "Threat - Threat List Activity - Rule", "High"),

    ("SOP-10", "Access - Gap-Azure-New User Added to Sudoers - Rule", "High"),
    ("SOP-10", "Threat - Gap-VMwareESXi – Virtual Machine Creation Monitoring - Rule", "Medium"),
    ("SOP-10", "Threat - GAP-Cohesity–Multiple Access Token Creations by Same User/IP - Rule", "High"),
    ("SOP-10", "Endpoint - Gap-CrowdStrike-Detection of Falcon Admin / RTR Role Assignment - Rule", "High"),
    ("SOP-10", "Threat - GAP - GitHub Organizations Repository Archived - Rule", "Medium"),
    ("SOP-10", "Threat - GAP-Windows-Remote File Copy via Commandline - Rule", "Medium"),

    ("SOP-11", "Network - GAP-MIST - Rogue SSID Detection in Corporate Networks - Rule", "High"),
    ("SOP-11", "Network - GAP-Meraki-SSID Spoofing Detection with Anomalous Traffic Volume - Rule", "High"),
    ("SOP-11", "Threat - GAP-MIST-Detection of Rogue Access Point Spoofing - Rule", "High"),

    ("SOP-12", "Risk - 24 Hour Risk Threshold Exceeded - Rule", "High"),
    ("SOP-12", "Risk - 7 Day ATT&CK Tactic Threshold Exceeded - Rule", "High"),

    ("SOP-13", "Audit - GAP-Index Not Reporting - Rule", "Medium"),
    ("SOP-13", "Audit - GAP-Sourcetype Not Reporting - Rule", "Medium"),
    ("SOP-13", "Audit - Heavy Forwarder not reporting more than 3 hours - Rule", "Medium"),
    ("SOP-13", "Audit - Azure Tenant logs Stopped Reporting for more than 4hrs - Rule", "High"),
    ("SOP-13", "Network - GAP - Firewall Not Reporting - Rule", "High"),
]

RULE_CATALOG: list[dict] = [
    {
        "sop": sop,
        "title": title,
        "category": SOP_CATEGORIES[sop],
        "category_prefix": title.split(" - ", 1)[0],
        "default_severity": severity,
    }
    for sop, title, severity in _CATALOG_ROWS
]

_BY_TITLE: dict[str, dict] = {row["title"]: row for row in RULE_CATALOG}

# Fallback keyword -> SOP matching for new/unmapped titles the SIEM team
# adds later, per the source doc's Section 4. Checked in order; first match
# wins. Only used when a title isn't an exact catalog hit.
_FALLBACK_KEYWORDS: list[tuple[str, str]] = [
    ("VPN", "SOP-01"), ("Brute Force", "SOP-01"), ("Password Spray", "SOP-01"),
    ("Disabled account", "SOP-01"), ("Anonymous Proxy", "SOP-01"), ("Unofficial GP", "SOP-01"),
    ("MFA", "SOP-02"), ("PingID", "SOP-02"), ("HDDT", "SOP-02"), ("Conditional Access Policy", "SOP-02"),
    ("Risky Signin", "SOP-03"), ("Permiso", "SOP-03"), ("PingID Risk", "SOP-03"),
    ("CrowdStrike-Identity-Protection", "SOP-03"),
    ("MSFT", "SOP-04"),
    ("FIM", "SOP-05"), ("npm", "SOP-05"), ("MSHTA", "SOP-05"), ("Audit Logs", "SOP-05"),
    ("LSASS", "SOP-05"), ("Disk Image", "SOP-05"), ("Nexthink", "SOP-05"), ("CrowdStrike", "SOP-05"),
    ("Teams", "SOP-06"), ("Masquerading", "SOP-06"), ("Phishing", "SOP-06"),
    ("Malware", "SOP-07"),
    ("Mass Deletion", "SOP-08"), ("DLP", "SOP-08"), ("Sensitive", "SOP-08"),
    ("Large Email", "SOP-08"), ("Anonymous Sharing", "SOP-08"),
    ("SMB", "SOP-09"), ("RDP", "SOP-09"), ("SMTP", "SOP-09"), ("VirusTotal", "SOP-09"),
    ("Claroty", "SOP-09"), ("Threat List", "SOP-09"),
    ("Sudoers", "SOP-10"), ("VMware", "SOP-10"), ("Cohesity", "SOP-10"),
    ("Falcon Admin", "SOP-10"), ("RTR", "SOP-10"), ("GitHub", "SOP-10"), ("Remote File Copy", "SOP-10"),
    ("MIST", "SOP-11"), ("Meraki", "SOP-11"), ("SSID", "SOP-11"), ("Rogue Access Point", "SOP-11"),
    ("Risk Threshold", "SOP-12"), ("ATT&CK Tactic Threshold", "SOP-12"),
    ("Not Reporting", "SOP-13"), ("Forwarder", "SOP-13"), ("Tenant logs Stopped", "SOP-13"),
]


def lookup_catalog_entry(title: str) -> dict | None:
    """Exact-match lookup against the fixed 77-title catalog."""
    return _BY_TITLE.get(title)


def guess_sop_from_title(title: str) -> str | None:
    """Fallback keyword matcher for titles not in the fixed catalog yet."""
    lowered = title.lower()
    for keyword, sop in _FALLBACK_KEYWORDS:
        if keyword.lower() in lowered:
            return sop
    return None


def all_titles() -> list[str]:
    return [row["title"] for row in RULE_CATALOG]
