"""Curated MITRE ATT&CK technique reference - practical triage notes for
the techniques most likely to show up in real alerts, not a mirror of
MITRE's own (much larger) site. Each entry is written for "what does this
mean when I see it in a ticket," not academic completeness.
"""

from __future__ import annotations

MITRE_TECHNIQUES: dict[str, dict] = {
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion / Privilege Escalation",
        "what_it_is": "Malicious code runs inside the memory space of a legitimate, already-running process, instead of as its own visible process.",
        "looks_like_in_practice": "An EDR alert naming a normal process (svchost.exe, explorer.exe) but flagging anomalous memory regions, unexpected threads, or outbound network activity that process doesn't normally do.",
        "common_false_positive": "Some legitimate security/monitoring software and DRM also inject into other processes - check the injecting process's own reputation before assuming malice.",
        "next_step": "Identify the injecting process and the target process. Memory-dump and hash analysis on the injected region if your EDR supports it.",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "what_it_is": "Extracting stored credentials (hashes, plaintext passwords, Kerberos tickets) from OS memory or files - classically LSASS memory on Windows.",
        "looks_like_in_practice": "A process (often a renamed or unusual binary) accessing lsass.exe memory, or known tool signatures (Mimikatz-style behavior) in EDR telemetry.",
        "common_false_positive": "Legitimate backup/AV software occasionally reads LSASS for unrelated reasons - rare, but check the process's signer before assuming compromise.",
        "next_step": "Treat as a high-confidence compromise indicator. Assume any credentials on that host are burned - reset them, don't just monitor.",
    },
    "T1486": {
        "name": "Data Encrypted for Impact (ransomware)",
        "tactic": "Impact",
        "what_it_is": "Files are being encrypted en masse, typically the final stage of a ransomware deployment.",
        "looks_like_in_practice": "Mass file-extension changes, sudden spike in file-write/rename operations, or shadow-copy deletion happening at the same time.",
        "common_false_positive": "Legitimate full-disk encryption rollouts or large compression/backup jobs can superficially resemble this - check timing and whether it was scheduled/expected.",
        "next_step": "This is an active incident, not a ticket to triage calmly - isolate immediately, this is one of the few cases where speed matters more than process.",
    },
    "T1021": {
        "name": "Remote Services (lateral movement)",
        "tactic": "Lateral Movement",
        "what_it_is": "Using legitimate remote access protocols (RDP, SMB, SSH, WinRM) to move from one compromised host to another.",
        "looks_like_in_practice": "A login to a new host using credentials that just authenticated somewhere else, especially off-hours or from a host that doesn't normally connect there.",
        "common_false_positive": "IT/helpdesk remote support and legitimate automation (scheduled jobs, config management) use the same protocols constantly - context (which account, which hosts, what time) is everything here.",
        "next_step": "Map which hosts the account touched and in what order - this tells you the scope, not just the entry point.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access / Persistence / Privilege Escalation / Defense Evasion",
        "what_it_is": "Using legitimate, valid credentials rather than exploiting a vulnerability - the account itself is real, just being used by someone who shouldn't have it.",
        "looks_like_in_practice": "Impossible travel, login from a new/unusual device or location, or activity inconsistent with the account owner's normal role.",
        "common_false_positive": "VPN exit-node geolocation quirks, new personal devices, and legitimate travel all produce the same surface signals - verify with the user before escalating.",
        "next_step": "Confirm with the account owner directly. If they didn't do it, treat this as a credential compromise, not just an anomaly.",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "what_it_is": "Exploiting a vulnerability in an internet-facing application (web app, VPN gateway, API) to gain initial access.",
        "looks_like_in_practice": "Unusual request patterns in web/WAF logs, a known CVE's exploit signature, or a public-facing service spawning unexpected child processes.",
        "common_false_positive": "Vulnerability scanners (including your own org's) generate similar traffic patterns - confirm the source IP isn't an authorized scanner first.",
        "next_step": "Check whether the application is patched for the relevant CVE. If exploited successfully, assume the application's service account is compromised.",
    },
    "T1071": {
        "name": "Application Layer Protocol (C2)",
        "tactic": "Command and Control",
        "what_it_is": "Malware communicating with its command-and-control server disguised as normal application traffic (HTTP/S, DNS, etc.) to blend in.",
        "looks_like_in_practice": "Regular, periodic outbound connections (beaconing) to an uncommon or newly-registered domain, especially at suspiciously consistent intervals.",
        "common_false_positive": "Legitimate software update checkers and telemetry/analytics SDKs also beacon periodically - check domain age and reputation (the IOC Enrichment API in this same SOC Lab) before escalating.",
        "next_step": "Check the destination domain's age and reputation. A domain registered days ago receiving regular check-ins from one host is a strong signal.",
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution (persistence)",
        "tactic": "Persistence",
        "what_it_is": "Configuring something to run automatically at boot/logon - registry Run keys, startup folder entries, scheduled tasks - so malware survives a reboot.",
        "looks_like_in_practice": "A new registry Run key or startup-folder entry pointing to an unsigned binary, or one located in an unusual path (temp folders, user-writable directories).",
        "common_false_positive": "Plenty of legitimate software (chat apps, cloud sync clients) registers autostart entries too - check signer and path, not just the existence of the entry.",
        "next_step": "Identify what the persisted binary actually is, then remove the persistence mechanism as part of remediation - don't just kill the running process.",
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "what_it_is": "Disabling or tampering with security tools - AV/EDR, logging, firewall rules - so the rest of the attack goes unnoticed.",
        "looks_like_in_practice": "EDR/AV service stopped or uninstalled unexpectedly, Windows Defender exclusions added without a change ticket, or log clearing (see T1070) around the same time.",
        "common_false_positive": "IT-driven AV migrations/updates can look identical - check for an associated, authorized change record before assuming malice.",
        "next_step": "This is almost always a sign something else is already happening - treat it as a strong escalation signal on its own, then look for what it was covering for.",
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "what_it_is": "Using a deceptive email (or message) to get a user to click a link, open an attachment, or hand over credentials.",
        "looks_like_in_practice": "A reported suspicious email - the Phishing Triage Bot in this same SOC Lab handles full evidence-based analysis of these directly.",
        "common_false_positive": "Legitimate marketing/notification emails with urgent-sounding subject lines get reported constantly - check sender authentication (SPF/DKIM/DMARC) before assuming malice.",
        "next_step": "If a link was clicked or credentials entered, treat as Valid Accounts (T1078) territory - reset credentials regardless of how convincing the phish looked.",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "what_it_is": "Using a command-line shell or scripting engine (PowerShell, cmd.exe, bash, Python) to execute commands - the single most common execution method in real intrusions, sub-technique .001 (PowerShell) especially.",
        "looks_like_in_practice": "PowerShell with encoded/obfuscated arguments, unusual parent-child process chains (Office app spawning cmd.exe), or scripting engines invoked by a process that doesn't normally need them.",
        "common_false_positive": "IT automation and legitimate admin scripts use the exact same interpreters constantly - the parent process and argument patterns matter far more than the interpreter itself.",
        "next_step": "Decode any encoded command-line arguments before judging intent - obfuscation itself (see T1027) is often more telling than the decoded content.",
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "what_it_is": "Creating a scheduled task or cron job so a payload runs again later or repeatedly - a classic, easy-to-miss persistence mechanism.",
        "looks_like_in_practice": "A newly-created scheduled task with an unusual name, pointing to a script/binary in a non-standard location, or running with elevated privileges it shouldn't need.",
        "common_false_positive": "Legitimate software installers create scheduled tasks routinely (update checkers, license validation) - check what the task actually runs, not just that one exists.",
        "next_step": "Always check what the task is set to RUN, not just that it exists - the task name is attacker-controlled and easy to make look benign.",
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation / Defense Evasion",
        "what_it_is": "Bypassing or abusing the OS's own privilege-elevation prompts (UAC bypass on Windows, sudo misuse on Linux) to run with higher privileges without a clean authorized prompt.",
        "looks_like_in_practice": "A process gaining administrator/SYSTEM privileges without a corresponding UAC prompt event, or known UAC-bypass technique signatures in EDR telemetry.",
        "common_false_positive": "Some legitimate installers use documented (if unusual) elevation methods - check if the binary is signed and from a known vendor.",
        "next_step": "Identify what the elevated process did with its new privileges - that's the actual impact, the bypass itself is just the means.",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "what_it_is": "Encoding, encrypting, or otherwise disguising malicious code/commands so static detection and human review don't immediately recognize them.",
        "looks_like_in_practice": "Base64-encoded PowerShell arguments, packed/high-entropy executable sections (the File Analyser in this same SOC Lab flags this directly), or strings that look like meaningless character soup.",
        "common_false_positive": "Legitimate commercial software packers (for IP protection, not malice) produce similar high-entropy signatures - reputation/signing matters more than entropy alone.",
        "next_step": "Decode/unpack before judging - obfuscation is itself a strong signal of intent to evade, even before you know what's inside.",
    },
    "T1036": {
        "name": "Masquerading",
        "tactic": "Defense Evasion",
        "what_it_is": "Making a malicious file or process look legitimate - naming it after a real Windows system file, placing it in a similar-looking path, or disguising its actual file type (the File Analyser in this same SOC Lab catches this directly via magic-byte vs extension mismatch).",
        "looks_like_in_practice": "A file named svchost.exe running from a non-system directory, or a file with a .pdf extension that's actually a PE executable.",
        "common_false_positive": "Genuinely rare to have an innocent explanation - this is one of the more reliable individual signals when confirmed.",
        "next_step": "Compare the file's actual hash/signature against the legitimate version it's impersonating, and check its running location.",
    },
    "T1070": {
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "what_it_is": "Deleting or tampering with logs, command history, or other forensic evidence to cover tracks after an action.",
        "looks_like_in_practice": "Windows Event Log service stopped/cleared, bash history cleared mid-session, or timestamps on files that don't match their content's expected creation time.",
        "common_false_positive": "Scheduled log rotation/retention policies can look similar - check whether the clearing aligns with a known, authorized retention schedule.",
        "next_step": "Treat as a strong indicator something happened just before the gap - focus investigation on the time window immediately preceding the log gap.",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "what_it_is": "Repeatedly guessing passwords (or spraying one common password across many accounts) to gain access - extremely common, and the SOC Incident Tracker's own seeded SOP for this covers it directly.",
        "looks_like_in_practice": "Many failed logins in a short window, from one source or against one account, sometimes followed by a single success.",
        "common_false_positive": "A user who forgot their password and is retrying, or a misconfigured service account with a stale credential, produce the same pattern - check if ANY attempt succeeded before assuming attack.",
        "next_step": "The single most important question is whether any attempt succeeded - that changes this from a perimeter-noise ticket into a confirmed-compromise ticket.",
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "what_it_is": "An attacker (or their tool) querying basic system info - OS version, hostname, installed software, hardware - almost always one of the first things done after gaining a foothold.",
        "looks_like_in_practice": "Commands like systeminfo, whoami, or similar discovery commands run shortly after an initial access event, often scripted/batched.",
        "common_false_positive": "IT inventory/asset-management tools run identical commands routinely and constantly - check if this is a known, scheduled inventory scan.",
        "next_step": "Rarely meaningful alone - its value is in what it's clustered with. Check what happened immediately before and after.",
    },
    "T1570": {
        "name": "Lateral Tool Transfer",
        "tactic": "Lateral Movement",
        "what_it_is": "Copying tools (or malware) from one compromised host to another, usually via SMB/admin shares, to extend the attacker's foothold.",
        "looks_like_in_practice": "An executable or script appearing on a second host shortly after suspicious activity on a first one, often via the same account, transferred over SMB.",
        "common_false_positive": "Legitimate software deployment tools (SCCM, similar) push files the same way - check whether it matches an authorized deployment window.",
        "next_step": "This is the clearest signal of active spread - check every host the same file/hash has touched, not just the two you already know about.",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "what_it_is": "Downloading additional tools or malware onto a compromised host from an external source, after initial access.",
        "looks_like_in_practice": "An outbound connection followed immediately by a new file appearing on disk, especially via certutil, bitsadmin, or PowerShell download cradles.",
        "common_false_positive": "Legitimate software auto-updaters do the same thing - check the destination domain's reputation and the binary's signature once downloaded.",
        "next_step": "Hash and check reputation on whatever was downloaded (the IOC Enrichment API/File Analyser in this same SOC Lab) before deciding severity.",
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "what_it_is": "Deleting backups, shadow copies, or other recovery mechanisms - a strong ransomware tell, usually done right before or during encryption (T1486).",
        "looks_like_in_practice": "vssadmin delete shadows, wbadmin commands deleting backup catalogs, or backup software/services being disabled.",
        "common_false_positive": "Legitimate disk-space cleanup of old shadow copies happens, but rarely targets ALL of them at once or coincides with other suspicious activity.",
        "next_step": "If seen alongside any other suspicious activity on the same host, treat as an active ransomware precursor - escalate immediately, don't wait for encryption to start.",
    },
}


def get_technique(technique_id: str) -> dict | None:
    return MITRE_TECHNIQUES.get(technique_id.strip().upper())


def list_techniques() -> list[dict]:
    return [{"id": tid, **data} for tid, data in sorted(MITRE_TECHNIQUES.items())]
