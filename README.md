# SOC Incident Tracker

A private, login-gated personal case-tracking dashboard - log every alert
you acknowledge, work through a Rule Book of real, named detection rules
(each with investigation steps, required fields, Splunk query hints,
containment actions, and a closure checklist), and dispose of it
(escalate / resolve / false positive) with a Tines-style dropdown-driven
workflow. Closure is verified - you can't resolve a ticket without a
disposition reason, or while still awaiting a stakeholder reply.

Bidirectional Telegram bot included - acknowledge, close, or escalate
tickets without opening the dashboard, get a shift summary or daily
digest on demand, and get pinged on: new tickets, ticket status changes,
logins, brute-force login attempts, password changes, stale tickets,
new high-severity CVEs, new entries on CISA's Known Exploited
Vulnerabilities catalog, and if one of the internal tools below goes
unreachable.

An "Investigate" tab calls the three other SOC Lab tools - IOC
Enrichment, Phishing Triage, File Analyser - directly over localhost, so
you never have to leave the tracker mid-investigation. A global search
bar covers tickets, the Rule Book, and the MITRE knowledge base at once.

Also includes a MITRE ATT&CK quick-reference knowledge tab (55 curated
techniques across all 14 tactics, practical triage notes rather than a
copy of MITRE's own site), a security news feed merged from 7 free
sources with photos where the source provides one, per-user incident
history, and CSV/PDF export.

This is the personal, single-user counterpart to the other four tools in
this portfolio, which are no longer public - they run as internal-only
services this tracker calls. It's not connected to any real employer's
Tines/Splunk instance; the Rule Book ships with real-world-shaped
examples (VPN brute force, password spraying, Azure risky sign-in, MFA
fatigue, CrowdStrike/Defender alerts, O365 phishing) for you to edit
into your own.

## How it works

- **`auth.py`** - bcrypt-hashed single admin password (changeable at
  runtime via Settings, stored in the database rather than a fixed env
  var), signed session cookies (`itsdangerous`, no server-side session
  store needed), per-IP login rate limiting. `HttpOnly` + `Secure` +
  `SameSite=Strict` cookies plus FastAPI's own JSON-body validation
  together cover CSRF.
- **`db.py`** - SQLite: incidents, incident_updates (note/audit trail),
  sops (Rule Book entries - free-text steps plus structured JSON fields,
  editable without a code change), settings (runtime-changeable config
  like the password hash and CVE-monitor dedup state), plus full-text
  substring search across incidents and SOPs.
- **`rule_book.py`** - 6 real SOP categories and 7 named detection rules
  with full structured guidance, auto-attached the moment a rule is
  selected for a new ticket.
- **`seed_sops.py`** - 6 generic SOPs seeded as a fallback for anything
  not in the Rule Book. Never overwrites a real SOP you've entered.
- **`integrations.py`** - calls IOC Enrichment, Phishing Triage, and File
  Analyser over localhost for the Investigate tab.
- **`telegram_bot.py`** - private, allowlisted-chat-id bot. `/tickets`,
  `/close <id> <note>`, `/escalate <id> <reason>`, `/falsepositive <id>
  <reason>`, `/note <id> <text>`, `/sop <alert type>`, `/summary [hours]`,
  `/digest`.
- **`notifications.py`** - formats every notification site's
  (subject, body) into one Telegram message, in one place.
- **`scheduler.py`** - four background jobs: stale-ticket reminders,
  CVE/KEV monitoring (`cve_monitor.py`), internal-tool reachability
  checks (`health_check.py`, only notifies on a state change), and a
  daily digest (`daily_digest.py`).
- **`mitre_knowledge.py`** - 55 curated MITRE ATT&CK techniques across
  all 14 tactics - what it looks like, common false positives, what to
  do next.
- **`security_feed.py`** - aggregates 7 free, no-API-key RSS feeds
  (Krebs, The Hacker News, BleepingComputer, SANS ISC, Dark Reading,
  Schneier on Security, The Record), extracts a real photo where the
  feed provides one (verified: only 2 of the 7 do - most security blogs
  don't embed images in RSS at all), detects CVE IDs in headlines, and
  can merge everything into one chronological "latest" view. Cached 30
  minutes.
- **`pdf_export.py`** - PDF version of the incident export alongside the
  existing CSV one.
- **`api.py`** - FastAPI app, everything under `/api/*` requires a valid
  session.

## Setup

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
copy .env.example .env
```

Generate the secret key and password hash (commands are in
`.env.example`), fill in `.env`, then:

```powershell
uvicorn tracker.api:app --reload
pytest -v
```

## What's next

- Personal weekly self-review (which dispositions needed correction,
  your own false-positive rate trend)
- MITRE-tactic-ordered timeline view across related tickets
