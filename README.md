# SOC Incident Tracker

A private, login-gated personal case-tracking dashboard - log every alert
you acknowledge, work through a per-alert-type SOP, and dispose of it
(escalate / resolve / false positive) with a Tines-style dropdown-driven
workflow. Bidirectional Telegram bot included - acknowledge, close, or
escalate tickets without opening the dashboard, get a shift summary
on demand, and get pinged if a ticket goes stale or someone logs in.

Also includes a MITRE ATT&CK quick-reference knowledge tab (curated
practical triage notes, not just technique IDs), a security news feed
from a handful of free sources, per-user incident history, and CSV
export.

This is the personal, single-user counterpart to the other four tools in
this portfolio - it's not connected to any real employer's Tines/Splunk
instance. You paste in what you're tracking yourself.

## Why this exists

The fifth piece of a small security-analyst portfolio, alongside
[IOC Enrichment API](https://github.com/dhananjaydave/ioc-enrichment-api),
[Phishing Triage Bot](https://github.com/dhananjaydave/phishing-triage-bot),
[File Analyser](https://github.com/dhananjaydave/file-analyser), and
[SOC Alert Triage Assistant](https://github.com/dhananjaydave/alert-triage-assistant).
Unlike those four, this one requires a real login - it's meant for one
person's actual day-to-day case tracking, not a public demo.

## How it works

- **`auth.py`** - bcrypt-hashed single admin password, signed session
  cookies (`itsdangerous`, no server-side session store needed),
  per-IP login rate limiting. `HttpOnly` + `Secure` + `SameSite=Strict`
  cookies plus FastAPI's own JSON-body validation together cover CSRF -
  a cross-site form POST can't produce a request the API will accept.
- **`db.py`** - SQLite: incidents (the tickets), incident_updates (the
  note/audit trail), sops (per-alert-type runbook steps - editable
  without a code change, and doubles as the source of the alert-type
  dropdown when creating a ticket, so nothing gets typed twice).
- **`seed_sops.py`** - generic, industry-standard SOPs for 6 common
  alert types, seeded on first run so the tracker is useful immediately.
  Never overwrites a real SOP you've already entered.
- **`telegram_bot.py`** - private, allowlisted-chat-id bot (same pattern
  as the Amul/Phishing bots elsewhere in this portfolio). `/tickets`,
  `/close <id> <note>`, `/escalate <id> <reason>`, `/falsepositive <id>
  <reason>`, `/note <id> <text>`, `/sop <alert type>`, `/summary [hours]`.
  Also pings on every dashboard login and on login-rate-limit triggers
  (deduplicated to once per window, not once per blocked attempt).
- **`scheduler.py`** - periodic check for tickets with no update in N
  hours (default 24), pings Telegram so nothing silently sits forgotten.
- **`mitre_knowledge.py`** - curated practical reference for 21 MITRE
  ATT&CK techniques most likely to show up in real alerts - what it looks
  like, common false positives, what to do next. Written as triage notes,
  not a copy of MITRE's own site.
- **`security_feed.py`** - aggregates 4 free, no-API-key security news
  RSS feeds (Krebs, The Hacker News, BleepingComputer, SANS ISC), cached
  30 minutes so the dashboard isn't hammering them on every load.
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
  your own false-positive rate trend) - same idea as the metrics
  dashboard in the Alert Triage Assistant, applied to real tracked cases
- MITRE-tactic-ordered timeline view across related tickets
