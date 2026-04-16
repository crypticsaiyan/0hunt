# 0hunt
### Ohita Hackathon 2026 Submission

An autonomous security agent that monitors the internet 24/7 for zero-day vulnerabilities and delivers structured, actionable Slack alerts — before your team even wakes up.

---

## The Problem

The most dangerous window in cybersecurity is the gap between when a zero-day is announced and when a patch is applied. Security teams are flooded with noise. By the time a real threat is manually triaged, PoC exploit code is already circulating on GitHub.

0hunt closes that gap automatically.

---

## How It Works

Every 30 minutes, the engine runs a full intelligence cycle:

```
[1] INGEST    → Poll HackerNews + Twitter for CVE keywords
[2] TRIAGE    → LLM determines if it's a real threat, extracts CVE ID
[3] DEEP DIVE → GitHub (PoCs), StackExchange, HN+Dev.to (community),
                Wikipedia (scope), Tavily (patch intel), NVD (CVSS) — all parallel
[4] SCORE     → Compute Exploit Probability Index (EPI)
[5] ALERT     → Push structured Slack briefing if EPI ≥ 4
[6] LOG       → Mark CVE as seen to prevent duplicate alerts
[7] DIGEST    → Daily summary posted to Slack every 24 hours
```

---

## Exploit Probability Index (EPI)

The EPI is a 1–10 composite score that answers: *"How likely is this to be exploited in the wild, right now?"*

| Component | Points |
|---|---|
| Base severity (LLM + NVD assessment) | 1–10 |
| Public PoC found on GitHub | +1.5 (1 repo) / +2.5 (2+ repos) |
| Community activity (HN/Dev.to) | +0.5 |

**Severity tiers:**
- `CRITICAL` (EPI ≥ 8.5) → `<!channel>` ping
- `HIGH` (EPI ≥ 6.5) → Standard alert
- `MEDIUM` (EPI ≥ 4.0) → Advisory alert

CVEs with EPI < 4 are silently logged and skipped — no noise.

---

## Ohita Integrations

| Integration | Role |
|---|---|
| **HackerNews** | Primary CVE/zero-day signal detection |
| **Twitter/X** | Real-time security community chatter |
| **GitHub** | PoC exploit code discovery |
| **StackExchange** | Technical workarounds (security.stackexchange.com) |
| **Dev.to** | Security community articles (filtered by CVE/software) |
| **Wikipedia** | Impact scope — what is the affected software, who uses it |
| **Tavily (Search)** | Patch intel — official fix, vendor advisories, patch version |
| **Slack** | Structured alert delivery |

**Total: 8 Ohita integrations**

---

## Setup

```bash
# 1. Install
npm install

# 2. Configure
cp .env.example .env
# Fill in your keys

# 3. Run
npm start
```

**.env**
```
OHITA_KEY=your_ohita_api_key
OPENROUTER_API_KEY=your_openrouter_key    # free models, no cost
SLACK_TOKEN=xoxb-your-slack-bot-token
SLACK_CHANNEL_ID=C0XXXXXXXXX
```

The engine uses free LLM models via OpenRouter — no paid AI API required.

To get your Slack token: create a Slack app at api.slack.com with `chat:write` scope, install it to your workspace, and store the `xoxb-` token in Ohita via `POST /v1/credentials/slack`.

---

## Why 0hunt Wins

1. **Runs forever** — 30-minute polling loop, crash recovery, daily digest proves it
2. **8 Ohita integrations** — maximum use of the platform across the full intel pipeline
3. **Novel scoring** — EPI gives a concrete 1–10 number, not vague labels
4. **Solves a real problem** — every security and DevOps team faces this gap
5. **Zero paid dependencies** — free LLMs, free NVD API, free Ohita tier
