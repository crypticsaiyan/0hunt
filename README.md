# 0hunt

![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?style=flat&logo=typescript&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-20+-339933?style=flat&logo=node.js&logoColor=white)
![Ohita](https://img.shields.io/badge/Ohita-8%20integrations-FF6B35?style=flat)
![License](https://img.shields.io/badge/license-MIT-green?style=flat)

**Autonomous zero-day vulnerability intelligence agent.** Monitors HackerNews, GitHub, StackExchange, Dev.to, Wikipedia, and more every 30 minutes — scores threats with a novel EPI algorithm — delivers structured Slack alerts before your team even wakes up.

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
[5] ALERT     → Push structured Slack briefing if EPI ≥ MIN_EPI
[6] LOG       → Mark CVE as seen to prevent duplicate alerts
[7] DIGEST    → Daily summary posted to Slack every 24 hours
```

---

## Exploit Probability Index (EPI)

The EPI is a 1–10 composite score that answers: *"How likely is this CVE to be exploited in the wild, right now?"*

| Component | Points |
|---|---|
| Base severity (LLM + NVD assessment) | 1–10 |
| Public PoC found on GitHub | +1.5 (1 repo) / +2.5 (2+ repos) |
| Community activity (HN / Dev.to) | +0.5 |

**Severity tiers:**

| EPI | Severity | Slack behavior |
|---|---|---|
| ≥ 8.5 | `CRITICAL` | `<!channel>` ping |
| ≥ 6.5 | `HIGH` | Standard alert |
| ≥ 4.0 | `MEDIUM` | Advisory alert |
| < MIN_EPI | — | Silently skipped |

---

## Ohita Integrations

| Integration | Role |
|---|---|
| **HackerNews** | Primary CVE/zero-day signal detection |
| **Twitter/X** | Real-time security community chatter |
| **GitHub** | PoC exploit code discovery |
| **StackExchange** | Technical workarounds (security.stackexchange.com) |
| **Dev.to** | Security community articles filtered by CVE/software |
| **Wikipedia** | Impact scope — what the software is and who uses it |
| **Tavily (Search)** | Patch intel — official fix, vendor advisories, patch version |
| **Slack** | Structured alert delivery with daily digest |

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
```bash
OHITA_KEY=your_ohita_api_key
OPENROUTER_API_KEY=your_openrouter_key    # free models — no cost

# Slack (BYOK via Ohita)
SLACK_TOKEN=xoxb-your-slack-bot-token
SLACK_CHANNEL_ID=C0XXXXXXXXX

# Personalization (optional)
WATCH_KEYWORDS=nginx,apache,chrome        # only alert on these — blank = watch everything
MIN_EPI=4                                 # minimum EPI to trigger alert (1–10)
```

> Uses free LLM models via OpenRouter — no paid AI API required.  
> To get your Slack token: create an app at [api.slack.com](https://api.slack.com) with `chat:write` scope, then store the `xoxb-` token in Ohita via `POST /v1/credentials/slack`.

---

## Personalization

0hunt can be scoped to your specific stack:

- **`WATCH_KEYWORDS`** — comma-separated list of software/terms to monitor. Set `nginx,apache,openssl` to only receive alerts affecting your infrastructure. Leave blank to monitor everything.
- **`MIN_EPI`** — minimum EPI threshold. Set `7` for HIGH+ only. Set `4` (default) for all meaningful threats.

---

## License

[MIT](./LICENSE)
