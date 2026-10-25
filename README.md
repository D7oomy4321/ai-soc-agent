# AI SOC Agents

An AI-assisted Security Operations Center (SOC) that triages security alerts with LLM agents, enriches them with threat intelligence, and keeps a **human analyst in the loop** for every response action.

> Graduation project — Computer Engineering, Yanbu Industrial College (YIC).

## How it works

```
 Alert (phishing email, URL, log event)
            │
            ▼
 ┌──────────────────────┐      ┌───────────────────────┐
 │  Web console         │ POST │  n8n: soc-triage      │
 │  (web/index.html)    │─────▶│  AI agent (Gemini)    │──▶ VT URL Lookup (VirusTotal)
 └──────────────────────┘      └───────────────────────┘
            ▲                              │ structured JSON verdict
            │◀─────────────────────────────┘ (severity, IOCs, proposed actions)
            │
   Analyst approves / rejects
            │ POST
            ▼
 ┌──────────────────────┐
 │  n8n: soc-decision   │──▶ Google Sheets audit log
 └──────────────────────┘
```

**Key principle:** the agent only *proposes* actions. Nothing is executed until an analyst approves it through the console, and every decision is written to an audit log.

## Repository layout

| Path | Contents |
|------|----------|
| `web/index.html` | Project landing page + multi-page SOC console (dashboard, incidents, analyze, approvals, audit log, reports, agents, knowledge base, integrations). Single self-contained file. |
| `n8n-workflows/soc-decision.json` | Receives analyst decisions and appends them to the audit log sheet. |
| `n8n-workflows/vt-url-lookup.json` | Sub-workflow: URL → VirusTotal v3 lookup → `clean / suspicious / malicious / unknown` verdict. |
| `n8n-workflows/soc-triage.json` | Main triage workflow: webhook → *Message an Agent* (bilingual AR/EN structured output: summary, type, MITRE, severity, confidence, reasons, missing info, proposed actions with impact & rollback, controls) → respond. |
| `docs/` | Report, screenshots, demo video. |

## Setup

### 1. n8n
1. Import each file in `n8n-workflows/` (**Workflows → Import from File**).
2. Create credentials and select them in the nodes:
   - **Google Gemini API** — for the triage agent.
   - **Header Auth** — name `x-apikey`, value = your VirusTotal API key (used by *VT URL Lookup*).
   - **Google Sheets OAuth2** — for the audit log.
3. In *soc-triage*, create an n8n Agent (Gemini model, with *VT URL Lookup* as a tool) and select it in **Message an Agent** (replaces `YOUR_AGENT_ID`).
4. In *soc-decision*, replace `YOUR_GOOGLE_SHEET_ID` with your sheet. The sheet needs the columns:
   `incident_id, action, target, decision, analyst_note, decided_at, severity`.
5. Activate the workflows and copy the **Production** webhook URLs.

### 2. Web console
1. Open `web/index.html` locally in a browser (download it — do not run it inside a sandboxed preview, outbound calls are blocked there).
2. Go to **Integrations**, paste the two webhook URLs (`…/webhook/soc-triage` and `…/webhook/soc-decision`), then **Save** and **Test connection**.
   The URLs are stored only in your browser (`localStorage`), never in the file.

## Security notes
- No API keys are stored in this repository. All secrets live in n8n credentials.
- The webhooks use `allowedOrigins: *` for the demo; restrict them (origin + auth header) before any real deployment.

## Tech stack
n8n · Google Gemini (Flash) · VirusTotal API v3 · Google Sheets · HTML/CSS/JavaScript

## Author
Albraa Yaseen Makhdoom — [LinkedIn](https://www.linkedin.com/in/albraa-makhdoom-9b1722347)
