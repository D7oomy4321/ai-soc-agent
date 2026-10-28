# AI SOC Agents

An AI-assisted Security Operations Center (SOC) that triages security alerts with an LLM agent, enriches them with threat intelligence, and keeps a **human analyst in the loop** for every response action.

> Graduation project — Computer Engineering, Yanbu Industrial College (YIC).

## How it works

```
 Alert (phishing email, URL, log event)
            │
            ▼
 ┌────────────────────┐  POST /triage   ┌──────────────────────────────┐
 │  Platform          │───────────────▶ │  Backend (Python FastAPI)    │
 │  web/index.html    │                 │  Triage Agent                │
 │                    │◀─────────────── │   ├─ VirusTotal URL lookup   │
 └────────────────────┘  JSON report    │   └─ Gemini (structured out) │
            │                           └──────────────────────────────┘
   Analyst approves / rejects
            │ POST /decision
            ▼
     SQLite audit log (soc_audit.db)
```

**Key principle:** the agent only *proposes* actions. Nothing is executed without an analyst decision, and every decision is recorded.

## Repository layout

| Path | Contents |
|------|----------|
| `backend/` | Python FastAPI server: Triage Agent (Gemini + VirusTotal), SQLite audit log. See `backend/README.md`. |
| `web/index.html` | Project landing page + multi-page SOC platform (dashboard, incidents, analyze, approvals, audit log, reports, agents, knowledge base, integrations). Single self-contained file. |
| `prototype-n8n/` | The first prototype, built as n8n workflows (kept for reference). |
| `docs/` | Report, screenshots, demo video. |

## Quick start

```bash
cd backend
python -m venv venv
venv\Scripts\activate             # macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
copy .env.example .env            # put your GEMINI_API_KEY and VT_API_KEY in .env
uvicorn main:app --reload
```

Open **http://127.0.0.1:8000/app** — the platform connects to the backend automatically.

| URL | What it is |
|-----|------------|
| http://127.0.0.1:8000/app | the platform |
| http://127.0.0.1:8000/docs | try the API |
| http://127.0.0.1:8000/audit/view | analyst decision log |

## Agents

| Agent | Role | Status |
|-------|------|--------|
| Triage | Classifies type, severity, confidence; proposes actions with impact and rollback | **Running** |
| Orchestrator | Routes alerts to agents and merges results | Planned |
| Threat intelligence | Checks IPs, domains, hashes, CVEs | Planned |
| Forensic investigation | Rebuilds the timeline and scope from logs | Planned |
| Case history | Finds similar past incidents | Planned |
| Report writer | Writes the report and cites NCA controls (RAG) | Planned |

## Security notes
- No API keys in the repository: secrets live only in `backend/.env` (git-ignored).
- Alert text is treated as untrusted data (prompt-injection rules).
- Actions are proposals; approved actions are recorded, execution is simulated.
- Parameterized SQL queries; HTML escaping on the audit page.
- CORS is open (`*`) for local use; add authentication before any public deployment.

## Tech stack
Python · FastAPI · Google Gemini (Flash, with model fallback) · VirusTotal API v3 · SQLite · HTML/CSS/JavaScript · n8n (first prototype)

## Author
Albraa Yaseen Makhdoom — [LinkedIn](https://www.linkedin.com/in/albraa-makhdoom-9b1722347)
