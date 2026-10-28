# AI SOC Agents — Backend

Python FastAPI server that runs the **Triage Agent** (Gemini + VirusTotal) and records analyst decisions in SQLite.

## Folder layout

```
soc-backend/
├── main.py              # FastAPI app and endpoints (start here)
├── config.py            # reads .env: API keys, models, timeouts
├── db.py                # SQLite audit log (analyst decisions)
├── agents/
│   └── triage.py        # Triage Agent: output schema, prompt, Gemini call with fallback
├── tools/
│   └── virustotal.py    # read-only URL reputation lookup
├── index.html           # the platform, served at /app
├── requirements.txt     # Python packages
├── .env.example         # template for your .env (keys)
└── .gitignore           # keeps .env, venv and the database out of Git
```

## How a request flows

```
Platform ──POST /triage──▶ main.py ──▶ agents/triage.py
                                          ├─▶ tools/virustotal.py  (check URLs)
                                          └─▶ Gemini (structured JSON, model fallback)
Platform ◀── triage report JSON ──────────┘

Platform ──POST /decision──▶ main.py ──▶ db.py ──▶ soc_audit.db
```

## Run

```bash
python -m venv venv
venv\Scripts\activate            # Windows  (macOS/Linux: source venv/bin/activate)
pip install -r requirements.txt
copy .env.example .env           # then put your real keys in .env
uvicorn main:app --reload
```

| URL | What it is |
|-----|------------|
| http://127.0.0.1:8000 | health check (model, VirusTotal on/off) |
| http://127.0.0.1:8000/app | the platform (connects automatically) |
| http://127.0.0.1:8000/docs | try the endpoints |
| http://127.0.0.1:8000/audit/view | analyst decision log |

## Environment variables (.env)

| Name | Required | Meaning |
|------|----------|---------|
| `GEMINI_API_KEY` | yes | from aistudio.google.com/apikey |
| `VT_API_KEY` | recommended | from virustotal.com → profile → API key |
| `GEMINI_MODEL` | no | main model (default `gemini-3.7-flash`) |
| `GEMINI_FALLBACK_MODEL` | no | comma-separated backup models, tried in order when the main one is busy |
| `GEMINI_TIMEOUT_MS` | no | max time per Gemini attempt (default 20000) |

## Security notes
- Keys live only in `.env`, which is never committed.
- The agent only **proposes** actions; nothing is executed. Decisions are recorded, execution is simulated.
- Alert text is treated as untrusted data (prompt-injection rules in the system prompt).
- SQL uses parameterized queries; the audit page escapes HTML (XSS).
