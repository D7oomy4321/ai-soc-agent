"""
main.py - خادم AI SOC Agents (FastAPI)

نقاط الخادم:
  GET  /             فحص الحالة (الموديل، VirusTotal)
  POST /triage       تحليل تنبيه بوكيل الفرز
  POST /decision     حفظ قرار المحلل (موافقة / رفض)
  GET  /audit        سجل القرارات JSON
  GET  /audit/view   سجل القرارات كجدول
  GET  /app          المنصة نفسها (index.html)
  GET  /docs         صفحة تجربة الطلبات (تلقائية من FastAPI)

التشغيل:  uvicorn main:app --reload
"""
from html import escape
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

import db
from agents.triage import run_triage
from config import FALLBACK_MODELS, MODEL, VT_API_KEY

app = FastAPI(title="AI SOC Agents API")

# يسمح للمنصة (GitHub Pages أو ملف محلي) بالاتصال بالخادم
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

db.init_db()
BASE_DIR = Path(__file__).parent


# ---------- ما يرسله الموقع ----------
class Alert(BaseModel):
    alert: str
    language: str | None = None


class Decision(BaseModel):
    incident_id: str
    action: str
    target: str | None = ""
    decision: str
    analyst_note: str | None = ""
    decided_at: str | None = ""
    severity: str | None = ""


# ---------- النقاط ----------
@app.get("/")
def health():
    return {"status": "ok", "service": "AI SOC Agents API",
            "model": MODEL, "fallback_models": FALLBACK_MODELS,
            "virustotal": bool(VT_API_KEY)}


@app.post("/triage")
def triage(body: Alert):
    try:
        return run_triage(body.alert)
    except Exception as e:
        print("TRIAGE ERROR:", e)
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/decision")
def decision(body: Decision):
    audit_id = db.save_decision(body.model_dump())
    print("DECISION SAVED:", body.incident_id, body.decision, body.action)
    return {"ok": True, "audit_id": audit_id}


@app.get("/audit")
def audit(limit: int = 100):
    return db.list_decisions(limit)


@app.get("/audit/view", response_class=HTMLResponse)
def audit_view():
    rows = db.list_decisions(1000)
    color = {"approved": "#3fd69a", "rejected": "#ff5f6d"}
    # escape يمنع تنفيذ أي HTML مكتوب في الملاحظات (حماية من XSS)
    trs = "".join(
        f"<tr><td>{r['id']}</td><td>{escape(r['incident_id'] or '')}</td>"
        f"<td>{escape(r['action'] or '')}</td><td dir='ltr'>{escape(r['target'] or '')}</td>"
        f"<td style='color:{color.get((r['decision'] or '').lower(), '#dde6f4')};font-weight:600'>{escape(r['decision'] or '')}</td>"
        f"<td>{escape(r['severity'] or '')}</td><td>{escape(r['analyst_note'] or '')}</td>"
        f"<td dir='ltr'>{escape((r['received_at'] or '')[:19].replace('T', ' '))}</td></tr>"
        for r in rows
    )
    return f"""<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>SOC Audit Log</title><style>
body{{font-family:Tahoma,sans-serif;background:#0a1220;color:#dde6f4;padding:24px;margin:0}}
h1{{font-size:1.3rem}} .wrap{{overflow-x:auto}} table{{width:100%;border-collapse:collapse;font-size:.9rem}}
th,td{{padding:10px;border-bottom:1px solid #1f2f4b;text-align:start}}
th{{background:#15223a;color:#8797b6}} tr:hover td{{background:#0f192b}}
</style></head><body><h1>سجل قرارات المحللين (Audit Log) — {len(rows)} قرار</h1>
<div class="wrap"><table><tr><th>#</th><th>الحادثة</th><th>الإجراء</th><th>الهدف</th><th>القرار</th>
<th>الخطورة</th><th>ملاحظة المحلل</th><th>الوقت (UTC)</th></tr>{trs}</table></div></body></html>"""


@app.get("/app")
def site():
    # يبحث عن المنصة بجانب main.py، أو في ../web/index.html (ترتيب الريبو على GitHub)
    for page in (BASE_DIR / "index.html", BASE_DIR.parent / "web" / "index.html"):
        if page.exists():
            return FileResponse(page)
    raise HTTPException(status_code=404, detail="index.html not found next to main.py or in ../web/")
