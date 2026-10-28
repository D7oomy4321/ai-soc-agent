"""
tools/virustotal.py - أداة فحص سمعة الروابط في VirusTotal
الأداة "قراءة فقط": تسأل VirusTotal عن تقرير موجود، ولا تفتح الرابط ولا ترسله للفحص.
"""
import base64
import re

import httpx

from config import VT_API_KEY

# يلتقط الروابط الكاملة التي تبدأ بـ http:// أو https://
URL_RE = re.compile(r"https?://[^\s|\"'<>]+", re.IGNORECASE)
MAX_URLS = 4  # الحد المجاني في VirusTotal: 4 طلبات بالدقيقة


def extract_urls(text: str) -> list[str]:
    """يستخرج الروابط من نص التنبيه بدون تكرار (أول 4 فقط)."""
    urls = (u.rstrip(".,;)") for u in URL_RE.findall(text))
    return list(dict.fromkeys(urls))[:MAX_URLS]


def vt_lookup(url: str) -> dict:
    """يرجع حكم VirusTotal على الرابط: clean / suspicious / malicious / unknown."""
    if not VT_API_KEY:
        return {"url": url, "verdict": "unknown", "note": "VirusTotal key not configured. Not checked."}

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        r = httpx.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": VT_API_KEY},
            timeout=15,
        )
    except httpx.HTTPError as e:
        return {"url": url, "verdict": "unknown", "note": f"VirusTotal unreachable: {e}"}

    if r.status_code == 404:
        return {"url": url, "found": False, "verdict": "unknown",
                "note": "VirusTotal has no report for this URL. It was NOT scanned."}
    if r.status_code != 200:
        return {"url": url, "found": False, "verdict": "unknown",
                "note": f"VirusTotal lookup failed (HTTP {r.status_code})."}

    a = r.json()["data"]["attributes"]
    s = a.get("last_analysis_stats", {})
    m, su = s.get("malicious", 0), s.get("suspicious", 0)

    # نفس قواعد مسار n8n القديم
    if m >= 3:
        verdict = "malicious"
    elif m >= 1 or su >= 2:
        verdict = "suspicious"
    else:
        verdict = "clean"

    flagged = [f"{name}: {res.get('result')}"
               for name, res in a.get("last_analysis_results", {}).items()
               if res.get("category") == "malicious"][:5]

    return {"url": url, "found": True, "verdict": verdict,
            "malicious": m, "suspicious": su,
            "harmless": s.get("harmless", 0), "undetected": s.get("undetected", 0),
            "flagged_by": flagged}


def enrich(text: str) -> list[dict]:
    """يفحص كل الروابط الموجودة في التنبيه."""
    return [vt_lookup(u) for u in extract_urls(text)]
