"""
config.py - الإعدادات والمفاتيح
كل القيم تُقرأ من ملف .env (لا تُكتب المفاتيح داخل الكود أبدًا).
"""
import os

from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

# ---------- Gemini ----------
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
MODEL = os.getenv("GEMINI_MODEL", "gemini-3.7-flash")
# موديلات احتياطية مفصولة بفاصلة، تُجرَّب بالترتيب إذا كان الأساسي مشغولًا
FALLBACK_MODELS = [m.strip() for m in os.getenv("GEMINI_FALLBACK_MODEL", "").split(",") if m.strip()]
GEMINI_TIMEOUT_MS = int(os.getenv("GEMINI_TIMEOUT_MS", "20000"))  # حد أقصى لكل محاولة

client = genai.Client(
    api_key=GEMINI_API_KEY,
    http_options=types.HttpOptions(timeout=GEMINI_TIMEOUT_MS),
)

# ---------- VirusTotal ----------
VT_API_KEY = os.getenv("VT_API_KEY")

# ---------- قاعدة البيانات ----------
DB_PATH = os.getenv("DB_PATH", "soc_audit.db")
