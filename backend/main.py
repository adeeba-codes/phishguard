"""
PhishGuard API v3.0 - CORRECTED VERSION
Production-ready FastAPI backend with proper error handling
"""

from supabase import create_client, Client
import os
import re
import base64
import urllib.parse
from collections import Counter, defaultdict
from typing import Optional
import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ValidationError
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

try:
    from google import genai as google_genai
except Exception:
    google_genai = None

# ─────────────────────────────────────────────────────────────
# Load ENV
# ─────────────────────────────────────────────────────────────

load_dotenv()
print("=" * 60)
print("Loading Environment Variables")
print("GEMINI_API_KEY:", bool(os.getenv("GEMINI_API_KEY")))
print("HF_API_KEY:", bool(os.getenv("HF_API_KEY")))
print("VIRUSTOTAL_API_KEY:", bool(os.getenv("VIRUSTOTAL_API_KEY")))
print("SUPABASE_URL:", bool(os.getenv("SUPABASE_URL")))
print("SUPABASE_SERVICE_KEY:", bool(os.getenv("SUPABASE_SERVICE_KEY")))
print("=" * 60)

# ─────────────────────────────────────────────────────────────
# App Setup
# ─────────────────────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="PhishGuard API",
    version="3.0.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json"
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ─────────────────────────────────────────────────────────────
# CORS - Now configurable
# ─────────────────────────────────────────────────────────────

ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173"
).split(",")

@app.options("/{full_path:path}")
async def options_handler(full_path: str):
    """Handle CORS preflight requests"""
    return {"message": "ok"}

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

print(f"✓ CORS configured for: {ALLOWED_ORIGINS}")

# ─────────────────────────────────────────────────────────────
# Environment Variables
# ─────────────────────────────────────────────────────────────

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
HF_API_KEY = os.getenv("HF_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

HF_MODEL_URL = "https://router.huggingface.co/hf-inference/models/ealvaradob/bert-finetuned-phishing"

# ─────────────────────────────────────────────────────────────
# Supabase Connection
# ─────────────────────────────────────────────────────────────

supabase: Optional[Client] = None

if SUPABASE_URL and SUPABASE_SERVICE_KEY:
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
        print("✓ Supabase connected")
    except Exception as e:
        print(f"✗ Supabase connection failed: {str(e)}")
        supabase = None
else:
    print("✗ Supabase credentials missing - database features disabled")

# ─────────────────────────────────────────────────────────────
# Request/Response Models
# ─────────────────────────────────────────────────────────────

class URLRequest(BaseModel):
    url: str
    user_id: Optional[str] = None
    device_id: Optional[str] = "anonymous"

class EmailRequest(BaseModel):
    email_text: str
    subject: Optional[str] = ""
    user_id: Optional[str] = None
    device_id: Optional[str] = "anonymous"

class AnalysisResult(BaseModel):
    label: str
    confidence: float
    red_flags: list[str]
    explanation: str
    virustotal_detections: Optional[int] = None

class HealthResponse(BaseModel):
    status: str
    database: bool
    gemini: bool
    huggingface: bool
    virustotal: bool

# ─────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────

SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".work", ".loan", ".click"}

SUSPICIOUS_EMAIL_KEYWORDS = [
    "verify your account",
    "click here immediately",
    "account suspended",
    "confirm your password",
    "bank account",
    "urgent",
    "limited time",
]

# ─────────────────────────────────────────────────────────────
# Feature Extraction Functions
# ─────────────────────────────────────────────────────────────

def extract_url_features(url: str) -> list[str]:
    flags = []
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        full = url.lower()

        if "@" in url:
            flags.append("Contains @ symbol")
        if re.match(r"\d{1,3}(\.\d{1,3}){3}", hostname):
            flags.append("Uses raw IP address")
        if len(url) > 75:
            flags.append("Very long URL")
        if not full.startswith("https"):
            flags.append("No HTTPS encryption")
        if any(full.endswith(tld) for tld in SUSPICIOUS_TLDS):
            flags.append("Suspicious domain extension")
        if re.search(r"(login|verify|secure|account|confirm)", full):
            flags.append("Sensitive keywords detected")
        if "//" in path:
            flags.append("Double slash redirect trick")

    except Exception as e:
        flags.append(f"Malformed URL: {str(e)[:50]}")

    return flags

def extract_email_features(text: str, subject: str) -> list[str]:
    flags = []
    combined = (subject + " " + text).lower()

    for kw in SUSPICIOUS_EMAIL_KEYWORDS:
        if kw in combined:
            flags.append(f"Suspicious phrase: {kw}")

    if re.search(r"(password|bank|credit card)", combined):
        flags.append("Requests sensitive information")

    links = re.findall(r"https?://\S+", text)
    if len(links) > 3:
        flags.append("Too many links")

    return flags

# ─────────────────────────────────────────────────────────────
# AI Classification
# ─────────────────────────────────────────────────────────────

def rule_based(text: str) -> tuple[str, float]:
    """Fallback rule-based classification"""
    triggers = ["login", "verify", "bank", "secure", "password", "click"]
    score = sum(1 for t in triggers if t in text.lower())
    prob = min(0.9, 0.2 + score * 0.12)
    label = "PHISHING" if prob > 0.5 else "SAFE"
    return label, round(prob if label == "PHISHING" else 1 - prob, 3)

async def hf_classify(text: str) -> tuple[str, float]:
    """HuggingFace model classification with fallback"""
    if not HF_API_KEY:
        return rule_based(text)

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(
                HF_MODEL_URL,
                headers={"Authorization": f"Bearer {HF_API_KEY}"},
                json={"inputs": text},
            )

        if response.status_code != 200:
            print(f"HF API error: {response.status_code}")
            return rule_based(text)

        data = response.json()
        scores = data[0] if isinstance(data, list) else data.get("scores", [])

        phish_score = next(
            (x["score"] for x in scores if "PHISH" in x["label"].upper()),
            0.5,
        )

        label = "PHISHING" if phish_score > 0.5 else "SAFE"
        conf = phish_score if label == "PHISHING" else 1 - phish_score

        return label, round(conf, 3)

    except Exception as e:
        print(f"HF classification failed: {str(e)}")
        return rule_based(text)

# ─────────────────────────────────────────────────────────────
# Gemini Explanation
# ─────────────────────────────────────────────────────────────
def _fallback_explanation(label: str, flags: list[str]) -> str:
    if label == "PHISHING":
        if flags:
            return (
                f"This content appears to be phishing because it contains "
                f"{', '.join(flags)}. Exercise caution before interacting with it."
            )
        return (
            "This content appears suspicious based on the security analysis."
        )

    return (
        "No major phishing indicators were detected. "
        "However, always verify the source before trusting any links or attachments."
    )

async def gemini_explain(input_text: str, label: str, flags: list[str]):

    if not GEMINI_API_KEY:
        print("Gemini API key missing")
        return _fallback_explanation(label, flags)

    if google_genai is None:
        print("google-genai package not installed")
        return _fallback_explanation(label, flags)

    flag_text = (
    "\n".join(f"- {flag}" for flag in flags)
    if flags
    else "- None"
)

    prompt = f"""
You are a cybersecurity analyst.

Verdict: {label}

Input:
{input_text}

Detected indicators:
{flag_text}

Explain in exactly two short sentences why this content was classified this way.
Use simple English.
"""

    try:

        client = google_genai.Client(
            api_key=GEMINI_API_KEY
        )

        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
        )

        if (
            response
            and hasattr(response, "text")
            and response.text
        ):
            print("Gemini Success")
            return response.text.strip()

        print("Gemini returned empty response")

    except Exception as e:

        print("=" * 60)
        print("GEMINI ERROR")
        print(type(e).__name__)
        print(e)
        print("=" * 60)

    return _fallback_explanation(label, flags)
# ─────────────────────────────────────────────────────────────
# VirusTotal Check
# ─────────────────────────────────────────────────────────────

async def virustotal_check(url: str) -> Optional[int]:
    """Check URL reputation on VirusTotal"""
    if not VIRUSTOTAL_API_KEY:
        return None

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
            )

        if response.status_code != 200:
            return None

        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        return stats.get("malicious", 0) + stats.get("suspicious", 0)

    except Exception as e:
        print(f"VirusTotal error: {str(e)}")
        return None

# ─────────────────────────────────────────────────────────────
# Database Functions
# ─────────────────────────────────────────────────────────────

async def save_scan(
    result: AnalysisResult,
    input_type: str,
    input_preview: str,
    user_id: Optional[str] = None,
    device_id: Optional[str] = None,
) -> bool:
    """Save scan to database, return success status"""
    if not supabase:
        print("⚠️ Database unavailable - scan not saved")
        return False

    try:
        supabase.table("scan_history").insert({
            "user_id": user_id,
            "device_id": device_id,
            "input_type": input_type,
            "input_preview": input_preview[:80],
            "label": result.label,
            "confidence": result.confidence,
            "red_flags": result.red_flags,
            "explanation": result.explanation[:300],
        }).execute()
        return True

    except Exception as e:
        print(f"✗ Database save failed: {str(e)}")
        return False

# ─────────────────────────────────────────────────────────────
# Routes - Health & Debug
# ─────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"message": "PhishGuard API v3.0 running"}

@app.get("/health", response_model=HealthResponse)
def health():
    return HealthResponse(
        status="ok",
        database=bool(supabase),
        gemini=bool(GEMINI_API_KEY),
        huggingface=bool(HF_API_KEY),
        virustotal=bool(VIRUSTOTAL_API_KEY),
    )
@app.get("/history/{user_id}")
async def get_history(user_id: str):
    if not supabase:
        raise HTTPException(503, "Database not available")
    try:
        result = supabase.table("scan_history")\
            .select("id, input_type, input_preview, label, confidence, red_flags, scanned_at")\
            .eq("user_id", user_id)\
            .order("scanned_at", desc=True)\
            .limit(50)\
            .execute()
        return { "scans": result.data or [] }
    except Exception as e:
        print(f"History fetch error: {e}")
        raise HTTPException(500, "Failed to load history")

@app.get("/debug")
async def debug():
    return {
        "status": "running",
        "allowed_origins": ALLOWED_ORIGINS,
        "database": bool(supabase),
        "gemini": bool(GEMINI_API_KEY),
        "huggingface": bool(HF_API_KEY),
        "virustotal": bool(VIRUSTOTAL_API_KEY),
    }
@app.get("/test-gemini")
async def test_gemini():

    if not GEMINI_API_KEY:
        return {
            "success": False,
            "error": "Gemini API key missing"
        }

    try:

        client = google_genai.Client(
            api_key=GEMINI_API_KEY
        )

        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents="Reply only with: Gemini is working."
        )

        return {
            "success": True,
            "response": response.text
        }

    except Exception as e:

        return {
            "success": False,
            "error": str(e),
            "type": type(e).__name__
        }

# ─────────────────────────────────────────────────────────────
# Routes - Analysis
# ─────────────────────────────────────────────────────────────

@app.post("/analyze-url", response_model=AnalysisResult)
@limiter.limit("30/minute")
async def analyze_url(request: Request, body: URLRequest):
    """Analyze URL for phishing threats"""
    url = body.url.strip()

    if not url:
        raise HTTPException(400, "URL cannot be empty")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    flags = extract_url_features(url)
    label, conf = await hf_classify(url)

    # Boost confidence if multiple flags present
    if label == "PHISHING" and len(flags) >= 3:
        conf = min(0.99, conf + 0.08)

    explanation = await gemini_explain(url, label, flags)
    vt = await virustotal_check(url)

    result = AnalysisResult(
        label=label,
        confidence=min(0.99, round(conf, 3)),
        red_flags=flags,
        explanation=explanation,
        virustotal_detections=vt,
    )

    # Save to database (non-blocking)
    await save_scan(
        result=result,
        input_type="url",
        input_preview=url,
        user_id=body.user_id,
        device_id=body.device_id,
    )

    return result

@app.post("/analyze-email", response_model=AnalysisResult)
@limiter.limit("20/minute")
async def analyze_email(request: Request, body: EmailRequest):
    """Analyze email for phishing threats"""
    text = body.email_text.strip()

    if not text:
        raise HTTPException(400, "Email content cannot be empty")

    combined = (body.subject + " " + text)
    flags = extract_email_features(text, body.subject)
    label, conf = await hf_classify(combined)

    explanation = await gemini_explain(text[:300], label, flags)

    result = AnalysisResult(
        label=label,
        confidence=min(0.99, round(conf, 3)),
        red_flags=flags,
        explanation=explanation,
    )

    # Save to database (non-blocking)
    await save_scan(
        result=result,
        input_type="email",
        input_preview=body.subject,
        user_id=body.user_id,
        device_id=body.device_id,
    )

    return result

# ─────────────────────────────────────────────────────────────
# Routes - Dashboard
# ─────────────────────────────────────────────────────────────

@app.get("/dashboard/{user_id}")
async def get_dashboard(user_id: str):
    """Get user dashboard statistics"""
    if not supabase:
        raise HTTPException(503, "Database unavailable")

    try:
        scans = supabase.table("scan_history") \
            .select("*") \
            .eq("user_id", user_id) \
            .order("scanned_at", desc=True) \
            .limit(200) \
            .execute()

        rows = scans.data or []

        daily = defaultdict(lambda: {"total": 0, "phishing": 0})
        flag_counter = Counter()

        for row in rows:
            day = row["scanned_at"][:10]
            daily[day]["total"] += 1

            if row["label"] == "PHISHING":
                daily[day]["phishing"] += 1

            for flag in (row.get("red_flags") or []):
                flag_counter[flag] += 1

        total = len(rows)
        phishing = sum(1 for r in rows if r["label"] == "PHISHING")
        safe = total - phishing

        recent_scans = [
            {
                "id": row["id"],
                "input_preview": row["input_preview"],
                "label": row["label"],
                "confidence": row["confidence"],
                "input_type": row["input_type"],
                "scanned_at": row["scanned_at"],
            }
            for row in rows[:15]
        ]

        return {
            "total": total,
            "phishing": phishing,
            "safe": safe,
            "daily_scans": [
                {"date": d, "total": v["total"], "phishing": v["phishing"]}
                for d, v in sorted(daily.items())[-30:]
            ],
            "top_flags": [
                {"flag": f, "count": c}
                for f, c in flag_counter.most_common(5)
            ],
            "recent_scans": recent_scans,
        }

    except Exception as e:
        print(f"✗ Dashboard error: {str(e)}")
        raise HTTPException(500, "Dashboard data unavailable")

# ─────────────────────────────────────────────────────────────
# Startup Event
# ─────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup_event():
    print("\n" + "=" * 60)
    print("PhishGuard API Started")
    print("=" * 60)
    print(f"Supabase Connected : {supabase is not None}")
    print(f"Gemini Key Present : {bool(GEMINI_API_KEY)}")
    print(f"HuggingFace Key : {bool(HF_API_KEY)}")
    print(f"VirusTotal Key : {bool(VIRUSTOTAL_API_KEY)}")
    print(f"Allowed Origins : {ALLOWED_ORIGINS}")
    print("=" * 60 + "\n")
