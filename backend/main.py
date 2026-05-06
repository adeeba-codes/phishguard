"""
PhishGuard API v2.1
FastAPI backend for phishing URL and email detection.
Fixes applied:
  - Single safe google.genai import (try/except)
  - /analyze-email route added
  - /health endpoint added
  - Rule override logic fixed (less aggressive)
  - Bare except: replaced with except Exception
  - Email feature extractor added
"""

import re
import os
import base64
import urllib.parse
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.requests import Request
from dotenv import load_dotenv   # ← ADD

load_dotenv()                    # ← ADD — reads your .env file

# Safe single import of google-genai
try:
    from google import genai as google_genai
except Exception:
    google_genai = None

# ─────────────────────────────────────────────────────────────────────────────
#  App & middleware
# ─────────────────────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="PhishGuard API", version="2.1.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://phishguard-adeeba.netlify.app",
        "http://localhost:5173",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)
# ─────────────────────────────────────────────────────────────────────────────
#  Environment variables
# ─────────────────────────────────────────────────────────────────────────────
GEMINI_API_KEY     = os.getenv("GEMINI_API_KEY", "")
HF_API_KEY         = os.getenv("HF_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

HF_MODEL_URL = (
   "https://router.huggingface.co/hf-inference/models/ealvaradob/bert-finetuned-phishing"

)

# ─────────────────────────────────────────────────────────────────────────────
#  Request / response schemas
# ─────────────────────────────────────────────────────────────────────────────
class URLRequest(BaseModel):
    url: str

class EmailRequest(BaseModel):
    email_text: str
    subject: Optional[str] = ""

class AnalysisResult(BaseModel):
    label: str                          # "PHISHING" | "SAFE"
    confidence: float                   # 0.0 – 1.0
    red_flags: list[str]
    explanation: str
    virustotal_detections: Optional[int] = None

# ─────────────────────────────────────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".top", ".work", ".loan", ".click", ".link",
}

SUSPICIOUS_EMAIL_KEYWORDS = [
    "verify your account", "click here immediately",
    "account will be suspended", "confirm your password",
    "unusual activity", "update your payment",
    "act now", "urgent action required",
    "bank account", "limited time offer",
    "you have won", "claim your prize",
]

# ─────────────────────────────────────────────────────────────────────────────
#  URL feature extractor
# ─────────────────────────────────────────────────────────────────────────────
def extract_url_features(url: str) -> list[str]:
    flags = []
    try:
        parsed   = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        path     = parsed.path     or ""
        full     = url.lower()

        if "@" in url:
            flags.append("Contains '@' symbol — used to obscure the true destination")

        if re.match(r"\d{1,3}(\.\d{1,3}){3}", hostname):
            flags.append("IP address used instead of a domain name")

        if full.count("-") > 3:
            flags.append("Excessive hyphens in the domain — common in spoofed domains")

        if len(url) > 75:
            flags.append(f"Unusually long URL ({len(url)} characters)")

        if full.count(".") > 4:
            flags.append("Deep subdomain nesting — often used to fake legitimacy")

        if any(full.endswith(tld) for tld in SUSPICIOUS_TLDS):
            flags.append("Suspicious top-level domain")

        if not full.startswith("https"):
            flags.append("No HTTPS — connection is not encrypted")

        for brand in ["paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook"]:
            if brand in hostname and not hostname.endswith(f"{brand}.com"):
                flags.append(f"Brand name '{brand}' in subdomain — possible spoofing")

        if re.search(r"(login|signin|account|secure|verify|update|confirm)", full):
            flags.append("Sensitive action keyword in URL")

        if "//" in path:
            flags.append("Double slashes in path — redirect trick")

    except Exception as e:
        print(f"URL feature extraction error: {e}")
        flags.append("Malformed URL structure")

    return flags

# ─────────────────────────────────────────────────────────────────────────────
#  Email feature extractor
# ─────────────────────────────────────────────────────────────────────────────
def extract_email_features(text: str, subject: str) -> list[str]:
    flags = []
    combined = (subject + " " + text).lower()

    for kw in SUSPICIOUS_EMAIL_KEYWORDS:
        if kw in combined:
            flags.append(f'Urgency/manipulation phrase detected: "{kw}"')

    if re.search(r"dear (customer|user|member|valued client)", combined):
        flags.append("Generic salutation — legitimate organisations use your real name")

    if re.search(r"\b(password|credit card|bank account|social security|ssn)\b", combined):
        flags.append("Requests sensitive personal information")

    if re.search(r"(expires? in \d+|within \d+ hours?|limited time)", combined):
        flags.append("Artificial time pressure — classic social engineering tactic")

    links = re.findall(r"https?://\S+", text)
    if len(links) > 3:
        flags.append(f"Contains {len(links)} links — phishing emails often overload with links")

    attachments = re.findall(r"\.(exe|zip|doc[xm]?|xls[xm]?|pdf)", combined)
    if attachments:
        flags.append(f"References attachment type(s): {', '.join(set(attachments))}")

    return flags

# ─────────────────────────────────────────────────────────────────────────────
#  Plain-English flag descriptions (for fallback explanation)
# ─────────────────────────────────────────────────────────────────────────────
def humanize_flags(flags: list[str]) -> list[str]:
    clean = []
    for f in flags:
        fl = f.lower()
        if "https" in fl:
            clean.append("it does not use a secure HTTPS connection")
        elif "@" in fl:
            clean.append("it uses an '@' symbol to hide the real destination")
        elif "brand" in fl or "spoof" in fl:
            clean.append("it imitates a trusted brand name")
        elif "keyword" in fl:
            clean.append("it contains suspicious action words like 'verify' or 'login'")
        elif "ip address" in fl:
            clean.append("it uses a raw IP address instead of a domain")
        elif "subdomain" in fl:
            clean.append("it uses deep subdomain nesting to appear legitimate")
        elif "urgency" in fl or "manipulation" in fl:
            clean.append("it uses urgency and fear to pressure the user")
        elif "sensitive" in fl:
            clean.append("it asks for sensitive personal information")
        else:
            clean.append("it shows suspicious structural patterns")
    return clean

# ─────────────────────────────────────────────────────────────────────────────
#  HuggingFace BERT classifier
# ─────────────────────────────────────────────────────────────────────────────
async def hf_classify(text: str) -> tuple[str, float]:
    """
    Calls HuggingFace ealvaradob/bert-finetuned-phishing.
    Falls back to rule_based() if the API is unavailable or key is missing.
    """
    if not HF_API_KEY:
        return rule_based(text)

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                HF_MODEL_URL,
                headers={"Authorization": f"Bearer {HF_API_KEY}"},
                json={"inputs": text},
            )

        if resp.status_code != 200:
            print(f"HF API returned {resp.status_code}")
            return rule_based(text)

        # HF returns [[{label, score}, {label, score}]]
        data = resp.json()
        if not data or not isinstance(data[0], list):
            return rule_based(text)

        scores     = data[0]
        phish_score = next(
            (x["score"] for x in scores if "PHISH" in x["label"].upper()),
            0.5
        )
        label = "PHISHING" if phish_score > 0.5 else "SAFE"
        conf  = phish_score if label == "PHISHING" else (1 - phish_score)
        return label, round(conf, 3)

    except Exception as e:
        print(f"HF classify error: {e}")
        return rule_based(text)

# ─────────────────────────────────────────────────────────────────────────────
#  Rule-based fallback scorer
# ─────────────────────────────────────────────────────────────────────────────
def rule_based(text: str) -> tuple[str, float]:
    """
    Simple heuristic used when HuggingFace is unavailable.
    Returns a conservative confidence score.
    """
    triggers = [
        "login", "verify", "secure", "@", "bank",
        "password", "account", "click", "urgent", "free",
    ]
    score = sum(1 for kw in triggers if kw in text.lower())
    prob  = min(0.85, 0.2 + score * 0.12)
    label = "PHISHING" if prob > 0.5 else "SAFE"
    return label, round(prob if label == "PHISHING" else 1 - prob, 3)

# ─────────────────────────────────────────────────────────────────────────────
#  Gemini Flash explanation
# ─────────────────────────────────────────────────────────────────────────────
GEMINI_MODELS = [
    "gemini-2.0-flash-lite",  # fastest + cheapest, try first
    "gemini-2.0-flash",       # fallback
    "gemini-2.5-flash",       # last resort
]

async def gemini_explain(input_text: str, label: str, flags: list[str]) -> str:
    if not GEMINI_API_KEY or google_genai is None:
        return _fallback_explanation(label, flags)

    flag_text = "\n".join(f"- {f}" for f in flags) if flags else "- No specific flags"
    prompt = (
        f"You are a cybersecurity expert explaining threats to a non-technical user.\n\n"
        f"This content was classified as: {label}\n"
        f"Input analysed: {input_text[:300]}\n\n"
        f"Detected red flags:\n{flag_text}\n\n"
        f"Write exactly 2 sentences explaining why this is {label.lower()}. "
        f"Be specific about the red flags. "
        f"Use plain English — no bullet points, no markdown, no jargon."
    )

    try:
        client = google_genai.Client(api_key=GEMINI_API_KEY)
        for model in GEMINI_MODELS:
            try:
                response = client.models.generate_content(
                    model=model,
                    contents=prompt,
                )
                text = response.text.strip().replace("\n", " ")
                print(f"Gemini OK using {model}")
                return text
            except Exception as e:
                print(f"Gemini {model} failed: {e}")
                continue   # try next model
    except Exception as e:
        print(f"Gemini client error: {e}")

    return _fallback_explanation(label, flags)


def _fallback_explanation(label: str, flags: list[str]) -> str:
    """Used when all Gemini models fail or quota is exhausted."""
    human = humanize_flags(flags[:2])
    if label == "PHISHING":
        joined = " and ".join(human) if human else "suspicious patterns"
        return f"This appears to be a phishing attempt because {joined}. Do not enter any personal information."
    return "No significant phishing indicators were found. This content appears to be legitimate."

# ─────────────────────────────────────────────────────────────────────────────
#  VirusTotal check (optional — 500 req/day free)
# ─────────────────────────────────────────────────────────────────────────────
async def virustotal_check(url: str) -> Optional[int]:
    if not VIRUSTOTAL_API_KEY:
        return None
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
            )
        if resp.status_code != 200:
            return None
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return stats.get("malicious", 0) + stats.get("suspicious", 0)
    except Exception as e:
        print(f"VirusTotal error: {e}")
        return None

# ─────────────────────────────────────────────────────────────────────────────
#  Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"message": "PhishGuard API v2.1 — visit /docs for the Swagger UI"}


@app.get("/health")
def health():
    """
    Used by cron-job.org to keep the Render free-tier service awake.
    Ping this every 14 minutes to prevent cold starts.
    """
    return {"status": "ok", "service": "PhishGuard API"}


@app.post("/analyze-url", response_model=AnalysisResult)
@limiter.limit("30/minute")
async def analyze_url(request: Request, body: URLRequest):
    url = body.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    # Prepend scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    flags         = extract_url_features(url)
    label, conf   = await hf_classify(url)

    # Confidence boost — only when BERT already agrees it's phishing
    # (avoids over-flagging safe URLs with incidental keywords)
    if label == "PHISHING" and len(flags) >= 3:
        conf = min(0.99, conf + 0.08)

    # Hard override only when flag count is very high (4+)
    if len(flags) >= 4:
        label = "PHISHING"
        conf  = max(conf, 0.85)

    explanation   = await gemini_explain(url, label, flags)
    vt_detections = await virustotal_check(url)

    return AnalysisResult(
        label=label,
        confidence=round(conf, 3),
        red_flags=flags,
        explanation=explanation,
        virustotal_detections=vt_detections,
    )


@app.post("/analyze-email", response_model=AnalysisResult)
@limiter.limit("20/minute")
async def analyze_email(request: Request, body: EmailRequest):
    text = body.email_text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Email text cannot be empty")

    combined_input = f"{body.subject or ''} {text}"
    flags          = extract_email_features(text, body.subject or "")
    label, conf    = await hf_classify(combined_input)

    # Confidence boost when BERT agrees
    if label == "PHISHING" and len(flags) >= 3:
        conf = min(0.99, conf + 0.07)

    # Hard override only at very high flag count
    if len(flags) >= 4:
        label = "PHISHING"
        conf  = max(conf, 0.82)

    explanation = await gemini_explain(text[:300], label, flags)

    return AnalysisResult(
        label=label,
        confidence=round(conf, 3),
        red_flags=flags,
        explanation=explanation,
        virustotal_detections=None,   # VT URL-only feature
    )
