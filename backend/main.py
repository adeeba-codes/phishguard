import pickle, numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.requests import Request
import re
import os
import httpx
import urllib.parse
from typing import Optional

# ─────────────────────────────────────────────
#  App setup
# ─────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="PhishGuard API", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Tighten to your Netlify URL in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
#  API Keys  (set these as Render env vars)
# ─────────────────────────────────────────────
GEMINI_API_KEY    = os.getenv("GEMINI_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")   # optional
HF_API_KEY        = os.getenv("HF_API_KEY", "")           # HuggingFace token

HF_MODEL_URL = (
    "https://api-inference.huggingface.co/models/ealvaradob/bert-finetuned-phishing"
)
GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-1.5-flash:generateContent"
)


# ─────────────────────────────────────────────
#  Request / Response schemas
# ─────────────────────────────────────────────
class URLRequest(BaseModel):
    url: str

class EmailRequest(BaseModel):
    email_text: str
    subject: Optional[str] = ""

class AnalysisResult(BaseModel):
    label: str                    # "PHISHING" | "SAFE"
    confidence: float             # 0.0 – 1.0
    red_flags: list[str]
    explanation: str
    virustotal_detections: Optional[int] = None


# ─────────────────────────────────────────────
#  Feature extractors
# ─────────────────────────────────────────────
SUSPICIOUS_KEYWORDS_EMAIL = [
    "verify your account", "click here immediately", "your account will be suspended",
    "confirm your password", "unusual activity", "update your payment",
    "you have won", "claim your prize", "limited time offer",
    "act now", "urgent action required", "bank account", "social security",
]

SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".work", ".loan"}
TRUSTED_DOMAINS  = {"google.com", "github.com", "microsoft.com", "apple.com", "amazon.com"}


def extract_url_features(url: str) -> dict:
    flags = []
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        path     = parsed.path or ""
        full     = url.lower()

        if "@" in url:
            flags.append("Contains '@' symbol — used to obscure true destination")
        if re.match(r"\d{1,3}(\.\d{1,3}){3}", hostname):
            flags.append("IP address used instead of domain name")
        if full.count("-") > 3:
            flags.append("Excessive hyphens in domain — common in spoofed domains")
        if len(url) > 75:
            flags.append(f"Unusually long URL ({len(url)} chars)")
        if full.count(".") > 4:
            flags.append("Deep subdomain nesting — often used to fake legitimacy")
        if any(full.endswith(tld) for tld in SUSPICIOUS_TLDS):
            flags.append("Suspicious top-level domain")
        if "https" not in full:
            flags.append("No HTTPS — connection is not encrypted")
        for brand in ["paypal", "apple", "microsoft", "google", "amazon", "netflix"]:
            if brand in hostname and not hostname.endswith(f"{brand}.com"):
                flags.append(f"Brand name '{brand}' in subdomain — possible spoofing")
        if re.search(r"(login|signin|account|secure|verify|update|confirm)", full):
            flags.append("Sensitive action keyword in URL")
        if "//" in path:
            flags.append("Double slashes in path — redirect trick")
    except Exception:
        flags.append("Malformed URL structure")
    return {"flags": flags}


def extract_email_features(text: str, subject: str) -> dict:
    flags = []
    combined = (subject + " " + text).lower()

    for kw in SUSPICIOUS_KEYWORDS_EMAIL:
        if kw in combined:
            flags.append(f"Urgency/manipulation phrase: \"{kw}\"")

    links = re.findall(r"https?://\S+", text)
    if len(links) > 3:
        flags.append(f"Contains {len(links)} links — phishing emails often load with links")

    if re.search(r"dear (customer|user|member|valued client)", combined):
        flags.append("Generic salutation — legitimate orgs use your name")

    if re.search(r"\b(password|ssn|credit card|social security|bank account)\b", combined):
        flags.append("Requests sensitive personal information")

    if re.search(r"(expires? in \d+|within \d+ hours?|limited time)", combined):
        flags.append("Artificial time pressure — classic social engineering")

    attachments = re.findall(r"\.(exe|zip|doc[xm]?|xls[xm]?|pdf)", combined)
    if attachments:
        flags.append(f"References attachment type(s): {', '.join(set(attachments))}")

    return {"flags": flags, "links": links}


# ─────────────────────────────────────────────
#  HuggingFace inference
# ─────────────────────────────────────────────
async def hf_classify(text: str) -> tuple[str, float]:
    """Returns (label, confidence). Falls back to rule-based on error."""
    if not HF_API_KEY:
        return _rule_based_fallback(text)
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                HF_MODEL_URL,
                headers={"Authorization": f"Bearer {HF_API_KEY}"},
                json={"inputs": text},
            )
            data = resp.json()
            # HF returns [[{label, score}, ...]]
            if isinstance(data, list) and isinstance(data[0], list):
                scores = {item["label"].upper(): item["score"] for item in data[0]}
                phish_score = scores.get("PHISHING", scores.get("LABEL_1", 0.5))
                label = "PHISHING" if phish_score > 0.5 else "SAFE"
                conf  = phish_score if label == "PHISHING" else 1 - phish_score
                return label, round(conf, 3)
    except Exception:
        pass
    return _rule_based_fallback(text)

def rf_classify(url: str) -> tuple[str, float]:
    """Use local Random Forest if available."""
    if not RF_MODEL:
        return _rule_based_fallback(url)
    feats = extract_url_features_numeric(url)   # returns list of 12 numbers
    prob  = RF_MODEL.predict_proba([feats])[0][1]
    label = "PHISHING" if prob > 0.5 else "SAFE"
    return label, round(float(prob if label == "PHISHING" else 1 - prob), 3)

def _rule_based_fallback(text: str) -> tuple[str, float]:
    """Simple heuristic when HF is unavailable."""
    score = 0
    t = text.lower()
    triggers = ["phish", "free", "click", "verify", "account", "bank", "password",
                "urgent", "@", "login", "confirm", "secure", "update"]
    for tr in triggers:
        if tr in t:
            score += 1
    prob = min(0.95, 0.1 + score * 0.09)
    label = "PHISHING" if prob > 0.5 else "SAFE"
    return label, round(prob if label == "PHISHING" else 1 - prob, 3)


# ─────────────────────────────────────────────
#  Gemini explanation
# ─────────────────────────────────────────────
def humanize_flags(flags):
    mapped = []

    for f in flags:
        f = f.lower()

        if "no https" in f:
            mapped.append("it does not use a secure (HTTPS) connection")
        elif "@" in f:
            mapped.append("it uses an '@' symbol to hide the real destination")
        elif "brand name" in f:
            mapped.append("it imitates a trusted brand name in the domain")
        elif "keyword" in f:
            mapped.append("it uses suspicious words like login or verify")
        elif "ip address" in f:
            mapped.append("it uses an IP address instead of a proper domain")
        else:
            mapped.append("it shows suspicious patterns")

    return mapped
async def gemini_explain(input_text: str, label: str, flags: list[str]) -> str:
    
    # --- Fallback (no API key) ---
    if not GEMINI_API_KEY:
        if label == "PHISHING":
            clean_flags = humanize_flags(flags[:2])
            return (
                "This URL appears to be a phishing attempt because "
                + " and ".join(clean_flags)
                + ". These are common tricks used to deceive users."
            )
        else:
            return "This URL does not show strong signs of phishing."

    # --- Gemini prompt ---
    clean_flags = humanize_flags(flags[:3])
    flags_text = ", ".join(clean_flags) if clean_flags else "no major indicators"

    prompt = (
    f"You are a cybersecurity expert.\n\n"
    f"The system classified the following as '{label}'.\n\n"
    f"Input: {input_text[:300]}\n\n"
    f"Key suspicious behaviors: {flags_text}\n\n"
    f"Explain in 2 short sentences why this is {label.lower()}.\n"
    f"Write naturally like a human explaining risk.\n"
    f"Do NOT repeat phrases like 'this contains'.\n"
    f"Do NOT use bullet points or lists.\n"
    f"Write in a single paragraph."
)

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                f"{GEMINI_URL}?key={GEMINI_API_KEY}",
                json={"contents": [{"parts": [{"text": prompt}]}]},
            )
            data = resp.json()
            text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
# Clean raw flag phrases in Gemini output
            clean_flags = humanize_flags(flags[:2])
            for raw, clean in zip(flags[:2], clean_flags):
             text = text.replace(raw, clean)
            # cleanup output
            text = text.replace("\n", " ")
            text = text.replace("- ", "")
            text = text.replace("•", "")

            return text

    except Exception:
        return f"Classified as {label} based on detected patterns."
# ─────────────────────────────────────────────
#  VirusTotal check (optional)
# ─────────────────────────────────────────────
async def virustotal_check(url: str) -> Optional[int]:
    if not VIRUSTOTAL_API_KEY:
        return None
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
            )
            if resp.status_code == 200:
                stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
                return stats.get("malicious", 0) + stats.get("suspicious", 0)
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────
#  Endpoints
# ─────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "service": "PhishGuard API"}


@app.post("/analyze-url", response_model=AnalysisResult)
@limiter.limit("30/minute")
@app.post("/analyze-url", response_model=AnalysisResult)
@limiter.limit("30/minute")
async def analyze_url(request: Request, body: URLRequest):
    url = body.url.strip()

    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # --- Rule-based features ---
    features = extract_url_features(url)
    red_flags = features["flags"]
    risk_score = len(red_flags)

    # --- AI prediction ---
    ai_label, conf = await hf_classify(url)

    # --- FINAL DECISION (IMPORTANT) ---
    if risk_score >= 2:
        label = "PHISHING"
    else:
        label = ai_label

    # --- Confidence adjustment ---
    if risk_score >= 3:
        conf = max(conf, 0.8)

    # --- Explanation (match decision) ---
    if label == "PHISHING":
        explanation = (
            "This URL appears to be a phishing attempt because it contains "
            + ", ".join(red_flags[:2])
            + ". These are common indicators of malicious links."
        )
    else:
        explanation = "No strong phishing indicators detected."

    # --- Optional VirusTotal ---
    vt_detections = await virustotal_check(url)

    return AnalysisResult(
        label=label,
        confidence=round(conf, 3),
        red_flags=red_flags,
        explanation=explanation,
        virustotal_detections=vt_detections,
    )

@app.post("/analyze-email", response_model=AnalysisResult)
@limiter.limit("20/minute")
async def analyze_email(request: Request, body: EmailRequest):
    text = body.email_text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Email text cannot be empty")

    features    = extract_email_features(text, body.subject or "")
    label, conf = await hf_classify(f"{body.subject} {text}")
    explanation = await gemini_explain(text[:400], label, features["flags"])

    if len(features["flags"]) >= 3 and label == "PHISHING":
        conf = min(0.99, conf + 0.08)

    return AnalysisResult(
        label=label,
        confidence=round(conf, 3),
        red_flags=features["flags"],
        explanation=explanation,
    )
try:
    with open("model.pkl", "rb") as f:
        RF_MODEL = pickle.load(f)
    USE_LOCAL_MODEL = True
except FileNotFoundError:
    RF_MODEL = None
    USE_LOCAL_MODEL = False