import pickle
import re
import os
import httpx
import urllib.parse
import base64
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.requests import Request

# Optional Gemini import
try:
    from google import genai
except Exception:
    genai = None

# ------------------ APP SETUP ------------------

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="PhishGuard API", version="2.0.0")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------ ENV ------------------

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
HF_API_KEY = os.getenv("HF_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

HF_MODEL_URL = "https://api-inference.huggingface.co/models/ealvaradob/bert-finetuned-phishing"

# ------------------ MODELS ------------------

class URLRequest(BaseModel):
    url: str

class EmailRequest(BaseModel):
    email_text: str
    subject: Optional[str] = ""

class AnalysisResult(BaseModel):
    label: str
    confidence: float
    red_flags: list[str]
    explanation: str
    virustotal_detections: Optional[int] = None

# ------------------ CONSTANTS ------------------

SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".work", ".loan"}

# ------------------ FEATURE EXTRACTION ------------------

def extract_url_features(url: str) -> list[str]:
    flags = []

    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        full = url.lower()

        if "@" in url:
            flags.append("Contains '@' symbol — used to obscure true destination")

        if re.match(r"\d{1,3}(\.\d{1,3}){3}", hostname):
            flags.append("IP address used instead of domain name")

        if any(full.endswith(tld) for tld in SUSPICIOUS_TLDS):
            flags.append("Suspicious top-level domain")

        if "https" not in full:
            flags.append("No HTTPS — connection is not encrypted")

        if re.search(r"(login|verify|secure|account|update|confirm)", full):
            flags.append("Sensitive action keyword in URL")

        if "//" in path:
            flags.append("Double slashes in path — redirect trick")

    except Exception:
        flags.append("Malformed URL")

    return flags

# ------------------ HUMANIZE FLAGS ------------------

def humanize_flags(flags: list[str]) -> list[str]:
    clean = []

    for f in flags:
        f = f.lower()

        if "https" in f:
            clean.append("it does not use a secure connection")
        elif "@" in f:
            clean.append("it hides the real destination using an '@' symbol")
        elif "brand" in f:
            clean.append("it imitates a trusted brand")
        elif "keyword" in f:
            clean.append("it uses suspicious words like login or verify")
        elif "ip" in f:
            clean.append("it uses an IP address instead of a domain")
        else:
            clean.append("it shows suspicious patterns")

    return clean

# ------------------ HUGGING FACE ------------------

async def hf_classify(text: str):
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
            return rule_based(text)

        data = resp.json()[0]
        phish_score = next(x["score"] for x in data if "PHISH" in x["label"].upper())

        label = "PHISHING" if phish_score > 0.5 else "SAFE"
        conf = phish_score if label == "PHISHING" else 1 - phish_score

        return label, round(conf, 3)

    except:
        return rule_based(text)

# ------------------ RULE FALLBACK ------------------

def rule_based(text: str):
    score = sum(k in text.lower() for k in ["login", "verify", "secure", "@", "bank"])
    prob = min(0.9, 0.2 + score * 0.15)

    label = "PHISHING" if prob > 0.5 else "SAFE"
    return label, prob

# ------------------ GEMINI ------------------
import google.generativeai as genai

genai.configure(api_key=GEMINI_API_KEY)
async def gemini_explain(input_text, label, flags):
    if not GEMINI_API_KEY:
        clean = humanize_flags(flags[:2])
        return "This URL appears to be a phishing attempt because " + " and ".join(clean) + "."

    try:
        model = genai.GenerativeModel("gemini-1.5-flash")

        prompt = f"""
        This URL is classified as {label}.
        Input: {input_text}
        Signals: {', '.join(humanize_flags(flags[:3]))}

        Explain in 2 simple sentences why this is {label.lower()}.
        No bullet points.
        """

        res = model.generate_content(prompt)

        text = res.text.replace("\n", " ").replace("•", "").replace("- ", "")
        return text.strip()

    except Exception as e:
        print("GEMINI ERROR:", e)
        return f"Classified as {label} based on detected patterns."

# ------------------ VIRUSTOTAL ------------------

async def virustotal_check(url: str):
    if not VIRUSTOTAL_API_KEY:
        return None

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY}
            )

        data = resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        return stats.get("malicious", 0) + stats.get("suspicious", 0)

    except:
        return None

# ------------------ ROUTES ------------------

@app.get("/")
def root():
    return {"message": "PhishGuard API running"}

@app.post("/analyze-url", response_model=AnalysisResult)
@limiter.limit("30/minute")
async def analyze_url(request: Request, body: URLRequest):

    url = body.url.strip()

    if not url:
        raise HTTPException(400, "URL cannot be empty")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    flags = extract_url_features(url)
    label, conf = await hf_classify(url)

    # Rule override
    if len(flags) >= 2:
        label = "PHISHING"

    if len(flags) >= 3:
        conf = max(conf, 0.8)

    explanation = await gemini_explain(url, label, flags)
    vt = await virustotal_check(url)

    return AnalysisResult(
        label=label,
        confidence=round(conf, 3),
        red_flags=flags,
        explanation=explanation,
        virustotal_detections=vt
    )
