"""
app.py
------
CyberSafe phishing-detection API.

Combines two signals into one risk score (0-100):
  1. An ML text classifier (TF-IDF + Logistic Regression) trained in train_model.py
  2. Transparent heuristics (suspicious URLs, urgency language, credential requests,
     lookalike domains, sender/display mismatch...) that also produce the human-readable
     reasons shown in the extension.

Run:
    pip install -r requirements.txt
    python train_model.py        # creates model.pkl
    uvicorn app:app --reload --port 8000
"""

import os
import re
from typing import List, Optional

import joblib
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

MODEL_PATH = "model.pkl"

app = FastAPI(title="CyberSafe API", version="1.0.0")

# The extension runs on a chrome-extension:// origin. For local development we
# allow all origins; in production restrict this to your extension's ID.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Load the trained ML model once at startup -----------------------------
_model = None
if os.path.exists(MODEL_PATH):
    _model = joblib.load(MODEL_PATH)


# ---- Request / response shapes ---------------------------------------------
class EmailInput(BaseModel):
    text: str
    subject: Optional[str] = ""
    sender: Optional[str] = ""          # raw "From" header, e.g. 'PayPal <no-reply@x.ru>'
    sender_domain: Optional[str] = ""   # the *real* domain the mail came from, if known


class Reason(BaseModel):
    label: str
    detail: str
    weight: int          # how much this nudged the score up (0-100 scale)
    severity: str        # "high" | "medium" | "low"


class Prediction(BaseModel):
    risk: int                 # final blended score, 0-100
    verdict: str              # "safe" | "caution" | "phishing"
    ml_probability: float     # raw model phishing probability, 0-1
    heuristic_score: int      # heuristic-only score, 0-100
    reasons: List[Reason]
    model_loaded: bool


# ---- Heuristics ------------------------------------------------------------
URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
IP_URL_RE = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}", re.IGNORECASE)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}
SUSPICIOUS_TLDS = {
    ".ru", ".cc", ".click", ".top", ".xyz", ".info", ".biz", ".online",
    ".support", ".app", ".live", ".work", ".zip", ".country", ".gq", ".tk",
}
URGENCY_WORDS = [
    "urgent", "immediately", "within 24 hours", "within 12 hours", "right now",
    "act now", "final notice", "last warning", "expires today", "expires soon",
    "before it's too late", "limited time", "asap", "do not delay",
]
THREAT_WORDS = [
    "suspended", "locked", "disabled", "deleted", "terminated", "closed",
    "unauthorized", "unusual activity", "security alert", "compromised",
    "permanently", "deactivated", "restricted",
]
CREDENTIAL_WORDS = [
    "verify your account", "confirm your password", "update your billing",
    "re-enter your password", "log in to confirm", "validate your account",
    "confirm your identity", "enter your pin", "one-time passcode", "otp",
    "social security", "ssn", "card number", "cvv", "bank details",
    "routing number", "wallet", "seed phrase",
]
GIFT_CARD_WORDS = ["gift card", "gift cards", "wire transfer", "bitcoin", "crypto", "btc"]


def _add(reasons, label, detail, weight, severity):
    reasons.append(Reason(label=label, detail=detail, weight=weight, severity=severity))


def heuristic_analysis(data: EmailInput):
    """Return (score_0_100, [Reason, ...]) from transparent rules."""
    blob = f"{data.subject}\n{data.text}".lower()
    reasons: List[Reason] = []
    score = 0

    urls = URL_RE.findall(data.text) + URL_RE.findall(data.subject)

    # IP-address links
    if IP_URL_RE.search(data.text):
        score += 25
        _add(reasons, "Link uses a raw IP address",
             "Legitimate companies link to named domains, not numeric IP addresses.",
             25, "high")

    # URL shorteners hide the true destination
    if any(s in blob for s in SHORTENERS):
        score += 18
        _add(reasons, "Shortened link",
             "A URL shortener hides where the link actually goes.", 18, "medium")

    # Suspicious TLDs in any link
    flagged_tlds = []
    for u in urls:
        host = re.sub(r"https?://", "", u).split("/")[0].lower()
        for tld in SUSPICIOUS_TLDS:
            if host.endswith(tld) and tld not in flagged_tlds:
                flagged_tlds.append(tld)
    if flagged_tlds:
        score += 15
        _add(reasons, "Unusual link domain",
             f"Links end in {', '.join(flagged_tlds)}, often used in scams.",
             15, "medium")

    # Lookalike domains: digits-for-letters or hyphenated brand names
    brand_hints = ["paypa1", "amaz0n", "g00gle", "micros0ft", "app1e", "netf1ix"]
    if any(b in blob for b in brand_hints) or re.search(r"(secure|verify|account|login)-[a-z0-9]+\.", blob):
        score += 20
        _add(reasons, "Lookalike / spoofed domain",
             "The link imitates a real brand using altered spelling or extra words.",
             20, "high")

    # Urgency pressure
    hit_urgency = [w for w in URGENCY_WORDS if w in blob]
    if hit_urgency:
        score += 12
        _add(reasons, "Creates false urgency",
             f"Pressure phrases like \u201c{hit_urgency[0]}\u201d push you to act without thinking.",
             12, "medium")

    # Threats / account-loss language
    hit_threat = [w for w in THREAT_WORDS if w in blob]
    if hit_threat:
        score += 12
        _add(reasons, "Threatens account loss",
             f"Mentions your account being {hit_threat[0]} to scare you into clicking.",
             12, "medium")

    # Requests for credentials / sensitive data
    hit_cred = [w for w in CREDENTIAL_WORDS if w in blob]
    if hit_cred:
        score += 22
        _add(reasons, "Asks for sensitive information",
             "Requests credentials or personal data that real services never ask for by email.",
             22, "high")

    # Gift cards / wire transfers / crypto (classic payment scams)
    if any(w in blob for w in GIFT_CARD_WORDS):
        score += 15
        _add(reasons, "Unusual payment request",
             "Asks for gift cards, wire transfers, or crypto, a common scam payout method.",
             15, "high")

    # Sender display name vs actual domain mismatch
    if data.sender and data.sender_domain:
        m = re.search(r"<([^>]+)>", data.sender)
        addr = m.group(1) if m else data.sender
        addr_domain = addr.split("@")[-1].strip().lower()
        if addr_domain and data.sender_domain.lower() not in addr_domain and addr_domain not in data.sender_domain.lower():
            score += 18
            _add(reasons, "Sender mismatch",
                 f"Display sender doesn't match the sending domain ({addr_domain}).",
                 18, "high")

    # Generic greeting
    if re.search(r"\b(dear customer|dear user|dear account holder|valued customer)\b", blob):
        score += 6
        _add(reasons, "Generic greeting",
             "Doesn't address you by name, typical of mass phishing.", 6, "low")

    return min(score, 100), reasons


def verdict_from(risk: int) -> str:
    if risk >= 65:
        return "phishing"
    if risk >= 35:
        return "caution"
    return "safe"


# ---- Routes ----------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": _model is not None}


@app.post("/predict", response_model=Prediction)
def predict(data: EmailInput):
    combined = f"{data.subject}\n{data.text}".strip()

    # 1) ML signal
    if _model is not None and combined:
        ml_prob = float(_model.predict_proba([combined])[0][1])
    else:
        ml_prob = 0.0

    # 2) Heuristic signal
    heur_score, reasons = heuristic_analysis(data)

    # 3) Blend: ML leads, heuristics adjust. Both on a 0-1 scale.
    blended = 0.65 * ml_prob + 0.35 * (heur_score / 100.0)
    risk = int(round(min(blended, 1.0) * 100))

    # Sort reasons by impact so the UI shows the strongest signals first.
    reasons.sort(key=lambda r: r.weight, reverse=True)

    return Prediction(
        risk=risk,
        verdict=verdict_from(risk),
        ml_probability=round(ml_prob, 3),
        heuristic_score=heur_score,
        reasons=reasons,
        model_loaded=_model is not None,
    )
