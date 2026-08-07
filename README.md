# CyberSafe — Phishing Detection Extension

A Chrome extension (Manifest V3) that flags phishing emails in real time, paired
with a Python ML backend. It gives you a 0–100 risk score, a plain-English
explanation of *why*, and rotating security tips.

```
  ┌─────────────────────────┐        ┌──────────────────────────┐
  │  Chrome Extension (MV3)  │        │   Python Backend (API)    │
  │                          │        │                           │
  │  popup.html/.css/.js  ───┼──────► │  FastAPI  /predict        │
  │  background.js (worker)  │  HTTP  │   ├─ ML model (TF-IDF +   │
  │  content.js (Gmail)   ───┼──────► │   │   Logistic Reg.)      │
  │                          │ JSON   │   └─ heuristics + reasons │
  └─────────────────────────┘        └──────────────────────────┘
```

The score blends two signals: an **ML text classifier** (65%) and transparent
**heuristics** (35%) such as lookalike domains, urgency language, and requests
for credentials. The heuristics also produce the human-readable reasons.

---

## 1. Run the backend

```bash
cd backend
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python train_model.py        # creates model.pkl (ships with a tiny demo dataset)
uvicorn app:app --reload --port 8000
```

Check it's up: open http://localhost:8000/health — you should see
`{"status":"ok","model_loaded":true}`.

## 2. Load the extension

1. Open `chrome://extensions`
2. Turn on **Developer mode** (top right)
3. Click **Load unpacked** and select the `extension/` folder
4. Pin CyberSafe from the puzzle-piece menu

## 3. Use it

- **In Gmail:** open any email. The toolbar badge turns green (OK), amber (!),
  or red (⚠) automatically. Click the icon for the full score and reasons.
- **Paste check:** click the icon → **Check text** → paste any message → **Analyze**.
  This works anywhere, no Gmail needed — great for demos.

---

## Make the model actually good

The bundled `sample_data.csv` has only 50 rows — enough to prove the pipeline,
not to be accurate. Replace it with a real labeled corpus (same `text,label`
columns, where `label` = 1 is phishing, 0 is legitimate), then re-run
`python train_model.py`. Good public sources: the "Phishing Email Dataset" on
Kaggle, or the Nazario phishing corpus combined with the Enron email set.

## Notes & limitations

- This is an educational/portfolio tool, not a guaranteed shield. Always use
  your own judgment.
- Gmail's page structure is not a public API; if email extraction breaks,
  update the selectors in `content.js`.
- The backend runs locally over HTTP. Before deploying anywhere real, serve it
  over HTTPS and lock CORS down to your extension's ID instead of `*`.

## Where to take it next

- Add live URL reputation lookups (e.g. Google Safe Browsing) in `app.py`.
- Support Outlook web by adding selectors + a match in `manifest.json`.
- Log scans (locally) so users can see a history and trends.
- Show an in-page banner on risky emails, not just the toolbar badge.
```