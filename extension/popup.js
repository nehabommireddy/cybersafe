// popup.js — UI logic for the CyberSafe popup.

const ARC_LEN = Math.PI * 80; // length of the semicircle gauge (r = 80)

const TIPS = [
  "Hover over links before clicking — the real destination shows in the corner.",
  "Real companies never ask for your password or codes by email.",
  "Urgency is a tactic. \u201cAct now or lose access\u201d is a classic phishing line.",
  "Check the sender's address, not just the display name. They rarely match in scams.",
  "When in doubt, go to the site directly instead of using the email's link.",
  "Turn on two-factor authentication — it blocks most account takeovers.",
  "Misspelled domains (paypa1.com) are a giveaway. Read links character by character.",
  "Unexpected attachment? Don't open it. Confirm with the sender through another channel.",
];

const el = (id) => document.getElementById(id);

// Promise wrapper around chrome.runtime.sendMessage
function send(message) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(message, (res) => {
      if (chrome.runtime.lastError) return resolve({ error: chrome.runtime.lastError.message });
      resolve(res || {});
    });
  });
}

function getActiveTab() {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => resolve(tabs[0]));
  });
}

// ---- Gauge + verdict rendering --------------------------------------------
function setGauge(risk) {
  const f = Math.max(0, Math.min(100, risk)) / 100;
  el("valueArc").style.strokeDasharray = ARC_LEN;
  el("valueArc").style.strokeDashoffset = ARC_LEN * (1 - f);
  el("needle").setAttribute("transform", `rotate(${-90 + f * 180} 100 100)`);
}

function applyVerdict(verdict) {
  document.body.classList.remove("v-safe", "v-caution", "v-phishing");
  document.body.classList.add(`v-${verdict}`);
}

const VERDICT_LABEL = { safe: "looks safe", caution: "be cautious", phishing: "likely phishing" };

function renderPrediction(pred, sourceLabel) {
  if (!pred || pred.error || typeof pred.risk !== "number") {
    el("scanned").textContent =
      "Couldn't reach the analyzer. Is the backend running on localhost:8000?";
    return;
  }
  el("score").textContent = pred.risk;
  el("verdict").textContent = VERDICT_LABEL[pred.verdict] || pred.verdict;
  applyVerdict(pred.verdict);
  setGauge(pred.risk);
  el("scanned").textContent = sourceLabel;

  // Reasons
  const panel = el("reasonsPanel");
  const list = el("reasonList");
  list.innerHTML = "";
  panel.hidden = false;

  if (!pred.reasons || pred.reasons.length === 0) {
    const li = document.createElement("li");
    li.className = "reason-empty";
    li.textContent =
      pred.verdict === "safe"
        ? "No common phishing signals found. Stay alert anyway."
        : "Flagged by the ML model, with no specific rule triggers.";
    list.appendChild(li);
    return;
  }

  for (const r of pred.reasons) {
    const li = document.createElement("li");
    li.className = `reason ${r.severity}`;
    li.innerHTML =
      `<span class="bar"></span><div><h3></h3><p></p></div>`;
    li.querySelector("h3").textContent = r.label;
    li.querySelector("p").textContent = r.detail;
    list.appendChild(li);
  }
}

// ---- Actions --------------------------------------------------------------
async function analyzeText(payload, sourceLabel) {
  el("scanned").textContent = "Analyzing\u2026";
  const res = await send({ type: "ANALYZE", payload });
  renderPrediction(res.prediction || res, sourceLabel);
}

async function scanCurrentEmail() {
  const tab = await getActiveTab();
  if (!tab || !/mail\.google\.com/.test(tab.url || "")) {
    el("scanned").textContent = "Open an email in Gmail, then try again.";
    return;
  }
  chrome.tabs.sendMessage(tab.id, { type: "EXTRACT_EMAIL" }, async (data) => {
    if (chrome.runtime.lastError || !data || data.empty) {
      el("scanned").textContent = "No open email found. Open one and try again.";
      return;
    }
    await analyzeText(
      { text: data.text, subject: data.subject, sender: data.sender, sender_domain: data.sender_domain },
      `Scanned: ${data.subject ? `\u201c${data.subject.slice(0, 40)}\u201d` : "current email"}`
    );
  });
}

async function checkHealth() {
  const res = await send({ type: "HEALTH" });
  const dot = el("connDot");
  const label = el("connLabel");
  if (res && res.ok) {
    dot.className = "dot online";
    label.textContent = res.model_loaded ? "connected" : "no model";
  } else {
    dot.className = "dot offline";
    label.textContent = "offline";
  }
}

async function loadLastForActiveTab() {
  const tab = await getActiveTab();
  if (!tab) return;
  const res = await send({ type: "GET_LAST", tabId: tab.id });
  if (res && res.prediction) {
    renderPrediction(res.prediction, "Auto-scanned: open email");
  }
}

// ---- Wire up --------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  el("tip").textContent = TIPS[Math.floor(Math.random() * TIPS.length)];
  checkHealth();
  loadLastForActiveTab();

  el("scanBtn").addEventListener("click", scanCurrentEmail);

  el("pasteBtn").addEventListener("click", () => {
    const area = el("pasteArea");
    area.hidden = !area.hidden;
    if (!area.hidden) el("pasteInput").focus();
  });

  el("analyzeBtn").addEventListener("click", () => {
    const text = el("pasteInput").value.trim();
    if (!text) {
      el("pasteInput").focus();
      return;
    }
    analyzeText({ text }, "Scanned: pasted text");
  });
});
