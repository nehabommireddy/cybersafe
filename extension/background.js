// background.js — service worker. Single source of truth for the API URL.
// Handles health checks, prediction requests, auto-scan results, and the
// toolbar badge that gives the "real-time" at-a-glance signal.

const API_URL = "http://localhost:8000";

// Cache the latest prediction per tab so the popup can show it instantly.
const lastByTab = new Map();

const BADGE = {
  safe: { text: "OK", color: "#18A999" },
  caution: { text: "!", color: "#E2982E" },
  phishing: { text: "\u26A0", color: "#E0524B" },
};

async function callPredict(payload) {
  const res = await fetch(`${API_URL}/predict`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function setBadge(tabId, verdict) {
  const b = BADGE[verdict];
  if (!b || tabId == null) return;
  chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
  chrome.action.setBadgeText({ tabId, text: b.text });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // --- Health check (popup connection dot) ---
  if (msg.type === "HEALTH") {
    fetch(`${API_URL}/health`)
      .then((r) => r.json())
      .then((d) => sendResponse({ ok: true, model_loaded: !!d.model_loaded }))
      .catch(() => sendResponse({ ok: false }));
    return true; // async
  }

  // --- Analyze on demand (popup: scan email / paste text) ---
  if (msg.type === "ANALYZE") {
    callPredict(msg.payload)
      .then((prediction) => {
        const tabId = sender.tab ? sender.tab.id : null;
        sendResponse({ prediction });
      })
      .catch((e) => sendResponse({ error: String(e) }));
    return true;
  }

  // --- Auto-scan pushed by the content script when an email opens ---
  if (msg.type === "AUTO_SCAN") {
    const tabId = sender.tab ? sender.tab.id : null;
    callPredict(msg.payload)
      .then((prediction) => {
        if (tabId != null) {
          lastByTab.set(tabId, prediction);
          setBadge(tabId, prediction.verdict);
        }
      })
      .catch(() => {});
    return false;
  }

  // --- Popup asks for the cached auto-scan result ---
  if (msg.type === "GET_LAST") {
    sendResponse({ prediction: lastByTab.get(msg.tabId) || null });
    return false;
  }
});

// Clean up cache + badge when tabs close or navigate away.
chrome.tabs.onRemoved.addListener((tabId) => lastByTab.delete(tabId));
chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === "loading") {
    lastByTab.delete(tabId);
    chrome.action.setBadgeText({ tabId, text: "" });
  }
});
