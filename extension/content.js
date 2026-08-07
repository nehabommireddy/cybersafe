// content.js — runs on Gmail. Extracts the currently open email and, when a
// new email is opened, pushes it to the background worker for an auto-scan.
//
// NOTE: Gmail's DOM is not a public API and its class names change over time.
// If extraction stops working, update the selectors below. These are the
// commonly used ones at the time of writing.

function visibleText(node) {
  return node ? (node.innerText || node.textContent || "").trim() : "";
}

function extractOpenEmail() {
  // Subject
  const subjectEl = document.querySelector("h2.hP");
  const subject = visibleText(subjectEl);

  // Body: the last visible message body in the open thread
  const bodies = Array.from(document.querySelectorAll(".a3s"));
  let bodyEl = null;
  for (const b of bodies) {
    if (b.offsetParent !== null) bodyEl = b; // last visible one wins
  }
  const text = visibleText(bodyEl);

  // Sender: span.gD carries the display name + an `email` attribute
  const senderEl = document.querySelector("span.gD");
  const display = visibleText(senderEl);
  const addr = senderEl ? senderEl.getAttribute("email") || "" : "";
  const sender = addr ? `${display} <${addr}>` : display;
  const sender_domain = addr.includes("@") ? addr.split("@").pop() : "";

  if (!subject && !text) return { empty: true };
  return { empty: false, subject, text, sender, sender_domain };
}

// Respond to the popup's explicit request.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "EXTRACT_EMAIL") {
    sendResponse(extractOpenEmail());
  }
  return false;
});

// ---- Auto-scan when an email is opened ------------------------------------
let lastKey = "";
let timer = null;

function maybeAutoScan() {
  const data = extractOpenEmail();
  if (data.empty || !data.text) return;
  const key = `${data.subject}::${data.text.length}`;
  if (key === lastKey) return; // already scanned this one
  lastKey = key;
  chrome.runtime.sendMessage({
    type: "AUTO_SCAN",
    payload: {
      text: data.text,
      subject: data.subject,
      sender: data.sender,
      sender_domain: data.sender_domain,
    },
  });
}

const observer = new MutationObserver(() => {
  clearTimeout(timer);
  timer = setTimeout(maybeAutoScan, 600); // debounce Gmail's frequent DOM churn
});
observer.observe(document.body, { childList: true, subtree: true });
