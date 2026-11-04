const form = document.querySelector("#scan-form");
const targetInput = document.querySelector("#target");
const authorization = document.querySelector("#authorized");
const scanButton = document.querySelector("#scan-button");
const formError = document.querySelector("#form-error");
const resultSection = document.querySelector("#result-section");
const resultContainer = document.querySelector("#scan-result");
const historyList = document.querySelector("#history-list");
const historyKey = "lass.scanHistory.v1";

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
}

function renderFindings(findings) {
  if (!findings.length) return '<div class="success-message">No baseline issues detected. The endpoint responded successfully.</div>';
  return `<div class="findings">${findings.map((finding) => `
    <article class="finding">
      <span class="severity ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
      <div><h3>${escapeHtml(finding.title)}</h3><p>${escapeHtml(finding.detail)}</p>
      <p class="recommendation"><strong>Fix:</strong> ${escapeHtml(finding.recommendation)}</p></div>
    </article>`).join("")}</div>`;
}

function renderResult(scan) {
  resultSection.hidden = false;
  document.querySelector("#scan-time").textContent = new Date(scan.timestamp).toLocaleString();
  if (scan.status === "failed") {
      resultContainer.innerHTML = '<div class="result-card"><div class="error-message">Could not reach this endpoint. Check that the service is available and try again.</div></div>';
    return;
  }
  const scoreClass = scan.score >= 80 ? "" : scan.score >= 55 ? "medium" : "low";
  resultContainer.innerHTML = `<div class="result-card">
    <div class="result-top">
      <div class="score-block"><div class="score-ring ${scoreClass}">${scan.score}</div><div class="score-caption">BASELINE SCORE<small>OUT OF 100</small></div></div>
      <div class="metrics"><div class="metric"><strong>${scan.status_code}</strong><small>HTTP STATUS</small></div><div class="metric"><strong>${Number(scan.latency_ms).toFixed(0)}<small style="display:inline"> ms</small></strong><small>RESPONSE TIME</small></div><div class="metric"><strong>Online</strong><small>ENDPOINT STATUS</small></div></div>
    </div>${renderFindings(scan.findings)}</div>`;
}

function readHistory() {
  try {
    const scans = JSON.parse(localStorage.getItem(historyKey) || "[]");
    return Array.isArray(scans) ? scans : [];
  } catch {
    return [];
  }
}

function saveScan(scan) {
  try {
    localStorage.setItem(historyKey, JSON.stringify([scan, ...readHistory()].slice(0, 20)));
  } catch {
    // Scanning still works when browser storage is unavailable.
  }
}

function loadHistory() {
  const scans = readHistory();
  if (!scans.length) {
    historyList.innerHTML = '<div class="empty-state">Your scan history is saved in this browser.</div>';
    return;
  }
  try {
    historyList.innerHTML = scans.map((scan) => `<div class="history-row">
      <span class="endpoint" title="${escapeHtml(scan.target_url)}">${escapeHtml(scan.target_url)}</span>
      <span class="status-pill ${scan.status === "failed" ? "failed" : ""}">${scan.status === "failed" ? "FAILED" : `HTTP ${scan.status_code}`}</span>
      <span class="history-score">${scan.score === null ? "—" : scan.score}</span>
      <span class="history-date">${new Date(scan.timestamp).toLocaleString()}</span>
    </div>`).join("");
  } catch {
    historyList.innerHTML = '<div class="empty-state">History could not be displayed.</div>';
  }
}

async function loadConfig() {
  try {
    const response = await fetch("/api/config");
    if (!response.ok || !(await response.json()).web_mode) return;
    document.querySelector(".local-badge").innerHTML = "<i></i> HOSTED SCAN MODE";
    document.querySelector(".hero > p").textContent = "Check the health, response time and basic security posture of a public API.";
    document.querySelector(".scan-card h2").textContent = "Start a public API scan";
    targetInput.placeholder = "https://api.example.com/health";
    targetInput.value = "";
    document.querySelector(".input-foot span").textContent = "Public IP addresses and hostnames only. Private networks are blocked.";
    document.querySelector(".safe-note").textContent = "PUBLIC TARGETS ONLY";
    document.querySelector(".browser-note").textContent = "Scans run from the hosted service and are limited to public IP addresses. Only scan systems you own or have permission to test.";
  } catch {
    // The local desktop UI remains usable if the optional config request fails.
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  formError.hidden = true;
  scanButton.disabled = true;
  scanButton.innerHTML = "<span>Scanning…</span><span aria-hidden=\"true\">◌</span>";
  try {
    if (!authorization.checked) throw new Error("Confirm that you own or are authorized to test this target.");
    const response = await fetch("/api/scans", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({target_url: targetInput.value})
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "The scan request failed.");
    saveScan(data);
    renderResult(data);
    loadHistory();
  } catch (error) {
    formError.textContent = error.message;
    formError.hidden = false;
  } finally {
    scanButton.disabled = false;
    scanButton.innerHTML = "<span>Run scan</span><span aria-hidden=\"true\">↗</span>";
  }
});

document.querySelector("#refresh-button").addEventListener("click", loadHistory);
loadConfig();
loadHistory();
