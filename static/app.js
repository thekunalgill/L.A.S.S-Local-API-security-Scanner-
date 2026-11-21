const AGENT_URL = "http://127.0.0.1:8765";
const TOKEN_KEY = "lass.agentToken.v1";
const form = document.querySelector("#scan-form");
const targetInput = document.querySelector("#target");
const authorization = document.querySelector("#authorized");
const scanButton = document.querySelector("#scan-button");
const formError = document.querySelector("#form-error");
const resultSection = document.querySelector("#result-section");
const resultContainer = document.querySelector("#scan-result");
const historyList = document.querySelector("#history-list");
const tokenInput = document.querySelector("#agent-token");
const agentStatus = document.querySelector("#agent-status");
const agentHelp = document.querySelector("#agent-help");
let memoryToken = "";

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
}

function getToken() {
  try {
    return sessionStorage.getItem(TOKEN_KEY) || memoryToken;
  } catch {
    return memoryToken;
  }
}

function setToken(value) {
  memoryToken = value.trim();
  try {
    if (memoryToken) sessionStorage.setItem(TOKEN_KEY, memoryToken);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    // Keep the pairing token in memory when browser storage is unavailable.
  }
}

function tokenHeaders() {
  const token = getToken();
  return token ? {"X-LASS-Token": token} : {};
}

function agentErrorMessage(error) {
  if (error instanceof TypeError) {
    return "Could not reach the local agent. Start it with `python -m lass.agent`, allow local-network access in your browser, and check that this page is not blocked by mixed-content rules.";
  }
  return error.message || "The local agent request failed.";
}

function setAgentStatus(connected, message) {
  agentStatus.dataset.state = connected ? "connected" : "offline";
  agentStatus.querySelector("span").textContent = message;
  agentHelp.hidden = connected;
  scanButton.disabled = !connected;
}

async function checkAgent() {
  agentStatus.dataset.state = "checking";
  agentStatus.querySelector("span").textContent = "Checking agent…";
  try {
    const response = await fetch(`${AGENT_URL}/api/health`, {cache: "no-store"});
    if (!response.ok) throw new Error("Agent health check failed.");
    setAgentStatus(true, "Agent connected");
    await loadHistory();
  } catch {
    setAgentStatus(false, "Agent not running");
  }
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
    resultContainer.innerHTML = `<div class="result-card"><div class="error-message">${escapeHtml(scan.error || "Could not reach this endpoint. Check that the service is available and try again.")}</div></div>`;
    return;
  }
  const scoreClass = scan.score >= 80 ? "" : scan.score >= 55 ? "medium" : "low";
  resultContainer.innerHTML = `<div class="result-card">
    <div class="result-top">
      <div class="score-block"><div class="score-ring ${scoreClass}">${scan.score}</div><div class="score-caption">BASELINE SCORE<small>OUT OF 100</small></div></div>
      <div class="metrics"><div class="metric"><strong>${scan.status_code}</strong><small>HTTP STATUS</small></div><div class="metric"><strong>${Number(scan.latency_ms).toFixed(0)}<small style="display:inline"> ms</small></strong><small>RESPONSE TIME</small></div><div class="metric"><strong>Online</strong><small>ENDPOINT STATUS</small></div></div>
    </div>${renderFindings(scan.findings)}</div>`;
}

function renderHistory(scans) {
  if (!scans.length) {
    historyList.innerHTML = '<div class="empty-state">No saved scans yet.</div>';
    return;
  }
  historyList.innerHTML = scans.map((scan) => `<div class="history-row">
    <span class="endpoint" title="${escapeHtml(scan.target_url)}">${escapeHtml(scan.target_url)}</span>
    <span class="status-pill ${scan.status === "failed" ? "failed" : ""}">${scan.status === "failed" ? "FAILED" : `HTTP ${scan.status_code}`}</span>
    <span class="history-score">${scan.score === null ? "—" : scan.score}</span>
    <span class="history-date">${new Date(scan.timestamp).toLocaleString()}</span>
  </div>`).join("");
}

async function loadHistory() {
  if (!getToken()) {
    historyList.innerHTML = '<div class="empty-state">Pair with the local agent to view saved scans.</div>';
    return;
  }
  try {
    const response = await fetch(`${AGENT_URL}/api/history`, {headers: tokenHeaders()});
    if (!response.ok) throw new Error("History could not be loaded.");
    renderHistory(await response.json());
  } catch (error) {
    historyList.innerHTML = `<div class="empty-state">${escapeHtml(agentErrorMessage(error))}</div>`;
  }
}

tokenInput.value = getToken();
tokenInput.addEventListener("input", () => {
  setToken(tokenInput.value);
  if (agentStatus.dataset.state === "connected") loadHistory();
});

document.querySelector("#check-agent").addEventListener("click", checkAgent);
document.querySelector("#refresh-button").addEventListener("click", loadHistory);

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  formError.hidden = true;
  scanButton.disabled = true;
  scanButton.innerHTML = "<span>Scanning…</span><span aria-hidden=\"true\">◌</span>";
  try {
    if (!getToken()) throw new Error("Paste the pairing token printed in the agent terminal.");
    if (!authorization.checked) throw new Error("Confirm that you own or are authorized to test this target.");
    const response = await fetch(`${AGENT_URL}/api/scans`, {
      method: "POST",
      headers: {"Content-Type": "application/json", ...tokenHeaders()},
      body: JSON.stringify({target_url: targetInput.value, authorized: authorization.checked})
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "The scan request failed.");
    renderResult(data);
    await loadHistory();
  } catch (error) {
    formError.textContent = agentErrorMessage(error);
    formError.hidden = false;
    if (error instanceof TypeError) setAgentStatus(false, "Agent not running");
  } finally {
    scanButton.innerHTML = "<span>Run scan</span><span aria-hidden=\"true\">↗</span>";
    scanButton.disabled = agentStatus.dataset.state !== "connected";
  }
});

checkAgent();
