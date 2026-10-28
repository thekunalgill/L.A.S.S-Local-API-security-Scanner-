const authPanel = document.querySelector("#auth-panel");
const appShell = document.querySelector("#app-shell");
const userChip = document.querySelector("#user-chip");
const loginForm = document.querySelector("#login-form");
const authError = document.querySelector("#auth-error");
const logoutButton = document.querySelector("#logout-button");
const form = document.querySelector("#scan-form");
const targetInput = document.querySelector("#target");
const scanButton = document.querySelector("#scan-button");
const formError = document.querySelector("#form-error");
const resultPanel = document.querySelector("#result");
const historyBody = document.querySelector("#history-body");

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
}

function formatTime(value) {
  return new Date(value).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

function showLoggedIn(user) {
  authPanel.hidden = true;
  appShell.hidden = false;
  userChip.textContent = `Signed in as ${user.username}`;
  loadHistory().catch(() => {});
}

function showLoggedOut() {
  authPanel.hidden = false;
  appShell.hidden = true;
  resultPanel.hidden = true;
  historyBody.innerHTML = '<tr><td class="empty-state" colspan="6">You need to sign in to view scan history.</td></tr>';
}

async function checkSession() {
  const response = await fetch("/api/auth/me", { credentials: "same-origin" });
  if (!response.ok) {
    showLoggedOut();
    return;
  }
  const user = await response.json();
  showLoggedIn(user);
}

function renderResult(scan) {
  const findings = scan.findings.length
    ? scan.findings.map((item) => `<article class="finding"><span class="severity ${escapeHtml(item.severity)}">${escapeHtml(item.severity)} −${item.deduction}</span><div><strong>${escapeHtml(item.title)}</strong><p>${escapeHtml(item.detail)}</p><p>↳ ${escapeHtml(item.recommendation)}</p></div></article>`).join("")
    : '<article class="finding"><span class="severity low">clear</span><div><strong>No baseline issues found</strong><p>This response passed the checks included in this scan.</p></div></article>';
  resultPanel.innerHTML = `<div class="result-top"><div><span class="result-label">SCAN #${scan.id} · ${escapeHtml(scan.target)}</span><h3>Baseline report</h3></div><div class="score">${scan.score}<small> / 100</small></div></div><div class="result-meta"><span>HTTP ${scan.status_code ?? "NO RESPONSE"}</span><span>${scan.latency_ms == null ? "—" : `${scan.latency_ms} ms`}</span><span>${formatTime(scan.created_at)}</span></div><div class="findings">${findings}</div>`;
  resultPanel.hidden = false;
  resultPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function loadHistory() {
  const response = await fetch("/api/history", { credentials: "same-origin" });
  if (!response.ok) throw new Error("Could not load scan history.");
  const scans = await response.json();
  if (!scans.length) {
    historyBody.innerHTML = '<tr><td class="empty-state" colspan="6">No scans yet. Start with a local endpoint above.</td></tr>';
    return;
  }
  historyBody.innerHTML = scans.map((scan) => `<tr><td class="target" title="${escapeHtml(scan.target)}">${escapeHtml(scan.target)}</td><td><span class="status-pill ${scan.status_code == null || scan.status_code >= 400 ? "bad" : ""}">${scan.status_code ?? "ERR"}</span></td><td>${scan.latency_ms == null ? "—" : `${scan.latency_ms} ms`}</td><td class="score-cell">${scan.score}</td><td>${formatTime(scan.created_at)}</td><td><button class="details-button" data-scan-id="${scan.id}" title="View scan findings" aria-label="View scan findings">↗</button></td></tr>`).join("");
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  authError.hidden = true;
  const username = document.querySelector("#login-username").value.trim();
  const password = document.querySelector("#login-password").value;
  try {
    const response = await fetch("/api/auth/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || "Login failed.");
    await checkSession();
  } catch (error) {
    authError.textContent = error.message || "Unable to sign in.";
    authError.hidden = false;
  }
});

logoutButton.addEventListener("click", async () => {
  await fetch("/api/auth/logout", {
    method: "POST",
    credentials: "same-origin",
  });
  showLoggedOut();
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  formError.hidden = true;
  resultPanel.hidden = true;
  scanButton.disabled = true;
  scanButton.querySelector("span").textContent = "Scanning…";
  try {
    const response = await fetch("/api/scans", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: targetInput.value.trim() }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail ?? "Scan failed.");
    renderResult(data);
    await loadHistory();
  } catch (error) {
    formError.textContent = error.message || "Could not reach the scanner.";
    formError.hidden = false;
  } finally {
    scanButton.disabled = false;
    scanButton.querySelector("span").textContent = "Run scan";
  }
});

historyBody.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-scan-id]");
  if (!button) return;
  const response = await fetch(`/api/scans/${button.dataset.scanId}`, { credentials: "same-origin" });
  if (response.ok) renderResult(await response.json());
});

document.querySelector("#refresh-button").addEventListener("click", () => loadHistory().catch(() => {}));
checkSession();