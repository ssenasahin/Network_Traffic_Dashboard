const form = document.querySelector("#scanForm");
const targetInput = document.querySelector("#target");
const portsInput = document.querySelector("#ports");
const timeoutInput = document.querySelector("#timeout");
const concurrencyInput = document.querySelector("#concurrency");
const bannerInput = document.querySelector("#banner");
const scanButton = document.querySelector("#scanButton");
const statusText = document.querySelector("#statusText");
const customPortsWrap = document.querySelector("#customPortsWrap");
const resultsBody = document.querySelector("#resultsBody");
const eventLog = document.querySelector("#eventLog");
const historyList = document.querySelector("#historyList");
const progressBar = document.querySelector("#progressBar");

const metrics = {
  activeTarget: document.querySelector("#activeTarget"),
  resolvedIp: document.querySelector("#resolvedIp"),
  scanned: document.querySelector("#scannedMetric"),
  open: document.querySelector("#openMetric"),
  duration: document.querySelector("#durationMetric"),
  state: document.querySelector("#stateMetric"),
  resultCount: document.querySelector("#resultCount"),
};

let selectedMode = "top20";
let socket = null;
let scanStarted = 0;
let openResults = [];

document.querySelectorAll("[data-mode]").forEach((button) => {
  button.addEventListener("click", () => {
    selectedMode = button.dataset.mode;
    document.querySelectorAll("[data-mode]").forEach((item) => item.classList.toggle("active", item === button));
    customPortsWrap.classList.toggle("hidden", selectedMode !== "custom");
  });
});

document.querySelector("#clearLog").addEventListener("click", () => {
  eventLog.innerHTML = "";
});

document.querySelector("#refreshHistory").addEventListener("click", loadHistory);

form.addEventListener("submit", (event) => {
  event.preventDefault();
  startScan();
});

function scanPayload() {
  return {
    target: targetInput.value.trim(),
    mode: selectedMode,
    ports: portsInput.value.trim() || null,
    timeout: Number(timeoutInput.value),
    concurrency: Number(concurrencyInput.value),
    banner: bannerInput.checked,
  };
}

function startScan() {
  if (socket) {
    socket.close();
  }
  resetScan();

  const protocol = location.protocol === "https:" ? "wss" : "ws";
  socket = new WebSocket(`${protocol}://${location.host}/ws/scan`);
  scanButton.disabled = true;
  metrics.state.textContent = "Running";
  statusText.textContent = "Tarama başlatılıyor...";
  scanStarted = performance.now();

  socket.addEventListener("open", () => {
    socket.send(JSON.stringify(scanPayload()));
  });

  socket.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);
    if (message.type === "meta") {
      metrics.activeTarget.textContent = message.target;
      metrics.resolvedIp.textContent = `IP: ${message.resolved_ip}`;
      appendLog(`target resolved -> ${message.resolved_ip}`, "log-open");
    }
    if (message.type === "progress") {
      updateProgress(message.scanned, message.total);
      handleResult(message.result);
    }
    if (message.type === "done") {
      metrics.duration.textContent = `${message.duration_ms} ms`;
      metrics.state.textContent = "Complete";
      statusText.textContent = `Tamamlandı. ${message.open_count} açık port bulundu.`;
      scanButton.disabled = false;
      appendLog(`scan complete -> #${message.id}`, "log-open");
      loadHistory();
      socket = null;
    }
    if (message.type === "error") {
      handleError(message.message);
    }
  });

  socket.addEventListener("error", () => handleError("WebSocket bağlantısı kurulamadı."));
  socket.addEventListener("close", () => {
    if (scanButton.disabled && metrics.state.textContent !== "Complete") {
      scanButton.disabled = false;
      metrics.state.textContent = "Stopped";
    }
  });
}

function resetScan() {
  openResults = [];
  resultsBody.innerHTML = `<tr class="empty-row"><td colspan="4">Henüz açık port bulunmadı.</td></tr>`;
  eventLog.innerHTML = "";
  progressBar.style.width = "0%";
  metrics.activeTarget.textContent = targetInput.value.trim() || "Bekleyen tarama";
  metrics.resolvedIp.textContent = "IP: -";
  metrics.scanned.textContent = "0";
  metrics.open.textContent = "0";
  metrics.duration.textContent = "0 ms";
  metrics.resultCount.textContent = "0 kayıt";
}

function updateProgress(scanned, total) {
  metrics.scanned.textContent = `${scanned}/${total}`;
  const elapsed = Math.round(performance.now() - scanStarted);
  metrics.duration.textContent = `${elapsed} ms`;
  progressBar.style.width = `${Math.round((scanned / total) * 100)}%`;
}

function handleResult(result) {
  if (result.state === "open") {
    openResults.push(result);
    metrics.open.textContent = openResults.length;
    metrics.resultCount.textContent = `${openResults.length} kayıt`;
    renderResults(openResults);
    appendLog(`open ${result.port}/tcp ${result.service} ${result.banner || ""}`.trim(), "log-open");
  } else if (Number(metrics.scanned.textContent.split("/")[0]) % 8 === 0) {
    appendLog(`closed ${result.port}/tcp`, "log-closed");
  }
}

function renderResults(results) {
  resultsBody.innerHTML = results
    .sort((a, b) => a.port - b.port)
    .map(
      (result) => `
        <tr>
          <td><span class="port-badge">${escapeHtml(result.port)}</span></td>
          <td>${escapeHtml(result.service)}</td>
          <td>${escapeHtml(result.latency_ms ?? "-")} ms</td>
          <td class="banner-cell">${escapeHtml(result.banner || "-")}</td>
        </tr>
      `,
    )
    .join("");
}

function appendLog(text, className = "") {
  const line = document.createElement("div");
  line.className = className;
  line.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
  eventLog.appendChild(line);
  eventLog.scrollTop = eventLog.scrollHeight;
}

function handleError(message) {
  scanButton.disabled = false;
  metrics.state.textContent = "Error";
  statusText.textContent = message;
  appendLog(message, "log-error");
  if (socket) {
    socket.close();
    socket = null;
  }
}

async function loadHistory() {
  try {
    const response = await fetch("/api/v1/history");
    const scans = await response.json();
    historyList.innerHTML = scans.length
      ? scans.map(historyButton).join("")
      : `<p class="status-text">Henüz kayıt yok.</p>`;
    historyList.querySelectorAll("[data-scan-id]").forEach((button) => {
      button.addEventListener("click", () => loadHistoryItem(button.dataset.scanId));
    });
  } catch {
    historyList.innerHTML = `<p class="status-text">Geçmiş alınamadı.</p>`;
  }
}

function historyButton(scan) {
  return `
    <button class="history-item" data-scan-id="${scan.id}">
      <strong>${escapeHtml(scan.target)}</strong>
      <span>${scan.open_count} açık / ${scan.ports_scanned} port · ${escapeHtml(scan.created_at)}</span>
    </button>
  `;
}

async function loadHistoryItem(id) {
  const response = await fetch(`/api/v1/history/${id}`);
  const scan = await response.json();
  openResults = scan.results;
  metrics.activeTarget.textContent = scan.target;
  metrics.resolvedIp.textContent = `IP: ${scan.resolved_ip}`;
  metrics.scanned.textContent = String(scan.ports_scanned);
  metrics.open.textContent = String(scan.open_count);
  metrics.duration.textContent = `${scan.duration_ms} ms`;
  metrics.state.textContent = "History";
  metrics.resultCount.textContent = `${scan.open_count} kayıt`;
  progressBar.style.width = "100%";
  renderResults(openResults);
  appendLog(`loaded historical scan #${id}`, "log-open");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

loadHistory();
