const form = document.querySelector("#scanForm");
const targetInput = document.querySelector("#targetInput");
const portsInput = document.querySelector("#portsInput");
const scanStatus = document.querySelector("#scanStatus");
const statusTarget = document.querySelector("#statusTarget");
const loader = document.querySelector("#loader");
const riskScore = document.querySelector("#riskScore");
const riskLabel = document.querySelector("#riskLabel");
const openPorts = document.querySelector("#openPorts");
const closedPorts = document.querySelector("#closedPorts");
const findingCount = document.querySelector("#findingCount");
const duration = document.querySelector("#duration");
const findingsList = document.querySelector("#findingsList");
const portsList = document.querySelector("#portsList");
const severityPills = document.querySelector("#severityPills");
const scopeBadge = document.querySelector("#scopeBadge");
const reportPreview = document.querySelector("#reportPreview");
const generatedAt = document.querySelector("#generatedAt");
const downloadMarkdown = document.querySelector("#downloadMarkdown");
const downloadJson = document.querySelector("#downloadJson");

let latestResult = null;

const severityOrder = ["critical", "high", "medium", "low", "info"];

function setLoading(isLoading, target = "") {
  form.querySelector("button").disabled = isLoading;
  loader.classList.toggle("hidden", !isLoading);
  if (isLoading) {
    scanStatus.textContent = "Scanning";
    statusTarget.textContent = target || "Awaiting target";
  }
}

function activeProfile() {
  const checked = form.querySelector("input[name='profile']:checked");
  return checked ? checked.value : "quick";
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function severityPill(severity, count) {
  return `<span class="pill ${severity}">${severity.toUpperCase()} ${count}</span>`;
}

function renderMetrics(result) {
  riskScore.textContent = result.risk_score;
  riskLabel.textContent = result.risk_label;
  openPorts.textContent = result.open_ports.length;
  closedPorts.textContent = `Closed: ${result.closed_count}`;
  findingCount.textContent = result.findings.length;
  duration.textContent = `Duration: ${result.duration_ms} ms`;
  scopeBadge.textContent = result.scope;
  generatedAt.textContent = new Date(result.generated_at).toLocaleString();
}

function renderSeverity(counts) {
  severityPills.innerHTML = severityOrder
    .filter((severity) => counts[severity] > 0)
    .map((severity) => severityPill(severity, counts[severity]))
    .join("");
}

function renderFindings(findings) {
  if (!findings.length) {
    findingsList.className = "findings empty-state";
    findingsList.textContent = "No vulnerabilities were identified by this basic scan.";
    return;
  }

  findingsList.className = "findings";
  findingsList.innerHTML = findings
    .map((finding, index) => `
      <article class="finding" style="animation-delay:${index * 45}ms">
        <div class="finding-head">
          <h4>${escapeHtml(finding.title)}</h4>
          <span class="pill ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity).toUpperCase()}</span>
        </div>
        <p><strong>Category:</strong> ${escapeHtml(finding.category)}</p>
        <p><strong>Evidence:</strong> <code>${escapeHtml(finding.evidence)}</code></p>
        <p><strong>Recommendation:</strong> ${escapeHtml(finding.recommendation)}</p>
      </article>
    `)
    .join("");
}

function renderPorts(ports) {
  if (!ports.length) {
    portsList.className = "ports empty-state";
    portsList.textContent = "No open ports found in the selected profile.";
    return;
  }

  portsList.className = "ports";
  portsList.innerHTML = ports
    .map((port, index) => `
      <article class="port-row" style="animation-delay:${index * 55}ms">
        <div>
          <strong>${escapeHtml(port.port)} / ${escapeHtml(port.service)}</strong>
          <span>${escapeHtml(port.latency_ms)} ms response</span>
          ${port.banner ? `<p><code>${escapeHtml(port.banner)}</code></p>` : ""}
        </div>
        <span class="pill low">OPEN</span>
      </article>
    `)
    .join("");
}

function renderReport(result) {
  reportPreview.textContent = result.report_markdown;
  downloadMarkdown.disabled = false;
  downloadJson.disabled = false;
}

function downloadFile(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

async function runScan(event) {
  event.preventDefault();
  const target = targetInput.value.trim();
  if (!target) return;

  setLoading(true, target);
  downloadMarkdown.disabled = true;
  downloadJson.disabled = true;

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target,
        profile: activeProfile(),
        customPorts: portsInput.value.trim(),
      }),
    });

    const payload = await response.json();
    if (!response.ok || !payload.ok) {
      throw new Error(payload.error || "Scan failed.");
    }

    latestResult = payload.result;
    localStorage.setItem("aegis:lastResult", JSON.stringify(latestResult));
    renderMetrics(latestResult);
    renderSeverity(latestResult.severity_counts);
    renderFindings(latestResult.findings);
    renderPorts(latestResult.open_ports);
    renderReport(latestResult);
    scanStatus.textContent = "Completed";
    statusTarget.textContent = latestResult.target.display;
  } catch (error) {
    scanStatus.textContent = "Error";
    statusTarget.textContent = error.message;
    findingsList.className = "findings empty-state";
    findingsList.textContent = error.message;
  } finally {
    setLoading(false, statusTarget.textContent);
  }
}

function hydrateLastResult() {
  const raw = localStorage.getItem("aegis:lastResult");
  if (!raw) return;
  try {
    latestResult = JSON.parse(raw);
    renderMetrics(latestResult);
    renderSeverity(latestResult.severity_counts);
    renderFindings(latestResult.findings);
    renderPorts(latestResult.open_ports);
    renderReport(latestResult);
    scanStatus.textContent = "Loaded";
    statusTarget.textContent = latestResult.target.display;
  } catch {
    localStorage.removeItem("aegis:lastResult");
  }
}

form.addEventListener("submit", runScan);

downloadMarkdown.addEventListener("click", () => {
  if (!latestResult) return;
  const safeTarget = latestResult.target.host.replace(/[^a-z0-9.-]/gi, "_");
  downloadFile(`santhosh-securescan-${safeTarget}.md`, latestResult.report_markdown, "text/markdown");
});

downloadJson.addEventListener("click", () => {
  if (!latestResult) return;
  const safeTarget = latestResult.target.host.replace(/[^a-z0-9.-]/gi, "_");
  downloadFile(`santhosh-securescan-${safeTarget}.json`, JSON.stringify(latestResult, null, 2), "application/json");
});

hydrateLastResult();


