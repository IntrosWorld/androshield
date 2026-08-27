// APK Fraud Analyzer dashboard logic
const API = ""; // same origin

const SEV_COLORS = {
  Low: "#22c55e", Medium: "#eab308", High: "#f97316", Critical: "#ef4444",
  Unknown: "#64748b",
};

let selectedFile = null;
let selectedBatchFiles = [];
const batchJobs = new Map();
let gaugeChart = null;
let currentId = null;
let currentAnalysis = null;
let currentReport = null;

const $ = (id) => document.getElementById(id);
const plain = (value) => String(value ?? "").replace(/[\u2014\u2013]/g, "-");
const esc = (value) => plain(value).replace(/[&<>"']/g, ch => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[ch]));
const safeHttpUrl = (value) => {
  try {
    const u = new URL(String(value));
    return (u.protocol === "https:" || u.protocol === "http:") ? u.href : "#";
  } catch (_) { return "#"; }
};
const statusChipTone = (status) => {
  const value = String(status || "").toLowerCase();
  if (["completed", "ok", "ready", "grounded"].includes(value)) return "chip-success";
  if (["queued", "running", "pending", "investigating", "reviewing"].includes(value)) return "chip-info";
  if (["approval_required", "unavailable", "warning"].includes(value)) return "chip-warning";
  return "chip-danger";
};
const severityChipTone = (severity) => ({
  Low: "chip-success",
  Medium: "chip-warning",
  High: "chip-danger",
  Critical: "chip-danger",
}[severity] || "");

const THEME_STORAGE_KEY = "apk-analyzer-theme";

function updateThemeControl(theme) {
  const button = $("theme-toggle");
  const icon = $("theme-icon");
  const label = $("theme-label");
  if (!button || !icon || !label) return;
  const light = theme === "light";
  const nextLabel = light ? "Dark mode" : "Light mode";
  button.setAttribute("aria-pressed", String(light));
  button.setAttribute("aria-label", `Switch to ${nextLabel.toLowerCase()}`);
  icon.className = `ti ${light ? "ti-moon" : "ti-sun"}`;
  label.textContent = nextLabel;
}

function applyTheme(theme, persist = true) {
  const next = theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  document.documentElement.classList.toggle("dark", next === "dark");
  updateThemeControl(next);
  if (persist) {
    try { localStorage.setItem(THEME_STORAGE_KEY, next); } catch (_) {}
  }
  if (currentAnalysis?.risk_score != null) {
    drawGauge(currentAnalysis.risk_score, SEV_COLORS[currentAnalysis.severity] || SEV_COLORS.Unknown);
  }
}

applyTheme(document.documentElement.dataset.theme, false);
$("theme-toggle")?.addEventListener("click", () => {
  applyTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light");
});

// --- Application settings ---
let settingsData = null;
const settingValue = (id) => $(id)?.value?.trim() || "";
const settingNumber = (id) => Number.parseInt($(id)?.value, 10);

function setSettingsStatus(message, tone = "") {
  const status = $("settings-status");
  if (!status) return;
  status.textContent = plain(message);
  status.dataset.tone = tone;
}

function renderSettings(data) {
  settingsData = data;
  $("setting-external-enabled").checked = Boolean(data.external_api_enabled);
  $("setting-agent-enabled").checked = Boolean(data.agent_enabled);
  $("setting-agent-workflow-enabled").checked = Boolean(data.agent_workflow_enabled);
  $("setting-agent-auto-run").checked = Boolean(data.agent_auto_run);
  $("setting-gemini-review").checked = Boolean(data.agent_gemini_review);
  $("setting-ollama-fallback").checked = Boolean(data.agent_ollama_fallback);
  $("setting-openrouter-zdr").checked = data.openrouter_zdr !== false;
  $("setting-ui-vision-enabled").checked = Boolean(data.ui_agent_vision_enabled);
  $("setting-provider").value = data.agent_provider || "ollama";
  $("setting-ollama-url").value = data.ollama_base_url || "";
  $("setting-ollama-model").value = data.ollama_model || "";
  $("setting-models-dir").value = data.ollama_models_dir || "";
  $("setting-gemini-model").value = data.gemini_model || "";
  $("setting-openrouter-model").value = data.openrouter_model || "";
  $("setting-ui-provider").value = data.ui_agent_provider || "ollama";
  $("setting-ui-model").value = data.ui_agent_model || "";
  $("setting-context-tokens").value = data.agent_context_tokens ?? 4096;
  $("setting-max-steps").value = data.agent_max_steps ?? 8;
  $("setting-max-tools").value = data.agent_max_tool_calls ?? 4;
  $("setting-time-budget").value = data.agent_time_budget_seconds ?? 420;
  $("setting-provider-timeout").value = data.agent_provider_timeout_seconds ?? 240;
  $("gemini-key-state").textContent = data.gemini_key_configured ? "(saved)" : "";
  $("openrouter-key-state").textContent = data.openrouter_key_configured ? "(saved)" : "";
  $("vt-key-state").textContent = data.virustotal_key_configured ? "(saved)" : "";
  $("setting-gemini-key").value = "";
  $("setting-openrouter-key").value = "";
  $("setting-vt-key").value = "";
  $("clear-gemini-key").checked = false;
  $("clear-openrouter-key").checked = false;
  $("clear-vt-key").checked = false;
}

async function loadSettings() {
  const response = await fetch(`${API}/api/settings`);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || "Could not load settings");
  renderSettings(data);
  return data;
}

function renderComponents(data) {
  const list = $("component-list");
  if (!list) return;
  const components = data.components || [];
  list.innerHTML = components.map(component => {
    const state = component.installed ? '<span class="chip chip-success">Installed</span>'
      : component.install_available ? `<button class="btn-secondary component-action" type="button" data-component-install="${esc(component.id)}"><i class="ti ti-download" aria-hidden="true"></i>${esc(component.action_label)}</button>`
      : `<button class="btn-secondary component-action" type="button" disabled title="${esc(component.unavailable_reason)}">Unavailable</button>`;
    return `<div class="component-row" data-component-id="${esc(component.id)}">
      <div><div class="component-name">${esc(component.name)}</div>
      <div class="component-meta">${esc(component.description)} Download: ${esc(component.download_size)}. Source: <a class="component-source" href="${esc(safeHttpUrl(component.source_url))}" target="_blank" rel="noopener noreferrer">${esc(component.source_name)}</a>${component.unavailable_reason ? `. ${esc(component.unavailable_reason)}.` : ""}</div></div>
      <div>${state}</div></div>`;
  }).join("") || '<p class="p-3 text-xs text-slate-500">No optional components are available.</p>';
}

async function loadComponents() {
  const response = await fetch(`${API}/api/components`);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || "Could not load optional components");
  renderComponents(data);
  return data;
}

async function pollComponentJob(jobId, button) {
  for (;;) {
    await new Promise(resolve => setTimeout(resolve, 1200));
    const response = await fetch(`${API}/api/components/jobs/${encodeURIComponent(jobId)}`);
    const job = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(job.detail || "Could not read download status");
    setSettingsStatus(job.message || "Download is running...");
    if (job.status === "completed") return job;
    if (job.status === "failed") throw new Error(job.message || "Download failed");
  }
}

$("component-list")?.addEventListener("click", async event => {
  const button = event.target.closest("[data-component-install]");
  if (!button) return;
  const componentId = button.dataset.componentInstall;
  setButtonBusy(button, true, "Starting...");
  setSettingsStatus("Starting optional component download...");
  try {
    const response = await fetch(`${API}/api/components/${encodeURIComponent(componentId)}/install`, {method: "POST"});
    const job = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(job.detail || "Could not start download");
    if (!job.already_installed) await pollComponentJob(job.id, button);
    await Promise.all([loadComponents(), loadSettings(), refreshHealth()]);
    setSettingsStatus("Optional component is installed and ready.", "success");
  } catch (error) {
    setSettingsStatus(error.message, "danger");
  } finally {
    setButtonBusy(button, false);
  }
});

function collectSettings() {
  const data = {
    external_api_enabled: $("setting-external-enabled").checked,
    agent_enabled: $("setting-agent-enabled").checked,
    agent_workflow_enabled: $("setting-agent-workflow-enabled").checked,
    agent_auto_run: $("setting-agent-auto-run").checked,
    agent_gemini_review: $("setting-gemini-review").checked,
    agent_ollama_fallback: $("setting-ollama-fallback").checked,
    openrouter_zdr: $("setting-openrouter-zdr").checked,
    ui_agent_vision_enabled: $("setting-ui-vision-enabled").checked,
    agent_provider: settingValue("setting-provider"),
    ollama_base_url: settingValue("setting-ollama-url"),
    ollama_model: settingValue("setting-ollama-model"),
    ollama_models_dir: settingValue("setting-models-dir"),
    gemini_model: settingValue("setting-gemini-model"),
    openrouter_model: settingValue("setting-openrouter-model"),
    ui_agent_provider: settingValue("setting-ui-provider"),
    ui_agent_model: settingValue("setting-ui-model"),
    agent_context_tokens: settingNumber("setting-context-tokens"),
    agent_max_steps: settingNumber("setting-max-steps"),
    agent_max_tool_calls: settingNumber("setting-max-tools"),
    agent_time_budget_seconds: settingNumber("setting-time-budget"),
    agent_provider_timeout_seconds: settingNumber("setting-provider-timeout"),
    clear_gemini_api_key: $("clear-gemini-key").checked,
    clear_openrouter_api_key: $("clear-openrouter-key").checked,
    clear_virustotal_api_key: $("clear-vt-key").checked,
  };
  const geminiKey = settingValue("setting-gemini-key");
  const openrouterKey = settingValue("setting-openrouter-key");
  const vtKey = settingValue("setting-vt-key");
  if (geminiKey) data.gemini_api_key = geminiKey;
  if (openrouterKey) data.openrouter_api_key = openrouterKey;
  if (vtKey) data.virustotal_api_key = vtKey;
  return data;
}

async function saveSettings() {
  const response = await fetch(`${API}/api/settings`, {
    method: "PUT",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(collectSettings()),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || "Could not save settings");
  renderSettings(data);
  await refreshHealth();
  return data;
}

$("settings-open")?.addEventListener("click", async () => {
  const dialog = $("settings-dialog");
  dialog.showModal();
  setSettingsStatus("Loading settings...");
  try {
    await Promise.all([loadSettings(), loadComponents()]);
    setSettingsStatus("Settings are stored locally on this computer.");
  } catch (error) {
    setSettingsStatus(error.message, "danger");
  }
});
$("settings-close")?.addEventListener("click", () => $("settings-dialog")?.close());
$("settings-dialog")?.addEventListener("click", event => {
  if (event.target === $("settings-dialog")) $("settings-dialog").close();
});
$("settings-form")?.addEventListener("submit", async event => {
  event.preventDefault();
  const button = $("settings-save");
  setButtonBusy(button, true, "Saving...");
  setSettingsStatus("Validating settings...");
  try {
    await saveSettings();
    setSettingsStatus("Settings saved and applied.", "success");
  } catch (error) {
    setSettingsStatus(error.message, "danger");
  } finally {
    setButtonBusy(button, false);
  }
});
$("settings-test")?.addEventListener("click", async () => {
  const button = $("settings-test");
  setButtonBusy(button, true, "Testing...");
  setSettingsStatus("Saving settings and checking the selected provider...");
  try {
    await saveSettings();
    const response = await fetch(`${API}/api/settings/test-provider`, {method: "POST"});
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || "Provider check failed");
    const provider = data.provider_health || {};
    if (!provider.available) throw new Error(provider.reason || "Provider is unavailable");
    const installed = provider.installed_models?.length ? ` ${provider.installed_models.length} local model(s) found.` : "";
    setSettingsStatus(`${provider.provider} / ${provider.model} is ready.${installed}`, "success");
  } catch (error) {
    setSettingsStatus(error.message, "danger");
  } finally {
    setButtonBusy(button, false);
  }
});
$("settings-import-model")?.addEventListener("click", async () => {
  const button = $("settings-import-model");
  const modelPath = settingValue("setting-gguf-path");
  const modelName = settingValue("setting-import-name");
  setButtonBusy(button, true, "Importing...");
  setSettingsStatus("Ollama is importing the GGUF. Large models can take several minutes.");
  try {
    const response = await fetch(`${API}/api/settings/import-model`, {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({model_path: modelPath, model_name: modelName}),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || "Model import failed");
    $("setting-ollama-model").value = data.model;
    await loadSettings();
    setSettingsStatus(`${data.model} was imported and selected.`, "success");
  } catch (error) {
    setSettingsStatus(error.message, "danger");
  } finally {
    setButtonBusy(button, false);
  }
});

function setButtonBusy(button, busy, busyLabel) {
  if (!button) return;
  if (busy && !button.dataset.idleHtml) button.dataset.idleHtml = button.innerHTML;
  button.setAttribute("aria-busy", String(busy));
  button.classList.toggle("btn-busy", busy);
  button.disabled = busy;
  if (busy) {
    button.textContent = busyLabel;
  } else if (button.dataset.idleHtml) {
    button.innerHTML = button.dataset.idleHtml;
  }
}

// --- Gemini badge ---
let healthData = {};
function refreshHealth() {
  return fetch(`${API}/api/health`).then(r => r.json()).then(h => {
    healthData = h;
    let badges = h.gemini_configured
      ? '<span class="chip chip-success">Gemini connected</span>'
      : '<span class="chip">Template mode (no GEMINI_API_KEY)</span>';
    if (h.openrouter_configured) {
      badges += ' <span class="chip chip-success">OpenRouter connected</span>';
    }
    if (h.analyzer_ready === false) {
      badges += ' <span class="chip chip-danger">Engine offline: start from .venv</span>';
    }
    if (h.agentic?.enabled) {
      badges += ` <span class="chip chip-info">AI Review: ${esc(h.agentic.provider)} / ${esc(h.agentic.model)}</span>`;
    }
    if (h.agentic_workflow?.enabled) {
      badges += ' <span class="chip chip-warning">Agentic Investigation enabled</span>';
    }
    $("gemini-badge").innerHTML = badges;
    updateEmuStatus();
    if (currentAnalysis) renderWorkflow(currentAnalysis.agentic_workflow);
  }).catch(() => {});
}
function updateEmuStatus() {
  const el = $("emu-status"); if (!el) return;
  const d = healthData.dynamic || {};
  const sel = $("dyn-device");
  const uiAgent = $("dyn-ui-agent");
  const uiMode = $("dyn-ui-agent-mode");
  if (uiAgent) {
    uiAgent.disabled = !healthData.ui_agent?.enabled;
    if (!healthData.ui_agent?.enabled) uiAgent.checked = false;
  }
  if (uiMode) {
    const visionOption = uiMode.querySelector('option[value="vision"]');
    if (visionOption) visionOption.disabled = !healthData.ui_agent?.vision_enabled;
    if (!healthData.ui_agent?.vision_enabled && uiMode.value === "vision") uiMode.value = "tree";
    uiMode.disabled = !healthData.ui_agent?.enabled || !uiAgent?.checked;
  }
  const uiNote = $("dyn-agent-note");
  if (uiNote) uiNote.textContent = healthData.ui_agent?.enabled
    ? `AI UI Explorer is ready (${healthData.ui_agent.provider} / ${healthData.ui_agent.model}). Choose UI tree${healthData.ui_agent.vision_enabled ? " or vision-assisted exploration" : " mode; screenshot vision is unavailable"}. Synthetic data only; high-impact actions are blocked and audited.`
    : "The UI agent is disabled on this server. Set UI_AGENT_ENABLED=true to enable it; real credentials and payment data are never used.";
  const workflowVision = $("workflow-vision"), workflowVisionState = $("workflow-vision-state");
  const visionReady = Boolean(healthData.ui_agent?.enabled && healthData.ui_agent?.vision_enabled);
  if (workflowVision && !currentAnalysis?.agentic_workflow) {
    workflowVision.disabled = !visionReady;
    workflowVision.checked = visionReady;
  }
  if (workflowVisionState) workflowVisionState.textContent = visionReady
    ? `Available: ${healthData.ui_agent.provider} / ${healthData.ui_agent.model}`
    : "Unavailable globally; enable screenshot vision in Settings.";
  if (d.available) {
    const dev = d.device || {};
    if (d.sandbox_present) {
      el.innerHTML = `<span class="chip chip-success"><i class="ti ti-device-mobile" aria-hidden="true"></i> ${esc(dev.avd_name || d.serial)}${dev.android_version ? ", Android " + esc(dev.android_version) : ""}</span>`
        + (healthData.frida_available ? ` <span class="chip chip-info">Frida ready</span>` : "");
    } else {
      el.innerHTML = `<span class="chip chip-warning">${esc(d.preferred_avd)} not running: pick a device deliberately</span>`;
    }
    if (sel) {
      const devices = d.devices || [];
      let opts = devices.map(x => {
        const name = x.avd_name || x.serial;
        const isSandbox = name === d.preferred_avd;
        return `<option value="${esc(x.serial)}" ${x.serial === d.serial ? "selected" : ""}>${isSandbox ? "[Sandbox] " : ""}${esc(name)} (${esc(x.serial)})</option>`;
      });
      if (!d.sandbox_present) opts.unshift(`<option value="" selected disabled>Select a device</option>`);
      sel.innerHTML = opts.join("");
    }
  } else {
    el.innerHTML = `<span class="chip">No emulator attached</span>`;
    if (sel) sel.innerHTML = `<option value="">No device available</option>`;
  }
}
refreshHealth();

$("dyn-ui-agent")?.addEventListener("change", event => {
  const mode = $("dyn-ui-agent-mode");
  if (mode) mode.disabled = !event.target.checked;
});

// --- File selection ---
const dropzone = $("dropzone"), fileInput = $("file-input"), folderInput = $("folder-input");
dropzone.addEventListener("click", () => fileInput.click());
dropzone.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    fileInput.click();
  }
});
dropzone.addEventListener("dragover", (e) => { e.preventDefault(); dropzone.classList.add("is-dragging"); });
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("is-dragging"));
dropzone.addEventListener("drop", (e) => {
  e.preventDefault(); dropzone.classList.remove("is-dragging");
  const apks = Array.from(e.dataTransfer.files || []).filter(file => file.name.toLowerCase().endsWith(".apk"));
  if (apks.length > 1) setBatchFiles(apks);
  else if (apks.length === 1) setFile(apks[0]);
  else showError("Please select a .apk file or a folder containing APKs.");
});
fileInput.addEventListener("change", () => { if (fileInput.files.length) setFile(fileInput.files[0]); });
$('folder-select-btn').addEventListener("click", () => folderInput.click());
folderInput.addEventListener("change", () => setBatchFiles(Array.from(folderInput.files || [])));

function setAnalyzeIdleLabel(label) {
  const button = $("analyze-btn");
  button.textContent = label;
  button.dataset.idleHtml = button.innerHTML;
}

function setFile(f) {
  if (!f.name.toLowerCase().endsWith(".apk")) {
    selectedFile = null;
    $("file-name").textContent = "";
    $("analyze-btn").disabled = true;
    dropzone.classList.remove("has-file");
    showError("Please select a .apk file.");
    return;
  }
  selectedFile = f;
  selectedBatchFiles = [];
  folderInput.value = "";
  $("file-name").textContent = `Selected: ${plain(f.name)}, ${(f.size / 1048576).toFixed(2)} MB`;
  setAnalyzeIdleLabel("Analyze APK");
  $("analyze-btn").disabled = false;
  dropzone.classList.add("has-file");
  hideError();
}

function setBatchFiles(files) {
  const apks = files.filter(file => file.name.toLowerCase().endsWith(".apk"));
  if (!apks.length) {
    selectedBatchFiles = [];
    $("file-name").textContent = "";
    $("analyze-btn").disabled = true;
    dropzone.classList.remove("has-file");
    showError("The selected folder does not contain any APK files.");
    return;
  }
  selectedFile = null;
  selectedBatchFiles = apks;
  fileInput.value = "";
  const totalMb = apks.reduce((sum, file) => sum + file.size, 0) / 1048576;
  const firstPath = apks[0].webkitRelativePath || apks[0].name;
  const folder = firstPath.includes("/") ? firstPath.split("/")[0] : "selected folder";
  $("file-name").textContent = `Selected: ${plain(folder)} - ${apks.length} APK(s), ${totalMb.toFixed(2)} MB`;
  setAnalyzeIdleLabel(`Analyze ${apks.length} APK${apks.length === 1 ? "" : "s"}`);
  $("analyze-btn").disabled = false;
  dropzone.classList.add("has-file");
  hideError();
}

// --- Analyze ---
const ANALYSIS_PHASE_LABELS = {
  queued: "Queued behind another analysis…",
  starting: "Starting analysis worker…",
  static_analysis: "Extracting static APK evidence…",
  intelligence: "Checking optional threat intelligence…",
  ai_review: "Reviewing extracted evidence…",
  reporting: "Generating the analyst report…",
};

async function waitForAnalysisJob(jobId) {
  for (let attempt = 0; attempt < 2400; attempt += 1) {
    const response = await fetch(`${API}/api/analysis-jobs/${encodeURIComponent(jobId)}`);
    const job = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(job.detail || "Could not read analysis progress");
    if (job.status === "completed" && job.sample_id) return job;
    if (job.status === "failed") throw new Error(job.message || "Analysis failed");
    $("loading-text").textContent = ANALYSIS_PHASE_LABELS[job.phase]
      || plain(job.message || "Analysis is running…");
    await new Promise(resolve => setTimeout(resolve, 750));
  }
  throw new Error("Analysis is still running. It will remain available in Recent Analyses when complete.");
}

function renderBatchProgress() {
  const jobs = Array.from(batchJobs.values());
  const completed = jobs.filter(job => job.status === "completed").length;
  const failed = jobs.filter(job => job.status === "failed").length;
  const active = jobs.length - completed - failed;
  $("batch-card").classList.remove("hidden");
  $("batch-summary").textContent = `${completed} completed - ${active} active${failed ? ` - ${failed} failed` : ""}`;
  $("batch-export-btn").disabled = !jobs.length || active > 0;
  $("batch-list").innerHTML = jobs.map(job => {
    const sample = job.sample;
    const status = job.status || "queued";
    const detail = status === "failed"
      ? (job.error || job.message || "Analysis failed")
      : (ANALYSIS_PHASE_LABELS[job.phase] || job.message || "Waiting for analysis capacity.");
    const score = sample?.analysis?.risk_score;
    const severity = sample?.analysis?.severity;
    return `<div class="batch-row" data-batch-job="${esc(job.id)}">
      <div class="min-w-0"><div class="batch-file">${esc(job.relativePath || job.filename)}</div><div class="batch-detail">${esc(detail)}</div></div>
      <div class="batch-score">${score == null ? "" : `${Number(score)}/100 - ${esc(severity || "Unknown")}`}</div>
      ${job.sample_id ? `<button type="button" class="btn-secondary batch-open" data-batch-open="${esc(job.id)}">View result</button>` : `<span class="chip ${statusChipTone(status)}">${esc(status)}</span>`}
    </div>`;
  }).join("");
}

function batchClassification(job) {
  if (job.status === "failed") return "Analysis failed";
  const rawScore = job.sample?.analysis?.risk_score;
  if (rawScore == null || rawScore === "") return "Unknown";
  const score = Number(rawScore);
  if (!Number.isFinite(score)) return "Unknown";
  if (score >= 41) return "Likely malicious";
  if (score >= 21) return "Suspicious";
  return "Not flagged";
}

function csvCell(value) {
  let text = plain(value).replace(/\r?\n/g, " ");
  // Prevent spreadsheet applications from evaluating attacker-controlled metadata.
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

function exportBatchCsv() {
  const jobs = Array.from(batchJobs.values());
  if (!jobs.length || jobs.some(job => !["completed", "failed"].includes(job.status))) return;
  const headers = [
    "apk_name", "package_name", "sha256", "risk_score", "severity",
    "classification", "analysis_status", "sample_id",
  ];
  const rows = jobs.map(job => {
    const sample = job.sample || {};
    const analysis = sample.analysis || {};
    const score = analysis.risk_score;
    return [
      job.relativePath || job.filename,
      sample.package_name || analysis.manifest?.package_name || "",
      sample.sha256 || analysis.file?.sha256 || "",
      score != null && score !== "" && Number.isFinite(Number(score)) ? Number(score) : "",
      analysis.severity || "",
      batchClassification(job),
      job.status || "unknown",
      job.sample_id || "",
    ];
  });
  const csv = [headers, ...rows].map(row => row.map(csvCell).join(",")).join("\r\n");
  const blob = new Blob(["\uFEFF", csv], {type: "text/csv;charset=utf-8"});
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `apk-batch-results-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

async function loadBatchSample(job) {
  if (!job.sample_id || job.sample) return;
  const response = await fetch(`${API}/api/samples/${encodeURIComponent(job.sample_id)}`);
  if (response.ok) job.sample = await response.json();
}

async function waitForBatchJobs() {
  for (let attempt = 0; attempt < 2400; attempt += 1) {
    const pending = Array.from(batchJobs.values()).filter(
      job => job.status !== "completed" && job.status !== "failed",
    );
    if (!pending.length) {
      await Promise.all(Array.from(batchJobs.values()).map(loadBatchSample));
      renderBatchProgress();
      return;
    }
    await Promise.all(pending.map(async existing => {
      const response = await fetch(`${API}/api/analysis-jobs/${encodeURIComponent(existing.id)}`);
      const update = await response.json().catch(() => ({}));
      if (!response.ok) {
        Object.assign(existing, {status: "failed", error: update.detail || "Could not read job progress"});
        return;
      }
      Object.assign(existing, update);
      if (existing.status === "completed") await loadBatchSample(existing);
    }));
    renderBatchProgress();
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  throw new Error("Batch analysis is still running. Completed samples remain available in Recent Analyses.");
}

async function analyzeBatch(files) {
  batchJobs.clear();
  $("results").classList.add("hidden");
  $("batch-card").classList.remove("hidden");
  $("batch-summary").textContent = "Uploading selected APKs...";
  $("batch-list").innerHTML = "";
  const form = new FormData();
  files.forEach(file => form.append("files", file, file.name));
  const response = await fetch(`${API}/api/analysis-jobs/batch`, {method: "POST", body: form});
  const submitted = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(submitted.detail || "Could not start folder analysis");
  submitted.jobs.forEach((job, index) => batchJobs.set(job.id, {
    ...job,
    clientFile: files[index],
    relativePath: files[index]?.webkitRelativePath || files[index]?.name || job.filename,
  }));
  renderBatchProgress();
  await waitForBatchJobs();
  await loadHistory();
}

$("batch-list").addEventListener("click", event => {
  const button = event.target.closest("[data-batch-open]");
  if (!button) return;
  const job = batchJobs.get(button.dataset.batchOpen);
  if (!job?.sample_id) return;
  if (job.clientFile) setFile(job.clientFile);
  openSample(job.sample_id);
});

$("batch-export-btn").addEventListener("click", exportBatchCsv);

$("analyze-btn").addEventListener("click", async () => {
  if (!selectedFile && !selectedBatchFiles.length) return;
  hideError();
  if (selectedBatchFiles.length) {
    const files = [...selectedBatchFiles];
    setButtonBusy($("analyze-btn"), true, `Analyzing ${files.length} APKs...`);
    try {
      await analyzeBatch(files);
    } catch (e) {
      showError(e.message);
    } finally {
      setButtonBusy($("analyze-btn"), false);
      $("analyze-btn").disabled = !selectedFile && !selectedBatchFiles.length;
    }
    return;
  }
  $("results").classList.add("hidden");
  $("loading").classList.remove("hidden");
  setButtonBusy($("analyze-btn"), true, "Analyzing APK…");

  const fd = new FormData();
  fd.append("file", selectedFile);
  try {
    const res = await fetch(`${API}/api/analysis-jobs`, { method: "POST", body: fd });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || "Analysis failed");
    }
    const submitted = await res.json();
    const completed = await waitForAnalysisJob(submitted.id);
    await openSample(completed.sample_id);
  } catch (e) {
    showError(e.message);
  } finally {
    $("loading").classList.add("hidden");
    $("loading-text").textContent = "Decompiling & analyzing APK…";
    setButtonBusy($("analyze-btn"), false);
    $("analyze-btn").disabled = !selectedFile;
  }
});

// --- Rendering ---
function render(a, report) {
  currentAnalysis = a;
  currentReport = report;
  // A failed/incomplete parse must NOT look like a clean "Low" app.
  if (a.valid_apk === false || a.risk_score == null || a.severity === "Unknown") {
    showError("Analysis could not complete. The file may not be a valid or parseable APK. "
      + ((a.errors && a.errors.length) ? a.errors.join("; ") : "No findings were extracted."));
    $("results").classList.add("hidden");
    return;
  }
  if (a.analysis_quality === "partial") {
    showError("Partial analysis: the manifest and bounded raw indicators were recovered, "
      + "but malformed DEX prevented control-flow analysis. Treat this result as incomplete "
      + "and do not clear the APK without manual or isolated dynamic review.");
  } else {
    hideError();
  }
  const sev = a.severity || "Low";
  const color = SEV_COLORS[sev] || "#94a3b8";

  // Gauge
  drawGauge(a.risk_score || 0, color);
  $("score-num").textContent = a.risk_score ?? 0;
  const chip = $("severity-chip");
  chip.textContent = sev;
  chip.className = `chip mt-2 ${severityChipTone(sev)}`;
  $("severity-scale").dataset.active = sev.toLowerCase();

  // Meta
  const m = a.manifest || {}, f = a.file || {};
  $("case-title").textContent = plain(f.filename || "Analyzed APK");
  $("case-package").textContent = plain(m.package_name || "Package unavailable");
  $("meta").innerHTML = [
    ["Version", m.version_name || "Not reported"], ["Size", `${((f.file_size||0)/1048576).toFixed(2)} MB`],
    ["SHA256", short(f.sha256)], ["MD5", short(f.md5)],
    ["Min SDK", m.min_sdk || "Not reported"], ["Target SDK", m.target_sdk || "Not reported"],
    ["Analysis", a.analysis_quality === "partial" ? "Partial" : "Full"],
  ].map(([k, v]) => `<div><span class="text-[10px] uppercase tracking-wide text-slate-600">${k}</span><br><span class="text-slate-200 break-all font-medium">${esc(v||"Not reported")}</span></div>`).join("");

  $("threat").textContent = plain(report.threat_assessment || "Unknown");
  $("threat").style.color = color;
  const permissionCount = (a.permissions?.dangerous || []).length;
  const apiCount = (a.apis?.suspicious_apis || []).length;
  const iocCount = ["domains", "urls", "ips", "telegram_tokens", "hardcoded_secrets"]
    .reduce((total, key) => total + ((a.iocs?.[key] || []).length), 0);
  const signatureCount = (a.yara?.matches || []).length;
  $("stat-perms").textContent = permissionCount;
  $("stat-apis").textContent = apiCount;
  $("stat-iocs").textContent = iocCount;
  $("stat-signatures").textContent = signatureCount;

  // AI summary
  $("exec-summary").textContent = plain(report.executive_summary || "No narrative summary was produced.");
  $("tech-summary").textContent = plain(report.technical_summary || "");
  $("behaviors").innerHTML = (a.detected_behaviors || []).map(
    b => `<span class="chip chip-info">${esc(b)}</span>`).join("") ||
    '<span class="text-slate-500 text-sm">No high-risk behaviours flagged.</span>';
  renderAgent(a.agentic);
  renderWorkflow(a.agentic_workflow);

  // Breakdown
  $("breakdown").innerHTML = (a.score_breakdown || []).map(b => `
    <div class="finding-row">
      <div class="finding-score" style="color:${color}">+${Number(b.points) || 0}</div>
      <div><div class="finding-name">${esc(b.category)}</div><div class="finding-detail">${esc(b.detail||"No detail supplied")}</div></div>
    </div>`).join("") || '<p class="text-slate-500 text-sm">No risk contributions.</p>';

  // Permissions
  $("perms").innerHTML = (a.permissions?.dangerous || []).map(p => `
    <div class="finding-row">
      <div class="finding-score text-rose-300">+${Number(p.score) || 0}</div>
      <div><div class="finding-name font-mono">${esc(p.name)}</div><div class="finding-detail">${esc(p.reason)}</div></div>
    </div>`).join("") || '<p class="text-slate-500 text-sm">No dangerous permissions.</p>';

  // APIs
  $("apis").innerHTML = (a.apis?.suspicious_apis || []).map(x => `
    <div class="finding-row">
      <div class="finding-score text-amber-300">+${Number(x.score) || 0}</div>
      <div><div class="finding-name font-mono">${esc(x.api)}</div><div class="finding-detail">${esc(x.behaviour)}. ${esc(x.evidence || "Evidence location unavailable")}</div></div>
    </div>`).join("") || '<p class="text-slate-500 text-sm">No suspicious APIs detected.</p>';

  // IOCs
  const i = a.iocs || {};
  const iocBlock = (label, arr) => (arr && arr.length)
    ? `<div class="ioc-group"><span class="ioc-label">${label}</span><span class="ioc-values">${arr.slice(0,15).map(esc).join("<br>")}</span></div>` : "";
  $("iocs").innerHTML = [
    iocBlock("Domains", i.domains), iocBlock("URLs", i.urls), iocBlock("IPs", i.ips),
    iocBlock("Telegram tokens", i.telegram_tokens), iocBlock("Secrets", i.hardcoded_secrets),
    (i.suspicious_keywords?.length ? `<div class="ioc-group"><span class="ioc-label">Keywords</span><span class="ioc-values">${i.suspicious_keywords.map(k=>esc(k.keyword)).join(", ")}</span></div>` : ""),
    (i.decoded_blobs ? `<div class="text-xs text-slate-500 px-1">${i.decoded_blobs} encoded blob(s) decoded and rescanned${i.native_strings_scanned ? `. ${i.native_strings_scanned} native-library strings scanned` : ""}</div>` : ""),
  ].filter(Boolean).join("") || '<p class="text-slate-500">No network IOCs found in static strings.</p>';

  // Recommendations
  $("recs").innerHTML = (report.recommended_actions || a.recommendations || []).map(
    (r, index) => `<li class="recommendation-item" data-index="${String(index + 1).padStart(2, "0")}">${esc(r)}</li>`).join("")
    || '<li class="text-slate-500">No specific actions.</li>';

  // YARA panel
  const yara = a.yara || {};
  if (yara.matches && yara.matches.length) {
    $("yara-card").classList.remove("hidden");
    $("yara-body").innerHTML = yara.matches.map(m => `
      <div class="finding-row">
        <div class="finding-score text-rose-300">+${Number(m.score) || 0}</div>
        <div><div class="finding-name font-mono">${esc(m.rule)}</div><div class="finding-detail">${esc(m.description)}${m.attack ? `. ATT&CK ${esc(m.attack)}` : ""}</div></div>
      </div>`).join("");
  } else {
    $("yara-card").classList.add("hidden");
  }

  // MITRE panel
  const mitre = a.mitre || {};
  if (mitre.techniques && mitre.techniques.length) {
    $("mitre-card").classList.remove("hidden");
    $("mitre-body").innerHTML = mitre.techniques.map(t =>
      `<a href="${t.url}" target="_blank" rel="noopener noreferrer" class="chip chip-info" title="${t.tactic}">${t.id} ${t.name}</a>`
    ).join("");
  } else {
    $("mitre-card").classList.add("hidden");
  }

  // ML panel
  const ml = a.ml || {};
  if (ml.available && ml.malware_probability != null) {
    $("ml-card").classList.remove("hidden");
    const prob = ml.malware_probability, pct = Math.round(prob * 100);
    const c = prob >= 0.5 ? "#ef4444" : "#22c55e";
    const m = ml.model_metrics || {};
    $("ml-body").innerHTML =
      `<div class="flex items-baseline gap-2 mb-2"><span class="text-2xl font-medium font-mono" style="color:${c}">${pct}%</span>`
      + `<span class="text-slate-400">ML decision: <span class="font-medium" style="color:${c}">${esc((ml.prediction||"").replace("_", " ").toUpperCase())}</span></span></div>`
      + `<div class="h-px mb-3" style="width:${pct}%;background:${c}"></div>`
      + ((ml.contributing_permissions||[]).length
          ? `<div class="text-xs text-slate-400 mb-1">Top contributing permissions:</div><div class="flex flex-wrap gap-1.5">`
            + ml.contributing_permissions.map(p => `<span class="chip chip-info">${esc(p.permission)}</span>`).join("") + `</div>`
          : "")
      + (m.f1_malware != null ? `<div class="text-xs text-slate-500 mt-3">Model: precision ${m.precision_malware?.toFixed(2)}, recall ${m.recall_malware?.toFixed(2)}, F1 ${m.f1_malware?.toFixed(2)}${m.roc_auc!=null?`, AUC ${m.roc_auc.toFixed(2)}`:""} (n=${m.n_samples})</div>` : "");
  } else {
    $("ml-card").classList.add("hidden");
  }

  // APKiD panel
  const apkid = a.apkid || {};
  if ((apkid.findings && apkid.findings.length) || (apkid.compilers && apkid.compilers.length)) {
    $("apkid-card").classList.remove("hidden");
    $("apkid-body").innerHTML =
      (apkid.findings || []).map(f =>
        `<div><span class="chip chip-warning">${esc(f.category)}</span> <span class="text-slate-200 font-mono text-xs">${esc(f.name)}</span></div>`).join("")
      + ((apkid.compilers || []).length ? `<div class="text-xs text-slate-500 mt-1">Compiler: ${apkid.compilers.map(esc).join(", ")}</div>` : "")
      + (!(apkid.findings||[]).length ? `<div class="text-slate-500 text-xs">No packer/obfuscator/anti-analysis tooling detected.</div>` : "");
  } else {
    $("apkid-card").classList.add("hidden");
  }

  // VirusTotal panel
  const vt = a.virustotal;
  const vtCard = $("vt-card"), vtBody = $("vt-body");
  if (vt && vt.queried) {
    vtCard.classList.remove("hidden");
    const fr = vt.file || {};
    if (fr.found) {
      const mal = fr.malicious || 0, tot = fr.total_engines || 0;
      const c = mal > 0 ? "#ef4444" : "#22c55e";
      vtBody.innerHTML =
        `<div class="flex items-baseline gap-2 mb-2"><span class="text-2xl font-medium font-mono" style="color:${c}">${mal}</span>`
        + `<span class="text-slate-400">/ ${tot} engines flagged this file as malicious</span></div>`
        + (fr.threat_label ? `<div class="mb-2">Threat label: <span class="font-mono text-amber-300">${esc(fr.threat_label)}</span></div>` : "")
        + ((fr.engine_hits || []).length
            ? `<div class="text-xs text-slate-400 mb-1">Detections:</div><div class="flex flex-wrap gap-1.5">`
              + fr.engine_hits.slice(0, 14).map(h => `<span class="chip chip-danger" title="${esc(h.engine)}">${esc(h.result)}</span>`).join("") + `</div>`
            : "")
        + ((vt.flagged_domains || []).length
            ? `<div class="mt-3 text-xs text-slate-400">Flagged domains: <span class="text-red-300 font-mono">${vt.flagged_domains.map(d => esc(d.domain)).join(", ")}</span></div>` : "")
        + (fr.permalink ? `<a href="${esc(safeHttpUrl(fr.permalink))}" target="_blank" rel="noopener noreferrer" class="inline-block mt-3 text-cyan-400 text-xs underline">View full VirusTotal report ↗</a>` : "");
    } else {
      vtBody.innerHTML = `<p class="text-slate-400">${esc(fr.note || fr.error || "Not found on VirusTotal.")}</p>`;
    }
  } else {
    vtCard.classList.add("hidden");
  }

  // Certificate + attack surface panel
  const cert = a.certificate || {}, comp = a.components || {};
  if (cert.present || (comp.exported && comp.exported.length) || (cert.flags && cert.flags.length)) {
    $("cert-card").classList.remove("hidden");
    let html = "";
    if (cert.present) {
      html += `<div><span class="text-slate-400">Subject:</span> <span class="text-slate-200 font-mono text-xs">${esc(cert.subject || "Not reported")}</span></div>`;
      if (cert.validity_years != null) html += `<div><span class="text-slate-400">Validity:</span> ${cert.validity_years} yrs${cert.self_signed ? ", self-signed" : ""}</div>`;
      if (cert.sha256) html += `<div><span class="text-slate-400">Cert SHA256:</span> <span class="font-mono text-xs">${short(cert.sha256)}</span></div>`;
    }
    (cert.flags || []).forEach(f =>
      html += `<div><span class="chip chip-danger">${esc(f.flag)}</span> <span class="text-slate-400 text-xs">${esc(f.detail)}</span></div>`);
    if (comp.count) html += `<div class="mt-1"><span class="text-slate-400">Exported components:</span> ${comp.count} (${comp.unguarded_count || 0} unguarded)</div>`;
    $("cert-body").innerHTML = html;
  } else {
    $("cert-card").classList.add("hidden");
  }

  $("pdf-btn").onclick = () => window.open(`${API}/api/samples/${currentId}/report.pdf`, "_blank");
  $("ioc-csv-btn").onclick = () => window.open(`${API}/api/samples/${currentId}/iocs.csv`, "_blank");
  $("ioc-json-btn").onclick = () => window.open(`${API}/api/samples/${currentId}/iocs.json`, "_blank");

  $("results").classList.remove("hidden");
  $("results").scrollIntoView({ behavior: "smooth", block: "start" });
  loadHistory();
}

function renderAgent(agent) {
  const body = $("agent-body"), button = $("agent-run-btn");
  if (!body || !button) return;
  const enabled = Boolean(healthData.agentic?.enabled);
  button.disabled = !enabled || !currentId;
  if (!agent) {
    body.innerHTML = enabled
      ? '<p class="text-slate-400">Ready. The model will choose from server-defined evidence tools; every action will be audited.</p>'
      : '<p class="text-slate-500">Disabled. Set <code>AGENT_ENABLED=true</code> to enable the bounded investigator.</p>';
    return;
  }
  const hypothesisCards = (agent.hypotheses || []).map(h => `
    <div class="agent-hypothesis">
      <div class="flex gap-2 items-start"><span class="chip chip-info shrink-0">${esc(h.confidence)}</span><span class="text-slate-200">${esc(h.claim)}</span></div>
      <div class="mt-2 text-xs text-slate-500">Evidence: ${(h.evidence_ids || []).map(esc).join(", ")}</div>
    </div>`);
  const primaryHypotheses = hypothesisCards.slice(0, 3).join("") || '<p class="text-slate-500">No grounded hypothesis was produced.</p>';
  const additionalHypotheses = hypothesisCards.slice(3).join("");
  const audit = (agent.audit || []).map(step => `
    <div class="flex justify-between gap-3 border-b border-slate-800 py-1.5">
      <span><span class="text-slate-500">${esc(step.step)}.</span> ${esc(step.action)}</span>
      <span class="text-xs ${step.status === "completed" || step.status === "ok" ? "text-cyan-400" : step.status === "approval_required" ? "text-amber-400" : "text-rose-400"}">${esc(step.status)}${step.executed === false ? ", not executed" : ""}</span>
    </div>`).join("");
  const gaps = (agent.gaps || []).map(g => `<li>${esc(g)}</li>`).join("");
  const review = agent.gemini_review ? `<div class="mt-3 text-xs text-slate-400">Gemini review: <span class="${agent.gemini_review.grounded ? "text-emerald-400" : "text-amber-400"}">${agent.gemini_review.grounded ? "grounded" : "issues found"}</span>${(agent.gemini_review.unsupported_claims || []).length ? `. Unsupported: ${agent.gemini_review.unsupported_claims.map(esc).join("; ")}` : ""}</div>` : "";
  body.innerHTML = `
    <div class="flex flex-wrap gap-2 mb-3"><span class="chip ${statusChipTone(agent.status)}">${esc(agent.status)}</span><span class="chip">${esc(agent.provider || "Unavailable")} / ${esc(agent.model || "Unavailable")}</span><span class="chip">${esc(agent.steps_used || 0)} steps, ${esc(agent.duration_ms || 0)} ms</span></div>
    <div class="space-y-2">${primaryHypotheses}</div>
    ${(additionalHypotheses || gaps || review || audit) ? `<details class="mt-4"><summary class="cursor-pointer text-xs font-medium text-cyan-500">View full AI Review${additionalHypotheses ? ` (${hypothesisCards.length} findings)` : ""}</summary>
      <div class="mt-3 space-y-2">${additionalHypotheses}</div>
      ${gaps ? `<div class="mt-3"><div class="text-xs uppercase tracking-wide text-slate-500">Evidence gaps</div><ul class="list-disc pl-5 mt-1 text-slate-400">${gaps}</ul></div>` : ""}
      ${review}
      <div class="mt-4"><div class="text-xs uppercase tracking-wide text-slate-500">Action audit (${(agent.audit || []).length})</div><div class="mt-2">${audit || "No actions."}</div></div>
    </details>` : ""}`;
}

$("agent-run-btn")?.addEventListener("click", async () => {
  if (!currentId) return;
  const button = $("agent-run-btn"), body = $("agent-body");
  const provider = healthData.agentic?.provider || "unknown";
  const model = healthData.agentic?.model || "unknown";
  const location = provider === "ollama" ? "locally through Ollama" : `through hosted ${provider}`;
  setButtonBusy(button, true, "Reviewing…");
  body.innerHTML = `<p class="text-cyan-300">AI Review is using <strong>${esc(model)}</strong> ${esc(location)}. Only extracted evidence is provided; the APK itself is not sent to the model.</p>`;
  try {
    const response = await fetch(`${API}/api/agent/investigate/${encodeURIComponent(currentId)}`, {method: "POST"});
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || "AI Review failed");
    currentAnalysis.agentic = data.agentic;
    currentReport = data.report || currentReport;
    $("exec-summary").textContent = plain(currentReport.executive_summary || "No narrative summary was produced.");
    $("tech-summary").textContent = plain(currentReport.technical_summary || "");
    renderAgent(data.agentic);
  } catch (error) {
    body.innerHTML = `<p class="text-rose-400">${esc(error.message)}</p>`;
  } finally {
    setButtonBusy(button, false);
    button.disabled = !healthData.agentic?.enabled;
  }
});

function workflowActionLabel(proposal) {
  const config = proposal?.config || {};
  if (config.use_frida) return "Approve Frida run";
  if (config.use_ui_agent && config.ui_agent_mode === "vision") return "Approve vision run";
  if (config.use_ui_agent) return "Approve UI-tree run";
  return "Approve baseline run";
}

function setWorkflowStatus(message = "", tone = "info") {
  const status = $("workflow-status");
  if (!status) return;
  status.textContent = plain(message);
  status.classList.toggle("hidden", !message);
  status.className = `mx-5 mt-4 rounded-lg border px-3 py-2 text-xs ${
    tone === "danger" ? "border-rose-400/40 text-rose-500" :
    tone === "success" ? "border-emerald-400/40 text-emerald-500" :
    "border-cyan-400/40 text-cyan-500"
  }${message ? "" : " hidden"}`;
}

let workflowProgressTimer = null;

function renderWorkflowProgress(progress) {
  const live = $("workflow-live");
  if (!live) return;
  const events = progress?.events || [];
  live.classList.toggle("hidden", !events.length);
  if (!events.length) return;
  live.innerHTML = `<div class="flex items-center justify-between gap-3 mb-2"><div><div class="text-xs uppercase tracking-wide text-cyan-500">Live investigation activity</div><div class="text-[11px] text-slate-500 mt-0.5">High-level actions and stated rationales, not private chain-of-thought.</div></div>${progress.active ? '<span class="chip chip-info">live</span>' : '<span class="chip chip-success">finished</span>'}</div>`
    + events.map(event => `<div class="border-t border-slate-800/70 py-2 text-xs">
      <div class="flex justify-between gap-3"><span class="text-slate-200">${esc(event.message)}</span><span class="text-slate-500">${esc(event.phase)}</span></div>
      ${event.reason ? `<div class="mt-1 text-slate-500">Reason: ${esc(event.reason)}</div>` : ""}
      ${event.action ? `<div class="mt-1 text-slate-500">Tool/action: <code>${esc(event.action)}</code>${event.evidence_count != null ? ` · ${esc(event.evidence_count)} evidence item(s)` : ""}</div>` : ""}
    </div>`).join("");
  live.scrollTop = live.scrollHeight;
}

async function pollWorkflowProgress() {
  if (!currentId) return;
  try {
    const response = await fetch(`${API}/api/agent/workflow/${encodeURIComponent(currentId)}/status`);
    if (!response.ok) return;
    const data = await response.json();
    renderWorkflowProgress(data.progress);
  } catch (_) {}
}

function startWorkflowProgressPolling() {
  if (workflowProgressTimer) clearInterval(workflowProgressTimer);
  pollWorkflowProgress();
  workflowProgressTimer = setInterval(pollWorkflowProgress, 900);
}

async function stopWorkflowProgressPolling() {
  if (workflowProgressTimer) clearInterval(workflowProgressTimer);
  workflowProgressTimer = null;
  await pollWorkflowProgress();
}

function renderWorkflow(workflow) {
  const body = $("workflow-body"), button = $("workflow-start-btn");
  if (!body || !button) return;
  const enabled = Boolean(healthData.agentic_workflow?.enabled && healthData.agentic?.enabled);
  const visionControl = $("workflow-vision"), visionState = $("workflow-vision-state");
  const visionReady = Boolean(healthData.ui_agent?.enabled && healthData.ui_agent?.vision_enabled);
  button.disabled = !enabled || !currentId;
  if (!workflow) {
    if (visionControl) {
      visionControl.disabled = !visionReady;
      visionControl.checked = visionReady;
    }
    if (visionState) visionState.textContent = visionReady
      ? `Available: ${healthData.ui_agent.provider} / ${healthData.ui_agent.model}`
      : "Unavailable globally; enable screenshot vision in Settings.";
    button.textContent = "Start Agentic Investigation";
    body.innerHTML = enabled
      ? '<p>Ready. Starting creates a proposal only; it does not execute the APK. Every emulator pass requires a matching APK re-upload and your explicit approval.</p>'
      : '<p class="text-slate-500">Disabled. Enable both <strong>AI Review</strong> and <strong>Agentic Investigation</strong> in Settings.</p>';
    return;
  }
  if (visionControl) {
    visionControl.checked = Boolean(workflow.allow_vision);
    visionControl.disabled = true;
  }
  if (visionState) visionState.textContent = workflow.allow_vision
    ? "Visual-model follow-up was allowed when this workflow started."
    : "Visual-model follow-up is off for this workflow.";
  button.disabled = true;
  button.textContent = workflow.status === "completed" ? "Workflow complete" : "Workflow active";
  const proposals = (workflow.proposals || []).map(proposal => {
    const config = proposal.config || {};
    const pending = proposal.status === "pending";
    return `<div class="agent-hypothesis">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div><div class="flex flex-wrap items-center gap-2"><span class="chip ${statusChipTone(proposal.status)}">${esc(proposal.status)}</span><strong class="text-slate-200">${esc(proposal.title)}</strong></div>
        <p class="mt-2 text-xs text-slate-500">${esc(proposal.reason)}</p></div>
        ${pending ? `<button class="btn-warning shrink-0" type="button" data-workflow-approve="${esc(proposal.id)}">${esc(workflowActionLabel(proposal))}</button>` : ""}
      </div>
      <div class="mt-2 text-xs text-slate-500">Fixed policy: ${esc(config.duration || 0)}s · Frida ${config.use_frida ? "on" : "off"} · UI ${config.use_ui_agent ? esc(config.ui_agent_mode) : "off"}</div>
    </div>`;
  }).join("");
  const observations = (workflow.observations || []).map(observation => {
    const network = observation.network || {}, frida = observation.frida || {}, ui = observation.ui_agent || {};
    const endpointCount = (network.urls || []).length + (network.domains || []).length + (network.ips || []).length;
    return `<div class="finding-row"><div class="finding-score text-cyan-300">${esc(observation.final_score ?? observation.dynamic_score ?? 0)}</div><div>
      <div class="finding-name">${esc(observation.action_kind || "sandbox observation")}</div>
      <div class="finding-detail">${observation.final_score != null ? `Final ${esc(observation.final_score)} (${esc(observation.final_severity || "Unknown")}) · dynamic ${esc(observation.dynamic_score ?? 0)}. ` : ""}${esc((observation.runtime_signals || []).length)} runtime signal(s), ${esc(endpointCount)} network indicator(s), ${esc(frida.event_count || 0)} Frida event(s), ${esc(ui.steps_used || 0)} UI step(s).</div>
    </div></div>`;
  }).join("");
  const audit = (workflow.audit || []).map(entry => `<div class="flex justify-between gap-3 border-b border-slate-800 py-1.5"><span>${esc(entry.detail || entry.event)}</span><span class="chip ${statusChipTone(entry.status)}">${esc(entry.status)}</span></div>`).join("");
  body.innerHTML = `<div class="flex flex-wrap gap-2 mb-3"><span class="chip ${statusChipTone(workflow.status)}">${esc(workflow.status)}</span><span class="chip">Policy ${esc(workflow.policy_version)}</span><span class="chip">Static score locked at ${esc(workflow.static_score_snapshot ?? "Unknown")}</span><span class="chip">Visual follow-up ${workflow.allow_vision ? "allowed" : "off"}</span></div>
    <div class="space-y-2">${proposals || '<p class="text-slate-500">No actions proposed.</p>'}</div>
    ${observations ? `<div class="mt-4"><div class="text-xs uppercase tracking-wide text-slate-500 mb-2">Approved observations</div><div class="finding-list">${observations}</div></div>` : ""}
    <details class="mt-4"><summary class="cursor-pointer text-xs text-slate-500">Workflow audit (${(workflow.audit || []).length})</summary><div class="mt-2">${audit || "No events."}</div></details>`;
}

$("workflow-start-btn")?.addEventListener("click", async () => {
  if (!currentId) return;
  const button = $("workflow-start-btn"), body = $("workflow-body");
  setButtonBusy(button, true, "Planning…");
  startWorkflowProgressPolling();
  setWorkflowStatus("Preparing an approval request. No APK is being executed yet.");
  body.innerHTML = '<p class="text-cyan-300">Reviewing saved evidence and preparing one approval request. No APK is being executed.</p>';
  try {
    const allowVision = Boolean($("workflow-vision")?.checked);
    const response = await fetch(`${API}/api/agent/workflow/${encodeURIComponent(currentId)}?allow_vision=${allowVision ? "true" : "false"}`, {method: "POST"});
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || "Could not start Agentic Investigation");
    currentAnalysis.agentic = data.agentic;
    currentAnalysis.agentic_workflow = data.workflow;
    currentReport = data.report || currentReport;
    renderAgent(data.agentic);
    renderWorkflow(data.workflow);
    setWorkflowStatus("Workflow created. Review the fixed action and approve it when ready.", "success");
  } catch (error) {
    body.innerHTML = `<p class="text-rose-400">${esc(error.message)}</p>`;
    setWorkflowStatus(error.message, "danger");
  } finally {
    await stopWorkflowProgressPolling();
    setButtonBusy(button, false);
    renderWorkflow(currentAnalysis?.agentic_workflow);
  }
});

$("workflow-body")?.addEventListener("click", async event => {
  const button = event.target.closest("[data-workflow-approve]");
  if (!button || !currentId) return;
  if (!selectedFile) {
    const message = "Approval was not sent: re-select the original APK in the upload area first. Browsers do not retain file access after a refresh or when opening a history case; its SHA256 will be verified before execution.";
    setWorkflowStatus(message, "danger");
    showError(message);
    return;
  }
  hideError();
  setWorkflowStatus("Approval sent. Running the fixed sandbox pass, then waiting for the OpenRouter evidence review. Keep this page open; this can take about a minute.");
  const form = new FormData();
  form.append("file", selectedFile);
  form.append("action_id", button.dataset.workflowApprove);
  const serial = $("dyn-device")?.value;
  if (serial) form.append("serial", serial);
  setButtonBusy(button, true, "Running safely…");
  startWorkflowProgressPolling();
  try {
    const response = await fetch(`${API}/api/agent/workflow/${encodeURIComponent(currentId)}/approve`, {method: "POST", body: form});
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || "Approved sandbox action failed");
    currentAnalysis.agentic_workflow = data.workflow;
    currentAnalysis.agentic = data.agentic_review;
    currentReport = data.report || currentReport;
    renderWorkflow(data.workflow);
    renderAgent(data.agentic_review);
    renderDynamic(data.dynamic);
    setWorkflowStatus(data.workflow.status === "approval_required"
      ? "Approved pass completed. The review proposed one additional action; approve it only if you want that pass."
      : "Approved pass and evidence review completed.", "success");
  } catch (error) {
    showError(error.message);
    setWorkflowStatus(`Approval failed: ${error.message}`, "danger");
  } finally {
    await stopWorkflowProgressPolling();
    setButtonBusy(button, false);
  }
});

$("workflow-settings-btn")?.addEventListener("click", () => $("settings-open")?.click());

// --- Sample history ---
const SEV_CHIP = (sev) => `<span class="chip ${severityChipTone(sev)}">${esc(sev)}</span>`;
async function loadHistory() {
  try {
    const r = await fetch(`${API}/api/samples`);
    const { samples } = await r.json();
    if (!samples || !samples.length) { $("history-card").classList.add("hidden"); return; }
    $("history-card").classList.remove("hidden");
    $("history-list").innerHTML = samples.slice(0, 12).map(s => {
      const analyzedAt = s.upload_time ? new Date(s.upload_time * 1000).toLocaleString([], {dateStyle: "medium", timeStyle: "short"}) : "Date unavailable";
      return `
      <div class="history-row flex items-center justify-between gap-3 py-2 px-3 rounded-lg cursor-pointer" data-id="${s.id}" role="button" tabindex="0">
        <div class="min-w-0">
          <div class="text-slate-200 text-sm truncate">${esc(s.filename || s.package_name || s.id)}</div>
          <div class="text-slate-500 text-xs mt-0.5"><span class="font-mono">${esc(s.package_name || "Package unavailable")}</span><span class="mx-1">·</span><span>${esc(analyzedAt)}</span></div>
        </div>
        <div class="flex items-center gap-2 shrink-0">
          <span class="text-slate-400 text-sm">${s.risk_score ?? "Unknown"}</span>${SEV_CHIP(s.severity)}
        </div>
      </div>`;
    }).join("");
    $("history-list").querySelectorAll("[data-id]").forEach(el => {
      const open = () => openSample(el.getAttribute("data-id"));
      el.addEventListener("click", open);
      el.addEventListener("keydown", event => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          open();
        }
      });
    });
  } catch (e) { /* ignore */ }
}
async function openSample(id) {
  try {
    const r = await fetch(`${API}/api/samples/${id}`);
    if (!r.ok) return;
    const s = await r.json();
    currentId = id;
    render(s.analysis, s.report);
  } catch (e) { showError("Could not load saved sample."); }
}
loadHistory();

function drawGauge(score, color) {
  const canvas = $("gauge");
  canvas.width = 180;
  canvas.height = 180;
  const ctx = canvas.getContext("2d");
  if (gaugeChart) gaugeChart.destroy();
  gaugeChart = new Chart(ctx, {
    type: "doughnut",
    data: { datasets: [{ data: [score, 100 - score], backgroundColor: [color, getComputedStyle(document.documentElement).getPropertyValue("--gauge-track").trim() || "#1e293b"], borderWidth: 0 }] },
    options: { cutout: "78%", rotation: -90, circumference: 360, plugins: { tooltip: { enabled: false }, legend: { display: false } }, responsive: false },
  });
}

// --- Dynamic analysis ---
$("dyn-run-btn").addEventListener("click", runDynamic);
async function runDynamic() {
  refreshHealth();
  if (!healthData.dynamic || !healthData.dynamic.available) {
    $("dyn-results").classList.remove("hidden");
    $("dyn-results").innerHTML = `<p class="text-amber-400 text-sm">No emulator attached. Start one: <code>emulator -avd &lt;name&gt;</code>, then retry.</p>`;
    return;
  }
  if (!selectedFile) {
    $("dyn-results").classList.remove("hidden");
    $("dyn-results").innerHTML = `<p class="text-amber-400 text-sm">Re-upload the APK above to run dynamic analysis on it.</p>`;
    return;
  }
  const dur = $("dyn-duration").value, frida = $("dyn-frida").checked;
  const uiAgent = $("dyn-ui-agent")?.checked || false;
  const uiAgentMode = uiAgent ? ($("dyn-ui-agent-mode")?.value || "tree") : "tree";
  if (frida && uiAgent) {
    $("dyn-results").classList.remove("hidden");
    $("dyn-results").innerHTML = `<p class="text-amber-400 text-sm">Run Frida hooks and AI UI Explorer as separate passes.</p>`;
    return;
  }
  const serial = $("dyn-device").value;
  $("dyn-results").classList.add("hidden");
  $("dyn-loading").classList.remove("hidden");
  $("dyn-loading-text").textContent = `Installing & running for ${dur}s${frida ? " with Frida hooks" : ""}${uiAgent ? " with bounded AI interaction" : ""}…`;
  setButtonBusy($("dyn-run-btn"), true, "Running safely…");

  const fd = new FormData();
  fd.append("file", selectedFile);
  fd.append("duration", dur);
  fd.append("use_frida", frida ? "true" : "false");
  fd.append("use_ui_agent", uiAgent ? "true" : "false");
  fd.append("ui_agent_mode", uiAgentMode);
  if (currentId) fd.append("sample_id", currentId);
  if (serial) fd.append("serial", serial);
  try {
    const res = await fetch(`${API}/api/dynamic`, { method: "POST", body: fd });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Dynamic analysis failed");
    if (currentAnalysis && data.final_score != null) {
      currentAnalysis.final_score = data.final_score;
      currentAnalysis.final_severity = data.final_severity;
      currentAnalysis.final_score_breakdown = data.final_score_breakdown || [];
      currentAnalysis.latest_dynamic = data;
    }
    renderDynamic(data);
  } catch (e) {
    $("dyn-results").classList.remove("hidden");
    $("dyn-results").innerHTML = `<p class="text-red-400 text-sm">${esc(e.message)}</p>`;
  } finally {
    $("dyn-loading").classList.add("hidden");
    setButtonBusy($("dyn-run-btn"), false);
  }
}

function renderDynamic(d) {
  $("dyn-results").classList.remove("hidden");
  if (!d.available) {
    $("dyn-results").innerHTML = `<p class="text-amber-400 text-sm">${esc(d.reason || "Emulator unavailable.")}</p>`;
    return;
  }
  if (!d.ran) {
    $("dyn-results").innerHTML = `<p class="text-amber-400 text-sm">${esc(d.reason || "APK did not run.")}</p>`;
    return;
  }
  const net = d.network || {};
  const list = (label, arr) => (arr && arr.length)
    ? `<div><span class="text-slate-400">${label}:</span> <span class="text-slate-300 font-mono text-xs break-all">${arr.slice(0,15).map(esc).join(", ")}</span></div>` : "";
  const fr = d.frida || {};
  const ua = d.ui_agent || {};
  const finalScore = d.final_score;
  const finalSeverity = d.final_severity || "Unknown";
  $("dyn-results").innerHTML =
    `<div class="flex items-center gap-3 mb-3"><span class="text-2xl font-medium font-mono text-amber-400">${d.dynamic_score ?? 0}</span><span class="text-slate-400 text-sm">dynamic behaviour score, ran ${d.duration}s${d.use_frida ? ", Frida" : ""}${d.rooted ? ", root" : ""}${d.has_launcher === false ? ", no launcher icon" : ""}</span></div>`
    + ((d.activated && d.activated.length) ? `<div class="text-xs text-slate-400 mb-2">Triggered: ${d.activated.map(x=>`<span class="chip chip-warning">${esc(x)}</span>`).join(" ")}</div>` : "")
    + `<div class="grid md:grid-cols-2 gap-x-6 gap-y-1 text-sm">`
    + list("Granted permissions", d.granted_permissions)
    + list("Services", (d.services||[]).map(s=>s.split("/").pop()))
    + list("URLs", net.urls) + list("Domains", net.domains) + list("IPs", net.ips)
    + (d.runtime_signals && d.runtime_signals.length ? `<div><span class="text-slate-400">Runtime signals:</span> <span class="text-amber-300 text-xs">${d.runtime_signals.map(esc).join(", ")}</span></div>` : "")
    + (d.crashes && d.crashes.length ? `<div><span class="text-slate-400">Crashes:</span> <span class="text-red-300 text-xs">${d.crashes.length}</span></div>` : "")
    + `</div>`
    + (fr.ran ? `<div class="mt-3"><div class="text-xs text-slate-400 mb-1">Frida-hooked events (${fr.event_count}):</div><div class="flex flex-wrap gap-1.5">`
        + (fr.findings||[]).map(f=>`<span class="chip chip-info">${esc(f.label)} ×${Number(f.count)||0}</span>`).join("") + `</div></div>`
      : (d.use_frida && fr.reason ? `<div class="mt-3 text-xs text-slate-500">Frida: ${esc(fr.reason.split("\n")[0])}</div>` : ""))
    + (d.use_ui_agent ? `<div class="mt-4 rounded-lg border border-cyan-900/60 bg-cyan-950/20 p-3">`
        + `<div class="flex flex-wrap items-center gap-2"><span class="text-sm font-semibold text-cyan-200">AI UI Explorer</span><span class="chip chip-info">${esc(ua.status || "unknown")}</span><span class="chip chip-info">${ua.mode === "vision" ? "Vision assisted" : "UI tree"}</span>${ua.vision_enabled ? `<span class="chip chip-info">${Number(ua.vision_actions)||0} visual action(s)</span>` : ""}<span class="text-xs text-slate-400">${Number(ua.steps_used)||0} actions · synthetic identity only</span></div>`
        + `<div class="mt-2 space-y-1 text-xs">${(ua.audit||[]).map(x=>`<div class="flex gap-2"><span class="text-slate-500">${Number(x.step)||0}.</span><span class="text-slate-300">${esc(x.action)}${x.target ? " · " + esc(x.target) : ""}${x.coordinates_percent ? ` · ${Number(x.coordinates_percent.x).toFixed(1)}%, ${Number(x.coordinates_percent.y).toFixed(1)}%` : ""}${x.value_key ? " · synthetic " + esc(x.value_key) : ""}</span><span class="${x.status === "ok" || x.status === "completed" ? "text-cyan-400" : "text-amber-400"}">${esc(x.status)}</span></div>`).join("") || `<div class="text-slate-500">${esc(ua.reason || "No UI actions were taken.")}</div>`}</div></div>` : "")
    + (d.score_breakdown && d.score_breakdown.length
        ? `<div class="mt-3 space-y-1">` + d.score_breakdown.map(b=>`<div class="text-xs flex justify-between"><span class="text-slate-400">${esc(b.category)}</span><span class="text-amber-400">+${Number(b.points)||0}</span></div>`).join("") + `</div>` : "")
    + (!d.granted_permissions?.length && !net.urls?.length && !d.services?.length && !fr.ran
        ? `<p class="text-slate-500 text-xs mt-2">No notable runtime behaviour observed in ${d.duration}s (app may need interaction, or is benign).</p>` : "")
    + (finalScore != null
        ? `<div class="mt-5 rounded-lg border border-cyan-700/50 bg-cyan-950/20 p-4">`
          + `<div class="text-[10px] uppercase tracking-wider text-slate-500">Final score after dynamic analysis</div>`
          + `<div class="mt-2 flex flex-wrap items-center gap-3"><span class="text-3xl font-semibold font-mono text-cyan-300">${Number(finalScore)}</span><span class="chip ${severityChipTone(finalSeverity)}">${esc(finalSeverity)}</span><span class="text-xs text-slate-400">Static ${Number(d.static_score)||0} + runtime contribution ${Math.max(0, Number(finalScore) - (Number(d.static_score)||0))}</span></div>`
          + `<div class="mt-3 space-y-1">${(d.final_score_breakdown||[]).map(b=>`<div class="text-xs flex justify-between gap-4"><span class="text-slate-400">${esc(b.category)}<span class="block text-slate-600">${esc(b.detail||"")}</span></span><span class="text-cyan-300">+${Number(b.points)||0}</span></div>`).join("")}</div>`
          + (Number(d.dynamic_points_capped) > 0 ? `<p class="mt-2 text-xs text-slate-500">${Number(d.dynamic_points_capped)} dynamic point(s) exceeded the 100-point cap.</p>` : "")
          + `</div>`
        : `<p class="mt-4 text-xs text-slate-500">A final score requires this run to be linked to its saved static-analysis case.</p>`);
}

function short(h) { return h ? `${h.slice(0, 10)}…${h.slice(-6)}` : "Not reported"; }
function showError(msg) { const e = $("error-box"); e.textContent = plain(msg); e.classList.remove("hidden"); }
function hideError() { $("error-box").classList.add("hidden"); }
