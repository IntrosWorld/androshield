// APK Fraud Analyzer dashboard logic
const API = ""; // same origin

const SEV_COLORS = {
  Low: "#22c55e", Medium: "#eab308", High: "#f97316", Critical: "#ef4444",
  Unknown: "#64748b",
};

let selectedFile = null;
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
  if (["running", "pending", "investigating"].includes(value)) return "chip-info";
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
    if (h.analyzer_ready === false) {
      badges += ' <span class="chip chip-danger">Engine offline: start from .venv</span>';
    }
    if (h.agentic?.enabled) {
      badges += ` <span class="chip chip-info">Agent: ${esc(h.agentic.provider)} / ${esc(h.agentic.model)}</span>`;
    }
    $("gemini-badge").innerHTML = badges;
    updateEmuStatus();
  }).catch(() => {});
}
function updateEmuStatus() {
  const el = $("emu-status"); if (!el) return;
  const d = healthData.dynamic || {};
  const sel = $("dyn-device");
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

// --- File selection ---
const dropzone = $("dropzone"), fileInput = $("file-input");
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
  if (e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]);
});
fileInput.addEventListener("change", () => { if (fileInput.files.length) setFile(fileInput.files[0]); });

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
  $("file-name").textContent = `Selected: ${plain(f.name)}, ${(f.size / 1048576).toFixed(2)} MB`;
  $("analyze-btn").disabled = false;
  dropzone.classList.add("has-file");
  hideError();
}

// --- Analyze ---
$("analyze-btn").addEventListener("click", async () => {
  if (!selectedFile) return;
  hideError();
  $("results").classList.add("hidden");
  $("loading").classList.remove("hidden");
  setButtonBusy($("analyze-btn"), true, "Analyzing APK…");

  const fd = new FormData();
  fd.append("file", selectedFile);
  try {
    const res = await fetch(`${API}/api/analyze`, { method: "POST", body: fd });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || "Analysis failed");
    }
    const data = await res.json();
    currentId = data.id;
    render(data.analysis, data.report);
  } catch (e) {
    showError(e.message);
  } finally {
    $("loading").classList.add("hidden");
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
  const hypotheses = (agent.hypotheses || []).map(h => `
    <div class="agent-hypothesis">
      <div class="flex gap-2 items-start"><span class="chip chip-info shrink-0">${esc(h.confidence)}</span><span class="text-slate-200">${esc(h.claim)}</span></div>
      <div class="mt-2 text-xs text-slate-500">Evidence: ${(h.evidence_ids || []).map(esc).join(", ")}</div>
    </div>`).join("") || '<p class="text-slate-500">No grounded hypothesis was produced.</p>';
  const audit = (agent.audit || []).map(step => `
    <div class="flex justify-between gap-3 border-b border-slate-800 py-1.5">
      <span><span class="text-slate-500">${esc(step.step)}.</span> ${esc(step.action)}</span>
      <span class="text-xs ${step.status === "completed" || step.status === "ok" ? "text-cyan-400" : step.status === "approval_required" ? "text-amber-400" : "text-rose-400"}">${esc(step.status)}${step.executed === false ? ", not executed" : ""}</span>
    </div>`).join("");
  const gaps = (agent.gaps || []).map(g => `<li>${esc(g)}</li>`).join("");
  const review = agent.gemini_review ? `<div class="mt-3 text-xs text-slate-400">Gemini review: <span class="${agent.gemini_review.grounded ? "text-emerald-400" : "text-amber-400"}">${agent.gemini_review.grounded ? "grounded" : "issues found"}</span>${(agent.gemini_review.unsupported_claims || []).length ? `. Unsupported: ${agent.gemini_review.unsupported_claims.map(esc).join("; ")}` : ""}</div>` : "";
  body.innerHTML = `
    <div class="flex flex-wrap gap-2 mb-3"><span class="chip ${statusChipTone(agent.status)}">${esc(agent.status)}</span><span class="chip">${esc(agent.provider || "Unavailable")} / ${esc(agent.model || "Unavailable")}</span><span class="chip">${esc(agent.steps_used || 0)} steps, ${esc(agent.duration_ms || 0)} ms</span></div>
    <div class="space-y-2">${hypotheses}</div>
    ${gaps ? `<div class="mt-3"><div class="text-xs uppercase tracking-wide text-slate-500">Evidence gaps</div><ul class="list-disc pl-5 mt-1 text-slate-400">${gaps}</ul></div>` : ""}
    ${review}
    <details class="mt-4"><summary class="cursor-pointer text-xs text-slate-500">Action audit (${(agent.audit || []).length})</summary><div class="mt-2">${audit || "No actions."}</div></details>`;
}

$("agent-run-btn")?.addEventListener("click", async () => {
  if (!currentId) return;
  const button = $("agent-run-btn"), body = $("agent-body");
  setButtonBusy(button, true, "Investigating…");
  body.innerHTML = '<p class="text-cyan-300">The bounded agent is reviewing extracted evidence. CPU-only local inference may take several minutes; the server remains responsive.</p>';
  try {
    const response = await fetch(`${API}/api/agent/investigate/${encodeURIComponent(currentId)}`, {method: "POST"});
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || "Agentic investigation failed");
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

// --- Sample history ---
const SEV_CHIP = (sev) => `<span class="chip ${severityChipTone(sev)}">${esc(sev)}</span>`;
async function loadHistory() {
  try {
    const r = await fetch(`${API}/api/samples`);
    const { samples } = await r.json();
    if (!samples || !samples.length) { $("history-card").classList.add("hidden"); return; }
    $("history-card").classList.remove("hidden");
    $("history-list").innerHTML = samples.slice(0, 12).map(s => `
      <div class="history-row flex items-center justify-between gap-3 py-2 px-3 rounded-lg cursor-pointer" data-id="${s.id}" role="button" tabindex="0">
        <div class="min-w-0">
          <span class="text-slate-200 text-sm truncate">${esc(s.filename || s.package_name || s.id)}</span>
          <span class="text-slate-500 text-xs ml-2 font-mono">${esc(s.package_name || "")}</span>
        </div>
        <div class="flex items-center gap-2 shrink-0">
          <span class="text-slate-400 text-sm">${s.risk_score ?? "Unknown"}</span>${SEV_CHIP(s.severity)}
        </div>
      </div>`).join("");
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
  const serial = $("dyn-device").value;
  $("dyn-results").classList.add("hidden");
  $("dyn-loading").classList.remove("hidden");
  $("dyn-loading-text").textContent = `Installing & running for ${dur}s${frida ? " with Frida hooks" : ""}…`;
  setButtonBusy($("dyn-run-btn"), true, "Running safely…");

  const fd = new FormData();
  fd.append("file", selectedFile);
  fd.append("duration", dur);
  fd.append("use_frida", frida ? "true" : "false");
  if (serial) fd.append("serial", serial);
  try {
    const res = await fetch(`${API}/api/dynamic`, { method: "POST", body: fd });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Dynamic analysis failed");
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
    + (d.score_breakdown && d.score_breakdown.length
        ? `<div class="mt-3 space-y-1">` + d.score_breakdown.map(b=>`<div class="text-xs flex justify-between"><span class="text-slate-400">${esc(b.category)}</span><span class="text-amber-400">+${Number(b.points)||0}</span></div>`).join("") + `</div>` : "")
    + (!d.granted_permissions?.length && !net.urls?.length && !d.services?.length && !fr.ran
        ? `<p class="text-slate-500 text-xs mt-2">No notable runtime behaviour observed in ${d.duration}s (app may need interaction, or is benign).</p>` : "");
}

function short(h) { return h ? `${h.slice(0, 10)}…${h.slice(-6)}` : "Not reported"; }
function showError(msg) { const e = $("error-box"); e.textContent = plain(msg); e.classList.remove("hidden"); }
function hideError() { $("error-box").classList.add("hidden"); }
