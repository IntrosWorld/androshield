// APK Fraud Analyzer — dashboard logic
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
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, ch => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[ch]));
const safeHttpUrl = (value) => {
  try {
    const u = new URL(String(value));
    return (u.protocol === "https:" || u.protocol === "http:") ? u.href : "#";
  } catch (_) { return "#"; }
};

// --- Gemini badge ---
let healthData = {};
function refreshHealth() {
  return fetch(`${API}/api/health`).then(r => r.json()).then(h => {
    healthData = h;
    let badges = h.gemini_configured
      ? '<span class="chip" style="background:#0e7490;color:#fff">Gemini connected</span>'
      : '<span class="chip" style="background:#334155;color:#cbd5e1">Template mode (no GEMINI_API_KEY)</span>';
    if (h.analyzer_ready === false) {
      badges += ' <span class="chip" style="background:#7f1d1d;color:#fecaca">Engine offline — start from .venv</span>';
    }
    if (h.agentic?.enabled) {
      badges += ` <span class="chip" style="background:#164e63;color:#a5f3fc">Agent: ${esc(h.agentic.provider)} / ${esc(h.agentic.model)}</span>`;
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
      el.innerHTML = `<span class="chip" style="background:#065f46;color:#a7f3d0">● ${esc(dev.avd_name || d.serial)}${dev.android_version ? " · Android " + esc(dev.android_version) : ""}</span>`
        + (healthData.frida_available ? ` <span class="chip" style="background:#1e293b;color:#67e8f9">Frida ready</span>` : "");
    } else {
      el.innerHTML = `<span class="chip" style="background:#78350f;color:#fed7aa">${esc(d.preferred_avd)} not running — pick a device deliberately</span>`;
    }
    if (sel) {
      const devices = d.devices || [];
      let opts = devices.map(x => {
        const name = x.avd_name || x.serial;
        const isSandbox = name === d.preferred_avd;
        return `<option value="${esc(x.serial)}" ${x.serial === d.serial ? "selected" : ""}>${isSandbox ? "[Sandbox] " : ""}${esc(name)} (${esc(x.serial)})</option>`;
      });
      if (!d.sandbox_present) opts.unshift(`<option value="" selected disabled>— choose a device —</option>`);
      sel.innerHTML = opts.join("");
    }
  } else {
    el.innerHTML = `<span class="chip" style="background:#334155;color:#cbd5e1">○ No emulator attached</span>`;
    if (sel) sel.innerHTML = `<option value="">— none —</option>`;
  }
}
refreshHealth();

// --- File selection ---
const dropzone = $("dropzone"), fileInput = $("file-input");
dropzone.addEventListener("click", () => fileInput.click());
dropzone.addEventListener("dragover", (e) => { e.preventDefault(); dropzone.classList.add("border-cyan-500"); });
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("border-cyan-500"));
dropzone.addEventListener("drop", (e) => {
  e.preventDefault(); dropzone.classList.remove("border-cyan-500");
  if (e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]);
});
fileInput.addEventListener("change", () => { if (fileInput.files.length) setFile(fileInput.files[0]); });

function setFile(f) {
  if (!f.name.toLowerCase().endsWith(".apk")) { showError("Please select a .apk file."); return; }
  selectedFile = f;
  $("file-name").textContent = `${f.name} (${(f.size / 1048576).toFixed(2)} MB)`;
  $("analyze-btn").disabled = false;
  hideError();
}

// --- Analyze ---
$("analyze-btn").addEventListener("click", async () => {
  if (!selectedFile) return;
  hideError();
  $("results").classList.add("hidden");
  $("loading").classList.remove("hidden");
  $("analyze-btn").disabled = true;

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
    $("analyze-btn").disabled = false;
  }
});

// --- Rendering ---
function render(a, report) {
  currentAnalysis = a;
  currentReport = report;
  // A failed/incomplete parse must NOT look like a clean "Low" app.
  if (a.valid_apk === false || a.risk_score == null || a.severity === "Unknown") {
    showError("Analysis could not complete — the file may not be a valid/parseable APK. "
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
  chip.style.background = color; chip.style.color = "#0b1020";

  // Meta
  const m = a.manifest || {}, f = a.file || {};
  $("meta").innerHTML = [
    ["File", f.filename], ["Package", m.package_name || "—"],
    ["Version", m.version_name || "—"], ["Size", `${((f.file_size||0)/1048576).toFixed(2)} MB`],
    ["SHA256", short(f.sha256)], ["MD5", short(f.md5)],
    ["Min SDK", m.min_sdk || "—"], ["Target SDK", m.target_sdk || "—"],
    ["Analysis", a.analysis_quality === "partial" ? "Partial" : "Full"],
  ].map(([k, v]) => `<div><span class="text-slate-500">${k}</span><br><span class="text-slate-200 break-all">${esc(v||"—")}</span></div>`).join("");

  $("threat").textContent = report.threat_assessment || "—";
  $("threat").style.color = color;

  // AI summary
  $("exec-summary").textContent = report.executive_summary || "—";
  $("tech-summary").textContent = report.technical_summary || "";
  $("behaviors").innerHTML = (a.detected_behaviors || []).map(
    b => `<span class="chip" style="background:#1e293b;color:#67e8f9">${esc(b)}</span>`).join("") ||
    '<span class="text-slate-500 text-sm">No high-risk behaviours flagged.</span>';
  renderAgent(a.agentic);

  // Breakdown
  const maxPts = Math.max(...(a.score_breakdown||[]).map(b=>b.points), 1);
  $("breakdown").innerHTML = (a.score_breakdown || []).map(b => `
    <div>
      <div class="flex justify-between text-sm mb-0.5">
        <span class="text-slate-200">${esc(b.category)}</span>
        <span class="text-cyan-400 font-semibold">+${b.points}</span>
      </div>
      <div class="h-1.5 bg-slate-800 rounded"><div class="h-1.5 rounded" style="width:${(b.points/maxPts*100)}%;background:${color}"></div></div>
      <div class="text-xs text-slate-500 mt-0.5">${esc(b.detail||"")}</div>
    </div>`).join("") || '<p class="text-slate-500 text-sm">No risk contributions.</p>';

  // Permissions
  $("perms").innerHTML = (a.permissions?.dangerous || []).map(p => `
    <div class="flex items-start gap-2">
      <span class="chip shrink-0" style="background:#7f1d1d;color:#fecaca">+${p.score}</span>
      <div><span class="text-slate-200 font-mono text-xs">${esc(p.name)}</span>
      <div class="text-xs text-slate-500">${esc(p.reason)}</div></div>
    </div>`).join("") || '<p class="text-slate-500 text-sm">No dangerous permissions.</p>';

  // APIs
  $("apis").innerHTML = (a.apis?.suspicious_apis || []).map(x => `
    <div class="flex items-start gap-2">
      <span class="chip shrink-0" style="background:#78350f;color:#fed7aa">+${x.score}</span>
      <div><span class="text-slate-200 font-mono text-xs">${esc(x.api)}</span>
      <div class="text-xs text-slate-500">${esc(x.behaviour)} · ${esc(x.evidence || "")}</div></div>
    </div>`).join("") || '<p class="text-slate-500 text-sm">No suspicious APIs detected.</p>';

  // IOCs
  const i = a.iocs || {};
  const iocBlock = (label, arr) => (arr && arr.length)
    ? `<div><span class="text-slate-400">${label}:</span> <span class="text-slate-300 break-all font-mono text-xs">${arr.slice(0,15).map(esc).join(", ")}</span></div>` : "";
  $("iocs").innerHTML = [
    iocBlock("Domains", i.domains), iocBlock("URLs", i.urls), iocBlock("IPs", i.ips),
    iocBlock("Telegram tokens", i.telegram_tokens), iocBlock("Secrets", i.hardcoded_secrets),
    (i.suspicious_keywords?.length ? `<div><span class="text-slate-400">Keywords:</span> <span class="text-slate-300 text-xs">${i.suspicious_keywords.map(k=>esc(k.keyword)).join(", ")}</span></div>` : ""),
    (i.decoded_blobs ? `<div class="text-xs text-slate-500">↳ ${i.decoded_blobs} Base64/hex blob(s) decoded &amp; rescanned${i.native_strings_scanned ? ` · ${i.native_strings_scanned} native-lib strings scanned` : ""}</div>` : ""),
  ].filter(Boolean).join("") || '<p class="text-slate-500">No network IOCs found in static strings.</p>';

  // Recommendations
  $("recs").innerHTML = (report.recommended_actions || a.recommendations || []).map(
    r => `<li class="flex gap-2"><span class="text-cyan-400">▸</span><span>${esc(r)}</span></li>`).join("")
    || '<li class="text-slate-500">No specific actions.</li>';

  // YARA panel
  const yara = a.yara || {};
  if (yara.matches && yara.matches.length) {
    $("yara-card").classList.remove("hidden");
    $("yara-body").innerHTML = yara.matches.map(m => `
      <div class="flex items-start gap-2">
        <span class="chip shrink-0" style="background:#581c87;color:#e9d5ff">+${m.score}</span>
        <div><span class="text-slate-200 font-mono text-xs">${m.rule}</span>
        <div class="text-xs text-slate-500">${m.description}${m.attack ? ` · ATT&CK ${m.attack}` : ""}</div></div>
      </div>`).join("");
  } else {
    $("yara-card").classList.add("hidden");
  }

  // MITRE panel
  const mitre = a.mitre || {};
  if (mitre.techniques && mitre.techniques.length) {
    $("mitre-card").classList.remove("hidden");
    $("mitre-body").innerHTML = mitre.techniques.map(t =>
      `<a href="${t.url}" target="_blank" class="chip" style="background:#1e293b;color:#fcd34d" title="${t.tactic}">${t.id} ${t.name}</a>`
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
      `<div class="flex items-baseline gap-2 mb-2"><span class="text-2xl font-bold" style="color:${c}">${pct}%</span>`
      + `<span class="text-slate-400">ML decision → <span class="font-semibold" style="color:${c}">${esc((ml.prediction||"").replace("_", " ").toUpperCase())}</span></span></div>`
      + `<div class="h-2 bg-slate-800 rounded mb-2"><div class="h-2 rounded" style="width:${pct}%;background:${c}"></div></div>`
      + ((ml.contributing_permissions||[]).length
          ? `<div class="text-xs text-slate-400 mb-1">Top contributing permissions:</div><div class="flex flex-wrap gap-1.5">`
            + ml.contributing_permissions.map(p => `<span class="chip" style="background:#1e293b;color:#93c5fd">${esc(p.permission)}</span>`).join("") + `</div>`
          : "")
      + (m.f1_malware != null ? `<div class="text-xs text-slate-500 mt-3">Model: precision ${m.precision_malware?.toFixed(2)} · recall ${m.recall_malware?.toFixed(2)} · F1 ${m.f1_malware?.toFixed(2)}${m.roc_auc!=null?` · AUC ${m.roc_auc.toFixed(2)}`:""} (n=${m.n_samples})</div>` : "");
  } else {
    $("ml-card").classList.add("hidden");
  }

  // APKiD panel
  const apkid = a.apkid || {};
  if ((apkid.findings && apkid.findings.length) || (apkid.compilers && apkid.compilers.length)) {
    $("apkid-card").classList.remove("hidden");
    $("apkid-body").innerHTML =
      (apkid.findings || []).map(f =>
        `<div><span class="chip" style="background:#7c2d12;color:#fed7aa">${esc(f.category)}</span> <span class="text-slate-200 font-mono text-xs">${esc(f.name)}</span></div>`).join("")
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
        `<div class="flex items-baseline gap-2 mb-2"><span class="text-2xl font-bold" style="color:${c}">${mal}</span>`
        + `<span class="text-slate-400">/ ${tot} engines flagged this file as malicious</span></div>`
        + (fr.threat_label ? `<div class="mb-2">Threat label: <span class="font-mono text-amber-300">${esc(fr.threat_label)}</span></div>` : "")
        + ((fr.engine_hits || []).length
            ? `<div class="text-xs text-slate-400 mb-1">Detections:</div><div class="flex flex-wrap gap-1.5">`
              + fr.engine_hits.slice(0, 14).map(h => `<span class="chip" style="background:#1e293b;color:#fca5a5" title="${esc(h.engine)}">${esc(h.result)}</span>`).join("") + `</div>`
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
      html += `<div><span class="text-slate-400">Subject:</span> <span class="text-slate-200 font-mono text-xs">${esc(cert.subject || "—")}</span></div>`;
      if (cert.validity_years != null) html += `<div><span class="text-slate-400">Validity:</span> ${cert.validity_years} yrs${cert.self_signed ? " · self-signed" : ""}</div>`;
      if (cert.sha256) html += `<div><span class="text-slate-400">Cert SHA256:</span> <span class="font-mono text-xs">${short(cert.sha256)}</span></div>`;
    }
    (cert.flags || []).forEach(f =>
      html += `<div><span class="chip" style="background:#7f1d1d;color:#fecaca">${esc(f.flag)}</span> <span class="text-slate-400 text-xs">${esc(f.detail)}</span></div>`);
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
  const statusColor = agent.status === "completed" ? "#67e8f9" : agent.status === "unavailable" ? "#fbbf24" : "#fca5a5";
  const hypotheses = (agent.hypotheses || []).map(h => `
    <div class="rounded-lg bg-slate-900/50 p-3">
      <div class="flex gap-2 items-start"><span class="chip shrink-0" style="background:#164e63;color:#a5f3fc">${esc(h.confidence)}</span><span class="text-slate-200">${esc(h.claim)}</span></div>
      <div class="mt-2 text-xs text-slate-500">Evidence: ${(h.evidence_ids || []).map(esc).join(", ")}</div>
    </div>`).join("") || '<p class="text-slate-500">No grounded hypothesis was produced.</p>';
  const audit = (agent.audit || []).map(step => `
    <div class="flex justify-between gap-3 border-b border-slate-800 py-1.5">
      <span><span class="text-slate-500">${esc(step.step)}.</span> ${esc(step.action)}</span>
      <span class="text-xs ${step.status === "completed" || step.status === "ok" ? "text-cyan-400" : step.status === "approval_required" ? "text-amber-400" : "text-rose-400"}">${esc(step.status)}${step.executed === false ? " · not executed" : ""}</span>
    </div>`).join("");
  const gaps = (agent.gaps || []).map(g => `<li>${esc(g)}</li>`).join("");
  const review = agent.gemini_review ? `<div class="mt-3 text-xs text-slate-400">Gemini review: <span class="${agent.gemini_review.grounded ? "text-emerald-400" : "text-amber-400"}">${agent.gemini_review.grounded ? "grounded" : "issues found"}</span>${(agent.gemini_review.unsupported_claims || []).length ? ` · Unsupported: ${agent.gemini_review.unsupported_claims.map(esc).join("; ")}` : ""}</div>` : "";
  body.innerHTML = `
    <div class="flex flex-wrap gap-2 mb-3"><span class="chip" style="background:#1e293b;color:${statusColor}">${esc(agent.status)}</span><span class="chip" style="background:#1e293b;color:#cbd5e1">${esc(agent.provider || "—")} · ${esc(agent.model || "—")}</span><span class="chip" style="background:#1e293b;color:#cbd5e1">${esc(agent.steps_used || 0)} steps · ${esc(agent.duration_ms || 0)} ms</span></div>
    <div class="space-y-2">${hypotheses}</div>
    ${gaps ? `<div class="mt-3"><div class="text-xs uppercase tracking-wide text-slate-500">Evidence gaps</div><ul class="list-disc pl-5 mt-1 text-slate-400">${gaps}</ul></div>` : ""}
    ${review}
    <details class="mt-4"><summary class="cursor-pointer text-xs text-slate-500">Action audit (${(agent.audit || []).length})</summary><div class="mt-2">${audit || "No actions."}</div></details>`;
}

$("agent-run-btn")?.addEventListener("click", async () => {
  if (!currentId) return;
  const button = $("agent-run-btn"), body = $("agent-body");
  button.disabled = true;
  button.textContent = "Investigating…";
  body.innerHTML = '<p class="text-cyan-300">The bounded agent is reviewing extracted evidence. CPU-only local inference may take several minutes; the server remains responsive.</p>';
  try {
    const response = await fetch(`${API}/api/agent/investigate/${encodeURIComponent(currentId)}`, {method: "POST"});
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || "Agentic investigation failed");
    currentAnalysis.agentic = data.agentic;
    currentReport = data.report || currentReport;
    $("exec-summary").textContent = currentReport.executive_summary || "—";
    $("tech-summary").textContent = currentReport.technical_summary || "";
    renderAgent(data.agentic);
  } catch (error) {
    body.innerHTML = `<p class="text-rose-400">${esc(error.message)}</p>`;
  } finally {
    button.textContent = "Run AI Investigation";
    button.disabled = !healthData.agentic?.enabled;
  }
});

// --- Sample history ---
const SEV_CHIP = (sev) => `<span class="chip" style="background:${SEV_COLORS[sev]||'#64748b'};color:#0b1020">${sev}</span>`;
async function loadHistory() {
  try {
    const r = await fetch(`${API}/api/samples`);
    const { samples } = await r.json();
    if (!samples || !samples.length) { $("history-card").classList.add("hidden"); return; }
    $("history-card").classList.remove("hidden");
    $("history-list").innerHTML = samples.slice(0, 12).map(s => `
      <div class="flex items-center justify-between gap-3 py-1.5 px-2 rounded hover:bg-white/5 cursor-pointer" data-id="${s.id}">
        <div class="min-w-0">
          <span class="text-slate-200 text-sm truncate">${esc(s.filename || s.package_name || s.id)}</span>
          <span class="text-slate-500 text-xs ml-2 font-mono">${esc(s.package_name || "")}</span>
        </div>
        <div class="flex items-center gap-2 shrink-0">
          <span class="text-slate-400 text-sm">${s.risk_score ?? "—"}</span>${SEV_CHIP(s.severity)}
        </div>
      </div>`).join("");
    $("history-list").querySelectorAll("[data-id]").forEach(el =>
      el.addEventListener("click", () => openSample(el.getAttribute("data-id"))));
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
    data: { datasets: [{ data: [score, 100 - score], backgroundColor: [color, "#1e293b"], borderWidth: 0 }] },
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
  $("dyn-run-btn").disabled = true;

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
    $("dyn-run-btn").disabled = false;
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
    `<div class="flex items-center gap-3 mb-3"><span class="text-2xl font-bold text-amber-400">${d.dynamic_score ?? 0}</span><span class="text-slate-400 text-sm">dynamic behaviour score · ran ${d.duration}s${d.use_frida ? " · Frida" : ""}${d.rooted ? " · root" : ""}${d.has_launcher === false ? " · no launcher icon" : ""}</span></div>`
    + ((d.activated && d.activated.length) ? `<div class="text-xs text-slate-400 mb-2">Triggered: ${d.activated.map(x=>`<span class="chip" style="background:#1e293b;color:#fcd34d">${esc(x)}</span>`).join(" ")}</div>` : "")
    + `<div class="grid md:grid-cols-2 gap-x-6 gap-y-1 text-sm">`
    + list("Granted permissions", d.granted_permissions)
    + list("Services", (d.services||[]).map(s=>s.split("/").pop()))
    + list("URLs", net.urls) + list("Domains", net.domains) + list("IPs", net.ips)
    + (d.runtime_signals && d.runtime_signals.length ? `<div><span class="text-slate-400">Runtime signals:</span> <span class="text-amber-300 text-xs">${d.runtime_signals.map(esc).join(", ")}</span></div>` : "")
    + (d.crashes && d.crashes.length ? `<div><span class="text-slate-400">Crashes:</span> <span class="text-red-300 text-xs">${d.crashes.length}</span></div>` : "")
    + `</div>`
    + (fr.ran ? `<div class="mt-3"><div class="text-xs text-slate-400 mb-1">Frida-hooked events (${fr.event_count}):</div><div class="flex flex-wrap gap-1.5">`
        + (fr.findings||[]).map(f=>`<span class="chip" style="background:#1e293b;color:#67e8f9">${esc(f.label)} ×${Number(f.count)||0}</span>`).join("") + `</div></div>`
      : (d.use_frida && fr.reason ? `<div class="mt-3 text-xs text-slate-500">Frida: ${esc(fr.reason.split("\n")[0])}</div>` : ""))
    + (d.score_breakdown && d.score_breakdown.length
        ? `<div class="mt-3 space-y-1">` + d.score_breakdown.map(b=>`<div class="text-xs flex justify-between"><span class="text-slate-400">${esc(b.category)}</span><span class="text-amber-400">+${Number(b.points)||0}</span></div>`).join("") + `</div>` : "")
    + (!d.granted_permissions?.length && !net.urls?.length && !d.services?.length && !fr.ran
        ? `<p class="text-slate-500 text-xs mt-2">No notable runtime behaviour observed in ${d.duration}s (app may need interaction, or is benign).</p>` : "");
}

function short(h) { return h ? `${h.slice(0, 10)}…${h.slice(-6)}` : "—"; }
function showError(msg) { const e = $("error-box"); e.textContent = msg; e.classList.remove("hidden"); }
function hideError() { $("error-box").classList.add("hidden"); }
