// APK Fraud Analyzer — dashboard logic
const API = ""; // same origin

const SEV_COLORS = {
  Low: "#22c55e", Medium: "#eab308", High: "#f97316", Critical: "#ef4444",
  Unknown: "#64748b",
};

let selectedFile = null;
let gaugeChart = null;
let currentId = null;

const $ = (id) => document.getElementById(id);

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
      el.innerHTML = `<span class="chip" style="background:#065f46;color:#a7f3d0">● ${dev.avd_name || d.serial}${dev.android_version ? " · Android " + dev.android_version : ""}</span>`
        + (healthData.frida_available ? ` <span class="chip" style="background:#1e293b;color:#67e8f9">Frida ready</span>` : "");
    } else {
      el.innerHTML = `<span class="chip" style="background:#78350f;color:#fed7aa">${d.preferred_avd} not running — pick a device deliberately</span>`;
    }
    if (sel) {
      const devices = d.devices || [];
      let opts = devices.map(x => {
        const name = x.avd_name || x.serial;
        const isSandbox = name === d.preferred_avd;
        return `<option value="${x.serial}" ${x.serial === d.serial ? "selected" : ""}>${isSandbox ? "[Sandbox] " : ""}${name} (${x.serial})</option>`;
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
  // A failed/incomplete parse must NOT look like a clean "Low" app.
  if (a.valid_apk === false || a.risk_score == null || a.severity === "Unknown") {
    showError("Analysis could not complete — the file may not be a valid/parseable APK. "
      + ((a.errors && a.errors.length) ? a.errors.join("; ") : "No findings were extracted."));
    $("results").classList.add("hidden");
    return;
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
  ].map(([k, v]) => `<div><span class="text-slate-500">${k}</span><br><span class="text-slate-200 break-all">${v||"—"}</span></div>`).join("");

  $("threat").textContent = report.threat_assessment || "—";
  $("threat").style.color = color;

  // AI summary
  $("exec-summary").textContent = report.executive_summary || "—";
  $("tech-summary").textContent = report.technical_summary || "";
  $("behaviors").innerHTML = (a.detected_behaviors || []).map(
    b => `<span class="chip" style="background:#1e293b;color:#67e8f9">${b}</span>`).join("") ||
    '<span class="text-slate-500 text-sm">No high-risk behaviours flagged.</span>';

  // Breakdown
  const maxPts = Math.max(...(a.score_breakdown||[]).map(b=>b.points), 1);
  $("breakdown").innerHTML = (a.score_breakdown || []).map(b => `
    <div>
      <div class="flex justify-between text-sm mb-0.5">
        <span class="text-slate-200">${b.category}</span>
        <span class="text-cyan-400 font-semibold">+${b.points}</span>
      </div>
      <div class="h-1.5 bg-slate-800 rounded"><div class="h-1.5 rounded" style="width:${(b.points/maxPts*100)}%;background:${color}"></div></div>
      <div class="text-xs text-slate-500 mt-0.5">${b.detail||""}</div>
    </div>`).join("") || '<p class="text-slate-500 text-sm">No risk contributions.</p>';

  // Permissions
  $("perms").innerHTML = (a.permissions?.dangerous || []).map(p => `
    <div class="flex items-start gap-2">
      <span class="chip shrink-0" style="background:#7f1d1d;color:#fecaca">+${p.score}</span>
      <div><span class="text-slate-200 font-mono text-xs">${p.name}</span>
      <div class="text-xs text-slate-500">${p.reason}</div></div>
    </div>`).join("") || '<p class="text-slate-500 text-sm">No dangerous permissions.</p>';

  // APIs
  $("apis").innerHTML = (a.apis?.suspicious_apis || []).map(x => `
    <div class="flex items-start gap-2">
      <span class="chip shrink-0" style="background:#78350f;color:#fed7aa">+${x.score}</span>
      <div><span class="text-slate-200 font-mono text-xs">${x.api}</span>
      <div class="text-xs text-slate-500">${x.behaviour}</div></div>
    </div>`).join("") || '<p class="text-slate-500 text-sm">No suspicious APIs detected.</p>';

  // IOCs
  const i = a.iocs || {};
  const iocBlock = (label, arr) => (arr && arr.length)
    ? `<div><span class="text-slate-400">${label}:</span> <span class="text-slate-300 break-all font-mono text-xs">${arr.slice(0,15).join(", ")}</span></div>` : "";
  $("iocs").innerHTML = [
    iocBlock("Domains", i.domains), iocBlock("URLs", i.urls), iocBlock("IPs", i.ips),
    iocBlock("Telegram tokens", i.telegram_tokens), iocBlock("Secrets", i.hardcoded_secrets),
    (i.suspicious_keywords?.length ? `<div><span class="text-slate-400">Keywords:</span> <span class="text-slate-300 text-xs">${i.suspicious_keywords.map(k=>k.keyword).join(", ")}</span></div>` : ""),
    (i.decoded_blobs ? `<div class="text-xs text-slate-500">↳ ${i.decoded_blobs} Base64/hex blob(s) decoded &amp; rescanned${i.native_strings_scanned ? ` · ${i.native_strings_scanned} native-lib strings scanned` : ""}</div>` : ""),
  ].filter(Boolean).join("") || '<p class="text-slate-500">No network IOCs found in static strings.</p>';

  // Recommendations
  $("recs").innerHTML = (report.recommended_actions || a.recommendations || []).map(
    r => `<li class="flex gap-2"><span class="text-cyan-400">▸</span><span>${r}</span></li>`).join("")
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
      + `<span class="text-slate-400">malware probability → <span class="font-semibold" style="color:${c}">${(ml.prediction||"").toUpperCase()}</span></span></div>`
      + `<div class="h-2 bg-slate-800 rounded mb-2"><div class="h-2 rounded" style="width:${pct}%;background:${c}"></div></div>`
      + ((ml.contributing_permissions||[]).length
          ? `<div class="text-xs text-slate-400 mb-1">Top contributing permissions:</div><div class="flex flex-wrap gap-1.5">`
            + ml.contributing_permissions.map(p => `<span class="chip" style="background:#1e293b;color:#93c5fd">${p.permission}</span>`).join("") + `</div>`
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
        `<div><span class="chip" style="background:#7c2d12;color:#fed7aa">${f.category}</span> <span class="text-slate-200 font-mono text-xs">${f.name}</span></div>`).join("")
      + ((apkid.compilers || []).length ? `<div class="text-xs text-slate-500 mt-1">Compiler: ${apkid.compilers.join(", ")}</div>` : "")
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
        + (fr.threat_label ? `<div class="mb-2">Threat label: <span class="font-mono text-amber-300">${fr.threat_label}</span></div>` : "")
        + ((fr.engine_hits || []).length
            ? `<div class="text-xs text-slate-400 mb-1">Detections:</div><div class="flex flex-wrap gap-1.5">`
              + fr.engine_hits.slice(0, 14).map(h => `<span class="chip" style="background:#1e293b;color:#fca5a5" title="${h.engine}">${h.result}</span>`).join("") + `</div>`
            : "")
        + ((vt.flagged_domains || []).length
            ? `<div class="mt-3 text-xs text-slate-400">Flagged domains: <span class="text-red-300 font-mono">${vt.flagged_domains.map(d => d.domain).join(", ")}</span></div>` : "")
        + (fr.permalink ? `<a href="${fr.permalink}" target="_blank" class="inline-block mt-3 text-cyan-400 text-xs underline">View full VirusTotal report ↗</a>` : "");
    } else {
      vtBody.innerHTML = `<p class="text-slate-400">${fr.note || fr.error || "Not found on VirusTotal."}</p>`;
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
      html += `<div><span class="text-slate-400">Subject:</span> <span class="text-slate-200 font-mono text-xs">${cert.subject || "—"}</span></div>`;
      if (cert.validity_years != null) html += `<div><span class="text-slate-400">Validity:</span> ${cert.validity_years} yrs${cert.self_signed ? " · self-signed" : ""}</div>`;
      if (cert.sha256) html += `<div><span class="text-slate-400">Cert SHA256:</span> <span class="font-mono text-xs">${short(cert.sha256)}</span></div>`;
    }
    (cert.flags || []).forEach(f =>
      html += `<div><span class="chip" style="background:#7f1d1d;color:#fecaca">${f.flag}</span> <span class="text-slate-400 text-xs">${f.detail}</span></div>`);
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
          <span class="text-slate-200 text-sm truncate">${s.filename || s.package_name || s.id}</span>
          <span class="text-slate-500 text-xs ml-2 font-mono">${s.package_name || ""}</span>
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
    $("dyn-results").innerHTML = `<p class="text-red-400 text-sm">${e.message}</p>`;
  } finally {
    $("dyn-loading").classList.add("hidden");
    $("dyn-run-btn").disabled = false;
  }
}

function renderDynamic(d) {
  $("dyn-results").classList.remove("hidden");
  if (!d.available) {
    $("dyn-results").innerHTML = `<p class="text-amber-400 text-sm">${d.reason || "Emulator unavailable."}</p>`;
    return;
  }
  if (!d.ran) {
    $("dyn-results").innerHTML = `<p class="text-amber-400 text-sm">${d.reason || "APK did not run."}</p>`;
    return;
  }
  const net = d.network || {};
  const list = (label, arr) => (arr && arr.length)
    ? `<div><span class="text-slate-400">${label}:</span> <span class="text-slate-300 font-mono text-xs break-all">${arr.slice(0,15).join(", ")}</span></div>` : "";
  const fr = d.frida || {};
  $("dyn-results").innerHTML =
    `<div class="flex items-center gap-3 mb-3"><span class="text-2xl font-bold text-amber-400">${d.dynamic_score ?? 0}</span><span class="text-slate-400 text-sm">dynamic behaviour score · ran ${d.duration}s${d.use_frida ? " · Frida" : ""}${d.rooted ? " · root" : ""}${d.has_launcher === false ? " · no launcher icon" : ""}</span></div>`
    + ((d.activated && d.activated.length) ? `<div class="text-xs text-slate-400 mb-2">Triggered: ${d.activated.map(x=>`<span class="chip" style="background:#1e293b;color:#fcd34d">${x}</span>`).join(" ")}</div>` : "")
    + `<div class="grid md:grid-cols-2 gap-x-6 gap-y-1 text-sm">`
    + list("Granted permissions", d.granted_permissions)
    + list("Services", (d.services||[]).map(s=>s.split("/").pop()))
    + list("URLs", net.urls) + list("Domains", net.domains) + list("IPs", net.ips)
    + (d.runtime_signals && d.runtime_signals.length ? `<div><span class="text-slate-400">Runtime signals:</span> <span class="text-amber-300 text-xs">${d.runtime_signals.join(", ")}</span></div>` : "")
    + (d.crashes && d.crashes.length ? `<div><span class="text-slate-400">Crashes:</span> <span class="text-red-300 text-xs">${d.crashes.length}</span></div>` : "")
    + `</div>`
    + (fr.ran ? `<div class="mt-3"><div class="text-xs text-slate-400 mb-1">Frida-hooked events (${fr.event_count}):</div><div class="flex flex-wrap gap-1.5">`
        + (fr.findings||[]).map(f=>`<span class="chip" style="background:#1e293b;color:#67e8f9">${f.label} ×${f.count}</span>`).join("") + `</div></div>`
      : (d.use_frida && fr.reason ? `<div class="mt-3 text-xs text-slate-500">Frida: ${fr.reason.split("\n")[0]}</div>` : ""))
    + (d.score_breakdown && d.score_breakdown.length
        ? `<div class="mt-3 space-y-1">` + d.score_breakdown.map(b=>`<div class="text-xs flex justify-between"><span class="text-slate-400">${b.category}</span><span class="text-amber-400">+${b.points}</span></div>`).join("") + `</div>` : "")
    + (!d.granted_permissions?.length && !net.urls?.length && !d.services?.length && !fr.ran
        ? `<p class="text-slate-500 text-xs mt-2">No notable runtime behaviour observed in ${d.duration}s (app may need interaction, or is benign).</p>` : "");
}

function short(h) { return h ? `${h.slice(0, 10)}…${h.slice(-6)}` : "—"; }
function showError(msg) { const e = $("error-box"); e.textContent = msg; e.classList.remove("hidden"); }
function hideError() { $("error-box").classList.add("hidden"); }
