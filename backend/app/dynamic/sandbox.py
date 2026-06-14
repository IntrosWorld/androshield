"""Dynamic analysis orchestrator (adb tier).

Runs an APK inside an attached Android emulator and observes its behaviour:
install -> launch -> capture logcat / granted runtime permissions / running services /
network indicators -> uninstall. Pure-parse helpers (`parse_*`) are separated from the
device I/O so they can be unit-tested without an emulator.

SAFETY: this is the *controlled exception* to "never execute an uploaded APK" — it runs
ONLY inside the emulator the user explicitly targets, never on the host, and only when
the user explicitly triggers it. Use an isolated AVD for real malware.
"""
import logging
import os
import re
import time

from . import adb, frida_runner
from ..analyzer import iocs as ioc_mod

log = logging.getLogger("dynamic.sandbox")

# Default dedicated analysis AVD; override with SANDBOX_AVD env var.
DEFAULT_SANDBOX_AVD = os.getenv("SANDBOX_AVD", "FraudSandbox")

# Dynamic-behaviour scoring (plan §7 "Dynamic Behavior Score").
_DYN_WEIGHTS = {
    "network_endpoint": 8,      # per distinct endpoint contacted (capped)
    "service_started": 6,       # background service running
    "runtime_dex_load": 15,     # loaded code at runtime
    "sms_runtime": 20,          # SMS activity observed in logs
    "accessibility_runtime": 12,
    "crash": 0,                 # informational
}

_DANGEROUS_RUNTIME = {
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CONTACTS", "RECORD_AUDIO",
    "READ_PHONE_STATE", "ACCESS_FINE_LOCATION", "READ_CALL_LOG",
}


# --------------------------------------------------------------------------- #
# Pure parsers (unit-testable)
# --------------------------------------------------------------------------- #

_GRANTED_RE = re.compile(r"(android\.permission\.[A-Z_]+):\s*granted=true")


def parse_granted_permissions(dumpsys_text):
    """Runtime permissions reported as granted=true in `dumpsys package`."""
    granted = []
    for m in _GRANTED_RE.finditer(dumpsys_text or ""):
        short = m.group(1).rsplit(".", 1)[-1]
        if short not in granted:
            granted.append(short)
    return granted


_SERVICE_RE = re.compile(r"ServiceRecord\{[^}]*\s([\w./]+)\}")


def parse_services(services_text):
    """Active services from `dumpsys activity services <pkg>`."""
    svcs = []
    for m in _SERVICE_RE.finditer(services_text or ""):
        name = m.group(1)
        if name not in svcs:
            svcs.append(name)
    return svcs


def parse_network(logcat_text):
    """Network indicators observed in logcat (reuses the static IOC regexes)."""
    lines = (logcat_text or "").splitlines()
    iocs = ioc_mod.extract_iocs(lines)
    return {
        "urls": iocs.get("urls", []),
        "domains": iocs.get("domains", []),
        "ips": iocs.get("ips", []),
    }


def parse_runtime_signals(logcat_text):
    """Heuristic runtime behaviour signals from logcat text."""
    text = logcat_text or ""
    low = text.lower()
    signals = []
    if "dexclassloader" in low or "in-memory dex" in low or re.search(r"dalvik.*load", low):
        signals.append("runtime_dex_load")
    if "smsmanager" in low or "sendtextmessage" in low or re.search(r"\bsms\b.*sent", low):
        signals.append("sms_runtime")
    if "accessibilityservice" in low or "accessibility event" in low:
        signals.append("accessibility_runtime")
    return signals


def parse_crashes(logcat_text, package):
    crashes = []
    lines = (logcat_text or "").splitlines()
    for i, ln in enumerate(lines):
        if "FATAL EXCEPTION" in ln or ("AndroidRuntime" in ln and "Process: " + (package or "") in ln):
            crashes.append(ln.strip())
    return crashes[:10]


def score_dynamic(network, services, runtime_signals, granted):
    breakdown = []
    score = 0
    endpoints = len(set(network.get("urls", []))) + len(set(network.get("domains", [])))
    if endpoints:
        pts = min(endpoints * _DYN_WEIGHTS["network_endpoint"], 24)
        score += pts
        breakdown.append({"category": "Network activity", "points": pts,
                          "detail": f"{endpoints} endpoint(s) contacted at runtime"})
    if services:
        pts = min(len(services) * _DYN_WEIGHTS["service_started"], 12)
        score += pts
        breakdown.append({"category": "Background services", "points": pts,
                          "detail": f"{len(services)} service(s) running"})
    for sig in set(runtime_signals):
        pts = _DYN_WEIGHTS.get(sig, 0)
        if pts:
            score += pts
            breakdown.append({"category": sig.replace("_", " ").title(), "points": pts,
                              "detail": "observed in runtime logs"})
    dangerous = [p for p in granted if p in _DANGEROUS_RUNTIME]
    if dangerous:
        pts = min(len(dangerous) * 3, 15)
        score += pts
        breakdown.append({"category": "Dangerous permissions granted", "points": pts,
                          "detail": ", ".join(dangerous)})
    return min(score, 100), breakdown


# --------------------------------------------------------------------------- #
# Device orchestration
# --------------------------------------------------------------------------- #

def _preferred_serial(devices):
    """Serial of the dedicated sandbox AVD, or None.

    Deliberately does NOT fall back to an arbitrary device — auto-runs must target the
    isolated sandbox only, never (e.g.) the user's other emulators. To use a different
    device the caller must pass an explicit serial.
    """
    for d in devices:
        if d.get("avd_name") == DEFAULT_SANDBOX_AVD:
            return d["serial"]
    return None


# Common actions malware registers receivers for — broadcast to each receiver so
# event-triggered / no-launcher-icon droppers actually activate.
_DEFAULT_TRIGGER_ACTIONS = [
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.USER_PRESENT",
    "android.intent.action.MY_PACKAGE_REPLACED",
    "android.net.conn.CONNECTIVITY_CHANGE",
    "android.provider.Telephony.SMS_RECEIVED",
]
_MAX_BROADCASTS = 60


def collect_triggers(apk_path):
    """Parse the APK for every entry point we can trigger: launcher activity,
    receivers (+ their declared intent-filter actions) and services."""
    out = {"main_activity": None, "receivers": [], "services": []}
    try:
        from androguard.core.apk import APK
        a = APK(apk_path)
        out["main_activity"] = a.get_main_activity()
        for r in (a.get_receivers() or []):
            actions = []
            try:
                filt = a.get_intent_filters("receiver", r)
                if isinstance(filt, dict):
                    actions = list(filt.get("action", []) or [])
            except Exception:
                pass
            out["receivers"].append({"name": r, "actions": actions})
        out["services"] = list(a.get_services() or [])
    except Exception as e:
        log.warning("trigger collection failed: %s", e)
    return out


def _component(package_name, name):
    """Build an `am -n` component spec, handling relative (.Foo) and absolute names."""
    if not name:
        return None
    return name if "/" in name else f"{package_name}/{name}"


# Positive-button labels on consent / permission dialogs to auto-tap.
_CONSENT_LABELS = ["Continue", "CONTINUE", "Allow", "ALLOW",
                   "While using the app", "Only this time", "Accept", "OK", "Agree"]


def dismiss_consent_dialogs(serial, rounds=5):
    """Auto-tap through consent / permission modals so the app proceeds. Delegates to the
    adb-layer helper (shared with the Frida unpacker)."""
    return adb.dismiss_consent_dialogs(serial, rounds=rounds)


def _relax_background_limits(package_name, serial):
    """Exempt the app from Android 8+/12+ background-execution limits so its services
    can actually start (otherwise the OS blocks shell-initiated service starts)."""
    for op in ("RUN_IN_BACKGROUND", "RUN_ANY_IN_BACKGROUND"):
        adb.shell(["cmd", "appops", "set", package_name, op, "allow"], serial=serial, timeout=15)
    adb.shell(["dumpsys", "deviceidle", "whitelist", "+" + package_name], serial=serial, timeout=15)
    adb.shell(["cmd", "deviceidle", "tempwhitelist", package_name], serial=serial, timeout=15)


def activate(package_name, triggers, serial):
    """Fire every entry point: launcher activity, receiver broadcasts, services.

    Returns a list describing what was triggered (for transparency in the report).
    """
    activated = []
    _relax_background_limits(package_name, serial)

    # 1) Launcher activity (explicit component, then a generic LAUNCHER launch).
    main = triggers.get("main_activity")
    if main:
        comp = _component(package_name, main)
        rc, o, e = adb.shell(["am", "start", "-n", comp], serial=serial, timeout=20)
        if rc == 0 and "Error" not in (o + e) and "Exception" not in (o + e):
            activated.append(f"activity:{main.rsplit('.', 1)[-1]}")
    adb.shell(["monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
              serial=serial, timeout=20)

    # 2) Broadcast to each declared receiver (its own actions + common triggers).
    broadcasts = 0
    for recv in triggers.get("receivers", []):
        comp = _component(package_name, recv["name"])
        actions = list(dict.fromkeys((recv.get("actions") or []) + _DEFAULT_TRIGGER_ACTIONS))
        fired_any = False
        for action in actions:
            if broadcasts >= _MAX_BROADCASTS:
                break
            rc, o, e = adb.shell(["am", "broadcast", "-a", action, "-n", comp],
                                 serial=serial, timeout=15)
            broadcasts += 1
            if rc == 0 and "Broadcast completed" in o:
                fired_any = True
        if fired_any:
            activated.append(f"broadcast:{recv['name'].rsplit('.', 1)[-1]}")

    # 3) Start declared services. Android 8+ blocks background `start-service` from the
    #    shell, so try `start-foreground-service` first (bypasses the limit), then fall
    #    back. This is what gets a dropper's worker service to actually execute.
    for svc in triggers.get("services", []):
        comp = _component(package_name, svc)
        started = False
        for verb in ("start-foreground-service", "start-service", "startservice"):
            rc, o, e = adb.shell(["am", verb, "-n", comp], serial=serial, timeout=15)
            blob = o + e
            if rc == 0 and "Error" not in blob and "not allowed" not in blob and "not found" not in blob.lower():
                started = True
                break
        activated.append(f"service:{svc.rsplit('.', 1)[-1]}" + ("" if started else "(blocked)"))

    return activated


def device_ready():
    return adb.available() and adb.first_device() is not None


def status():
    if not adb.available():
        return {"available": False, "devices": [],
                "reason": "adb not found (set ANDROID_HOME or add platform-tools to PATH)"}
    devices = adb.list_devices_detailed()
    if not devices:
        return {"available": False, "devices": [],
                "reason": f"No emulator/device attached. Start the sandbox: emulator -avd {DEFAULT_SANDBOX_AVD}"}
    preferred = _preferred_serial(devices)
    dev = next((d for d in devices if d["serial"] == preferred), None)
    return {
        "available": True,
        "serial": preferred,                       # None unless the sandbox AVD is up
        "preferred_avd": DEFAULT_SANDBOX_AVD,
        "sandbox_present": preferred is not None,
        "device": ({"android_version": dev.get("android_version"), "abi": dev.get("abi"),
                    "avd_name": dev.get("avd_name")} if dev else None),
        "devices": devices,
    }


def run_dynamic(apk_path, package_name, main_activity, duration=15, use_frida=False, serial=None):
    """Install, run, observe, and uninstall the APK in the attached emulator.

    When use_frida is True the app is launched *under Frida* (so API hooks fire) instead
    of a plain `am start`; logcat/dumpsys are still captured around it.
    """
    if not serial:
        devices = adb.list_devices_detailed()
        serial = _preferred_serial(devices)
        if not serial:
            return {"available": False, "ran": False,
                    "reason": f"Dedicated sandbox AVD '{DEFAULT_SANDBOX_AVD}' is not running. "
                              f"Start it (emulator -avd {DEFAULT_SANDBOX_AVD}) or select a device explicitly."}

    duration = max(5, min(int(duration or 15), 120))
    result = {"available": True, "ran": False, "serial": serial,
              "package": package_name, "duration": duration, "use_frida": use_frida,
              "steps": []}

    def step(msg):
        result["steps"].append(msg)
        log.info("[dynamic] %s", msg)

    # Root the device so protected broadcasts (BOOT_COMPLETED etc.) can be delivered
    # to receivers — required to activate event-triggered malware. No-op if not rootable.
    result["rooted"] = adb.root(serial=serial)

    # --- Install ---
    rc, out, err = adb.install(apk_path, serial=serial)
    if rc != 0:
        result["reason"] = f"Install failed: {(err or out).strip()[:300]}"
        step("install failed")
        return result
    step("installed")

    try:
        adb.logcat_clear(serial)

        # Discover every entry point (activity / receivers+actions / services).
        triggers = collect_triggers(apk_path)
        result["main_activity"] = triggers.get("main_activity")
        result["has_launcher"] = bool(triggers.get("main_activity"))

        # --- Activate (hardened Frida unpacker if requested, else trigger sequence) ---
        if use_frida:
            step("hardened Frida run (anti-VM bypass + spawn-gating + payload capture)")
            _relax_background_limits(package_name, serial)
            fr = frida_runner.run_unpack(package_name, duration, serial=serial, triggers=triggers)
            result["frida"] = fr
            result["ran"] = bool(fr.get("ran"))
            if fr.get("ran"):
                result["antivm_applied"] = fr.get("antivm_applied")
                result["payload_dumps"] = fr.get("dumps")
                # Surface runtime C2 endpoints captured by the hooks.
                c2 = []
                for e in fr.get("events", []):
                    if e.get("category") == "network" and e.get("detail"):
                        c2.append(e["detail"])
                result["c2_endpoints"] = sorted(set(c2))
                step(f"frida: {len(result.get('payload_dumps') or [])} dump(s), "
                     f"{len(result['c2_endpoints'])} C2 endpoint(s)")
            else:
                # Frida unavailable/failed — fall back to the adb trigger sequence.
                step(f"frida unavailable ({(fr.get('reason') or '')[:60]}), activating via triggers")
                result["activated"] = activate(package_name, triggers, serial)
                dismiss_consent_dialogs(serial)
                time.sleep(duration)
                result["ran"] = True
        else:
            result["activated"] = activate(package_name, triggers, serial)
            step(f"triggered: {', '.join(result['activated']) or 'nothing launchable'}")
            result["ran"] = True
            # Tap through any consent/permission modal blocking the app, then re-fire
            # the entry points (the app couldn't run while the dialog was up).
            consent = dismiss_consent_dialogs(serial)
            if consent:
                result["consent_dismissed"] = consent
                step(f"dismissed consent: {', '.join(consent)}")
                activate(package_name, triggers, serial)
            time.sleep(duration)
            dismiss_consent_dialogs(serial, rounds=2)

        # --- Observe ---
        pid = adb.pid_of(package_name, serial)
        result["pid"] = pid

        # Capture the app's own log lines (by PID) plus any system log mentioning the
        # package. Avoids `logcat -c`, which hangs on API-35 emulators.
        logcat_pid = adb.logcat_by_pid(pid, serial) if pid else ""
        logcat_full = adb.logcat_dump(serial)
        pkg_lines = "\n".join(l for l in logcat_full.splitlines() if package_name in l)
        logcat = (logcat_pid + "\n" + pkg_lines).strip()
        _, dump_pkg, _ = adb.shell(["dumpsys", "package", package_name], serial=serial, timeout=40)
        _, dump_svc, _ = adb.shell(["dumpsys", "activity", "services", package_name],
                                   serial=serial, timeout=40)

        granted = parse_granted_permissions(dump_pkg)
        services = parse_services(dump_svc)
        network = parse_network(logcat)
        runtime_signals = parse_runtime_signals(logcat)
        crashes = parse_crashes(logcat, package_name)

        # Merge Frida-captured C2 endpoints (URLs the app contacted at runtime) into the
        # network indicators — these are high-value dynamic-only IOCs.
        c2 = result.get("c2_endpoints") or []
        if c2:
            from ..analyzer import iocs as _ioc
            extra = _ioc.extract_iocs(c2)
            network["urls"] = sorted(set(network.get("urls", []) + extra.get("urls", [])))
            network["domains"] = sorted(set(network.get("domains", []) + extra.get("domains", [])))
            network["ips"] = sorted(set(network.get("ips", []) + extra.get("ips", [])))

        score, breakdown = score_dynamic(network, services, runtime_signals, granted)
        # Runtime C2 contact is a strong dynamic signal.
        if c2:
            breakdown.append({"category": "Runtime C2 contact", "points": 25,
                              "detail": "; ".join(sorted(set(c2))[:3])})
            score = min(score + 25, 100)
        # Payload artefacts dumped (unpacked DEX) — concrete dropper evidence.
        if result.get("payload_dumps"):
            breakdown.append({"category": "Payload unpacked", "points": 15,
                              "detail": f"{len(result['payload_dumps'])} artefact(s) captured"})
            score = min(score + 15, 100)
        # Fold in Frida-hooked behaviour, if any.
        frida_res = result.get("frida") or {}
        if frida_res.get("ran") and frida_res.get("frida_score"):
            breakdown.append({"category": "Frida-hooked behaviour",
                              "points": frida_res["frida_score"],
                              "detail": ", ".join(f["label"] for f in frida_res.get("findings", []))})
            score = min(score + frida_res["frida_score"], 100)
        result.update({
            "granted_permissions": granted,
            "services": services,
            "network": network,
            "runtime_signals": runtime_signals,
            "crashes": crashes,
            "dynamic_score": score,
            "score_breakdown": breakdown,
            "logcat_lines": len((logcat or "").splitlines()),
        })
        step("captured behaviour")
    finally:
        adb.force_stop(package_name, serial)
        adb.uninstall(package_name, serial=serial)
        step("uninstalled")

    return result
