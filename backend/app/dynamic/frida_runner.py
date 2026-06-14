"""Frida tier — live API hooking during dynamic analysis.

Spawns the app under Frida, loads `frida_hooks.js`, collects the events the hooks emit
for `duration` seconds, then aggregates them into behaviour findings + a score bump.

Requires `frida-server` (matching the installed frida version + device ABI) running on
the emulator. We do NOT auto-download it — if it isn't running, we return clear setup
instructions instead of failing the whole request.
"""
import base64
import logging
import os
import time

from . import adb

log = logging.getLogger("dynamic.frida")

_HOOKS_PATH = os.path.join(os.path.dirname(__file__), "frida_hooks.js")
_ANTIVM_PATH = os.path.join(os.path.dirname(__file__), "frida_antivm.js")

# Frida event category -> (dynamic score, behaviour label).
_EVENT_SCORE = {
    "sms": (20, "SMS send at runtime (OTP exfiltration)"),
    "network": (8, "Network request at runtime"),
    "dynamic_load": (15, "Dynamic code loading at runtime"),
    "exec": (12, "Shell command execution at runtime"),
    "clipboard": (8, "Clipboard read at runtime"),
    "crypto": (4, "Encryption at runtime"),
}


def available() -> bool:
    try:
        import frida  # noqa: F401
        return True
    except Exception:
        return False


def frida_version():
    try:
        import frida
        return frida.__version__
    except Exception:
        return None


def _hooks_source():
    with open(_HOOKS_PATH, encoding="utf-8") as fh:
        return fh.read()


def _get_frida_device(serial, frida):
    device = None
    if serial:
        try:
            device = frida.get_device(serial, timeout=5)
        except Exception:
            device = None
    if device is None:
        try:
            device = frida.get_usb_device(timeout=5)
        except Exception:
            try:
                devs = frida.get_device_manager().enumerate_devices()
                device = next((d for d in devs if d.type in ("usb", "remote")), None)
            except Exception:
                device = None
    return device


def _fire_triggers(package_name, triggers, serial):
    """Start the app's process via its entry points (so spawn-gating can catch it)."""
    default_actions = ["android.intent.action.BOOT_COMPLETED",
                       "android.intent.action.USER_PRESENT"]
    for recv in (triggers or {}).get("receivers", []):
        comp = recv["name"] if "/" in recv["name"] else f"{package_name}/{recv['name']}"
        for action in list(dict.fromkeys((recv.get("actions") or []) + default_actions))[:6]:
            adb.shell(["am", "broadcast", "-a", action, "-n", comp], serial=serial, timeout=12)
    for svc in (triggers or {}).get("services", []):
        comp = svc if "/" in svc else f"{package_name}/{svc}"
        adb.shell(["am", "start-foreground-service", "-n", comp], serial=serial, timeout=12)
    adb.shell(["monkey", "-p", package_name, "1"], serial=serial, timeout=12)


def run_unpack(package_name, duration=20, serial=None, dump_dir=None, triggers=None):
    """Run the app hardened against anti-VM and capture its decrypted payload.

    Uses spawn-gating so it works even for no-launcher (event-triggered) droppers: gate
    new processes, fire the app's triggers, catch its spawn at birth, install
    frida_antivm.js (spoof emulator + capture Cipher/DexClassLoader output), resume.
    Dumps go to dump_dir; on-disk DEX paths are pulled via adb.
    """
    if not available():
        return {"available": False, "reason": "frida-python is not installed"}
    if dump_dir is None:
        dump_dir = os.path.join(os.path.dirname(__file__), "..", "..", "tools", "dumps")
    dump_dir = os.path.abspath(dump_dir)
    os.makedirs(dump_dir, exist_ok=True)

    import frida
    ver = frida.__version__
    events, dumps, dex_paths, antivm = [], [], [], []
    counter = {"n": 0}

    def on_message(message, data):
        if message.get("type") != "send":
            if message.get("type") == "error":
                log.warning("frida error: %s", message.get("description"))
            return
        p = message.get("payload") or {}
        cat = p.get("category")
        if cat == "payload_dump" and p.get("data"):
            try:
                raw = base64.b64decode(p["data"])
                counter["n"] += 1
                ext = {"dex": "dex", "zip": "jar"}.get(p.get("kind"), "bin")
                fn = os.path.join(dump_dir, f"{package_name}_payload_{counter['n']}.{ext}")
                with open(fn, "wb") as fh:
                    fh.write(raw)
                dumps.append({"file": fn, "size": len(raw), "kind": p.get("kind"),
                              "detail": p.get("detail"), "via": p.get("api")})
            except Exception as e:
                log.warning("dump save failed: %s", e)
        elif cat == "dynamic_load":
            d = p.get("detail", "")
            if d.startswith("path="):
                dex_paths.append(d[5:].strip())
            events.append(p)
        elif cat == "antivm":
            antivm.append(p.get("detail"))
        elif cat and cat != "_status":
            events.append(p)

    with open(_ANTIVM_PATH, encoding="utf-8") as fh:
        script_src = fh.read()

    device = session = script = None
    target = {"pid": None}
    instrumented = {"done": False}
    gating = False

    def _instrument(pid):
        nonlocal session, script
        try:
            session = device.attach(pid)
            script = session.create_script(script_src)
            script.on("message", on_message)
            script.load()
            instrumented["done"] = True
        except Exception as e:
            log.warning("instrument failed: %s", e)

    def on_spawn(spawn):
        ident = spawn.identifier or ""
        if not ident:
            # Identifier often unresolved at gate time — resolve via the process cmdline.
            try:
                rc, out, _ = adb.shell(["cat", "/proc/%d/cmdline" % spawn.pid],
                                       serial=serial, timeout=5)
                ident = (out or "").replace("\x00", " ").strip()
            except Exception:
                ident = ""
        match = ident == package_name or (ident and package_name in ident)
        if not instrumented["done"] and match:
            target["pid"] = spawn.pid
            _instrument(spawn.pid)
            try:
                device.resume(spawn.pid)
            except Exception:
                pass
        else:
            try:
                device.resume(spawn.pid)   # don't freeze unrelated processes
            except Exception:
                pass

    try:
        device = _get_frida_device(serial, frida)
        if device is None:
            return {"available": True, "ran": False, "reason": _setup_hint(ver)}

        # Launcher apps: spawn suspended → hook → resume (catches earliest code).
        main = (triggers or {}).get("main_activity")
        if main:
            try:
                pid = device.spawn([package_name])
                target["pid"] = pid
                _instrument(pid)
                device.resume(pid)
            except Exception:
                main = None

        # No-launcher: clear the one-time review modal first (so it won't block the spawn),
        # then PRIMARY = spawn-gating (hooks installed before any app code → catches the
        # startup C2 beacon), FALLBACK = attach-after-start if gating doesn't catch it.
        if not instrumented["done"]:
            _fire_triggers(package_name, triggers, serial)
            adb.dismiss_consent_dialogs(serial, rounds=4)        # complete the review
            adb.shell(["am", "force-stop", package_name], serial=serial, timeout=15)
            time.sleep(1.5)

            device.on("spawn-added", on_spawn)
            device.enable_spawn_gating()
            gating = True
            _fire_triggers(package_name, triggers, serial)
            waited = 0.0
            while not instrumented["done"] and waited < 20:
                time.sleep(0.5)
                waited += 0.5

        # Fallback: attach to the running process if gating didn't catch a spawn.
        if not instrumented["done"]:
            _fire_triggers(package_name, triggers, serial)
            waited = 0.0
            while waited < 15:
                pid_str = adb.pid_of(package_name, serial)
                if pid_str:
                    try:
                        target["pid"] = int(pid_str)
                        _instrument(int(pid_str))
                    except Exception as e:
                        log.warning("attach failed: %s", e)
                    break
                adb.dismiss_consent_dialogs(serial, rounds=1)
                time.sleep(1.0)
                waited += 1.0

        if not instrumented["done"]:
            return {"available": True, "ran": False,
                    "reason": "could not start/attach to app process (triggers didn't launch it)"}

        time.sleep(max(8, min(int(duration or 20), 120)))
    except Exception as e:
        log.exception("frida unpack failed")
        return {"available": True, "ran": False, "reason": f"frida error: {e}"}
    finally:
        try:
            if gating:
                device.disable_spawn_gating()
            if script:
                script.unload()
            if session:
                session.detach()
            if target["pid"]:
                device.kill(target["pid"])
        except Exception:
            pass

    # Pull any on-disk DEX the dropper loaded.
    for path in dict.fromkeys(dex_paths):
        try:
            dest = os.path.join(dump_dir, package_name + "_" + os.path.basename(path))
            rc, out, err = adb._run(["pull", path, dest], serial=serial, timeout=30)
            if rc == 0 and os.path.exists(dest):
                dumps.append({"file": dest, "size": os.path.getsize(dest),
                              "kind": "dex-ondisk", "detail": path, "via": "adb pull"})
        except Exception:
            pass

    return {
        "available": True, "ran": True, "frida_version": ver,
        "antivm_applied": antivm, "dex_load_paths": dex_paths,
        "events": events[:100], "dumps": dumps, "dump_count": len(dumps),
    }


def _setup_hint(version):
    return (
        "frida-server is not reachable on the device. Set it up once:\n"
        f"  1) Download frida-server {version or '<version>'} for your emulator ABI from "
        "https://github.com/frida/frida/releases\n"
        "  2) adb root && adb push frida-server-<ver>-android-<abi> /data/local/tmp/frida-server\n"
        "  3) adb shell \"chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &\""
    )


def run_frida(package_name, duration=15, serial=None):
    """Spawn the app under Frida and collect hooked runtime events.

    serial: target a specific adb device so Frida never attaches to the wrong emulator.
    """
    if not available():
        return {"available": False, "reason": "frida-python is not installed"}

    import frida
    ver = frida.__version__
    events = []

    def on_message(message, data):
        if message.get("type") == "send":
            payload = message.get("payload") or {}
            if payload.get("category") and payload.get("category") != "_status":
                events.append(payload)
        elif message.get("type") == "error":
            log.warning("frida script error: %s", message.get("description"))

    device = pid = session = script = None
    try:
        device = None
        if serial:
            try:
                device = frida.get_device(serial, timeout=5)
            except Exception:
                device = None
        if device is None:
            try:
                device = frida.get_usb_device(timeout=5)
            except Exception:
                devs = frida.get_device_manager().enumerate_devices()
                device = next((d for d in devs if d.type in ("usb", "remote")), None)
        if device is None:
            return {"available": True, "ran": False, "reason": _setup_hint(ver)}

        pid = device.spawn([package_name])
        session = device.attach(pid)
        script = session.create_script(_hooks_source())
        script.on("message", on_message)
        script.load()
        device.resume(pid)

        time.sleep(max(5, min(int(duration or 15), 120)))
    except frida.ServerNotRunningError:
        return {"available": True, "ran": False, "reason": _setup_hint(ver)}
    except frida.TransportError:
        return {"available": True, "ran": False, "reason": _setup_hint(ver)}
    except Exception as e:
        log.exception("frida run failed")
        return {"available": True, "ran": False, "reason": f"frida error: {e}"}
    finally:
        try:
            if script:
                script.unload()
            if session:
                session.detach()
            if device and pid:
                device.kill(pid)
        except Exception:
            pass

    # Aggregate events into findings + score.
    score = 0
    counts = {}
    for ev in events:
        cat = ev.get("category")
        counts[cat] = counts.get(cat, 0) + 1
    findings = []
    for cat, n in counts.items():
        pts, label = _EVENT_SCORE.get(cat, (0, cat))
        score += min(pts * n, pts * 3)  # diminishing returns per category
        findings.append({"category": cat, "label": label, "count": n})

    return {
        "available": True,
        "ran": True,
        "event_count": len(events),
        "events": events[:100],
        "findings": findings,
        "frida_score": min(score, 60),
        "frida_version": ver,
    }
