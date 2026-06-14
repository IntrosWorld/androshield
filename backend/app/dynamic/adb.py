"""Thin, defensive wrapper around the Android Debug Bridge (adb).

Locates adb from PATH or ANDROID_HOME/ANDROID_SDK_ROOT. Every call has a timeout and
returns (returncode, stdout, stderr) instead of raising, so the sandbox orchestrator
can degrade gracefully when no emulator is attached.
"""
import os
import shutil
import subprocess


def adb_path():
    p = shutil.which("adb")
    if p:
        return p
    exe = "adb.exe" if os.name == "nt" else "adb"
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        root = os.getenv(env)
        if root:
            cand = os.path.join(root, "platform-tools", exe)
            if os.path.exists(cand):
                return cand
    return None


def available() -> bool:
    return adb_path() is not None


def _run(args, timeout=60, serial=None):
    adb = adb_path()
    if not adb:
        return -2, "", "adb not found (set ANDROID_HOME or add platform-tools to PATH)"
    cmd = [adb]
    if serial:
        cmd += ["-s", serial]
    cmd += args
    try:
        # Decode as UTF-8 with replacement — logcat/dumpsys output contains bytes the
        # Windows default codepage (cp1252) can't decode, which otherwise crashes.
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", f"adb timed out after {timeout}s: {' '.join(args)}"
    except Exception as e:  # pragma: no cover
        return -3, "", str(e)


def list_devices():
    """Return serials of online devices (state == 'device')."""
    rc, out, _ = _run(["devices"], timeout=15)
    if rc != 0:
        return []
    devices = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if not line or "\t" not in line:
            continue
        serial, state = line.split("\t", 1)
        if state.strip() == "device":
            devices.append(serial.strip())
    return devices


def first_device():
    devs = list_devices()
    return devs[0] if devs else None


def shell(cmd, serial=None, timeout=30):
    return _run(["shell"] + (cmd if isinstance(cmd, list) else [cmd]), timeout=timeout, serial=serial)


def install(apk_path, serial=None, timeout=180):
    # -r reinstall, -t allow test apks, -d allow downgrade,
    # --bypass-low-target-sdk-block installs old samples that target < SDK 24 (common
    # for legacy malware) which modern Android otherwise refuses.
    rc, out, err = _run(["install", "-r", "-t", "-d", "--bypass-low-target-sdk-block", apk_path],
                        timeout=timeout, serial=serial)
    if rc != 0 and "bypass-low-target-sdk-block" in (err or ""):
        # Older adb without the flag — retry without it.
        return _run(["install", "-r", "-t", "-d", apk_path], timeout=timeout, serial=serial)
    return rc, out, err


def uninstall(package, serial=None, timeout=60):
    return _run(["uninstall", package], timeout=timeout, serial=serial)


def launch(package, activity, serial=None, timeout=30):
    if activity:
        comp = activity if "/" in activity else f"{package}/{activity}"
        return _run(["shell", "am", "start", "-n", comp], timeout=timeout, serial=serial)
    # Fallback: launch the default LAUNCHER intent for the package.
    return _run(["shell", "monkey", "-p", package, "-c",
                 "android.intent.category.LAUNCHER", "1"], timeout=timeout, serial=serial)


def force_stop(package, serial=None):
    return _run(["shell", "am", "force-stop", package], timeout=30, serial=serial)


def logcat_clear(serial=None):
    # `logcat -c` hangs on some Android 15/API-35 emulators, so keep the timeout short
    # and treat failure as non-fatal (capture uses PID/package filtering instead).
    return _run(["logcat", "-c"], timeout=6, serial=serial)


def logcat_dump(serial=None, timeout=30):
    rc, out, err = _run(["logcat", "-d", "-v", "time"], timeout=timeout, serial=serial)
    return out


def logcat_by_pid(pid, serial=None, timeout=30):
    """Dump only the target app's log lines (avoids relying on `logcat -c`)."""
    if not pid:
        return ""
    rc, out, err = _run(["logcat", "-d", "--pid", str(pid), "-v", "time"],
                        timeout=timeout, serial=serial)
    return out


def pid_of(package, serial=None):
    rc, out, _ = shell(["pidof", package], serial=serial, timeout=15)
    out = out.strip()
    return out.split()[0] if out else None


_CONSENT_LABELS = ["Continue", "CONTINUE", "Allow", "ALLOW",
                   "While using the app", "Only this time", "Accept", "OK", "Agree"]


def dismiss_consent_dialogs(serial=None, rounds=5):
    """Auto-tap through consent / permission modals (e.g. legacy ReviewPermissionsActivity)
    that block an app from running. Locates the positive button via uiautomator and taps
    its centre. Best-effort; returns labels tapped."""
    import re
    import time as _t
    tapped = []
    for _ in range(rounds):
        rc, out, _ = _run(["shell", "uiautomator", "dump", "/sdcard/_consent.xml"],
                          serial=serial, timeout=20)
        rc, xml, _ = _run(["shell", "cat", "/sdcard/_consent.xml"], serial=serial, timeout=15)
        if not xml:
            break
        hit = None
        for label in _CONSENT_LABELS:
            pat1 = r'text="%s"[^>]*?bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"' % re.escape(label)
            pat2 = r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"[^>]*?text="%s"' % re.escape(label)
            m = re.search(pat1, xml) or re.search(pat2, xml)
            if m:
                x1, y1, x2, y2 = map(int, m.groups())
                _run(["shell", "input", "tap", str((x1 + x2) // 2), str((y1 + y2) // 2)],
                     serial=serial, timeout=10)
                tapped.append(label)
                hit = label
                _t.sleep(1.0)
                break
        if not hit:
            break
    return tapped


def root(serial=None):
    """Best-effort `adb root` so protected broadcasts (e.g. BOOT_COMPLETED) deliver.

    No-op on non-rootable (production) images. Restarts adbd, so we re-wait after.
    """
    import time
    rc, out, err = _run(["root"], serial=serial, timeout=20)
    time.sleep(2)
    _run(["wait-for-device"], serial=serial, timeout=30)
    is_root = False
    rc2, uid, _ = shell(["id", "-u"], serial=serial, timeout=10)
    if uid.strip() == "0":
        is_root = True
    return is_root


def device_props(serial=None):
    rc, out, _ = shell(["getprop", "ro.build.version.release"], serial=serial, timeout=15)
    rc2, abi, _ = shell(["getprop", "ro.product.cpu.abi"], serial=serial, timeout=15)
    return {"android_version": out.strip(), "abi": abi.strip()}


def avd_name(serial):
    """The AVD name behind an emulator serial (via `adb emu avd name`)."""
    rc, out, _ = _run(["emu", "avd", "name"], serial=serial, timeout=10)
    for ln in (out or "").splitlines():
        ln = ln.strip()
        if ln and ln != "OK":
            return ln
    return None


def list_devices_detailed():
    devs = []
    for s in list_devices():
        props = device_props(s)
        devs.append({
            "serial": s,
            "avd_name": avd_name(s) if s.startswith("emulator-") else None,
            "android_version": props.get("android_version"),
            "abi": props.get("abi"),
            "is_emulator": s.startswith("emulator-"),
        })
    return devs
