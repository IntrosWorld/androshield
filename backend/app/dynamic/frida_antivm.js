// Anti-anti-VM + runtime unpacker for packed Android droppers.
// Injected at spawn (before app code runs). Two jobs:
//   1) Spoof emulator indicators so anti-VM checks pass.
//   2) Capture the decrypted second-stage payload (Cipher output + DexClassLoader load)
//      and stream it back to the Python runner, which saves it for static analysis.

function emit(o) { send(o); }

function headStr(bytes, n) {
    var s = "";
    for (var i = 0; i < n && i < bytes.length; i++) {
        var c = bytes[i] & 0xff;
        s += (c >= 32 && c < 127) ? String.fromCharCode(c) : ".";
    }
    return s;
}

Java.perform(function () {
    var B64 = null;
    try { B64 = Java.use("android.util.Base64"); } catch (e) {}

    function dumpBytes(tag, bytes) {
        try {
            if (!bytes || bytes.length < 200) return;
            var head = headStr(bytes, 8);
            // Interesting if it's a DEX ("dex\n"), a ZIP/JAR ("PK"), or a big blob.
            var isDex = head.indexOf("dex") === 0;
            var isZip = head.charCodeAt(0) === 80 && head.charCodeAt(1) === 75;
            if (!(isDex || isZip || bytes.length > 4000)) return;
            var b64 = B64 ? B64.encodeToString(bytes, 2 /*NO_WRAP*/) : null;
            emit({ category: "payload_dump", api: tag,
                   detail: "len=" + bytes.length + " head=" + head + (isDex ? " [DEX]" : isZip ? " [ZIP]" : ""),
                   kind: isDex ? "dex" : isZip ? "zip" : "blob", data: b64 });
        } catch (e) {}
    }

    // --- 1) Anti-VM: spoof Build identity to a real Pixel ---
    try {
        var Build = Java.use("android.os.Build");
        var P = {
            FINGERPRINT: "google/oriole/oriole:13/TQ3A.230805.001/10316531:user/release-keys",
            MODEL: "Pixel 6", MANUFACTURER: "Google", BRAND: "google",
            DEVICE: "oriole", PRODUCT: "oriole", HARDWARE: "oriole", BOARD: "oriole",
            HOST: "abfarm-release", TAGS: "release-keys", BOOTLOADER: "slider-1.0",
            DISPLAY: "TQ3A.230805.001", ID: "TQ3A.230805.001", TYPE: "user", USER: "android-build"
        };
        for (var k in P) { try { Build[k].value = P[k]; } catch (e) {} }
        emit({ category: "antivm", api: "Build.spoof", detail: "Build.* -> Pixel 6" });
    } catch (e) {}

    // --- SystemProperties / System.getProperty: hide qemu/goldfish ---
    try {
        var SP = Java.use("android.os.SystemProperties");
        SP.get.overload("java.lang.String").implementation = function (key) {
            var v = this.get(key);
            var lk = key.toLowerCase();
            if (lk.indexOf("qemu") >= 0 || lk.indexOf("goldfish") >= 0 || lk.indexOf("ranchu") >= 0) return "";
            if (key === "ro.hardware") return "oriole";
            if (key === "ro.product.model") return "Pixel 6";
            if (key === "ro.kernel.qemu") return "";
            return v;
        };
    } catch (e) {}

    // --- Telephony: real-looking identifiers ---
    try {
        var TM = Java.use("android.telephony.TelephonyManager");
        function spoof(method, value) {
            try {
                TM[method].overloads.forEach(function (ov) {
                    ov.implementation = function () { return value; };
                });
            } catch (e) {}
        }
        spoof("getDeviceId", "356938035643809");
        spoof("getImei", "356938035643809");
        spoof("getLine1Number", "+14155552671");
        spoof("getSubscriberId", "310260000000000");
        spoof("getNetworkOperatorName", "Verizon");
        spoof("getSimOperatorName", "Verizon");
    } catch (e) {}

    // --- File checks: hide emulator artefacts ---
    try {
        var QEMU = ["qemu", "goldfish", "ranchu", "/dev/socket/qemud", "/dev/qemu_pipe",
                    "genymotion", "vbox", "/sys/qemu_trace", "bluestacks", "nox", "/proc/tty/drivers"];
        var JFile = Java.use("java.io.File");
        JFile.exists.implementation = function () {
            try {
                var p = this.getAbsolutePath().toLowerCase();
                for (var i = 0; i < QEMU.length; i++) if (p.indexOf(QEMU[i]) >= 0) return false;
            } catch (e) {}
            return this.exists();
        };
    } catch (e) {}

    // --- 2) Unpacker capture: decrypted payload via Cipher ---
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        ["doFinal"].forEach(function (m) {
            Cipher[m].overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var out = ov.apply(this, arguments);
                    try { if (out && out.length) dumpBytes("Cipher." + m, out); } catch (e) {}
                    return out;
                };
            });
        });
        emit({ category: "antivm", api: "Cipher.hook", detail: "watching doFinal for payload" });
    } catch (e) {}

    // --- DexClassLoader / InMemoryDexClassLoader: capture loaded DEX ---
    try {
        var DCL = Java.use("dalvik.system.DexClassLoader");
        DCL.$init.overloads.forEach(function (ov) {
            ov.implementation = function () {
                try { emit({ category: "dynamic_load", api: "DexClassLoader",
                             detail: "path=" + arguments[0] }); } catch (e) {}
                return ov.apply(this, arguments);
            };
        });
    } catch (e) {}
    try {
        var IMDCL = Java.use("dalvik.system.InMemoryDexClassLoader");
        IMDCL.$init.overloads.forEach(function (ov) {
            ov.implementation = function () {
                try {
                    var buf = arguments[0];
                    // ByteBuffer -> byte[]
                    if (buf && buf.remaining) {
                        var n = buf.remaining(); var arr = Java.array("byte", new Array(n));
                        buf.get(arr); buf.rewind();
                        dumpBytes("InMemoryDexClassLoader", arr);
                    }
                } catch (e) {}
                return ov.apply(this, arguments);
            };
        });
    } catch (e) {}

    // --- Behaviour + C2 ---
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function () {
            emit({ category: "network", api: "URL.openConnection", detail: this.toString() });
            return this.openConnection();
        };
    } catch (e) {}
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function (c) {
            emit({ category: "exec", api: "Runtime.exec", detail: c });
            return this.exec(c);
        };
    } catch (e) {}

    emit({ category: "_status", api: "hooks_installed", detail: "antivm+unpacker ready" });
});
