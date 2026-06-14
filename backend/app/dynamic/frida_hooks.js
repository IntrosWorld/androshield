// Frida instrumentation for runtime API hooking.
// Each hook posts a structured event back to the Python runner via send().
// Defensive: every hook is wrapped so a missing class on a given device/API level
// doesn't abort the rest.

function emit(category, api, detail) {
    send({ category: category, api: api, detail: detail });
}

function safe(name, fn) {
    try { fn(); } catch (e) { /* class not present on this device */ }
}

Java.perform(function () {
    // --- SMS exfiltration ---
    safe("SmsManager", function () {
        var SmsManager = Java.use("android.telephony.SmsManager");
        SmsManager.sendTextMessage.overload(
            "java.lang.String", "java.lang.String", "java.lang.String",
            "android.app.PendingIntent", "android.app.PendingIntent"
        ).implementation = function (dest, sc, text, a, b) {
            emit("sms", "SmsManager.sendTextMessage", "to=" + dest + " body=" + text);
            return this.sendTextMessage(dest, sc, text, a, b);
        };
    });

    // --- HTTP / C2 ---
    safe("URL", function () {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function () {
            emit("network", "URL.openConnection", this.toString());
            return this.openConnection();
        };
    });
    safe("OkHttp", function () {
        var Builder = Java.use("okhttp3.Request$Builder");
        Builder.url.overload("java.lang.String").implementation = function (u) {
            emit("network", "OkHttp.Request.url", u);
            return this.url(u);
        };
    });

    // --- Dynamic code loading (dropper) ---
    safe("DexClassLoader", function () {
        var DCL = Java.use("dalvik.system.DexClassLoader");
        DCL.$init.implementation = function (path, opt, libs, parent) {
            emit("dynamic_load", "DexClassLoader.<init>", path);
            return this.$init(path, opt, libs, parent);
        };
    });

    // --- Command execution ---
    safe("Runtime.exec", function () {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
            emit("exec", "Runtime.exec", cmd);
            return this.exec(cmd);
        };
    });

    // --- Clipboard theft (OTP / wallet) ---
    safe("Clipboard", function () {
        var CM = Java.use("android.content.ClipboardManager");
        CM.getPrimaryClip.implementation = function () {
            emit("clipboard", "ClipboardManager.getPrimaryClip", "clipboard read");
            return this.getPrimaryClip();
        };
    });

    // --- Crypto (exfil obfuscation) ---
    safe("Cipher", function () {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.doFinal.overload("[B").implementation = function (data) {
            emit("crypto", "Cipher.doFinal", "len=" + (data ? data.length : 0));
            return this.doFinal(data);
        };
    });

    send({ category: "_status", api: "hooks_installed", detail: "ok" });
});
