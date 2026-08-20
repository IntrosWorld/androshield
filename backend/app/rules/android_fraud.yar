/*
 * Starter YARA ruleset for Android banking-fraud / spyware triage.
 *
 * These rules are scanned against a TEXT blob the analyzer builds from the APK's
 * decompiled DEX strings + declared permissions (not the raw zipped bytes), so the
 * string atoms below are class descriptors, permission names and IOC patterns.
 *
 * meta.score is read by the analyzer and folded into the risk score.
 */

rule SMS_OTP_Stealer
{
    meta:
        description = "Reads/intercepts SMS and has a network channel — OTP theft pattern"
        severity = "high"
        score = "20"
        attack = "T1582"
    strings:
        $sms1 = "MANIFEST_PERMISSION:android.permission.READ_SMS"
        $sms2 = "MANIFEST_PERMISSION:android.permission.RECEIVE_SMS"
        $internet = "MANIFEST_PERMISSION:android.permission.INTERNET"
        $net1 = "Ljava/net/HttpURLConnection;"
    condition:
        // Generic dependencies commonly contain SmsManager and "http" strings.
        // Require an app-declared SMS-reading capability plus an outbound channel.
        any of ($sms1, $sms2) and any of ($internet, $net1)
}

rule Accessibility_Overlay_Trojan
{
    meta:
        description = "Accessibility service + overlay — auto-click / fake login overlay"
        severity = "critical"
        score = "25"
        attack = "T1417.002"
    strings:
        $acc1 = "MANIFEST_PERMISSION:android.permission.BIND_ACCESSIBILITY_SERVICE"
        $acc2 = "Landroid/accessibilityservice/AccessibilityService;"
        $ovl  = "MANIFEST_PERMISSION:android.permission.SYSTEM_ALERT_WINDOW"
    condition:
        (any of ($acc1, $acc2)) and $ovl
}

rule Notification_Listener_Theft
{
    meta:
        description = "Reads notifications — OTP / banking alert stealing"
        severity = "high"
        score = "15"
        attack = "T1517"
    strings:
        $n = "Landroid/service/notification/NotificationListenerService;"
        $k1 = "otp" nocase
        $k2 = "bank" nocase
        $k3 = "card number" nocase
        $k4 = "cvv" nocase
        $k5 = "netbanking" nocase
    condition:
        // Wearables, launchers and automation tools legitimately mirror notifications.
        // Require credential/banking targeting before treating it as theft evidence.
        $n and 2 of ($k*)
}

rule Dynamic_Dropper
{
    meta:
        description = "Runtime DEX loading + install-packages — dropper / second stage"
        severity = "high"
        score = "18"
        attack = "T1407"
    strings:
        $dex = "Ldalvik/system/DexClassLoader;"
        $inmem = "Ldalvik/system/InMemoryDexClassLoader;"
        $inst = "MANIFEST_PERMISSION:android.permission.REQUEST_INSTALL_PACKAGES"
    condition:
        any of ($dex, $inmem) and $inst
}

rule Telegram_C2_Exfil
{
    meta:
        description = "Telegram bot API used as C2 / exfiltration channel"
        severity = "high"
        score = "18"
        attack = "T1646"
    strings:
        $t1 = "api.telegram.org" nocase
        $t2 = "/bot" nocase
        $t3 = /[0-9]{8,10}:[A-Za-z0-9_-]{35}/
    condition:
        $t1 or $t3 or ($t2 and $t3)
}

rule Device_Admin_AntiRemoval
{
    meta:
        description = "Device-admin abuse - lock/wipe and resist uninstallation"
        severity = "medium"
        score = "12"
        attack = "T1626.001"
    strings:
        $api  = "Landroid/app/admin/DevicePolicyManager;"
        $perm = "MANIFEST_PERMISSION:android.permission.BIND_DEVICE_ADMIN"
        $recv = "android.app.action.DEVICE_ADMIN_ENABLED"
    condition:
        // The API alone is referenced by libraries in benign apps; require the app to
        // actually register as a device admin (permission + receiver action).
        $perm and ($api or $recv)
}

rule Banking_Credential_Keywords
{
    meta:
        description = "Hardcoded banking/credential keywords — phishing/credential targeting"
        severity = "medium"
        score = "10"
        attack = "T1660"
    strings:
        $k1 = "netbanking" nocase
        $k2 = "ifsc" nocase
        $k3 = "cvv" nocase
        $k4 = "upi" nocase
        $k5 = "otp" nocase
        $k6 = "card number" nocase
        $sms1 = "MANIFEST_PERMISSION:android.permission.READ_SMS"
        $sms2 = "MANIFEST_PERMISSION:android.permission.RECEIVE_SMS"
        $accessibility = "MANIFEST_PERMISSION:android.permission.BIND_ACCESSIBILITY_SERVICE"
    condition:
        // Overlay alone is legitimate in media/floating-window apps. Credential terms
        // need an OTP-reading or accessibility capability before they become phishing
        // evidence.
        3 of ($k*) and any of ($sms*, $accessibility)
}
