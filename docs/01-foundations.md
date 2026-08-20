# 01 — Foundations: What an APK Actually Is

> **Prerequisites: none.** This chapter builds from "what is an Android app" to the
> exact binary structures the analyzer parses. If you already know DEX and AXML, skim
> to [§7 Why static analysis works](#7-why-static-analysis-works--and-where-it-fails).

---

## 1. The one-sentence version

An **APK** (Android Package) is a **ZIP archive** containing compiled bytecode, a
binary-encoded manifest, resources, native libraries, and a cryptographic signature —
everything the Android runtime needs to install and run an application.

Because it is a ZIP, you can read every byte of it **without running it**. That single
fact is what makes this entire platform possible.

---

## 2. Anatomy of an APK

Unzip any `.apk` and you get roughly this:

```
myapp.apk (ZIP archive)
├── AndroidManifest.xml        ← binary XML (AXML), NOT plain text
├── classes.dex                ← compiled Dalvik bytecode
├── classes2.dex, classes3.dex ← additional DEX files (multidex)
├── resources.arsc             ← compiled resource table (strings, layouts, colors)
├── res/                       ← compiled resources (drawables, layouts, XML)
├── assets/                    ← raw files shipped verbatim with the app
├── lib/
│   ├── arm64-v8a/*.so         ← native code, per CPU architecture
│   ├── armeabi-v7a/*.so
│   └── x86_64/*.so
└── META-INF/
    ├── MANIFEST.MF            ← per-file digests
    ├── CERT.SF                ← signature file
    └── CERT.RSA               ← the signing certificate + signature
```

### What the analyzer reads from each

| Entry | Analyzer stage | What it yields |
|---|---|---|
| `AndroidManifest.xml` | manifest, permissions, components, MITRE | package name, SDK levels, permissions, activities/services/receivers/providers, export flags |
| `classes*.dex` | api_patterns, iocs, obfuscation | method call graph, string pool, class-name statistics |
| `lib/**/*.so` | iocs (native string scan) | C2 URLs and keywords hidden outside the DEX |
| `META-INF/*.RSA` | cert_analysis | issuer/subject, validity window, debug-cert detection |
| whole file | hashing, YARA, APKiD | SHA-256/MD5, signature matches, packer fingerprints |

---

## 3. `AndroidManifest.xml` — the app's declaration of intent

Every Android app must declare, up front and in a machine-readable file, exactly what it
is and what it wants. This is the **single richest source of static evidence**.

### 3.1 It is not text XML

Inside the APK the manifest is stored as **AXML** — Android's binary XML format. It is a
compact chunk-based encoding with a deduplicated string pool. Opening it in a text
editor produces garbage. Androguard decodes it back into a traversable XML tree.

AXML structure, simplified:

```
┌─────────────────┐
│ Header (chunk)  │  magic, file size
├─────────────────┤
│ String Pool     │  all strings, deduplicated, offset-indexed
├─────────────────┤
│ Resource Map    │  attribute name → android resource ID
├─────────────────┤
│ Namespace Start │
│ Element Start   │  tag index, attribute array (name, value, type)
│   ...           │
│ Element End     │
│ Namespace End   │
└─────────────────┘
```

> **Why this matters for fraud analysis:** malware authors sometimes emit *deliberately
> malformed* AXML that Android's lenient runtime parser accepts but strict analysis
> tools reject. Our parser therefore degrades gracefully rather than failing — see the
> [degradation ladder](04-static-analysis-pipeline.md#3-the-degradation-ladder).

### 3.2 What a manifest declares

```xml
<manifest package="com.example.bank">
  <uses-permission android:name="android.permission.RECEIVE_SMS"/>
  <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
  <application android:label="SecureBank" android:allowBackup="true">
    <activity android:name=".MainActivity">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
    <receiver android:name=".SmsReceiver" android:exported="true">
      <intent-filter><action android:name="android.provider.Telephony.SMS_RECEIVED"/></intent-filter>
    </receiver>
    <service android:name=".A11yService"
             android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
  </application>
</manifest>
```

Read as evidence, that fragment says: *this app wants to see every incoming SMS, wants
to draw over other apps, has a broadcast receiver wired to SMS delivery, and binds an
accessibility service.* Individually each is legal. Together they are the exact skeleton
of a banking overlay trojan.

**This is the core insight of the whole platform: combinations discriminate, individual
features do not.** See [risk scoring §5, correlated fraud chains](05-risk-scoring.md#5-correlated-fraud-chains).

---

## 4. The Android permission model

### 4.1 Protection levels

| Level | Meaning | Granted how |
|---|---|---|
| `normal` | Minimal risk (`INTERNET`, `VIBRATE`) | Automatically at install |
| `dangerous` | Access to private data or device functions (`READ_SMS`, `CAMERA`) | Runtime prompt (Android 6.0+) |
| `signature` | Only for apps signed with the same key as the declarer | Automatic if keys match |
| `signatureOrSystem` / `privileged` | System apps only | Platform-controlled |
| **Special access** | `SYSTEM_ALERT_WINDOW`, `BIND_ACCESSIBILITY_SERVICE`, `REQUEST_INSTALL_PACKAGES`, notification access | User must toggle in a Settings screen |

The **special access** category is where fraud lives. These permissions cannot be
granted by a normal prompt — the app must socially engineer the user into a Settings
menu. Malware routinely does exactly that, with fake "enable to continue" screens.

### 4.2 Why raw permission counting is a bad detector

A naive scanner scores "number of dangerous permissions". This fails badly in both
directions:

- **False positives:** a legitimate file manager wants storage + install-packages +
  package visibility. A password manager wants clipboard access and credential
  vocabulary. An authenticator app is full of OTP and cryptography strings. All look
  "dangerous" to a counting scanner.
- **False negatives:** a dropper may declare almost nothing, then load its real payload
  at runtime via `DexClassLoader`.

Our permission stage therefore applies **weights with written justifications**,
**diminishing returns** across multiple permissions, and **deliberately does not score
ubiquitous permissions** (`INTERNET` and `ACCESS_NETWORK_STATE` are absent from the
weight table entirely — they are context inputs, not findings). See
[`permissions.py`](../backend/app/analyzer/permissions.py) and
[05 — Risk Scoring](05-risk-scoring.md).

---

## 5. DEX — the compiled code

### 5.1 From Java/Kotlin to DEX

```
Java / Kotlin source
        │  javac / kotlinc
        ▼
   .class files (JVM bytecode, stack-based, one class per file)
        │  d8 / R8   ← also does minification + optimisation
        ▼
   classes.dex (Dalvik bytecode, register-based, ALL classes in one file)
        │  installed on device
        ▼
   AOT/JIT compiled by ART into native code at install/run time
```

Two differences from JVM bytecode matter to us:

1. **Register-based, not stack-based.** DEX instructions operate on virtual registers,
   which makes the bytecode denser and the call graph easier to recover.
2. **One file, shared constant pools.** All classes, methods, fields, type descriptors,
   and **strings** live in shared, deduplicated pools.

### 5.2 DEX layout

```
┌──────────────┐
│ header       │  magic "dex\n035", checksum, offsets to every section
├──────────────┤
│ string_ids   │──▶ string_data: every literal string in the app
├──────────────┤
│ type_ids     │──▶ type descriptors: Ljava/lang/String;  I  [B
├──────────────┤
│ proto_ids    │    method signatures
├──────────────┤
│ field_ids    │
├──────────────┤
│ method_ids   │    class + name + prototype
├──────────────┤
│ class_defs   │    class metadata, superclass, interfaces
├──────────────┤
│ data         │    code items — the actual instructions
└──────────────┘
```

### 5.3 Type descriptors (you will see these everywhere)

| Descriptor | Java type |
|---|---|
| `V` | `void` |
| `I` | `int` |
| `Z` | `boolean` |
| `[B` | `byte[]` |
| `Ljava/lang/String;` | `java.lang.String` |
| `Landroid/telephony/SmsManager;` | `android.telephony.SmsManager` |

The `L…;` form is why the API detector's patterns look like
`Landroid/telephony/(?:gsm/)?SmsManager;` — see
[`api_patterns.py`](../backend/app/analyzer/api_patterns.py).

### 5.4 The string pool is a gift to analysts

Every hardcoded URL, API key, Telegram bot token, SQL fragment, and log message ends up
in `string_ids`. Extracting the whole pool costs almost nothing and yields most of the
platform's IOCs. Malware counters this with Base64/hex encoding and runtime
decryption — which is why our IOC stage **decodes Base64/hex candidates and re-scans the
decoded text** ([`iocs.py`](../backend/app/analyzer/iocs.py)).

### 5.5 Cross-references: the difference between "mentions" and "calls"

Androguard builds an `Analysis` object (conventionally named `dx`) containing the
**call graph**. For any method you can ask "who calls this?" via `get_xref_from()`.

This distinction is critical and is a first-class concept in our API detector:

| Evidence type | Meaning | Confidence | Score |
|---|---|---|---|
| **invoked** | A real callsite was recovered in the call graph | `high` | full weight |
| **reference** | The class/method descriptor exists in the string pool, but no callsite was found | `low` | reduced weight |

Why this matters: a bundled advertising SDK contains the descriptor
`Landroid/telephony/SmsManager;` without ever sending an SMS. Scoring that as "sends
SMS" was a real, measured source of false positives. The detector now labels it
honestly. See [04 §6](04-static-analysis-pipeline.md#6-suspicious-api-detection).

---

## 6. Code signing

Every APK must be signed. Android supports several schemes:

| Scheme | Since | Where the signature lives |
|---|---|---|
| v1 (JAR signing) | Android 1.0 | `META-INF/*.SF`, `*.RSA` — per-file digests |
| v2 | Android 7.0 | APK Signing Block before the ZIP central directory — signs the whole file |
| v3 | Android 9 | v2 + key-rotation lineage |
| v4 | Android 11 | Incremental-install side file |

### What signing does and does not prove

- ✅ It proves **the app has not been modified since signing** and that updates come
  from the same key.
- ❌ It does **not** prove the developer is trustworthy. Almost all Android apps are
  **self-signed** — there is no CA hierarchy.

So "self-signed" is **not** a red flag; it is the norm. Our certificate stage therefore
ignores self-signing entirely and flags only genuinely anomalous patterns:

- The **Android debug certificate** (`CN=Android Debug`) on a distributed app — a strong
  indicator of a hastily repackaged or non-production build.
- **Generic/placeholder issuer fields** (`CN=Unknown`, empty organisation).
- **Absurd validity windows** (e.g. decades long, or already expired).

See [`cert_analysis.py`](../backend/app/analyzer/cert_analysis.py).

### Repackaging

The dominant fraud distribution technique: take a real banking app, decompile it, inject
malicious classes, rebuild, **re-sign with the attacker's key**, and distribute via
SMS/WhatsApp links. The signature will be valid — just not the bank's. This is why the
certificate is evidence, and why the package name alone can never be trusted.

---

## 7. Why static analysis works — and where it fails

### It works because

- The manifest is a **mandatory, complete, machine-readable declaration of capability**.
  An app cannot receive SMS without saying so.
- The DEX **string pool** leaks endpoints and secrets.
- The **call graph** distinguishes capability from use.
- It is **fast** (seconds), **safe** (no execution), and **deterministic** — the same
  input always produces the same output, which makes it auditable and testable.

### It fails against

| Evasion | Effect | Our mitigation |
|---|---|---|
| **Packers / encrypted DEX** | Real code unavailable until runtime | APKiD packer fingerprint scores the *presence* of packing; obfuscation signals; recommend dynamic analysis |
| **Runtime payload download (dropper)** | Malicious code is not in the APK at all | `DexClassLoader` detection correlated with install-packages and dropper signatures |
| **String encryption** | IOCs invisible to a naive scan | Base64/hex auto-decode and re-scan; native `.so` string scan |
| **Reflection** | Call graph is incomplete | Reference-level (low-confidence) evidence is preserved rather than discarded |
| **Native payloads** | Logic lives in `.so`, not DEX | Bounded ASCII string extraction from native libraries |
| **Time/geo-gated behaviour** | Nothing malicious is visible statically | Out of scope for static; this is the honest case for the [dynamic sandbox](09-dynamic-analysis.md) |

### The honest conclusion

Static analysis produces **an explainable triage ranking, not a calibrated malware
probability**. That framing is deliberate and is repeated throughout the codebase and
the [evaluation chapter](13-evaluation-and-accuracy.md). The platform reserves the
verdict *"Confirmed Malicious"* exclusively for independent multi-engine corroboration —
never for its own heuristics, no matter how high the score.

---

## 8. Tooling landscape (and why androguard)

| Tool | Language | Needs Java? | Role here |
|---|---|---|---|
| **androguard** | Pure Python | **No** | ✅ Our parser: AXML, DEX, call graph, certificates |
| `apktool` | Java | Yes | Resource + smali decoding |
| `jadx` | Java | Yes | DEX → readable Java |
| `aapt2` | Native (SDK) | SDK required | Manifest/badging dump |
| **YARA** | C (Python binding) | No | ✅ Pattern signatures |
| **APKiD** | Python (YARA-based) | No | ✅ Packer/compiler/anti-analysis fingerprints |
| **Frida** | C + JS | No (needs device agent) | ✅ Dynamic hooking tier |

Androguard was chosen because a **pure-Python dependency chain installs with one
`pip install`, ships manylinux wheels, containerises in a slim image, and needs no
JDK**. For a tool that must be trivially reproducible by a reviewer, that matters more
than raw decompilation quality.

---

**Next:** [02 — Threat Model](02-threat-model.md) — what we are actually hunting.
