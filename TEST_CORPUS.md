# External APK test corpus

The APK binaries live under `samples/external-test-corpus/` and are intentionally
ignored by Git. They are test inputs only; the static pipeline must never execute
them.

## Pinned external controls

| File | Purpose / expected label | Primary source | SHA-256 |
|---|---|---|---|
| `fossify-calculator-1.4.0.apk` | Reproducible benign control | [F-Droid package](https://f-droid.org/en/packages/org.fossify.math/) / [APK](https://f-droid.org/repo/org.fossify.math_10.apk) | `7c5443c22d6d62c67dfe80df33ea9161ff0fa440f92590bcb45d7008b57613ed` |
| `owasp-uncrackable-level1.apk` | Intentionally protected OWASP training app; benign but contains anti-analysis behavior | [OWASP MASTG source](https://github.com/OWASP/owasp-mastg/tree/master/Crackmes/Android/Level_01) / [APK](https://raw.githubusercontent.com/OWASP/owasp-mastg/master/Crackmes/Android/Level_01/UnCrackable-Level1.apk) | `1da8bf57d266109f9a07c01bf7111a1975ce01f190b9d914bcd3ae3dbef96f21` |
| `aegis-3.4.2.apk` | Benign authenticator: OTP, cryptography, boot receiver, clipboard stress | [F-Droid package](https://f-droid.org/en/packages/com.beemdevelopment.aegis/) | `ab633d31cc0fa49e3ae29a3b816a7fcbe04033a3227f42bd30cf86fcd3be4159` |
| `keepassdx-4.4.5.apk` | Benign password manager: credential vocabulary, clipboard, package visibility | [F-Droid package](https://f-droid.org/packages/com.kunzisoft.keepass.libre/) | `23d6917bf11fcde7f4a2b8072faa893df857955d6201244e370357bd7d65c598` |
| `material-files-1.7.4.apk` | Benign file manager: storage management, package installation, shell/network code | [F-Droid package](https://f-droid.org/en/packages/me.zhanghai.android.files/) | `ebc5138b6f713f0f73b5467a1a8a4ac3ccfcb2e82135372665b6811a8947641f` |
| `newpipe-0.29.0.apk` | Benign media client: overlay, boot, sockets, crash collection, credential-like strings | [F-Droid package](https://f-droid.org/en/packages/org.schabi.newpipe/) | `1765284f67c09c983b025954da4f142419e93cc510f39f735700b670b04ba3ff` |

F-Droid independently reports Fossify Calculator version 10 as reproducible on its
[verification page](https://verification.f-droid.org/packages/org.fossify.math/).

Verify every download before analysis:

```powershell
Get-ChildItem .\samples\external-test-corpus\*.apk |
  Get-FileHash -Algorithm SHA256
```

If a hash differs, do not silently update this file. Review the upstream version and
record the new expected hash as a deliberate corpus change.

## Observed static results on `exp-2`

| Sample | Expected | Score | Severity | Evidence verdict |
|---|---:|---:|---|---|
| Fossify Calculator 1.4.0 | benign | 9 | Low | No Strong Malicious Evidence |
| OWASP UnCrackable Level 1 | training / protected, not malware | 5 | Low | No Strong Malicious Evidence |
| Aegis Authenticator 3.4.2 | benign | 10 | Low | No Strong Malicious Evidence |
| KeePassDX 4.4.5 | benign | 5 | Low | No Strong Malicious Evidence |
| Material Files 1.7.4 | benign capability stress case | 17 | Low | No Strong Malicious Evidence |
| NewPipe 0.29.0 | benign overlay/network stress case | 18 | Low | No Strong Malicious Evidence |
| `.w.apk` (existing local packed sample) | packed malicious regression | 46 | High | Likely Malicious |
| `test_fakebank.apk` (generated synthetic fixture) | fraud-positive | 100 | Critical | Likely Malicious |

The `.w.apk` score is 46 / High after benign calibration. Its verdict remains
`Likely Malicious`, supported by invoked DEX loading, an obfuscated payload path, boot
persistence, and background-only entry points rather than generic permission stacking.

These are calibration expectations, not universal ground truth. Static heuristics can
support `Likely Malicious`; only independent corroboration such as sufficient
multi-engine consensus can produce `Confirmed Malicious`.

## Safety

- Use `/api/analyze` or `app.analyzer.static_analyzer.analyze()` for this corpus.
- Do not install APKs on a personal phone or the host.
- Dynamic analysis is opt-in and belongs only in a disposable, isolated Android AVD.
- Do not commit APK binaries to Git.
