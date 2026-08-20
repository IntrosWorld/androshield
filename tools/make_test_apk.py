"""Generate a HARMLESS test APK for the analyzer.

This produces a syntactically valid APK (binary AndroidManifest.xml + minimal
classes.dex) that *declares* dangerous permissions and *embeds the string
signatures* of suspicious APIs/IOCs the analyzer scans for — so the platform
flags it as Critical — WITHOUT containing any executable malicious logic.

Safety:
  * No real code runs: classes.dex has zero classes/methods, only a string table.
  * The suspicious "behaviour" is purely declarative (permissions) and textual
    (strings), exactly the metadata a static analyzer reads.
  * The APK is intentionally unsigned, so Android will refuse to install it on a
    real device. It exists only to feed this analyzer.

No Android SDK required — the binary AXML and DEX are encoded by hand.
"""
import base64
import hashlib
import os
import struct
import zlib
import zipfile

# ---------------------------------------------------------------------------
# Binary AndroidManifest.xml (AXML) encoder
# ---------------------------------------------------------------------------

# Framework attribute names that carry a resource id. These MUST occupy the
# first string-pool indices (parallel to the resource-map chunk).
RES_ATTRS = [
    ("versionCode", 0x0101021B),
    ("versionName", 0x0101021C),
    ("minSdkVersion", 0x0101020C),
    ("targetSdkVersion", 0x01010270),
    ("name", 0x01010003),
    ("label", 0x01010001),
    ("permission", 0x01010006),
]
ANDROID_URI = "http://schemas.android.com/apk/res/android"
ANDROID_PREFIX = "android"

TYPE_STRING = 0x03


class El:
    def __init__(self, tag, attrs=None, children=None):
        # attrs: list of (ns, name, value)  ns in {"a", None}
        self.tag = tag
        self.attrs = attrs or []
        self.children = children or []


class StringPool:
    def __init__(self):
        self._list = []
        self._index = {}
        # Reserve resource-mapped attribute names at the front.
        for name, _rid in RES_ATTRS:
            self.intern(name)

    def intern(self, s):
        if s not in self._index:
            self._index[s] = len(self._list)
            self._list.append(s)
        return self._index[s]

    @staticmethod
    def _enc(s):
        b = s.encode("utf-8")
        n16, n8 = len(s), len(b)
        assert n16 < 128 and n8 < 128, f"string too long for simple encoder: {s!r}"
        return bytes([n16]) + bytes([n8]) + b + b"\x00"

    def build(self):
        count = len(self._list)
        data = b""
        offsets = []
        for s in self._list:
            offsets.append(len(data))
            data += self._enc(s)
        strings_start = 28 + 4 * count
        body = b"".join(struct.pack("<I", o) for o in offsets) + data
        # pad to 4 bytes
        pad = (-(28 + len(body))) % 4
        body += b"\x00" * pad
        size = 28 + len(body)
        header = struct.pack(
            "<HHIIIII",
            0x0001,          # RES_STRING_POOL_TYPE
            28,              # headerSize
            size,            # chunk size
            count,           # stringCount
            0,               # styleCount
            0x00000100,      # flags: UTF8_FLAG
            strings_start,   # stringsStart
        )
        header += struct.pack("<I", 0)  # stylesStart
        return header + body


def _xml_chunk(ctype, ext):
    """Wrap an XML node extension in a ResXMLTree_node chunk."""
    size = 16 + len(ext)
    return struct.pack("<HHIII", ctype, 16, size, 1, 0xFFFFFFFF) + ext


def build_axml(root):
    sp = StringPool()
    uri_idx = sp.intern(ANDROID_URI)
    prefix_idx = sp.intern(ANDROID_PREFIX)

    # Pre-intern tags and string values (depth-first) so the pool is complete
    # before we emit indices.
    def collect(el):
        sp.intern(el.tag)
        for ns, name, val in el.attrs:
            if ns is None:
                sp.intern(name)
            sp.intern(val)
        for c in el.children:
            collect(c)
    collect(root)

    res_name_idx = {name: i for i, (name, _r) in enumerate(RES_ATTRS)}

    def attr_name_idx(ns, name):
        if ns == "a":
            return res_name_idx[name]  # 0..6
        return sp.intern(name)

    def emit_el(el):
        out = b""
        # --- start element ---
        attr_bytes = b""
        for ns, name, val in el.attrs:
            ns_idx = uri_idx if ns == "a" else 0xFFFFFFFF
            n_idx = attr_name_idx(ns, name)
            v_idx = sp.intern(val)
            # raw value = string index; typed value = TYPE_STRING -> same index
            attr_bytes += struct.pack("<III", ns_idx, n_idx, v_idx)
            attr_bytes += struct.pack("<HBBI", 8, 0, TYPE_STRING, v_idx)
        ext = struct.pack(
            "<IIHHHHHH",
            0xFFFFFFFF,            # ns
            sp.intern(el.tag),    # name
            20,                   # attributeStart
            20,                   # attributeSize
            len(el.attrs),        # attributeCount
            0, 0, 0,              # id/class/style index
        ) + attr_bytes
        out += _xml_chunk(0x0102, ext)  # RES_XML_START_ELEMENT_TYPE
        # --- children ---
        for c in el.children:
            out += emit_el(c)
        # --- end element ---
        end_ext = struct.pack("<II", 0xFFFFFFFF, sp.intern(el.tag))
        out += _xml_chunk(0x0103, end_ext)  # RES_XML_END_ELEMENT_TYPE
        return out

    body = emit_el(root)

    # resource map: parallel to first len(RES_ATTRS) strings
    resmap = struct.pack("<HHI", 0x0180, 8, 8 + 4 * len(RES_ATTRS))
    resmap += b"".join(struct.pack("<I", rid) for _n, rid in RES_ATTRS)

    start_ns = _xml_chunk(0x0100, struct.pack("<II", prefix_idx, uri_idx))
    end_ns = _xml_chunk(0x0101, struct.pack("<II", prefix_idx, uri_idx))

    string_pool = sp.build()
    payload = string_pool + resmap + start_ns + body + end_ns
    total = 8 + len(payload)
    return struct.pack("<HHI", 0x0003, 8, total) + payload  # RES_XML_TYPE


# ---------------------------------------------------------------------------
# Minimal classes.dex (string table only — zero classes/methods)
# ---------------------------------------------------------------------------

def _uleb128(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def build_dex(strings):
    # DEX requires string_ids sorted by UTF-16 code point order.
    strings = sorted(set(strings))
    n = len(strings)

    header_size = 0x70
    string_ids_off = header_size
    data_off = string_ids_off + 4 * n

    # string_data items
    data = b""
    string_data_offsets = []
    for s in strings:
        string_data_offsets.append(data_off + len(data))
        b = s.encode("utf-8")
        data += _uleb128(len(s)) + b + b"\x00"

    # align map to 4 bytes
    map_pad = (-(data_off + len(data))) % 4
    data += b"\x00" * map_pad
    map_off = data_off + len(data)

    # map_list: header, string_id, string_data, map_list
    string_data_start = string_data_offsets[0] if string_data_offsets else map_off
    entries = [
        (0x0000, 1, 0),                      # header
        (0x0001, n, string_ids_off),         # string_id_item
        (0x2002, n, string_data_start),      # string_data_item
        (0x1000, 1, map_off),                # map_list
    ]
    map_bytes = struct.pack("<I", len(entries))
    for t, size, off in entries:
        map_bytes += struct.pack("<HHII", t, 0, size, off)

    file_size = map_off + len(map_bytes)
    data_size = file_size - data_off

    string_ids = b"".join(struct.pack("<I", o) for o in string_data_offsets)

    # Header (checksum + signature filled after assembly)
    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 32, file_size)
    struct.pack_into("<I", header, 36, header_size)
    struct.pack_into("<I", header, 40, 0x12345678)   # endian tag
    struct.pack_into("<I", header, 44, 0)            # link_size
    struct.pack_into("<I", header, 48, 0)            # link_off
    struct.pack_into("<I", header, 52, map_off)
    struct.pack_into("<I", header, 56, n)            # string_ids_size
    struct.pack_into("<I", header, 60, string_ids_off)
    # type/proto/field/method/class sizes + offsets all zero (64..104)
    struct.pack_into("<I", header, 104, data_size)
    struct.pack_into("<I", header, 108, data_off)

    body = bytes(header) + string_ids + data[:map_off - data_off] + map_bytes
    body = bytearray(body)

    # SHA-1 signature over everything after the signature field (offset 32)
    sig = hashlib.sha1(bytes(body[32:])).digest()
    body[12:32] = sig
    # Adler-32 checksum over everything after the checksum field (offset 12)
    checksum = zlib.adler32(bytes(body[12:])) & 0xFFFFFFFF
    struct.pack_into("<I", body, 8, checksum)
    return bytes(body)


# ---------------------------------------------------------------------------
# Assemble the test APK
# ---------------------------------------------------------------------------

PACKAGE = "com.test.fakebank.sandbox"

PERMISSIONS = [
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.INTERNET",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.READ_CONTACTS",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_CALL_LOG",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
]

# Suspicious API class descriptors + IOC strings the analyzer scans for.
DEX_STRINGS = [
    # --- suspicious API signatures (declarative only; never invoked) ---
    "Landroid/telephony/SmsManager;",
    "sendTextMessage",
    "Landroid/accessibilityservice/AccessibilityService;",
    "Landroid/service/notification/NotificationListenerService;",
    "Landroid/webkit/WebView;",
    "Ldalvik/system/DexClassLoader;",
    "loadClass",
    "Ljava/lang/Runtime;",
    "exec",
    "Ljava/net/HttpURLConnection;",
    "connect",
    "Landroid/content/ClipboardManager;",
    "getPrimaryClip",
    "Landroid/app/admin/DevicePolicyManager;",
    "wipeData",
    "Ljava/lang/reflect/Method;",
    "Landroid/util/Base64;",
    # --- network IOCs (non-routable / fake) ---
    "http://malicious-bank-verify.xyz/api/upload.php",
    "https://evil-bank-phish.top/login",
    "http://192.168.66.66:8080/c2/beacon",
    # --- fake Telegram bot token (10 digits : exactly 35 chars) ---
    "5123456789:" + "AAFakeTelegramTestBotToken1234567890"[:35],
    # --- banking/fraud keywords ---
    "otp", "cvv", "upi", "ifsc", "netbanking",
    "card number", "account number password login pin",
    # --- harmless marker ---
    "TEST-SAMPLE-HARMLESS-generated-for-analyzer-only",
]

# A Base64-encoded C2 URL — exercises the auto-decode-and-rescan feature.
DEX_STRINGS.append(base64.b64encode(b"http://hidden-c2-decoded.xyz/exfil.php").decode())


def build_manifest():
    intent_main = El("intent-filter", children=[
        El("action", [("a", "name", "android.intent.action.MAIN")]),
        El("category", [("a", "name", "android.intent.category.LAUNCHER")]),
    ])
    intent_boot = El("intent-filter", children=[
        El("action", [("a", "name", "android.intent.action.BOOT_COMPLETED")]),
    ])
    application = El("application", [("a", "label", "SecureBank Verify")], children=[
        El("activity", [("a", "name", PACKAGE + ".MainActivity")], [intent_main]),
        El("service", [
            ("a", "name", PACKAGE + ".SmsRelayService"),
            ("a", "permission", "android.permission.BIND_ACCESSIBILITY_SERVICE"),
        ]),
        El("receiver", [("a", "name", PACKAGE + ".BootReceiver")], [intent_boot]),
    ])
    children = [El("uses-sdk", [
        ("a", "minSdkVersion", "21"), ("a", "targetSdkVersion", "33")])]
    for p in PERMISSIONS:
        children.append(El("uses-permission", [("a", "name", p)]))
    children.append(application)

    manifest = El("manifest", [
        (None, "package", PACKAGE),
        ("a", "versionCode", "13"),
        ("a", "versionName", "1.3.7"),
    ], children)
    return build_axml(manifest)


def main(out_path):
    manifest = build_manifest()
    dex = build_dex(DEX_STRINGS)
    # Dummy native lib -> obfuscation signal; embeds an ASCII C2 URL so the
    # native-string scanner has something to find.
    fake_so = (b"\x7fELF" + b"\x00" * 64
               + b"http://native-lib-c2.top/beacon\x00"
               + b"libnativehelper.so\x00" + b"\x00" * 900)

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", manifest)
        z.writestr("classes.dex", dex)
        z.writestr("lib/arm64-v8a/libnativehelper.so", fake_so)
        z.writestr("assets/README.txt",
                   "Harmless analyzer test sample. Unsigned; not installable. "
                   "Contains no executable malicious code.")
    print(f"Wrote {out_path} ({os.path.getsize(out_path)} bytes)")


if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(__file__), "..", "samples", "test_fakebank.apk")
    main(os.path.abspath(out))
