"""Static-only optimization benchmark. Never installs, launches, or sends APKs anywhere.

Uses perf_counter medians for speed comparisons; cProfile is optional for attribution.
Reports contain timings and parity flags, never extracted findings or APK contents.
"""
import argparse
import cProfile
import gc
import json
import logging
import os
import platform
import pstats
import random
import statistics
import string
import sys
import time
import warnings
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "backend"), str(ROOT / "tools")]
from app.analyzer import iocs, native_accel, obfuscation, static_analyzer
from make_test_apk import DEX_STRINGS, build_dex, build_manifest


def fixture_strings(count):
    rng = random.Random(41)
    strings = list(DEX_STRINGS)
    for index in range(count):
        text = "".join(rng.choices(string.ascii_letters + string.digits, k=80)) + str(index)
        if index % 17 == 0:
            text += " otp password"
        if index % 29 == 0:
            text += " é中文"
        strings.append(text)
    return strings


def comparable(output):
    """Androguard's component membership lists can arrive in set iteration order.

    Normalize only these known unordered metadata lists. Scores, ordered findings,
    keyword ties, evidence, errors and every other field must still match exactly.
    """
    if not isinstance(output, dict) or not isinstance(output.get("manifest"), dict):
        return output
    manifest = output["manifest"].copy()
    for key in ("activities", "services", "receivers", "providers"):
        if key in manifest:
            manifest[key] = sorted(manifest[key])
    return {**output, "manifest": manifest}


def measure_pair(function, repeats):
    previous = os.environ.get("ANDROSHIELD_NATIVE")
    values = {"python": [], "native": []}
    expected = None
    try:
        # Warm imports, caches, native calls, and filesystem paths separately.
        for mode in ("0", "1"):
            os.environ["ANDROSHIELD_NATIVE"] = mode
            output = function()
            if mode == "0":
                expected = comparable(output)
            elif comparable(output) != expected:
                raise AssertionError("Native and Python findings differ")
        for repeat in range(repeats):
            # Alternate AB/BA to reduce order effects on caches and CPU state.
            for mode in (("0", "1") if repeat % 2 == 0 else ("1", "0")):
                os.environ["ANDROSHIELD_NATIVE"] = mode
                gc.collect()
                start = time.perf_counter()
                output = function()
                elapsed = time.perf_counter() - start
                if comparable(output) != expected:
                    raise AssertionError("Findings changed between benchmark runs")
                values["native" if mode == "1" else "python"].append(elapsed * 1000)
    finally:
        if previous is None:
            os.environ.pop("ANDROSHIELD_NATIVE", None)
        else:
            os.environ["ANDROSHIELD_NATIVE"] = previous
    python_ms = statistics.median(values["python"])
    native_ms = statistics.median(values["native"])
    return {"python_ms": round(python_ms, 3), "native_ms": round(native_ms, 3),
            "speedup": round(python_ms / native_ms, 3), "parity": True,
            "runs_ms": {key: [round(x, 3) for x in val] for key, val in values.items()}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, action="append", default=[])
    parser.add_argument("--strings", type=int, default=20000)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", action="store_true")
    args = parser.parse_args()
    if not 0 < args.strings <= 100000 or not 3 <= args.repeats <= 31:
        parser.error("use 1..100000 strings and 3..31 repeats")
    if native_accel._extension is None:
        parser.error("build/install backend/native first")
    from loguru import logger
    logger.remove()
    logging.disable(logging.CRITICAL)
    warnings.filterwarnings("ignore", message="`sklearn.utils.parallel.delayed`.*", category=UserWarning)
    work = ROOT / "desktop/build/optimization"
    work.mkdir(parents=True, exist_ok=True)
    strings = fixture_strings(args.strings)
    sample = work / "synthetic-strings.apk"
    with zipfile.ZipFile(sample, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", build_manifest())
        archive.writestr("classes.dex", build_dex(strings))
    results = {"python": platform.python_version(), "platform": platform.platform(),
               "native_api": native_accel._extension.API_VERSION,
               "parity_normalization": ["manifest.activities", "manifest.services", "manifest.receivers", "manifest.providers"],
               "repeats": args.repeats, "synthetic_strings": len(strings), "kernels": {}, "pipeline": []}
    functions = {
        "keyword_counts": lambda: native_accel.keyword_counts(strings, iocs.SUSPICIOUS_KEYWORDS, iocs._KEYWORD_RE),
        "entropy_counts": lambda: native_accel.entropy_counts(strings, obfuscation._shannon_entropy),
        "full_ioc_extraction": lambda: iocs.extract_iocs(strings),
        "full_obfuscation": lambda: obfuscation.analyze_obfuscation(None, [], strings),
    }
    for name, function in functions.items():
        results["kernels"][name] = measure_pair(function, args.repeats)
        print(name, results["kernels"][name], flush=True)
    for apk in [sample, *args.apk]:
        apk = apk.resolve()
        print("Measuring static pipeline:", apk.name, flush=True)
        timing = measure_pair(lambda: static_analyzer.analyze(str(apk)), args.repeats)
        item = {"file": apk.name, "bytes": apk.stat().st_size, **timing}
        if args.profile:
            previous = os.environ.get("ANDROSHIELD_NATIVE")
            try:
                os.environ["ANDROSHIELD_NATIVE"] = "0"
                profiler = cProfile.Profile()
                profiler.runcall(static_analyzer.analyze, str(apk))
                profiler.dump_stats(str(work / f"{apk.stem}-python.prof"))
                stats = pstats.Stats(profiler).sort_stats("cumulative")
                item["profile_top"] = [{"file": Path(key[0]).name, "function": key[2],
                                        "cumulative_ms": round(stats.stats[key][3] * 1000, 3)}
                                       for key in stats.fcn_list[:12]]
            finally:
                if previous is None:
                    os.environ.pop("ANDROSHIELD_NATIVE", None)
                else:
                    os.environ["ANDROSHIELD_NATIVE"] = previous
        results["pipeline"].append(item)
        print(item, flush=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print("Saved aggregate benchmark:", args.output, flush=True)


if __name__ == "__main__":
    main()
