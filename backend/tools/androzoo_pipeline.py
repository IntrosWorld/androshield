"""Reproducible, secret-safe AndroZoo sampling and APK download pipeline.

AndroZoo APKs are untrusted research artefacts. This tool downloads them but never
installs or executes them. Dynamic execution remains an explicit action in FraudSandbox.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import heapq
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


METADATA_URL = "https://androzoo.uni.lu/static/lists/latest.csv.gz"
DOWNLOAD_URL = "https://androzoo.uni.lu/api/download"
MANIFEST_FIELDS = [
    "label", "sha256", "pkg_name", "apk_size", "dex_date", "vt_detection",
    "vt_scan_date", "markets", "selection_rule", "seed",
]
BAD_SHA256 = "BC564D52C6E79E1676C19D9602B1359A33B8714A1DC5FCB8ED602209D0B70266"


class PipelineError(RuntimeError):
    pass


def _backend_dir() -> Path:
    return Path(__file__).resolve().parents[1]


def load_api_key(env_file: Path | None = None) -> str:
    """Load the key from the process or backend/.env without ever printing it."""
    key = os.getenv("ANDROZOO_API_KEY", "").strip()
    path = env_file or (_backend_dir() / ".env")
    if not key and path.is_file():
        for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, value = line.split("=", 1)
            if name.strip() == "ANDROZOO_API_KEY":
                key = value.strip().strip('"\'')
                break
    if len(key) < 8 or any(char.isspace() for char in key):
        raise PipelineError(
            "ANDROZOO_API_KEY is missing or malformed; set it in backend/.env"
        )
    return key


def fetch_metadata(output: Path, url: str = METADATA_URL, max_retries: int = 100) -> Path:
    """Download the nightly gzip metadata, reconnecting and resuming after stalls."""
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    partial = output.with_suffix(output.suffix + ".part")
    failures = 0
    while True:
        existing = partial.stat().st_size if partial.exists() else 0
        headers = {"User-Agent": "AndroShield-AndroZoo/1.0"}
        if existing:
            headers["Range"] = f"bytes={existing}-"
        request = urllib.request.Request(url, headers=headers)
        try:
            response = urllib.request.urlopen(request, timeout=90)
            status = getattr(response, "status", response.getcode())
            if existing and status != 206:
                print("metadata server ignored resume; restarting the index download")
                existing = 0
            mode = "ab" if existing else "wb"
            content_length = _int(response.headers.get("Content-Length"), 0)
            content_range = response.headers.get("Content-Range", "")
            expected_total = 0
            if "/" in content_range and content_range.rsplit("/", 1)[1].isdigit():
                expected_total = int(content_range.rsplit("/", 1)[1])
            elif status == 200 and content_length:
                expected_total = content_length
            expected_end = existing + content_length if content_length else 0
            downloaded = existing
            report_step = 64 * 1024 * 1024
            next_report = ((downloaded // report_step) + 1) * report_step
            with response, partial.open(mode) as handle:
                while True:
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    handle.write(block)
                    downloaded += len(block)
                    if downloaded >= next_report:
                        print(f"metadata downloaded: {downloaded / (1024 ** 3):.2f} GiB")
                        next_report += report_step
            if expected_end and downloaded < expected_end:
                raise TimeoutError(
                    f"connection ended at {downloaded} of {expected_end} expected bytes"
                )
            if expected_total and downloaded < expected_total:
                raise TimeoutError(
                    f"connection ended at {downloaded} of {expected_total} total bytes"
                )
            break
        except (OSError, urllib.error.URLError) as exc:
            failures += 1
            if failures > max_retries:
                detail = str(getattr(exc, "reason", exc))[:200]
                raise PipelineError(
                    f"metadata download failed after {max_retries} reconnects: {detail}"
                ) from exc
            delay = min(30, max(2, failures * 2))
            current = partial.stat().st_size if partial.exists() else 0
            print(
                f"metadata connection interrupted at {current / (1024 ** 2):.1f} MiB; "
                f"retrying in {delay}s ({failures}/{max_retries})"
            )
            time.sleep(delay)
    with partial.open("rb") as handle:
        gzip_magic = handle.read(2)
    if partial.stat().st_size < 1024 or gzip_magic != b"\x1f\x8b":
        raise PipelineError("metadata response is not a valid gzip stream")
    os.replace(partial, output)
    print(f"metadata ready: {output} ({output.stat().st_size / (1024 ** 3):.2f} GiB)")
    return output


def _int(value: str | None, default: int = -1) -> int:
    try:
        return int(value or "")
    except (TypeError, ValueError):
        return default


def _date(value: str | None) -> str:
    text = (value or "").strip()
    return text[:10] if len(text) >= 10 else ""


def _rank(seed: int, label: str, sha256: str) -> int:
    digest = hashlib.blake2b(
        f"{seed}:{label}:{sha256}".encode("ascii", "ignore"), digest_size=8
    ).digest()
    return int.from_bytes(digest, "big")


class _UniquePackageSample:
    """Keep the deterministic N lowest-ranked hashes with unique package names."""

    def __init__(self, limit: int):
        self.limit = limit
        self.by_package: dict[str, tuple[int, dict]] = {}
        self.heap: list[tuple[int, str, str]] = []

    def _clean(self) -> None:
        while self.heap:
            negative_rank, sha256, package = self.heap[0]
            current = self.by_package.get(package)
            if current and current[0] == -negative_rank and current[1]["sha256"] == sha256:
                return
            heapq.heappop(self.heap)

    def add(self, rank: int, row: dict) -> None:
        package = row["pkg_name"]
        current = self.by_package.get(package)
        if current:
            if rank >= current[0]:
                return
            self.by_package[package] = (rank, row)
            heapq.heappush(self.heap, (-rank, row["sha256"], package))
            return
        if len(self.by_package) < self.limit:
            self.by_package[package] = (rank, row)
            heapq.heappush(self.heap, (-rank, row["sha256"], package))
            return
        self._clean()
        worst_rank, _worst_sha, worst_package = self.heap[0]
        if rank >= -worst_rank:
            return
        heapq.heappop(self.heap)
        del self.by_package[worst_package]
        self.by_package[package] = (rank, row)
        heapq.heappush(self.heap, (-rank, row["sha256"], package))

    def rows(self) -> list[dict]:
        return [row for _rank_value, row in sorted(self.by_package.values())]


def select_manifest(
    metadata: Path,
    manifest: Path,
    benign_count: int = 20,
    malicious_count: int = 20,
    seed: int = 2020,
    min_scan_date: str = "2022-01-01",
    min_size: int = 100_000,
    max_size: int = 30_000_000,
    malicious_vt_min: int = 10,
) -> list[dict]:
    """Stream AndroZoo metadata and write an immutable balanced evaluation manifest."""
    if benign_count < 0 or malicious_count < 0 or benign_count + malicious_count < 1:
        raise PipelineError("request at least one benign or likely-malicious sample")
    benign = _UniquePackageSample(benign_count)
    malicious = _UniquePackageSample(malicious_count)
    required = {"sha256", "apk_size", "pkg_name", "vt_detection", "vt_scan_date", "markets"}
    opener = gzip.open if metadata.suffix.lower() == ".gz" else open
    try:
        stream = opener(metadata, "rt", encoding="utf-8-sig", errors="replace", newline="")
    except OSError as exc:
        raise PipelineError(f"cannot open metadata: {exc}") from exc
    scanned = 0
    with stream:
        reader = csv.DictReader(stream)
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise PipelineError(f"metadata is missing columns: {', '.join(sorted(missing))}")
        for raw in reader:
            scanned += 1
            sha256 = (raw.get("sha256") or "").strip().upper()
            package = (raw.get("pkg_name") or "").strip()
            size = _int(raw.get("apk_size"))
            vt = _int(raw.get("vt_detection"))
            scan_date = _date(raw.get("vt_scan_date"))
            markets = (raw.get("markets") or "").strip()
            if (len(sha256) != 64 or sha256 == BAD_SHA256 or not package
                    or not min_size <= size <= max_size or scan_date < min_scan_date):
                continue
            base = {
                "sha256": sha256, "pkg_name": package, "apk_size": str(size),
                "dex_date": (raw.get("dex_date") or "").strip(),
                "vt_detection": str(vt), "vt_scan_date": (raw.get("vt_scan_date") or "").strip(),
                "markets": markets, "seed": str(seed),
            }
            if vt == 0 and "play.google.com" in markets.split("|") and benign_count:
                row = dict(base, label="benign_candidate",
                           selection_rule="play.google.com; vt_detection=0; unique package")
                benign.add(_rank(seed, row["label"], sha256), row)
            elif vt >= malicious_vt_min and malicious_count:
                row = dict(base, label="likely_malicious",
                           selection_rule=f"vt_detection>={malicious_vt_min}; unique package")
                malicious.add(_rank(seed, row["label"], sha256), row)
    rows = benign.rows() + malicious.rows()
    if len(benign.rows()) != benign_count or len(malicious.rows()) != malicious_count:
        raise PipelineError(
            f"insufficient candidates after scanning {scanned:,} rows: "
            f"benign={len(benign.rows())}/{benign_count}, "
            f"likely_malicious={len(malicious.rows())}/{malicious_count}"
        )
    manifest = manifest.resolve()
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with manifest.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=MANIFEST_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    print(f"selected {len(rows)} samples from {scanned:,} metadata rows")
    print(f"manifest: {manifest}")
    print(f"manifest SHA256: {digest}")
    return rows


def _download_one(row: dict, output: Path, key: str, retries: int = 2) -> tuple[str, str]:
    sha256 = row["sha256"].strip().upper()
    expected_size = _int(row.get("apk_size"), 0)
    label_dir = output / row.get("label", "unlabelled")
    label_dir.mkdir(parents=True, exist_ok=True)
    destination = label_dir / f"{sha256}.apk"
    if destination.is_file():
        existing_hash = hashlib.sha256(destination.read_bytes()).hexdigest().upper()
        if existing_hash == sha256:
            return sha256, "already verified"
        destination.unlink()
    partial = destination.with_suffix(".apk.part")
    query = urllib.parse.urlencode({"apikey": key, "sha256": sha256})
    request = urllib.request.Request(
        f"{DOWNLOAD_URL}?{query}", headers={"User-Agent": "AndroShield-AndroZoo/1.0"}
    )
    last_error = "download failed"
    for attempt in range(retries + 1):
        hasher = hashlib.sha256()
        size = 0
        prefix = b""
        try:
            with urllib.request.urlopen(request, timeout=180) as response, partial.open("wb") as handle:
                while True:
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    if not prefix:
                        prefix = block[:4]
                    size += len(block)
                    if size > max(expected_size + 1024 * 1024, 512 * 1024 * 1024):
                        raise PipelineError("response exceeded expected APK size")
                    hasher.update(block)
                    handle.write(block)
            if prefix[:2] != b"PK":
                raise PipelineError("server response was not an APK/ZIP")
            if hasher.hexdigest().upper() != sha256:
                raise PipelineError("SHA256 mismatch")
            if expected_size and size != expected_size:
                raise PipelineError(f"size mismatch ({size} != {expected_size})")
            os.replace(partial, destination)
            return sha256, "downloaded and verified"
        except (OSError, urllib.error.URLError, PipelineError) as exc:
            last_error = str(getattr(exc, "reason", exc))[:240]
            partial.unlink(missing_ok=True)
            if attempt < retries:
                time.sleep(2 ** attempt)
    return sha256, f"failed: {last_error}"


def download_manifest(manifest: Path, output: Path, workers: int = 4) -> list[tuple[str, str]]:
    key = load_api_key()
    workers = max(1, min(int(workers), 20))
    with manifest.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows or any(len((row.get("sha256") or "").strip()) != 64 for row in rows):
        raise PipelineError("manifest is empty or contains an invalid SHA256")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    results: list[tuple[str, str]] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_download_one, row, output, key): row for row in rows}
        for future in as_completed(futures):
            sha256, status = future.result()
            results.append((sha256, status))
            print(f"{sha256[:12]}… {status}")
    failures = [item for item in results if item[1].startswith("failed:")]
    print(f"download summary: {len(results) - len(failures)} verified, {len(failures)} failed")
    if failures:
        raise PipelineError("one or more APK downloads failed")
    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("key-status", help="check key configuration without printing it")
    fetch = commands.add_parser("fetch-metadata", help="download/resume latest.csv.gz")
    fetch.add_argument("--output", type=Path, required=True)
    select = commands.add_parser("select", help="create a deterministic evaluation manifest")
    select.add_argument("--metadata", type=Path, required=True)
    select.add_argument("--manifest", type=Path, required=True)
    select.add_argument("--benign", type=int, default=20)
    select.add_argument("--malicious", type=int, default=20)
    select.add_argument("--seed", type=int, default=2020)
    select.add_argument("--min-scan-date", default="2022-01-01")
    select.add_argument("--min-size", type=int, default=100_000)
    select.add_argument("--max-size", type=int, default=30_000_000)
    select.add_argument("--malicious-vt-min", type=int, default=10)
    download = commands.add_parser("download", help="download and verify a manifest")
    download.add_argument("--manifest", type=Path, required=True)
    download.add_argument("--output", type=Path, required=True)
    download.add_argument("--workers", type=int, default=4)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "key-status":
            load_api_key()
            print("AndroZoo API key is configured (value hidden).")
        elif args.command == "fetch-metadata":
            fetch_metadata(args.output)
        elif args.command == "select":
            select_manifest(
                args.metadata, args.manifest, args.benign, args.malicious, args.seed,
                args.min_scan_date, args.min_size, args.max_size, args.malicious_vt_min,
            )
        elif args.command == "download":
            download_manifest(args.manifest, args.output, args.workers)
        return 0
    except (PipelineError, OSError, csv.Error, gzip.BadGzipFile) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
