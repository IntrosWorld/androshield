"""Safely extract a bounded APK sample from a CICMalDroid class archive.

The archive is read sequentially and processing stops as soon as the requested
number of APKs has been written.  This avoids expanding a multi-gigabyte corpus
when only a calibration batch is needed.  APKs are copied as inert files; they
are never opened by Android, installed, or executed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tarfile
from pathlib import Path


HASH_APK = re.compile(r"^[0-9a-fA-F]{64}\.apk$")


def safe_apk_name(member: tarfile.TarInfo, class_name: str) -> str | None:
    """Return a safe hash filename for a regular member in the requested class."""
    if not member.isfile():
        return None
    normalised = member.name.replace("\\", "/").strip("/")
    parts = normalised.split("/")
    if len(parts) != 2 or parts[0].casefold() != class_name.casefold():
        return None
    return parts[1].lower() if HASH_APK.fullmatch(parts[1]) else None


def sample_archive(
    archive: Path,
    output: Path,
    *,
    class_name: str,
    count: int,
    skip: int = 0,
    max_member_bytes: int = 100 * 1024 * 1024,
    max_total_bytes: int = 500 * 1024 * 1024,
) -> list[dict]:
    if count < 1 or skip < 0 or max_member_bytes < 1 or max_total_bytes < 1:
        raise ValueError("count and byte limits must be positive; skip cannot be negative")
    output.mkdir(parents=True, exist_ok=True)
    selected: list[dict] = []
    eligible_seen = 0
    total_bytes = 0

    # Stream mode is intentional: it lets us stop without scanning/decompressing
    # the rest of the very large tar.gz archive.
    with tarfile.open(archive, mode="r|gz") as tar:
        for member in tar:
            filename = safe_apk_name(member, class_name)
            if filename is None or member.size > max_member_bytes:
                continue
            if eligible_seen < skip:
                eligible_seen += 1
                continue
            if total_bytes + member.size > max_total_bytes:
                break
            source = tar.extractfile(member)
            if source is None:
                continue

            destination = output / filename
            temporary = output / f".{filename}.part"
            digest = hashlib.sha256()
            written = 0
            with temporary.open("wb") as target:
                while True:
                    chunk = source.read(min(1024 * 1024, member.size - written))
                    if not chunk:
                        break
                    target.write(chunk)
                    digest.update(chunk)
                    written += len(chunk)
            source.close()
            if written != member.size or digest.hexdigest() != filename[:-4]:
                temporary.unlink(missing_ok=True)
                continue
            os.replace(temporary, destination)
            selected.append({"filename": filename, "bytes": written, "sha256": digest.hexdigest()})
            total_bytes += written
            eligible_seen += 1
            if len(selected) >= count:
                break

    manifest = {
        "archive": str(archive.resolve()),
        "class": class_name,
        "skip": skip,
        "requested": count,
        "extracted": len(selected),
        "total_bytes": total_bytes,
        "samples": selected,
    }
    (output / "sample_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return selected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--class-name", default="Benign")
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--skip", type=int, default=0)
    parser.add_argument("--max-member-mb", type=int, default=100)
    parser.add_argument("--max-total-mb", type=int, default=500)
    args = parser.parse_args()
    rows = sample_archive(
        args.archive,
        args.output,
        class_name=args.class_name,
        count=args.count,
        skip=args.skip,
        max_member_bytes=args.max_member_mb * 1024 * 1024,
        max_total_bytes=args.max_total_mb * 1024 * 1024,
    )
    print(f"Extracted {len(rows)} APK(s) to {args.output.resolve()}")
    print(f"Total: {sum(row['bytes'] for row in rows) / 1024 / 1024:.2f} MiB")
    return 0 if rows else 2


if __name__ == "__main__":
    raise SystemExit(main())
