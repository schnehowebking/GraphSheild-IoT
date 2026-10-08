#!/usr/bin/env python3
"""Hash every raw source file actually consumed by external processing."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(16 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--processing-root", default="results/external_raw_processing_v1")
    parser.add_argument("--input-root", default="dataset/datasetsforexternalaudit")
    parser.add_argument("--output", default="results/external_raw_source_hashes_v1")
    args = parser.parse_args()
    processing = (ROOT / args.processing_root).resolve()
    sources = (ROOT / args.input_root).resolve()
    output = (ROOT / args.output).resolve()
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite existing output: {output}")
    output.mkdir(parents=True)

    lists = [
        ("CIC-DDoS2019", processing / "cicddos2019/source_files.csv"),
        ("IoT-23", processing / "iot23/source_files.csv"),
        ("TON_IoT", processing / "toniot_final/source_files.csv"),
    ]
    selected: dict[str, str] = {}
    for dataset, listing in lists:
        with listing.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                relative = row["relative_path"]
                previous = selected.setdefault(relative, dataset)
                if previous != dataset:
                    raise AssertionError(f"Source assigned to multiple datasets: {relative}")

    started = time.time()
    rows = []
    for index, (relative, dataset) in enumerate(sorted(selected.items()), start=1):
        path = sources / relative
        before = path.stat()
        digest = sha256(path)
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise RuntimeError(f"Source changed while hashing: {relative}")
        rows.append({
            "dataset": dataset, "relative_path": relative, "bytes": before.st_size,
            "modified_utc": datetime.fromtimestamp(before.st_mtime, timezone.utc).isoformat(),
            "sha256": digest,
        })
        print(f"[{index}/{len(selected)}] {dataset}: {relative}", flush=True)

    csv_path = output / "raw_source_fingerprints.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": "SHA-256", "files": len(rows),
        "bytes": sum(int(row["bytes"]) for row in rows),
        "datasets": {name: sum(row["dataset"] == name for row in rows)
                     for name in ["CIC-DDoS2019", "IoT-23", "TON_IoT"]},
        "source_files_changed_during_hashing": False,
        "runtime_seconds": time.time() - started,
    }
    manifest_path = output / "source_hash_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (output / "CHECKSUMS.sha256").write_text(
        f"{sha256(csv_path)}  {csv_path.name}\n{sha256(manifest_path)}  {manifest_path.name}\n",
        encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
