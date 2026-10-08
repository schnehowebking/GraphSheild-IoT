#!/usr/bin/env python3
"""Independently verify external raw-processing artifacts."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

try:
    from scripts.process_external_raw_datasets import FEATURES, WINDOW_COLUMNS
except ModuleNotFoundError:  # direct `python scripts/...` execution
    from process_external_raw_datasets import FEATURES, WINDOW_COLUMNS


FILES = {
    "CIC-DDoS2019": "cicddos2019_windows.csv",
    "IoT-23": "iot23_windows.csv",
    "TON_IoT": "toniot_windows.csv",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    parser.add_argument("--write-report", action="store_true")
    args = parser.parse_args()
    root = Path(args.output).resolve()
    manifest = json.loads((root / "processing_manifest.json").read_text(encoding="utf-8"))
    checks = {}
    for dataset, record in manifest["datasets"].items():
        path = root / "windows" / FILES[dataset]
        with path.open(encoding="utf-8", newline="") as handle:
            header = next(csv.reader(handle))
        if header != WINDOW_COLUMNS:
            raise AssertionError(f"Unexpected schema for {path}")
        rows = bad = materially_negative = roundoff_negative = 0
        labels: dict[str, int] = {}
        for chunk in pd.read_csv(path, chunksize=100_000):
            rows += len(chunk)
            values = chunk[FEATURES].to_numpy(dtype=float)
            bad += int((~np.isfinite(values)).sum())
            materially_negative += int((values < -1e-12).sum())
            roundoff_negative += int(((values < 0) & (values >= -1e-12)).sum())
            if not set(chunk["label"].unique()).issubset({0, 1}):
                raise AssertionError(f"Non-binary label in {path}")
            for key, count in chunk["label"].value_counts().items():
                labels[str(int(key))] = labels.get(str(int(key)), 0) + int(count)
        if rows != record["windows"] or labels != record["window_label_counts"]:
            raise AssertionError(f"Manifest mismatch for {dataset}")
        if bad or materially_negative:
            raise AssertionError(
                f"Invalid feature values for {dataset}: nonfinite={bad}, "
                f"materially_negative={materially_negative}"
            )
        checks[dataset] = {
            "rows": rows, "labels": labels, "nonfinite": bad,
            "materially_negative": materially_negative,
            "roundoff_negative_within_1e-12": roundoff_negative,
        }

    checksum_rows = {}
    for line in (root / "CHECKSUMS.sha256").read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", 1)
        checksum_rows[relative] = expected
        if sha256(root / relative) != expected:
            raise AssertionError(f"Checksum mismatch: {relative}")
    semantics = list(csv.DictReader((root / "feature_semantics.csv").open(encoding="utf-8")))
    if [row["feature"] for row in semantics] != FEATURES:
        raise AssertionError("Feature semantics do not match canonical feature order")
    report = {
        "passed": True, "datasets": checks, "checksums_verified": len(checksum_rows),
        "feature_semantics_verified": len(semantics),
        "source_hash_status": "deferred_to_final_hash_pass",
    }
    if args.write_report:
        (root / "verification_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
