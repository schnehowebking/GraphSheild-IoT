#!/usr/bin/env python3
"""Fit the canonical detector on actual OVS train runs and select its threshold on disjoint validation runs."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from reviewer_revision.core import (  # noqa: E402
    FEATURES,
    FittedDetector,
    Partition,
    read_json,
    sha,
    write_json,
)
from run_ovs_controller_trials import sha256  # noqa: E402


RECORD_COLUMNS = [
    "row_id",
    "run_id",
    "window_index",
    "window_start_ts",
    "window_end_ts",
    "phase",
    "label",
    "seed",
]


def verify_checksums(directory):
    directory = Path(directory)
    count = 0
    for line in (directory / "CHECKSUMS.sha256").read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", 1)
        path = directory / relative
        if not path.is_file() or sha256(path) != expected:
            raise AssertionError(f"Collection checksum mismatch: {path}")
        count += 1
    return count


def load_collection(directory, expected_role, protocol, expected_protocol_sha256=None):
    directory = Path(directory).resolve()
    checksums = verify_checksums(directory)
    config = read_json(directory / "collection_configuration.json")
    if config["role"] != expected_role or config.get("smoke"):
        raise ValueError(f"Expected a complete {expected_role} collection")
    if expected_protocol_sha256 and config["protocol_sha256"] != expected_protocol_sha256:
        raise ValueError("Collection protocol hash mismatch")
    expected = protocol["calibration_train" if expected_role == "train" else "calibration_validation"]
    if int(config["seed_start"]) != int(expected["seed_start"]) or int(config["runs"]) != int(expected["runs"]):
        raise ValueError(f"{expected_role} seed range differs from the preregistered protocol")
    frame = pd.read_csv(directory / "calibration_windows.csv", float_precision="round_trip")
    required = set(RECORD_COLUMNS + FEATURES)
    if not required.issubset(frame.columns):
        raise ValueError(f"Missing collection columns: {sorted(required - set(frame.columns))}")
    if frame.row_id.duplicated().any() or frame.run_id.nunique() != int(expected["runs"]):
        raise ValueError(f"Invalid {expected_role} run or row identities")
    if set(frame.seed) != set(range(int(expected["seed_start"]), int(expected["seed_start"]) + int(expected["runs"]))):
        raise ValueError(f"Incomplete {expected_role} seed set")
    values = frame[FEATURES].to_numpy(float)
    if not np.isfinite(values).all() or (values < 0).any():
        raise ValueError(f"Invalid {expected_role} features")
    if not set(frame.label.astype(int).unique()) == {0, 1}:
        raise ValueError(f"{expected_role} requires both classes")
    frame["window_start_ts"] = pd.to_datetime(frame.window_start_ts, utc=True)
    frame["window_end_ts"] = pd.to_datetime(frame.window_end_ts, utc=True)
    if (frame.window_start_ts >= frame.window_end_ts).any():
        raise ValueError("Invalid window timestamp ordering")
    frame = frame.sort_values(["window_start_ts", "run_id", "window_index"], kind="stable").reset_index(drop=True)
    return directory, config, frame, checksums


def partition(frame, role):
    records = frame[RECORD_COLUMNS].copy()
    return Partition(role=role, x=frame[FEATURES].copy(), y=frame.label.to_numpy(int), records=records)


def git_commit():
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else "unavailable"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", required=True)
    parser.add_argument("--validation", required=True)
    parser.add_argument("--output", default=str(ROOT / "deployment_ovs_v2"))
    parser.add_argument("--protocol", default=str(ROOT / "configs/ovs_experiment_protocol_v2.json"))
    parser.add_argument("--registry", default=str(ROOT / "configs/threshold_registry_ovs_v2.json"))
    parser.add_argument("--detector-config", default=str(ROOT / "configs/canonical_detector_ovs_v2.json"))
    args = parser.parse_args()

    output = Path(args.output).resolve()
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite {output}")
    protocol_path = Path(args.protocol).resolve()
    registry_path = Path(args.registry).resolve()
    detector_config_path = Path(args.detector_config).resolve()
    protocol, registry = read_json(protocol_path), read_json(registry_path)
    detector_config = read_json(detector_config_path)
    protocol_sha256 = sha256(protocol_path)
    train_dir, train_config, train_frame, train_checksum_count = load_collection(
        args.train, "train", protocol, protocol_sha256)
    val_dir, val_config, val_frame, val_checksum_count = load_collection(
        args.validation, "validation", protocol, protocol_sha256)

    if set(train_frame.seed) & set(val_frame.seed):
        raise ValueError("Train/validation seed leakage")
    if train_frame.window_end_ts.max() >= val_frame.window_start_ts.min():
        raise ValueError("Validation must be collected strictly after training")
    if detector_config["features"] != FEATURES:
        raise ValueError("OVS detector configuration must retain the canonical feature order")
    fitted = FittedDetector(detector_config).fit(
        partition(train_frame, "train"), partition(val_frame, "validation"), registry)
    fitted.save(output, evaluation_paths=["fresh confirmatory Kali and Ubuntu artifacts only"], test_rows=0)

    profile_rows = []
    for split_name, frame in [("train", train_frame), ("validation", val_frame)]:
        for label, group in frame.groupby("label"):
            for feature in FEATURES:
                profile_rows.append({
                    "split": split_name,
                    "label": int(label),
                    "feature": feature,
                    "n": len(group),
                    "minimum": float(group[feature].min()),
                    "median": float(group[feature].median()),
                    "maximum": float(group[feature].max()),
                })
    pd.DataFrame(profile_rows).to_csv(output / "feature_distribution_profile.csv", index=False)
    manifest = {
        "protocol_version": protocol["version"],
        "protocol_sha256": protocol_sha256,
        "threshold_registry_sha256": sha256(registry_path),
        "detector_configuration_sha256": sha256(detector_config_path),
        "threshold_registry_object_hash": read_json(output / "threshold_selection.json")["registry_hash"],
        "git_commit": git_commit(),
        "train": {
            "collection": train_dir.name,
            "windows_sha256": sha256(train_dir / "calibration_windows.csv"),
            "checksums_verified": train_checksum_count,
            "rows": len(train_frame),
            "runs": int(train_frame.run_id.nunique()),
            "seeds": sorted(int(seed) for seed in train_frame.seed.unique()),
            "start": train_frame.window_start_ts.min().isoformat(),
            "end": train_frame.window_end_ts.max().isoformat(),
        },
        "validation": {
            "collection": val_dir.name,
            "windows_sha256": sha256(val_dir / "calibration_windows.csv"),
            "checksums_verified": val_checksum_count,
            "rows": len(val_frame),
            "runs": int(val_frame.run_id.nunique()),
            "seeds": sorted(int(seed) for seed in val_frame.seed.unique()),
            "start": val_frame.window_start_ts.min().isoformat(),
            "end": val_frame.window_end_ts.max().isoformat(),
        },
        "model_sha256": sha(output / "model.joblib"),
        "selected_threshold": fitted.threshold,
        "selection_source": "dedicated validation collection only",
        "test_rows_seen": 0,
        "feature_order": FEATURES,
    }
    write_json(output / "ovs_training_manifest.json", manifest)
    files = sorted(path for path in output.iterdir() if path.is_file())
    (output / "CHECKSUMS.sha256").write_text("".join(
        f"{sha256(path)}  {path.name}\n" for path in files), encoding="utf-8")
    print(json.dumps({"status": "complete", "output": str(output), "model_sha256": manifest["model_sha256"],
                      "threshold": fitted.threshold, "train_rows": len(train_frame),
                      "validation_rows": len(val_frame), "test_rows_seen": 0}, indent=2))


if __name__ == "__main__":
    main()
