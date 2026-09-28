#!/usr/bin/env python3
"""Verify actual-OVS model provenance and reproduce validation-only threshold selection."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from reviewer_revision.core import FEATURES, RuntimeDetector, read_json, select_threshold, write_json  # noqa: E402
from run_ovs_controller_trials import sha256  # noqa: E402
from train_ovs_detector import load_collection, partition  # noqa: E402


def verify_checksums(directory):
    directory = Path(directory)
    count = 0
    for line in (directory / "CHECKSUMS.sha256").read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", 1)
        path = directory / relative
        if not path.is_file() or sha256(path) != expected:
            raise AssertionError(f"Deployment checksum mismatch: {relative}")
        count += 1
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment", default=str(ROOT / "deployment_ovs_v2"))
    parser.add_argument("--train", required=True)
    parser.add_argument("--validation", required=True)
    parser.add_argument("--protocol", default=str(ROOT / "configs/ovs_experiment_protocol_v2.json"))
    parser.add_argument("--registry", default=str(ROOT / "configs/threshold_registry_ovs_v2.json"))
    parser.add_argument("--detector-config", default=str(ROOT / "configs/canonical_detector_ovs_v2.json"))
    args = parser.parse_args()

    deployment = Path(args.deployment).resolve()
    protocol_path, registry_path = Path(args.protocol).resolve(), Path(args.registry).resolve()
    protocol, registry = read_json(protocol_path), read_json(registry_path)
    checksum_count = verify_checksums(deployment)
    protocol_sha256 = sha256(protocol_path)
    train_dir, _, train_frame, train_checksums = load_collection(
        args.train, "train", protocol, protocol_sha256)
    val_dir, _, val_frame, val_checksums = load_collection(
        args.validation, "validation", protocol, protocol_sha256)
    if set(train_frame.seed) & set(val_frame.seed):
        raise AssertionError("Train/validation seed overlap")
    if train_frame.window_end_ts.max() >= val_frame.window_start_ts.min():
        raise AssertionError("Temporal ordering violation")

    manifest = read_json(deployment / "ovs_training_manifest.json")
    if manifest["detector_configuration_sha256"] != sha256(Path(args.detector_config).resolve()):
        raise AssertionError("Detector configuration hash mismatch")
    if manifest["test_rows_seen"] != 0:
        raise AssertionError("Test rows entered fitting or threshold selection")
    if manifest["train"]["windows_sha256"] != sha256(train_dir / "calibration_windows.csv"):
        raise AssertionError("Training source hash mismatch")
    if manifest["validation"]["windows_sha256"] != sha256(val_dir / "calibration_windows.csv"):
        raise AssertionError("Validation source hash mismatch")
    if manifest["feature_order"] != FEATURES:
        raise AssertionError("Feature-order mismatch")

    detector = RuntimeDetector(directory=deployment, registry_path=registry_path)
    validation = partition(val_frame, "validation")
    probabilities = detector.predict_proba_or_action(validation.x)
    selected, recomputed_curve = select_threshold(validation, probabilities, registry)
    if selected != detector.threshold or selected != manifest["selected_threshold"]:
        raise AssertionError("Validation-selected threshold mismatch")
    saved_curve = pd.read_csv(deployment / "validation_threshold_curve.csv", float_precision="round_trip")
    pd.testing.assert_frame_equal(saved_curve.reset_index(drop=True), recomputed_curve.reset_index(drop=True),
                                  check_exact=False, rtol=0, atol=1e-15)
    if int(saved_curve.selected.sum()) != 1:
        raise AssertionError("Threshold curve must select exactly one operating point")
    try:
        detector.predict_proba_or_action(val_frame[FEATURES + ["label"]])
    except ValueError:
        label_rejected = True
    else:
        raise AssertionError("Runtime detector accepted a label column")
    if not np.isfinite(probabilities).all():
        raise AssertionError("Nonfinite validation probability")

    report = {
        "passed": True,
        "deployment_checksums_verified": checksum_count,
        "train_collection_checksums_verified": train_checksums,
        "validation_collection_checksums_verified": val_checksums,
        "train_runs": int(train_frame.run_id.nunique()),
        "validation_runs": int(val_frame.run_id.nunique()),
        "train_rows": len(train_frame),
        "validation_rows": len(val_frame),
        "test_rows_seen": 0,
        "model_sha256": detector.selection["model_hash"],
        "selected_threshold": detector.threshold,
        "selection_split": "dedicated actual-OVS validation only",
        "temporal_ordering": True,
        "disjoint_seed_sets": True,
        "label_column_rejected": label_rejected,
        "feature_order": FEATURES,
    }
    write_json(deployment / "training_verification.json", report)
    files = sorted(path for path in deployment.iterdir()
                   if path.is_file() and path.name != "CHECKSUMS.sha256")
    (deployment / "CHECKSUMS.sha256").write_text("".join(
        f"{sha256(path)}  {path.name}\n" for path in files), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
