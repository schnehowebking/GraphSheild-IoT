import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from reviewer_revision.core import FEATURES, RuntimeDetector
from scripts.run_ovs_controller_trials import sha256
from scripts.train_ovs_detector import main as train_main
from scripts.verify_ovs_detector import main as verify_main


ROOT = Path(__file__).resolve().parents[1]


def make_collection(path, role, seed_start, runs, timestamp_start, protocol_hash):
    path.mkdir()
    rows = []
    timestamp = timestamp_start
    for seed in range(seed_start, seed_start + runs):
        run_id = f"ovs_{role}_{seed:08d}"
        for window_index, label in enumerate([0, 1]):
            rate = 100.0 + seed % 7 if label == 0 else 3000.0 + seed % 11
            rows.append({
                "row_id": f"{run_id}_window_{window_index:03d}", "run_id": run_id,
                "seed": seed, "window_index": window_index,
                "window_start_ts": timestamp.isoformat(),
                "window_end_ts": (timestamp + timedelta(seconds=5)).isoformat(),
                "phase": "attack" if label else "benign", "label": label,
                "pkt_rate": rate, "byte_rate": rate * 1200, "pkt_sum": rate * 5,
                "events": 5.0, "unique_src": 3.0 if label else 1.0,
                "src_ip_entropy": 1.5 if label else 0.0,
                "flow_count": 15.0 if label else 5.0, "flow_rate": 3.0 if label else 1.0,
            })
            timestamp += timedelta(seconds=5)
    pd.DataFrame(rows).to_csv(path / "calibration_windows.csv", index=False)
    config = {"role": role, "smoke": False, "protocol_sha256": protocol_hash,
              "seed_start": seed_start, "runs": runs}
    (path / "collection_configuration.json").write_text(json.dumps(config), encoding="utf-8")
    files = sorted(item for item in path.iterdir() if item.is_file())
    (path / "CHECKSUMS.sha256").write_text("".join(
        f"{sha256(item)}  {item.name}\n" for item in files), encoding="utf-8")


def test_actual_ovs_training_and_threshold_verification_end_to_end(tmp_path, monkeypatch):
    protocol = ROOT / "configs/ovs_experiment_protocol_v2.json"
    registry = ROOT / "configs/threshold_registry_ovs_v2.json"
    detector_config = ROOT / "configs/canonical_detector_ovs_v2.json"
    train = tmp_path / "train"
    validation = tmp_path / "validation"
    deployment = tmp_path / "deployment"
    make_collection(train, "train", 51000, 40, datetime(2026, 1, 1, tzinfo=timezone.utc), sha256(protocol))
    make_collection(validation, "validation", 52000, 20, datetime(2026, 1, 2, tzinfo=timezone.utc), sha256(protocol))

    monkeypatch.setattr(sys, "argv", ["train_ovs_detector.py", "--train", str(train),
        "--validation", str(validation), "--output", str(deployment),
        "--protocol", str(protocol), "--registry", str(registry),
        "--detector-config", str(detector_config)])
    train_main()
    monkeypatch.setattr(sys, "argv", ["verify_ovs_detector.py", "--train", str(train),
        "--validation", str(validation), "--deployment", str(deployment),
        "--protocol", str(protocol), "--registry", str(registry),
        "--detector-config", str(detector_config)])
    verify_main()

    report = json.loads((deployment / "training_verification.json").read_text(encoding="utf-8"))
    assert report["passed"] and report["test_rows_seen"] == 0
    assert report["train_runs"] == 40 and report["validation_runs"] == 20
    runtime = RuntimeDetector(directory=deployment, registry_path=registry)
    sample = pd.DataFrame([[100.0, 120000.0, 500.0, 5.0, 1.0, 0.0, 5.0, 1.0]], columns=FEATURES)
    assert len(runtime.predict_proba_or_action(sample)) == 1
