#!/usr/bin/env python3
"""Collect enforcement-free actual-OVS windows for fitting or validation.

The protocol fixes disjoint seed ranges before collection.  Labels are appended
only after feature extraction and never enter a model or threshold during this
stage.  Pilot and confirmatory seed ranges are rejected by construction.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from reviewer_revision.core import FEATURES  # noqa: E402
from run_ovs_controller_trials import (  # noqa: E402
    COOKIE_METER,
    collect_window,
    command,
    ovs_lab,
    preflight,
    schedule,
    sha256,
    version,
)


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", required=True, choices=["train", "validation"])
    parser.add_argument("--output", required=True)
    parser.add_argument("--protocol", default=str(ROOT / "configs/ovs_experiment_protocol_v2.json"))
    parser.add_argument("--smoke", action="store_true", help="Collect one short run for environment verification only")
    args = parser.parse_args()
    preflight()

    protocol_path = Path(args.protocol).resolve()
    protocol = read_json(protocol_path)
    split_key = "calibration_train" if args.role == "train" else "calibration_validation"
    split = protocol[split_key]
    traffic = protocol["traffic"]
    seed_start = int(split["seed_start"])
    runs = 1 if args.smoke else int(split["runs"])
    window_seconds = 2 if args.smoke else int(traffic["window_seconds"])
    benign_windows = attack_windows = recovery_windows = 1 if args.smoke else None
    benign_windows = benign_windows or int(traffic["benign_windows"])
    attack_windows = attack_windows or int(traffic["attack_windows"])
    recovery_windows = recovery_windows or int(traffic["recovery_windows"])
    max_attackers = int(traffic["maximum_attacker_namespaces"])

    output = Path(args.output).resolve()
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite {output}")
    output.mkdir(parents=True)

    configuration = {
        "protocol_version": protocol["version"],
        "protocol_sha256": sha256(protocol_path),
        "role": args.role,
        "output": str(output),
        "seed_start": seed_start,
        "runs": runs,
        "smoke": bool(args.smoke),
        "window_seconds": window_seconds,
        "poll_seconds": float(traffic["poll_seconds"]),
        "benign_windows": benign_windows,
        "attack_windows": attack_windows,
        "recovery_windows": recovery_windows,
        "max_attackers": max_attackers,
        "benign_rates_mbps": traffic["benign_total_mbps"],
        "attack_rates_mbps": traffic["attack_total_mbps"],
        "enforcement_enabled": False,
        "inference_enabled": False,
        "label_use": "appended after feature extraction for fitting or validation only",
        "canonical_features": FEATURES,
        "measurement_type": "actual_single_host_ovs_calibration",
    }
    (output / "collection_configuration.json").write_text(
        json.dumps(configuration, indent=2) + "\n", encoding="utf-8")
    environment = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "os_release": platform.freedesktop_os_release(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "ovs": version(["ovs-vsctl", "--version"]),
        "iperf3": version(["iperf3", "--version"]),
        "kernel": platform.release(),
    }
    (output / "environment.json").write_text(json.dumps(environment, indent=2) + "\n", encoding="utf-8")

    all_rows = []
    for run_index in range(runs):
        seed = seed_start + run_index
        run_id = f"ovs_{args.role}_{seed:08d}"
        run_dir = output / run_id
        run_dir.mkdir()
        token = f"c{os.getpid()%1000:03d}{seed%100:02d}"
        rows = []
        print(f"{args.role} run {run_index + 1}/{runs}: seed={seed}", flush=True)
        with ovs_lab(token, meter_rate=1000, max_attackers=max_attackers) as lab:
            capture = subprocess.Popen(
                ["tcpdump", "-i", "any", "-c", "2000", "-w", str(run_dir / "traffic_sample.pcap"),
                 "net", "10.253.0.0/24"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            lab.servers.append(capture)
            (run_dir / "ovs_initial.txt").write_text(lab.dump_flows(), encoding="utf-8")
            planned = schedule(seed, benign_windows, attack_windows, recovery_windows, max_attackers,
                               benign_rates=tuple(traffic["benign_total_mbps"]),
                               attack_rates=tuple(traffic["attack_total_mbps"]))
            for window_index, planned_item in enumerate(planned):
                window_dir = run_dir / f"window_{window_index:03d}"
                window_dir.mkdir()
                # Deliberately omit phase and label from the extractor input.
                traffic_only = {key: planned_item[key]
                                for key in ["benign_mbps", "attack_mbps", "active_attackers"]}
                started_at = datetime.now(timezone.utc).isoformat()
                features, dominant, throughput = collect_window(
                    lab, traffic_only, window_seconds, float(traffic["poll_seconds"]), window_dir)
                ended_at = datetime.now(timezone.utc).isoformat()
                row = {
                    "row_id": f"{run_id}_window_{window_index:03d}",
                    "run_id": run_id,
                    "seed": seed,
                    "window_index": window_index,
                    "window_start_ts": started_at,
                    "window_end_ts": ended_at,
                    "phase": planned_item["phase"],
                    "label": planned_item["label"],
                    "scheduled_benign_mbps": planned_item["benign_mbps"],
                    "scheduled_attack_mbps": planned_item["attack_mbps"],
                    "scheduled_attackers": planned_item["active_attackers"],
                    **features,
                    "dominant_source": dominant,
                    "observed_throughput_mbps": throughput,
                    "enforcement_applied": False,
                    "measurement_type": "actual_single_host_ovs_calibration",
                    "label_use": "post_extraction_fit_or_validation_only",
                }
                rows.append(row)
                all_rows.append(row)
            lab.clear_meter()
            final = lab.dump_flows() + "\n" + command(
                ["ovs-ofctl", "-O", "OpenFlow13", "dump-meters", lab.bridge]).stdout
            if COOKIE_METER in final or "meter=1" in final:
                raise AssertionError("Calibration unexpectedly left enforcement state")
            (run_dir / "ovs_final.txt").write_text(final, encoding="utf-8")
            if capture.poll() is None:
                capture.terminate()
                try:
                    capture.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    capture.kill()
                    capture.wait()
        pd.DataFrame(rows).to_csv(run_dir / "window_features.csv", index=False)

    frame = pd.DataFrame(all_rows)
    frame.to_csv(output / "calibration_windows.csv", index=False)
    profile = {
        "role": args.role,
        "runs": int(frame.run_id.nunique()),
        "windows": len(frame),
        "seed_min": int(frame.seed.min()),
        "seed_max": int(frame.seed.max()),
        "labels": {str(key): int(value) for key, value in frame.label.value_counts().sort_index().items()},
        "start": frame.window_start_ts.min(),
        "end": frame.window_end_ts.max(),
        "feature_order": FEATURES,
    }
    (output / "collection_profile.json").write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    files = sorted(path for path in output.rglob("*") if path.is_file())
    (output / "CHECKSUMS.sha256").write_text("".join(
        f"{sha256(path)}  {path.relative_to(output).as_posix()}\n" for path in files), encoding="utf-8")
    print(json.dumps({"status": "complete", **profile, "output": str(output)}, indent=2))


if __name__ == "__main__":
    main()
