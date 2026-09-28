#!/usr/bin/env python3
"""Independently verify paired actual-OVS trial artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from run_ovs_controller_trials import FEATURES, binary_metrics  # noqa: E402
sys.path.insert(0, str(ROOT))
from integration.audit_hash_chain import verify_hash_chained_jsonl  # noqa: E402
from reviewer_revision.core import RuntimeDetector  # noqa: E402


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def close(a, b):
    if isinstance(a, str) or isinstance(b, str):
        return a == b
    if a is None or (isinstance(a, float) and np.isnan(a)):
        return b is None
    return np.isclose(float(a), float(b), rtol=0, atol=1e-12)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    parser.add_argument("--deployment-dir", default=str(ROOT / "deployment"))
    parser.add_argument("--threshold-registry", default=str(ROOT / "configs/threshold_registry.json"))
    parser.add_argument("--protocol", default=str(ROOT / "configs/ovs_experiment_protocol_v2.json"))
    args = parser.parse_args()
    output = Path(args.output).resolve()
    config = json.loads((output / "experiment_configuration.json").read_text())
    deployment = Path(args.deployment_dir).resolve()
    runtime = RuntimeDetector(directory=deployment, registry_path=Path(args.threshold_registry).resolve())
    selection = json.loads((deployment / "threshold_selection.json").read_text())
    expected_threshold = runtime.threshold
    if config.get("model_hash", selection["model_hash"]) != selection["model_hash"]:
        raise AssertionError("Experiment configuration model hash mismatch")
    environment = json.loads((output / "environment.json").read_text())
    if environment["model_sha256"] != selection["model_hash"]:
        raise AssertionError("Environment model hash mismatch")
    trials = pd.read_csv(output / "trial_level_results.csv", float_precision="round_trip")
    expected_pairs = int(config["trials"])
    if len(trials) != expected_pairs * 2 or trials.seed.nunique() != expected_pairs:
        raise AssertionError("Unexpected paired trial count")
    legacy_f1_semantics = config.get("metrics_definition") != "confusion_count_f1_v2"
    confirmatory_protocol_verified = False
    if config.get("protocol_role") == "confirmatory" and not config.get("smoke", False):
        protocol_path = Path(args.protocol).resolve()
        protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
        if config.get("protocol_sha256") != sha256(protocol_path):
            raise AssertionError("Confirmatory protocol hash mismatch")
        if int(config["max_attackers"]) != int(protocol["traffic"]["maximum_attacker_namespaces"]):
            raise AssertionError("Confirmatory attacker count differs from protocol")
        os_id = str(environment.get("os_release", {}).get("ID", "")).lower()
        protocol_key = "confirmatory_kali" if os_id == "kali" else "confirmatory_ubuntu" if os_id == "ubuntu" else None
        if protocol_key is None:
            raise AssertionError(f"Unsupported confirmatory operating system: {os_id!r}")
        definition = protocol[protocol_key]
        expected_seeds = set(range(int(definition["seed_start"]),
                                   int(definition["seed_start"]) + int(definition["runs"])))
        if set(trials.seed.astype(int)) != expected_seeds:
            raise AssertionError("Confirmatory seed set differs from protocol")
        if expected_pairs != int(definition["runs"]):
            raise AssertionError("Confirmatory trial count differs from protocol")
        if legacy_f1_semantics:
            raise AssertionError("Confirmatory result uses the legacy F1 definition")
        confirmatory_protocol_verified = True
    checked_windows = 0
    audit_chains_verified = 0
    for seed, pair in trials.groupby("seed"):
        if set(pair.setting) != {"audit_disabled", "audit_enabled"}:
            raise AssertionError(f"Unpaired settings for seed {seed}")
        frames = {}
        for setting in ["audit_disabled", "audit_enabled"]:
            folder = output / f"seed_{int(seed):08d}_{setting}"
            frame = pd.read_csv(folder / "window_results.csv", float_precision="round_trip")
            frames[setting] = frame
            if list(frame[FEATURES].columns) != FEATURES:
                raise AssertionError("Canonical feature order mismatch")
            values = frame[FEATURES].to_numpy(float)
            if not np.isfinite(values).all() or (values < 0).any():
                raise AssertionError("Invalid runtime features")
            if not np.allclose(frame.threshold, expected_threshold, rtol=0, atol=0):
                raise AssertionError("Saved operating threshold mismatch")
            expected = (frame.probability.to_numpy(float) >= expected_threshold).astype(int)
            if not np.array_equal(expected, frame.prediction.to_numpy(int)):
                raise AssertionError("Prediction does not trace to saved threshold")
            if "model_hash" in frame and not (frame.model_hash == selection["model_hash"]).all():
                raise AssertionError("Row-level model hash mismatch")
            metrics = binary_metrics(frame.label, frame.prediction)
            saved = json.loads((folder / "trial_metrics.json").read_text())
            for name, value in metrics.items():
                if legacy_f1_semantics and name in {"f1", "undefined_metrics"}:
                    continue
                if not close(value, saved[name]):
                    raise AssertionError(f"Metric mismatch {seed} {setting} {name}")
            audit = folder / "audit.jsonl"
            lines = len(audit.read_text().splitlines()) if audit.exists() else 0
            if setting == "audit_enabled" and lines != len(frame) + 1:
                raise AssertionError("Audit-enabled record count mismatch")
            if setting == "audit_enabled":
                verification = verify_hash_chained_jsonl(audit)
                if not verification["valid_embedded_hash_chain"]:
                    raise AssertionError("Invalid audit hash chain")
                audit_chains_verified += 1
            if setting == "audit_disabled" and lines:
                raise AssertionError("Audit-disabled trial wrote audit records")
            final = (folder / "ovs_final_after_rollback.txt").read_text()
            if "cookie=0x475402" in final or "meter=1" in final:
                raise AssertionError("Rollback left model-driven enforcement behind")
            pcap = folder / "traffic_sample.pcap"
            if not pcap.exists() or pcap.stat().st_size <= 24:
                raise AssertionError("Missing packet-capture evidence")
            checked_windows += len(frame)
        columns = ["phase", "label", "scheduled_benign_mbps", "scheduled_attack_mbps"]
        if "scheduled_attackers" in frames["audit_enabled"].columns:
            columns.append("scheduled_attackers")
        pd.testing.assert_frame_equal(frames["audit_enabled"][columns], frames["audit_disabled"][columns])
    summary = pd.read_csv(output / "trial_summary_with_ci.csv")
    paired = pd.read_csv(output / "paired_audit_differences.csv")
    if not ((summary.n + summary.undefined_trials) == expected_pairs).all():
        raise AssertionError("Summary trial counts do not account for undefined metrics")
    if not ((paired.pairs + paired.undefined_pairs) == expected_pairs).all():
        raise AssertionError("Paired summaries do not account for undefined metric pairs")
    checksum_count = 0
    for line in (output / "CHECKSUMS.sha256").read_text().splitlines():
        expected, relative = line.split("  ", 1)
        if sha256(output / relative) != expected:
            raise AssertionError(f"Checksum mismatch: {relative}")
        checksum_count += 1
    report = {"passed": True, "paired_trials": expected_pairs, "executions": len(trials),
              "windows_verified": checked_windows, "checksums_verified": checksum_count,
              "same_inputs_within_pairs": True, "threshold_verified": expected_threshold,
              "model_hash_verified": selection["model_hash"],
              "audit_chains_verified": audit_chains_verified,
              "confirmatory_protocol_verified": confirmatory_protocol_verified,
              "legacy_f1_semantics": legacy_f1_semantics,
              "measurement_type": "actual_single_host_ovs_runtime"}
    (output / "verification_report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
