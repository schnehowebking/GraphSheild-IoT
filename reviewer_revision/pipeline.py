"""Versioned data preparation, experiments, runtime checks and reproducibility artifacts."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

from reviewer_revision.core import CONFIG, FEATURES, ROOT, FittedDetector, RuntimeDetector, frame_hash, metrics, now, read_json, rewards, sha, versions, write_json
from reviewer_revision.data import GRAPH_FEATURES, OBSERVABLE, generate_run, graph_features, make_folds, partition, prepare_windows
from reviewer_revision.policies import GraphPolicy, POLICIES, UNSUPPORTED
from reviewer_revision.statistics import confidence_intervals, pairwise_statistics, summarize_policies, trial_summary


def save_predictions(windows, p, a, model, fold, policy, selection_file, elapsed_ms, abstained=None):
    d = windows[["row_id", "run_id", "window_start_ts", "window_end_ts", "switch_id", "dst_ip", "scenario_id", "label"]].copy()
    d["fold"], d["policy"] = fold, policy
    d["probability"], d["prediction"] = p, a
    d["threshold"] = model.threshold
    d["action"] = np.where(a, "RATE_LIMIT", "NONE")
    d["abstained"] = np.zeros(len(d), dtype=int) if abstained is None else abstained
    d["reward"] = rewards(d.label.to_numpy(), a)
    d["threshold_selection_file"] = selection_file
    d["inference_batch_ms"] = elapsed_ms
    return d


def temporal_and_policies(config, output, registry):
    raw = pd.concat([generate_run(config, i, config["seed"] + i) for i in range(config["simulation_runs"])], ignore_index=True)
    raw.to_csv(output / "raw_events.csv", index=False)
    windows = prepare_windows(raw)
    windows.to_csv(output / "windows.csv", index=False)
    gf = graph_features(raw[OBSERVABLE], windows[["row_id", "run_id", "window_start_ts", "switch_id", "dst_ip"]],
                        config["graph_history_seconds"], config["graph_decay_seconds"])
    pd.concat([windows[["row_id"]], gf], axis=1).to_csv(output / "graph_features.csv", index=False)
    folds, definitions = make_folds(windows, config)
    definitions.to_csv(output / "temporal_fold_definitions.csv", index=False)
    write_json(output / "data_profile.json", {"measurement_type": "controlled simulation", "windows": len(windows),
        "raw_events": len(raw), "simulation_time_steps": config["simulation_runs"] * config["windows_per_run"],
        "window_scope": "five-second switch-destination aggregates", "runs": config["simulation_runs"],
        "labels": {str(k): int(v) for k, v in windows.label.value_counts().items()},
        "scenarios": {str(k): int(v) for k, v in windows.scenario_id.value_counts().items()},
        "start": windows.window_start_ts.min(), "end": windows.window_end_ts.max(),
        "run_seeds": {f"run_{i:04d}": config["seed"] + i for i in range(config["simulation_runs"])},
        "fold_count": len(folds), "test_windows": int(definitions.loc[definitions.split == "test", "n"].sum())})
    predictions, metadata = [], []
    for fold, idx in enumerate(folds):
        print(f"Fold {fold + 1}/{len(folds)}: train={len(idx['train'])}, validation={len(idx['validation'])}, test={len(idx['test'])}", flush=True)
        parts = {role: partition(windows, windows[FEATURES], ids, role) for role, ids in idx.items()}
        canonical = FittedDetector().fit(parts["train"], parts["validation"], registry)
        model_dir = output / "models" / f"fold_{fold}" / "ml_window_baseline"
        canonical.save(model_dir, ["temporal_predictions.csv", "policy_predictions.csv"], test_rows=len(idx["test"]))
        start = time.perf_counter()
        p = canonical.predict_proba_or_action(parts["test"].x)
        elapsed = (time.perf_counter() - start) * 1000
        a = (p >= canonical.threshold).astype(int)
        predictions.append(save_predictions(parts["test"].records, p, a, canonical, fold, "ml_window_baseline",
            str((model_dir / "threshold_selection.json").relative_to(output)), elapsed))
        metadata.append({"fold": fold, "policy": "ml_window_baseline", **canonical.get_metadata(),
            "test_rows": len(p), "inference_time_ms": elapsed, "model_hash": sha(model_dir / "model.joblib")})
        teacher = canonical.predict_proba_or_action(parts["train"].x)
        for name, features in POLICIES.items():
            gparts = {role: partition(windows, gf[features], ids, role) for role, ids in idx.items()}
            policy = GraphPolicy(name, config).fit(gparts["train"], gparts["validation"], registry, teacher_train=teacher)
            policy_dir = output / "models" / f"fold_{fold}" / name
            policy.save(policy_dir, ["policy_predictions.csv"], test_rows=len(idx["test"]))
            start = time.perf_counter()
            p = policy.predict_proba_or_action(gparts["test"].x)
            a = policy.actions_from_probabilities(p)
            elapsed = (time.perf_counter() - start) * 1000
            abstained = ((p >= policy.threshold) & (a == 0)).astype(int)
            predictions.append(save_predictions(parts["test"].records, p, a, policy, fold, name,
                str((policy_dir / "threshold_selection.json").relative_to(output)), elapsed, abstained))
            metadata.append({"fold": fold, "policy": name, **policy.get_metadata(), "test_rows": len(p),
                "test_episodes": gparts["test"].records.run_id.nunique(), "inference_time_ms": elapsed,
                "model_hash": sha(policy_dir / "model.joblib")})
    # Predetermined final chronological fold; never choose deployment by test F1.
    deployment = output / "deployment"
    shutil.copytree(output / "models" / f"fold_{len(folds)-1}" / "ml_window_baseline", deployment)
    for name in ["model_metadata.json", "feature_schema.json", "threshold_selection.json", "validation_threshold_curve.csv"]:
        shutil.copyfile(deployment / name, output / name)
    pp = pd.concat(predictions, ignore_index=True)
    pp.to_csv(output / "policy_predictions.csv", index=False)
    tp = pp[pp.policy == "ml_window_baseline"].copy()
    tp.to_csv(output / "temporal_predictions.csv", index=False)
    pd.DataFrame([{"fold": int(f), **metrics(g.label.to_numpy(), g.probability.to_numpy(), g.prediction.to_numpy()),
        "threshold": float(g.threshold.iloc[0]), "threshold_selection_file": g.threshold_selection_file.iloc[0]}
        for f, g in tp.groupby("fold")]).to_csv(output / "temporal_fold_metrics.csv", index=False)
    write_json(output / "temporal_aggregate_metrics.json", {**metrics(tp.label.to_numpy(), tp.probability.to_numpy(), tp.prediction.to_numpy()),
        "folds": len(folds), "aggregation": "pooled disjoint test windows; fold models differ",
        "measurement_type": "controlled simulation", "deployment_fold": len(folds) - 1})
    print("Computing temporal cluster confidence intervals and paired policy statistics", flush=True)
    confidence_intervals(tp, config["bootstrap_seed"], config["bootstrap_replicates"]).to_csv(output / "temporal_confidence_intervals.csv", index=False)
    summarize_policies(pp).to_csv(output / "policy_comparison.csv", index=False)
    pairwise_statistics(pp, config["bootstrap_seed"], config["bootstrap_replicates"]).to_csv(output / "policy_pairwise_statistics.csv", index=False)
    write_json(output / "policy_feature_manifest.json", {"policies": {"ml_window_baseline": FEATURES, **POLICIES}, "observable_events": OBSERVABLE})
    write_json(output / "policy_configuration.json", {"fits": metadata, "unsupported_claims": UNSUPPORTED,
        "risk_selector_limit": registry["policy_action"]["risk_selector_max_benign_probability"],
        "comparison_test_set_hash": frame_hash(tp[["fold", "row_id", "label"]])})
    return RuntimeDetector(deployment), pp


def stress(config, output, runtime):
    from sdn import CompletedWindowController
    from integration.audit_hash_chain import verify_hash_chained_jsonl
    records, trial_rows = [], []
    stress_dir = output / "stress_inputs"
    stress_dir.mkdir()
    for trial in range(config["stress_trials"]):
        seed = config["seed"] + 10000 + trial
        raw = generate_run(config, 1000 + trial, seed, windows=config["stress_windows"])
        raw.to_csv(stress_dir / f"trial_{trial:02d}_events.csv", index=False)
        d = prepare_windows(raw)
        d.to_csv(stress_dir / f"trial_{trial:02d}_windows.csv", index=False)
        input_hash = frame_hash(d[FEATURES])
        # Counterbalance order; both conditions use exactly the same features/seed/model.
        order = [False, True] if trial % 2 == 0 else [True, False]
        for enabled in order:
            setting = "audit_enabled" if enabled else "audit_disabled"
            controller = CompletedWindowController(runtime, output / "audit_logs" / f"trial_{trial:02d}.jsonl", enabled)
            runtime.decide(d[FEATURES].iloc[0].to_dict())  # identical untimed warmup
            result_rows = []
            start_all = time.perf_counter()
            for row in d.itertuples(index=False):
                features = {name: getattr(row, name) for name in FEATURES}
                start = time.perf_counter_ns()
                decision = controller.detect_completed_window(features, row.row_id)
                latency = (time.perf_counter_ns() - start) / 1e6
                result_rows.append({"row_id": row.row_id, "label": row.label, "probability": decision["probability"],
                    "prediction": decision["prediction"], "action": decision["action"], "latency_ms": latency,
                    "threshold": decision["threshold"], "trial": trial, "setting": setting, "seed": seed,
                    "input_hash": input_hash, "topology": "baseline", "threshold_selection_file": "deployment/threshold_selection.json"})
            elapsed = (time.perf_counter() - start_all) * 1000
            result = pd.DataFrame(result_rows)
            records.extend(result_rows)
            m = metrics(result.label.to_numpy(), result.probability.to_numpy(), result.prediction.to_numpy())
            trial_rows.append({"trial": trial, "setting": setting, "topology": "baseline", "seed": seed,
                "input_hash": input_hash, "order": order.index(enabled), **m, "elapsed_ms": elapsed,
                **{f"latency_p{q}_ms": float(np.percentile(result.latency_ms, q)) for q in [50, 90, 99]},
                "threshold": runtime.threshold, "measurement_type": "controlled_simulation_actual_controller_method_timing",
                "audit_valid": bool(verify_hash_chained_jsonl(controller.audit_path)["valid_embedded_hash_chain"]) if enabled else None})
        print(f"Paired stress trial {trial + 1}/{config['stress_trials']} complete", flush=True)
    pd.DataFrame(records).to_csv(output / "stress_predictions.csv", index=False)
    trials = pd.DataFrame(trial_rows)
    trials.to_csv(output / "live_trial_level_results.csv", index=False)
    trial_summary(trials).to_csv(output / "live_trial_summary_with_ci.csv", index=False)
    paired = []
    for metric in ["f1", "recall", "fpr", "latency_p50_ms", "latency_p90_ms", "elapsed_ms"]:
        d = trials.pivot(index="trial", columns="setting", values=metric)
        delta = (d.audit_enabled - d.audit_disabled).to_numpy()
        from scipy.stats import t
        half = t.ppf(.975, len(delta) - 1) * delta.std(ddof=1) / np.sqrt(len(delta))
        paired.append({"metric": metric, "audit_on_minus_off_mean": float(delta.mean()),
            "ci_lower": float(delta.mean() - half), "ci_upper": float(delta.mean() + half), "n_pairs": len(delta)})
    pd.DataFrame(paired).to_csv(output / "stress_paired_differences.csv", index=False)


def topology_external(config, output, runtime):
    summary, records = [], []
    for index, (name, scale) in enumerate(config["topology_scales"].items()):
        raw = generate_run(config, 2000 + index, config["seed"] + 20000 + index, scale=scale)
        raw.to_csv(output / f"topology_{name}_events.csv", index=False)
        d = prepare_windows(raw)
        p = runtime.predict_proba_or_action(d[FEATURES]); a = (p >= runtime.threshold).astype(int)
        d = d.assign(probability=p, prediction=a, topology=name, threshold=runtime.threshold,
                     threshold_selection_file="deployment/threshold_selection.json")
        records.append(d)
        summary.append({"topology": name, "scale": scale, "measurement_type": "controlled_simulation",
            **metrics(d.label.to_numpy(), p, a), "threshold": runtime.threshold})
    all_topology = pd.concat(records, ignore_index=True)
    all_topology.to_csv(output / "topology_predictions.csv", index=False)
    pd.DataFrame(summary).to_csv(output / "topology_comparison.csv", index=False)
    flash = all_topology[all_topology.topology == "medium_industrial_iot"]
    pd.DataFrame([{"scenario": name, **metrics(g.label.to_numpy(), g.probability.to_numpy(), g.prediction.to_numpy()),
        "threshold": runtime.threshold} for name, g in flash.groupby("scenario_id")]).to_csv(output / "flash_crowd_comparison.csv", index=False)
    external, external_predictions = [], []
    for path in sorted((ROOT / "data/external/processed").glob("*_windows.csv")):
        d = pd.read_csv(path)
        p = runtime.predict_proba_or_action(d[FEATURES]); a = (p >= runtime.threshold).astype(int)
        external.append({"dataset": path.stem, **metrics(d.label.to_numpy(), p, a),
            "threshold": runtime.threshold, "threshold_type": "fixed_transfer_threshold_no_target_labels",
            "input_sha256": sha(path), "validity": "diagnostic feature-compatible transfer; feature meanings differ from controller telemetry"})
        external_predictions.append(pd.DataFrame({"dataset": path.stem, "source_row": np.arange(len(d)), "label": d.label,
            "probability": p, "prediction": a, "threshold": runtime.threshold,
            "threshold_selection_file": "deployment/threshold_selection.json"}))
    if not external:
        raise FileNotFoundError("No prepared external datasets; cannot produce Table 8")
    pd.DataFrame(external).to_csv(output / "external_comparison.csv", index=False)
    pd.concat(external_predictions, ignore_index=True).to_csv(output / "external_predictions.csv", index=False)


def audit_rollback(config, output, runtime):
    from integration.audit_hash_chain import append_hash_chained_jsonl, verify_hash_chained_jsonl
    from sdn import CompletedWindowController
    benchmarks = []
    for count in [50, 200, 800]:
        path = output / "audit_logs" / f"scale_{count}.jsonl"
        for index in range(count):
            start = time.perf_counter_ns()
            append_hash_chained_jsonl(path, {"index": index, "action": "NONE", "seed": config["seed"]})
            benchmarks.append({"target_records": count, "record": index, "append_ms": (time.perf_counter_ns() - start) / 1e6,
                               "bytes_after": path.stat().st_size})
        assert verify_hash_chained_jsonl(path)["valid_embedded_hash_chain"]
    bd = pd.DataFrame(benchmarks)
    bd.to_csv(output / "audit_record_timings.csv", index=False)
    pd.DataFrame([{"records": n, "p50_ms": float(g.append_ms.quantile(.5)), "p99_ms": float(g.append_ms.quantile(.99)),
        "bytes": int(g.bytes_after.max()), "measurement_type": "actual_local_hash_chain_append_no_fsync_no_consensus"}
        for n, g in bd.groupby("target_records")]).to_csv(output / "audit_scalability.csv", index=False)
    source = output / "audit_logs/scale_50.jsonl"
    tampered = output / "audit_logs/tampered_fixture.jsonl"
    tampered.write_text(source.read_text().replace('"action":"NONE"', '"action":"BLOCK"', 1))
    valid_before = verify_hash_chained_jsonl(source)
    append_hash_chained_jsonl(source, {"event": "reopen_and_append"})
    valid_after = verify_hash_chained_jsonl(source)
    truncated = output / "audit_logs/truncated_fixture.jsonl"
    truncated.write_text(source.read_text()[:-10])
    write_json(output / "audit_verification.json", {"valid_before": valid_before, "valid_after_reopen": valid_after,
        "tamper_detected": not verify_hash_chained_jsonl(tampered)["valid_embedded_hash_chain"],
        "partial_trailing_record_detected": not verify_hash_chained_jsonl(truncated)["valid_embedded_hash_chain"],
        "limits": "Complete suffix truncation requires an externally trusted tip; no fsync, concurrency or Go-service consensus test"})
    controller = CompletedWindowController(runtime, output / "audit_logs/rollback.jsonl")
    controller.mode = "shadow"
    controller.shadow_policy = lambda features: "TEST_SHADOW_PROPOSAL"
    features = pd.read_csv(output / "windows.csv")[FEATURES].iloc[0].to_dict()
    before = controller.detect_completed_window(features, "before_rollback")
    start = time.perf_counter_ns()
    event = controller.rollback_to_baseline()
    elapsed = (time.perf_counter_ns() - start) / 1e6
    after = controller.detect_completed_window(features, "after_rollback")
    restored = controller.mode == "baseline_only" and controller.shadow_policy is None and after["shadow_action"] is None
    assert restored and before["prediction"] == after["prediction"]
    write_json(output / "rollback_verification.json", {"before": before, "transition": event, "after": after,
        "baseline_mode_restored": restored, "rollback_ms_including_audit": elapsed,
        "audit_chain_valid": verify_hash_chained_jsonl(controller.audit_path)["valid_embedded_hash_chain"],
        "scope": "actual in-process controller mode transition with injected test shadow callback; no network rule reversal"})


def finish(config, output, started, registry):
    from reviewer_revision.reporting import write_reports
    from reviewer_revision.verify import verify_results
    from reviewer_revision.artifacts import export_estimator_metadata
    export_estimator_metadata(output)
    verification = verify_results(output)
    write_json(output / "verification_report.json", verification)
    old = pd.read_csv(ROOT / "docs/legacy_q1_evaluation_summary_v2.csv")
    new = read_json(output / "temporal_aggregate_metrics.json")
    comparison = old[["mode", "n", "f1", "precision", "recall", "threshold"]].copy()
    comparison["version"] = "legacy_preserved"
    comparison = pd.concat([comparison, pd.DataFrame([{"mode": "forward_chaining_completed_switch_destination_windows", "n": new["n"],
        "f1": new["f1"], "precision": new["precision"], "recall": new["recall"], "version": config["version"]}])], ignore_index=True)
    comparison["comparability"] = "different test sets and aggregation scope; descriptive comparison only"
    comparison.to_csv(output / "old_versus_new.csv", index=False)
    from reviewer_revision.core import preservation_status
    write_json(output / "preservation_verification.json", preservation_status())
    tables = output / "tables"; tables.mkdir()
    table_map = {"2": "temporal_fold_metrics.csv", "3": "topology_comparison.csv", "4": "live_trial_summary_with_ci.csv",
                 "5": "flash_crowd_comparison.csv", "6": "audit_scalability.csv", "7": "rollback_verification.json",
                 "8": "external_comparison.csv", "9": "policy_comparison.csv"}
    for table, name in table_map.items():
        shutil.copyfile(output / name, tables / ("table_" + table + Path(name).suffix))
    elapsed = time.perf_counter() - started
    write_reports(output, config, table_map, elapsed)
    inputs = [ROOT / "configs/canonical_detector.json", ROOT / "configs/threshold_registry.json", ROOT / "configs/reviewer_revision.json"]
    inputs += sorted((ROOT / "data/external/processed").glob("*_windows.csv"))
    sources = [ROOT / "sdn.py", ROOT / "scripts/q1_system_upgrade_v2.py", ROOT / "scripts/run_reviewer_revision.py"]
    sources += sorted((ROOT / "reviewer_revision").glob("*.py"))
    sources += sorted((ROOT / "tests").glob("*.py"))
    sources += [ROOT / "ml/train_sdn_window_model.py", ROOT / "scripts/true_temporal_split.py", ROOT / "requirements-reviewer-lock.txt"]
    manifest = {"version": config["version"], "created_at": now(), "command": " ".join(sys.argv),
        "runtime_seconds": elapsed, "config": config, "registry": registry, "environment": versions(),
        "input_hashes": {str(p.relative_to(ROOT)): sha(p) for p in inputs},
        "source_hashes": {str(p.relative_to(ROOT)): sha(p) for p in sources}, "tables": table_map,
        "excluded_claims": UNSUPPORTED, "outputs": sorted(str(p.relative_to(output)) for p in output.rglob("*") if p.is_file())}
    write_json(output / "experiment_manifest.json", manifest)
    lines = [f"{sha(p)}  {p.relative_to(output).as_posix()}" for p in sorted(output.rglob("*")) if p.is_file() and p.name != "CHECKSUMS.sha256"]
    (output / "CHECKSUMS.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Completed in {elapsed:.1f}s. Verified revised artifacts: {output}", flush=True)


def run(config, output):
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite existing output directory: {output}")
    output.mkdir(parents=True)
    started = time.perf_counter()
    registry = read_json(ROOT / "configs/threshold_registry.json")
    write_json(output / "experiment_configuration.json", config)
    write_json(output / "environment_versions.json", versions())
    config_dir = output / "configs"; config_dir.mkdir()
    for name in ["canonical_detector.json", "threshold_registry.json", "reviewer_revision.json"]:
        shutil.copyfile(ROOT / "configs" / name, config_dir / name)
    runtime, _ = temporal_and_policies(config, output, registry)
    stress(config, output, runtime)
    topology_external(config, output, runtime)
    audit_rollback(config, output, runtime)
    finish(config, output, started, registry)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(ROOT / "configs/reviewer_revision.json"))
    parser.add_argument("--output")
    parser.add_argument("--folds", type=int)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    config = read_json(args.config)
    if args.folds is not None:
        config["fold_count"] = args.folds
    if args.smoke:
        config.update(simulation_runs=8, windows_per_run=12, stress_trials=2, stress_windows=6,
                      bootstrap_replicates=30, graph_forest_trees=12)
    run(config, args.output or ROOT / config["output_directory"])
