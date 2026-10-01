"""Independently recompute summaries from persisted row-level evidence."""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

from reviewer_revision.core import metrics, read_json, rewards, sha
from reviewer_revision.statistics import summarize_policies, trial_summary, confidence_intervals, pairwise_statistics


def read_csv(path):
    return pd.read_csv(path, float_precision="round_trip")


def check_metrics(expected, actual, context):
    for key, value in expected.items():
        if key == "undefined_metrics":
            observed = actual.get(key)
            if pd.isna(observed):
                observed = ""
            assert value == observed, (context, key, value, observed)
        elif value is None:
            assert pd.isna(actual.get(key)), (context, key, actual.get(key))
        elif isinstance(value, (int, float)):
            assert np.isclose(value, actual[key], rtol=1e-10, atol=1e-12), (context, key, value, actual[key])


def verify_results(output, require_model_binaries=True):
    output = Path(output)
    temporal, pp = read_csv(output / "temporal_predictions.csv"), read_csv(output / "policy_predictions.csv")
    assert not temporal.row_id.duplicated().any(), "Duplicated temporal test windows"
    assert pp.groupby("policy").size().nunique() == 1
    scores = ["probability", "threshold", "prediction", "reward"]
    assert np.isfinite(pp[scores].to_numpy()).all(), "Nonfinite inference results"
    summary = read_csv(output / "policy_comparison.csv").set_index("policy")
    recomputed = summarize_policies(pp).set_index("policy")
    checks = 0
    for name, d in pp.groupby("policy"):
        current = recomputed.loc[name]
        check_metrics(metrics(d.label.to_numpy(), d.probability.to_numpy(), d.prediction.to_numpy()), summary.loc[name], name)
        for key in ["policy_agreement_with_baseline", "disagreement_count", "abstention_count", "agreement_with_deployed_model_final_fold_only"]:
            assert np.isclose(current[key], summary.loc[name, key]), (name, key)
        assert json.loads(current.action_distribution) == json.loads(summary.loc[name, "action_distribution"])
        assert np.array_equal(d.reward.to_numpy(), rewards(d.label.to_numpy(), d.prediction.to_numpy()))
        for selection_file, g in d.groupby("threshold_selection_file"):
            selection = read_json(output / selection_file)
            assert np.all(g.threshold == selection["selected_value"])
            model_path = (output / selection_file).parent / "model.joblib"
            if model_path.exists():
                assert selection["model_hash"] == sha(model_path)
            elif require_model_binaries:
                raise AssertionError(f"Missing model artifact: {model_path}")
            expected = g.probability.to_numpy() >= selection["selected_value"]
            if name == "temporal_graph_with_risk_selector":
                registry = read_json(output / "configs/threshold_registry.json")
                expected &= 1 - g.probability.to_numpy() <= registry["policy_action"]["risk_selector_max_benign_probability"]
            assert np.array_equal(expected.astype(int), g.prediction.to_numpy()), name
            checks += 1
    check_metrics(metrics(temporal.label.to_numpy(), temporal.probability.to_numpy(), temporal.prediction.to_numpy()),
                  read_json(output / "temporal_aggregate_metrics.json"), "temporal aggregate")
    folds = read_csv(output / "temporal_fold_metrics.csv").set_index("fold")
    for f, d in temporal.groupby("fold"):
        check_metrics(metrics(d.label.to_numpy(), d.probability.to_numpy(), d.prediction.to_numpy()), folds.loc[f], f)
    definitions = read_csv(output / "temporal_fold_definitions.csv")
    for f, d in definitions.groupby("fold"):
        d = d.set_index("split")
        assert pd.Timestamp(d.loc["train", "end"]) <= pd.Timestamp(d.loc["validation", "start"])
        assert pd.Timestamp(d.loc["validation", "end"]) <= pd.Timestamp(d.loc["test", "start"])
        assert len(temporal[temporal.fold == f]) == d.loc["test", "n"]
    stress = read_csv(output / "stress_predictions.csv")
    trials = read_csv(output / "live_trial_level_results.csv").set_index(["trial", "setting"])
    for (trial, setting), d in stress.groupby(["trial", "setting"]):
        check_metrics(metrics(d.label.to_numpy(), d.probability.to_numpy(), d.prediction.to_numpy()), trials.loc[(trial, setting)], (trial, setting))
        for q in [50, 90, 99]:
            assert np.isclose(np.percentile(d.latency_ms, q), trials.loc[(trial, setting), f"latency_p{q}_ms"])
    for trial, d in stress.groupby("trial"):
        off, on = [d[d.setting == setting].sort_values("row_id") for setting in ["audit_disabled", "audit_enabled"]]
        for col in ["row_id", "label", "probability", "prediction", "threshold", "input_hash", "seed"]:
            assert np.array_equal(off[col].to_numpy(), on[col].to_numpy()), ("Unpaired stress", trial, col)
    saved = read_csv(output / "live_trial_summary_with_ci.csv")
    rebuilt = trial_summary(trials.reset_index())
    pd.testing.assert_frame_equal(saved.sort_index(axis=1), rebuilt.sort_index(axis=1), check_dtype=False, rtol=1e-10, atol=1e-12)
    for predictions, summary_name, group_col in [("topology_predictions.csv", "topology_comparison.csv", "topology"),
                                                ("external_predictions.csv", "external_comparison.csv", "dataset")]:
        source = read_csv(output / predictions)
        summary = read_csv(output / summary_name).set_index(group_col)
        for name, d in source.groupby(group_col):
            check_metrics(metrics(d.label.to_numpy(), d.probability.to_numpy(), d.prediction.to_numpy()), summary.loc[name], name)
    topology = read_csv(output / "topology_predictions.csv")
    flash = read_csv(output / "flash_crowd_comparison.csv").set_index("scenario")
    for scenario, d in topology[topology.topology == "medium_industrial_iot"].groupby("scenario_id"):
        check_metrics(metrics(d.label.to_numpy(), d.probability.to_numpy(), d.prediction.to_numpy()), flash.loc[scenario], scenario)
    # Recreate uncertainty and paired tests from persisted evidence and recorded seeds.
    config = read_json(output / "experiment_configuration.json")
    for filename, regenerated in [
        ("temporal_confidence_intervals.csv", confidence_intervals(temporal, config["bootstrap_seed"], config["bootstrap_replicates"])),
        ("policy_pairwise_statistics.csv", pairwise_statistics(pp, config["bootstrap_seed"], config["bootstrap_replicates"]))]:
        pd.testing.assert_frame_equal(read_csv(output / filename), regenerated, check_dtype=False, rtol=1e-10, atol=1e-12)
    audit_rows = read_csv(output / "audit_record_timings.csv")
    audit_summary = read_csv(output / "audit_scalability.csv").set_index("records")
    for count, d in audit_rows.groupby("target_records"):
        assert np.isclose(d.append_ms.quantile(.5), audit_summary.loc[count, "p50_ms"])
        assert np.isclose(d.append_ms.quantile(.99), audit_summary.loc[count, "p99_ms"])
        assert d.bytes_after.max() == audit_summary.loc[count, "bytes"]
    paired = read_csv(output / "stress_paired_differences.csv").set_index("metric")
    from scipy.stats import t
    for metric in paired.index:
        pair = trials.reset_index().pivot(index="trial", columns="setting", values=metric)
        delta = (pair.audit_enabled - pair.audit_disabled).to_numpy()
        half = t.ppf(.975, len(delta)-1) * delta.std(ddof=1) / np.sqrt(len(delta))
        assert np.isclose(delta.mean(), paired.loc[metric, "audit_on_minus_off_mean"])
        assert np.isclose(delta.mean()-half, paired.loc[metric, "ci_lower"])
        assert np.isclose(delta.mean()+half, paired.loc[metric, "ci_upper"])
    audit = read_json(output / "audit_verification.json")
    assert audit["valid_after_reopen"]["valid_embedded_hash_chain"] and audit["tamper_detected"] and audit["partial_trailing_record_detected"]
    rollback = read_json(output / "rollback_verification.json")
    assert rollback["baseline_mode_restored"] and rollback["audit_chain_valid"]
    return {"passed": True, "policy_model_threshold_checks": checks, "recomputed": [
        "temporal aggregate and folds", "policy metrics/rewards/actions/agreement", "stress metrics and latency quantiles",
        "paired audit inputs and decisions", "stress means/std/median/t-CIs/ranges", "topology", "flash crowd", "external",
        "bootstrap confidence intervals", "paired policy statistics and McNemar", "audit timing summaries", "paired stress intervals"],
        "invalid_metric_policy": "Undefined mathematical metrics remain null/empty with explicit reasons; no silent replacement",
        "temporal_prediction_rows": len(temporal), "policy_prediction_rows": len(pp), "stress_prediction_rows": len(stress)}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    parser.add_argument("--evidence-only", action="store_true",
                        help="Recompute saved metrics when duplicate fold model binaries were omitted from a public evidence bundle")
    args = parser.parse_args()
    print(json.dumps(verify_results(Path(args.output), require_model_binaries=not args.evidence_only), indent=2))
