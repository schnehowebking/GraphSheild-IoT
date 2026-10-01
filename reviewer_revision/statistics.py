"""Whole-test-run cluster bootstrap and paired comparisons."""
from __future__ import annotations

import numpy as np
import pandas as pd
from scipy.stats import binomtest, t

from reviewer_revision.core import metrics, rewards

METRIC_NAMES = ["accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc", "fpr", "fnr", "benign_damage", "reward_mean"]


def cluster_draws(records, seed, replicates):
    groups = [g.index.to_numpy() for _, g in records.groupby(["fold", "run_id"], sort=True)]
    if len(groups) < 2:
        raise ValueError("At least two independent test-run clusters required for uncertainty")
    rng = np.random.default_rng(seed)
    for _ in range(replicates):
        yield np.concatenate([groups[i] for i in rng.integers(0, len(groups), len(groups))])


def confidence_intervals(records, seed, replicates):
    records = records.reset_index(drop=True)
    samples = {name: [] for name in METRIC_NAMES}
    for indices in cluster_draws(records, seed, replicates):
        d = records.iloc[indices]
        m = metrics(d.label.to_numpy(), d.probability.to_numpy(), d.prediction.to_numpy())
        for name in samples:
            if m[name] is not None:
                samples[name].append(m[name])
    estimate = metrics(records.label.to_numpy(), records.probability.to_numpy(), records.prediction.to_numpy())
    return pd.DataFrame([{"metric": name, "estimate": estimate[name],
        "ci_lower": float(np.quantile(v, .025)) if v else None,
        "ci_upper": float(np.quantile(v, .975)) if v else None,
        "valid_replicates": len(v), "undefined_replicates": replicates - len(v),
        "bootstrap_seed": seed, "replicates": replicates,
        "method": "percentile whole-test-run cluster bootstrap; shared training treated as fixed",
        "independent_test_clusters": records.groupby(["fold", "run_id"]).ngroups}
        for name, v in samples.items()])


def simple_f1(y, a):
    tp = ((y == 1) & (a == 1)).sum()
    den = (y == 1).sum() + (a == 1).sum()
    return float(2 * tp / den) if den else None


def pairwise_statistics(predictions, seed, replicates):
    base = predictions[predictions.policy == "ml_window_baseline"].sort_values(["fold", "row_id"]).reset_index(drop=True)
    rows = []
    for policy, d in predictions.groupby("policy"):
        if policy == "ml_window_baseline":
            continue
        d = d.sort_values(["fold", "row_id"]).reset_index(drop=True)
        if not d[["fold", "row_id", "label"]].equals(base[["fold", "row_id", "label"]]):
            raise ValueError("Policies did not use the same untouched test windows")
        y, a, b = d.label.to_numpy(), d.prediction.to_numpy(), base.prediction.to_numpy()
        f1diff, rdiff = [], []
        ra, rb = rewards(y, a), rewards(y, b)
        for idx in cluster_draws(base, seed, replicates):
            left, right = simple_f1(y[idx], a[idx]), simple_f1(y[idx], b[idx])
            if left is not None and right is not None:
                f1diff.append(left - right)
            rdiff.append(float((ra[idx] - rb[idx]).mean()))
        b_only = int(((b == y) & (a != y)).sum())
        a_only = int(((a == y) & (b != y)).sum())
        rows.append({"policy": policy, "baseline": "ml_window_baseline", "n": len(y),
            "disagreement_count": int((a != b).sum()), "identical_predictions": bool(np.array_equal(a, b)),
            "identical_probabilities": bool(np.array_equal(d.probability.to_numpy(), base.probability.to_numpy())),
            "max_probability_difference": float(np.abs(d.probability.to_numpy() - base.probability.to_numpy()).max()),
            "f1_difference": simple_f1(y, a) - simple_f1(y, b),
            "f1_diff_ci_lower": float(np.quantile(f1diff, .025)) if f1diff else None,
            "f1_diff_ci_upper": float(np.quantile(f1diff, .975)) if f1diff else None,
            "reward_mean_difference": float((ra - rb).mean()),
            "reward_diff_ci_lower": float(np.quantile(rdiff, .025)), "reward_diff_ci_upper": float(np.quantile(rdiff, .975)),
            "baseline_only_correct": b_only, "policy_only_correct": a_only,
            "mcnemar_exact_p_diagnostic": float(binomtest(a_only, a_only + b_only, .5).pvalue) if a_only + b_only else 1.,
            "mcnemar_caveat": "window independence violated; descriptive diagnostic only, cluster CI is primary",
            "bootstrap_seed": seed, "replicates": replicates, "f1_valid_replicates": len(f1diff)})
    return pd.DataFrame(rows)


def trial_summary(trials):
    names = METRIC_NAMES + ["latency_p50_ms", "latency_p90_ms", "latency_p99_ms", "elapsed_ms"]
    rows = []
    for (topology, setting), group in trials.groupby(["topology", "setting"], sort=True):
        for metric in names:
            values = group[metric].dropna().to_numpy(dtype=float)
            n = len(values)
            if n == 0:
                rows.append({"topology": topology, "setting": setting, "metric": metric, "n": 0, "undefined_trials": len(group)})
                continue
            sd = float(values.std(ddof=1)) if n > 1 else None
            half = float(t.ppf(.975, n - 1) * sd / np.sqrt(n)) if n > 1 else None
            mean = float(values.mean())
            rows.append({"topology": topology, "setting": setting, "metric": metric, "n": n,
                "mean": mean, "std": sd, "median": float(np.median(values)), "minimum": float(values.min()), "maximum": float(values.max()),
                "ci_lower": mean - half if half is not None else None, "ci_upper": mean + half if half is not None else None,
                "undefined_trials": len(group) - n, "method": "Student-t 95% CI across independent run seeds",
                "measurement_type": "controlled simulation inputs; measured in-process sdn.CompletedWindowController execution"})
    return pd.DataFrame(rows)


def summarize_policies(predictions):
    base = predictions[predictions.policy == "ml_window_baseline"].set_index(["fold", "row_id"])
    rows = []
    for policy, d in predictions.groupby("policy", sort=True):
        d = d.set_index(["fold", "row_id"]).sort_index()
        b = base.loc[d.index]
        m = metrics(d.label.to_numpy(), d.probability.to_numpy(), d.prediction.to_numpy())
        rows.append({"policy": policy, **m, "policy_agreement_with_baseline": float((d.prediction == b.prediction).mean()),
            "disagreement_count": int((d.prediction != b.prediction).sum()),
            "agreement_with_deployed_model_final_fold_only": float((d.loc[d.index.get_level_values("fold") == predictions.fold.max(), "prediction"] == b.loc[b.index.get_level_values("fold") == predictions.fold.max(), "prediction"]).mean()),
            "abstention_count": int(d.abstained.sum()), "action_distribution": d.action.value_counts().to_json(),
            "agreement_scope": "corresponding fold canonical model; only last fold model is deployment artifact",
            "deployment_status": "canonical_baseline" if policy == "ml_window_baseline" else "offline_shadow_only"})
    return pd.DataFrame(rows)
