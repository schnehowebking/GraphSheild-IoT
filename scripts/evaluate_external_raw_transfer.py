#!/usr/bin/env python3
"""Apply the frozen canonical detector to raw-derived external windows.

This is a fixed-threshold transfer diagnostic. External labels are never used
for fitting, preprocessing, threshold selection, or prediction.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score


ROOT = Path(__file__).resolve().parents[1]
SEED = 20260928
BOOTSTRAPS = 2000


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def confusion(y: np.ndarray, pred: np.ndarray) -> tuple[int, int, int, int]:
    tn = int(((y == 0) & (pred == 0)).sum())
    fp = int(((y == 0) & (pred == 1)).sum())
    fn = int(((y == 1) & (pred == 0)).sum())
    tp = int(((y == 1) & (pred == 1)).sum())
    return tn, fp, fn, tp


def from_counts(tn: int, fp: int, fn: int, tp: int) -> dict[str, float]:
    div = lambda a, b: float(a / b) if b else 0.0
    precision, recall = div(tp, tp + fp), div(tp, tp + fn)
    return {
        "accuracy": div(tn + tp, tn + fp + fn + tp),
        "precision": precision,
        "recall": recall,
        "f1": div(2 * precision * recall, precision + recall),
        "fpr": div(fp, fp + tn), "fnr": div(fn, fn + tp),
        "benign_damage": div(fp, fp + tn),
    }


def evaluate(frame: pd.DataFrame, label_col: str, eligible: np.ndarray) -> tuple[dict, list[dict]]:
    subset = frame.loc[eligible].copy()
    y = subset[label_col].to_numpy(dtype=int)
    pred = subset["prediction"].to_numpy(dtype=int)
    proba = subset["probability"].to_numpy(dtype=float)
    tn, fp, fn, tp = confusion(y, pred)
    metrics = {"n": len(y), "tn": tn, "fp": fp, "fn": fn, "tp": tp, **from_counts(tn, fp, fn, tp)}
    metrics["roc_auc"] = float(roc_auc_score(y, proba)) if len(np.unique(y)) == 2 else None
    metrics["pr_auc"] = float(average_precision_score(y, proba)) if len(np.unique(y)) == 2 else None

    blocks = []
    for _, group in subset.groupby("scenario_id", sort=True):
        blocks.append(confusion(group[label_col].to_numpy(dtype=int), group["prediction"].to_numpy(dtype=int)))
    rng = np.random.default_rng(SEED)
    draws = {name: [] for name in ["accuracy", "precision", "recall", "f1", "fpr", "fnr", "benign_damage"]}
    array = np.asarray(blocks, dtype=np.int64)
    for _ in range(BOOTSTRAPS):
        sampled = array[rng.integers(0, len(array), size=len(array))].sum(axis=0)
        values = from_counts(*map(int, sampled))
        for name in draws:
            draws[name].append(values[name])
    intervals = [
        {"metric": name, "lower_95": float(np.quantile(values, .025)),
         "upper_95": float(np.quantile(values, .975)), "method": "scenario-block bootstrap",
         "bootstrap_seed": SEED, "bootstrap_replicates": BOOTSTRAPS, "blocks": len(blocks)}
        for name, values in draws.items()
    ]
    return metrics, intervals


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--processed-root", default="results/external_raw_processing_v1")
    parser.add_argument("--deployment", default="results/reviewer_revision_v1/deployment")
    parser.add_argument("--output", default="results/external_raw_transfer_v1")
    args = parser.parse_args()
    processed = (ROOT / args.processed_root).resolve()
    deployment = (ROOT / args.deployment).resolve()
    output = (ROOT / args.output).resolve()
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite existing output: {output}")
    output.mkdir(parents=True)

    schema = json.loads((deployment / "feature_schema.json").read_text(encoding="utf-8"))
    features = schema["features"] if isinstance(schema["features"][0], str) else [x["name"] for x in schema["features"]]
    selection = json.loads((deployment / "threshold_selection.json").read_text(encoding="utf-8"))
    threshold = float(selection["selected_value"])
    model_path = deployment / "model.joblib"
    if sha256(model_path) != selection["model_hash"]:
        raise AssertionError("Deployment model hash does not match threshold selection")
    model = joblib.load(model_path)

    inputs = {
        "CIC-DDoS2019": processed / "cicddos2019/windows/cicddos2019_windows.csv",
        "IoT-23": processed / "iot23/windows/iot23_windows.csv",
        "TON_IoT": processed / "toniot_final/windows/toniot_windows.csv",
    }
    all_predictions, summaries, cis = [], [], []
    for dataset, path in inputs.items():
        if not path.exists():
            raise FileNotFoundError(path)
        frame = pd.read_csv(path)
        x = frame[features].apply(pd.to_numeric, errors="raise")
        x["src_ip_entropy"] = x["src_ip_entropy"].clip(lower=0.0)
        values = x.to_numpy(dtype=float)
        if not np.isfinite(values).all():
            raise ValueError(f"Nonfinite feature in {dataset}")
        proba = np.asarray(model.predict_proba(x)[:, list(model.classes_).index(1)], dtype=float)
        pred = (proba >= threshold).astype(int)
        saved = frame[["scenario_id", "window_start_epoch", "label", "target_label", "target_eligible"]].copy()
        saved.insert(0, "dataset", dataset)
        saved["probability"] = proba
        saved["prediction"] = pred
        all_predictions.append(saved)

        modes = [("binary", "label", np.ones(len(frame), dtype=bool))]
        if dataset == "IoT-23":
            modes.append(("ddos_only", "target_label", frame["target_eligible"].eq(1).to_numpy()))
        elif dataset == "TON_IoT":
            modes.append(("ddos_dos", "target_label", frame["target_eligible"].eq(1).to_numpy()))
        for mode, label_col, eligible in modes:
            metric, intervals = evaluate(saved, label_col, eligible)
            summaries.append({
                "dataset": dataset, "label_mode": mode,
                "evaluation_mode": "fixed_transfer_threshold_no_target_labels",
                "measurement_type": "offline_flow_derived_diagnostic",
                "threshold": threshold, "threshold_source": "internal_validation_only",
                **metric,
            })
            for interval in intervals:
                cis.append({"dataset": dataset, "label_mode": mode, **interval})

    predictions = pd.concat(all_predictions, ignore_index=True)
    predictions.to_csv(output / "external_predictions.csv", index=False)
    pd.DataFrame(summaries).to_csv(output / "external_metrics.csv", index=False)
    pd.DataFrame(cis).to_csv(output / "external_confidence_intervals.csv", index=False)
    provenance = {
        "evaluation_mode": "fixed_transfer_threshold_no_target_labels",
        "measurement_type": "offline_flow_derived_diagnostic",
        "canonical_controller_equivalence_claimed": False,
        "reason": "Flow-derived feature proxies differ from controller event and flow-table semantics.",
        "feature_order": features, "model_sha256": sha256(model_path),
        "threshold": threshold, "threshold_selection": selection,
        "bootstrap_seed": SEED, "bootstrap_replicates": BOOTSTRAPS,
        "input_sha256": {name: sha256(path) for name, path in inputs.items()},
    }
    (output / "evaluation_manifest.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    (output / "METHODOLOGY.md").write_text(
        "# External fixed-transfer diagnostic\n\n"
        "The frozen canonical RandomForest and its internal-validation operating threshold are applied "
        "without fitting or selecting anything on external labels. Labels are read only after probabilities "
        "and actions are produced. Confidence intervals resample complete scenario blocks with a fixed seed. "
        "These public flow-derived features are conditional proxies and are not claimed equivalent to live "
        "SDN-controller telemetry; therefore these values are diagnostic evidence, not canonical zero-shot "
        "deployment performance. DDoS/DoS modes exclude windows containing other attack families only after "
        "label-free window construction.\n", encoding="utf-8")
    generated = sorted(p for p in output.iterdir() if p.name != "CHECKSUMS.sha256")
    (output / "CHECKSUMS.sha256").write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in generated), encoding="utf-8")
    print(pd.DataFrame(summaries).to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
