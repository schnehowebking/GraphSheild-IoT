#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from upgrade_common import ensure_dir  # noqa: E402


def repo_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix().replace("\\", "/")


LEAKY_FIELDS = {
    "label",
    "true_attack",
    "status",
    "detected_api",
    "mitigation_rule_id",
    "mitigation_success",
    "error",
    "result",
    "window_start_ts",
    "window_end_ts",
    "run_id",
    "topology_id",
    "scenario_id",
    "phase",
    "transaction_id",
    "baseline_action",
    "enforced_action",
    "rl_action",
    "safe_action",
    "shadow_action_applied",
    "p_attack",
    "p_attack_raw",
}

LEAKY_SUBSTRINGS = (
    "future",
    "outcome",
    "post_action",
    "post-action",
    "postaction",
    "mitigation",
    "status",
    "detected",
    "result",
    "error",
    "label",
    "attack_target",
    "true_attack",
    "transaction",
    "audit",
)


def is_leaky_column(column: str) -> bool:
    lower = column.strip().lower()
    return lower in LEAKY_FIELDS or any(part in lower for part in LEAKY_SUBSTRINGS)


def safe_auc(metric_fn: Any, y_true: np.ndarray, score: np.ndarray) -> float | None:
    if len(np.unique(y_true)) < 2:
        return None
    return float(metric_fn(y_true, score))


def model_scores(model: Any, x: pd.DataFrame) -> np.ndarray:
    proba = model.predict_proba(x)
    classes = list(getattr(model, "classes_", [0, 1]))
    idx = classes.index(1) if 1 in classes else min(1, proba.shape[1] - 1)
    return proba[:, idx].astype(float)


def metrics_at_threshold(y_true: np.ndarray, score: np.ndarray, threshold: float) -> dict[str, Any]:
    y_pred = (score >= threshold).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    return {
        "threshold": float(threshold),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": safe_auc(roc_auc_score, y_true, score),
        "pr_auc": safe_auc(average_precision_score, y_true, score),
        "brier": float(brier_score_loss(y_true, np.clip(score, 0.0, 1.0))),
        "tn": int(cm[0, 0]),
        "fp": int(cm[0, 1]),
        "fn": int(cm[1, 0]),
        "tp": int(cm[1, 1]),
    }


def choose_threshold(y_true: np.ndarray, score: np.ndarray) -> float:
    candidates = sorted(set(np.round(np.linspace(0.01, 0.99, 99), 4).tolist()) | set(np.round(score, 4).tolist()))
    best_threshold = 0.5
    best_key = (-1.0, -1.0, 1.0)
    for threshold in candidates:
        y_pred = (score >= float(threshold)).astype(int)
        current_f1 = f1_score(y_true, y_pred, zero_division=0)
        current_recall = recall_score(y_true, y_pred, zero_division=0)
        current_fp_rate = float(((y_true == 0) & (y_pred == 1)).sum() / max(1, (y_true == 0).sum()))
        key = (float(current_f1), float(current_recall), -current_fp_rate)
        if key > best_key:
            best_key = key
            best_threshold = float(threshold)
    return best_threshold


def time_bounds(df: pd.DataFrame) -> dict[str, str]:
    return {
        "start": df["window_start_ts"].min().isoformat(),
        "end": df["window_end_ts"].max().isoformat(),
    }


def count_dict(series: pd.Series) -> dict[str, int]:
    return {str(k): int(v) for k, v in series.value_counts().sort_index().items()}


def validate_split(train: pd.DataFrame, validation: pd.DataFrame, test: pd.DataFrame, feature_columns: list[str]) -> None:
    if train.empty or validation.empty or test.empty:
        raise ValueError("train/validation/test split produced an empty partition")
    train_end = train["window_end_ts"].max()
    val_start = validation["window_start_ts"].min()
    val_end = validation["window_end_ts"].max()
    test_start = test["window_start_ts"].min()
    if val_start < train_end:
        raise ValueError("validation begins before train ends")
    if test_start < val_end:
        raise ValueError("test begins before validation ends")
    if train["window_start_ts"].max() >= validation["window_start_ts"].min() and train_end > val_start:
        raise ValueError("train/validation time ranges overlap")
    if validation["window_start_ts"].max() >= test["window_start_ts"].min() and val_end > test_start:
        raise ValueError("validation/test time ranges overlap")
    if test["label"].nunique() < 2:
        raise ValueError("test set has only one class")
    if not feature_columns:
        raise ValueError("no numeric runtime features exist")
    included_leaky = sorted(col for col in feature_columns if is_leaky_column(col))
    if included_leaky:
        raise ValueError(f"leaky fields included in runtime features: {included_leaky}")


def plot_curves(y_true: np.ndarray, score: np.ndarray, roc_path: Path, pr_path: Path) -> None:
    fpr, tpr, _ = roc_curve(y_true, score)
    plt.figure(figsize=(5.2, 4.2), dpi=220)
    plt.plot(fpr, tpr, label="true temporal")
    plt.plot([0, 1], [0, 1], color="0.6", linewidth=1)
    plt.xlabel("False positive rate")
    plt.ylabel("True positive rate")
    plt.title("True Timestamped Temporal ROC")
    plt.tight_layout()
    plt.savefig(roc_path)
    plt.close()

    precision, recall, _ = precision_recall_curve(y_true, score)
    plt.figure(figsize=(5.2, 4.2), dpi=220)
    plt.plot(recall, precision, label="true temporal")
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title("True Timestamped Temporal PR")
    plt.tight_layout()
    plt.savefig(pr_path)
    plt.close()


def run_temporal_split(input_csv: Path, out_dir: Path) -> dict[str, Any]:
    if not input_csv.exists():
        raise FileNotFoundError(input_csv)
    df = pd.read_csv(input_csv)
    if "window_start_ts" not in df.columns:
        raise ValueError("timestamp column is missing: window_start_ts")
    if "window_end_ts" not in df.columns:
        raise ValueError("timestamp column is missing: window_end_ts")
    if "label" not in df.columns:
        raise ValueError("label column is missing")

    df = df.copy()
    df["window_start_ts"] = pd.to_datetime(df["window_start_ts"], utc=True, errors="coerce", format="mixed")
    df["window_end_ts"] = pd.to_datetime(df["window_end_ts"], utc=True, errors="coerce", format="mixed")
    if df["window_start_ts"].isna().any() or df["window_end_ts"].isna().any():
        raise ValueError("timestamps cannot be parsed")
    df["label"] = pd.to_numeric(df["label"], errors="raise").astype(int)
    df = df.sort_values(["window_start_ts", "window_end_ts"]).reset_index(drop=True)

    numeric_columns: list[str] = []
    for column in df.columns:
        if is_leaky_column(column):
            continue
        values = pd.to_numeric(df[column], errors="coerce")
        if values.notna().any():
            numeric_columns.append(column)
            df[column] = values.replace([np.inf, -np.inf], np.nan).fillna(0.0)

    n = len(df)
    train_end = int(n * 0.60)
    validation_end = int(n * 0.80)
    train = df.iloc[:train_end].copy()
    validation = df.iloc[train_end:validation_end].copy()
    test = df.iloc[validation_end:].copy()
    validate_split(train, validation, test, numeric_columns)

    x_train = train[numeric_columns]
    y_train = train["label"].to_numpy(dtype=int)
    x_validation = validation[numeric_columns]
    y_validation = validation["label"].to_numpy(dtype=int)
    x_test = test[numeric_columns]
    y_test = test["label"].to_numpy(dtype=int)

    if len(np.unique(y_train)) < 2:
        raise ValueError("train set has only one class")
    if len(np.unique(y_validation)) < 2:
        raise ValueError("validation set has only one class")

    model = RandomForestClassifier(
        n_estimators=240,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=1,
    )
    model.fit(x_train, y_train)

    validation_score = model_scores(model, x_validation)
    threshold = choose_threshold(y_validation, validation_score)
    test_score = model_scores(model, x_test)
    test_pred = (test_score >= threshold).astype(int)
    out_metrics = metrics_at_threshold(y_test, test_score, threshold)
    out_metrics.update(
        {
            "mode": "true_timestamp_temporal_split",
            "train_n": int(len(train)),
            "validation_n": int(len(validation)),
            "test_n": int(len(test)),
            "train_time_start": train["window_start_ts"].min().isoformat(),
            "train_time_end": train["window_end_ts"].max().isoformat(),
            "validation_time_start": validation["window_start_ts"].min().isoformat(),
            "validation_time_end": validation["window_end_ts"].max().isoformat(),
            "test_time_start": test["window_start_ts"].min().isoformat(),
            "test_time_end": test["window_end_ts"].max().isoformat(),
            "threshold_selected_on": "validation_split_only",
            "leaky_fields_excluded": sorted(LEAKY_FIELDS),
            "feature_columns": numeric_columns,
        }
    )

    ensure_dir(out_dir)
    (out_dir / "metrics.json").write_text(json.dumps(out_metrics, indent=2), encoding="utf-8")
    pd.DataFrame(
        confusion_matrix(y_test, test_pred, labels=[0, 1]),
        index=["true_benign", "true_attack"],
        columns=["pred_benign", "pred_attack"],
    ).to_csv(out_dir / "confusion_matrix.csv")
    pred_df = test[
        ["window_start_ts", "window_end_ts", "run_id", "topology_id", "scenario_id", "phase", "label"]
    ].copy()
    pred_df["y_score"] = test_score
    pred_df["y_pred"] = test_pred
    pred_df["threshold"] = threshold
    pred_df.to_csv(out_dir / "test_predictions.csv", index=False)
    plot_curves(y_test, test_score, out_dir / "roc_curve.png", out_dir / "pr_curve.png")
    (out_dir / "feature_list.json").write_text(
        json.dumps(
            {
                "feature_columns": numeric_columns,
                "leaky_fields_excluded": sorted(LEAKY_FIELDS),
                "threshold_selected_on": "validation_split_only",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    split_profile = {
        "input_csv": repo_path(input_csv),
        "split_name": "controlled_timestamped_temporal_split",
        "split_rule": "earliest 60% train, next 20% validation, latest 20% test after sorting by window_start_ts",
        "train": {"n": int(len(train)), **time_bounds(train), "label_counts": count_dict(train["label"])},
        "validation": {
            "n": int(len(validation)),
            **time_bounds(validation),
            "label_counts": count_dict(validation["label"]),
        },
        "test": {"n": int(len(test)), **time_bounds(test), "label_counts": count_dict(test["label"])},
        "time_ranges_non_overlapping": True,
        "feature_columns": numeric_columns,
    }
    (out_dir / "split_profile.json").write_text(json.dumps(split_profile, indent=2), encoding="utf-8")
    joblib.dump(model, out_dir / "true_temporal_model.joblib")
    return out_metrics


def main() -> int:
    # Keep legacy metric helpers importable for historical artifact tests. New CLI
    # runs only the whole-run canonical pipeline and never rewrites old outputs.
    from reviewer_revision.pipeline import main as revision_main
    revision_main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
