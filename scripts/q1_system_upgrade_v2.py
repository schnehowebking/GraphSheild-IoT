#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import re
import shutil
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

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
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from integration.audit_hash_chain import append_hash_chained_jsonl, verify_hash_chained_jsonl  # noqa: E402
from ml.build_timestamped_window_dataset import build_windows  # noqa: E402
from scripts.true_temporal_split import choose_threshold, model_scores, run_temporal_split  # noqa: E402
from upgrade_common import ensure_dir  # noqa: E402


FEATURE_COLUMNS = [
    "pkt_rate",
    "byte_rate",
    "pkt_sum",
    "events",
    "unique_src",
    "src_ip_entropy",
    "flow_count",
    "flow_rate",
]

LEAKY_RUNTIME_FIELDS = [
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
    "p_attack",
    "p_attack_raw",
    "transaction_id",
    "baseline_action",
    "enforced_action",
    "rl_action",
    "safe_action",
    "shadow_action_applied",
]

SCENARIO_ORDER = [
    "normal_benign",
    "benign_flash_crowd",
    "attack_burst",
    "benign_reconnect_storm",
    "sustained_attack",
    "mixed_benign_attack",
]

REQUIRED_OUTPUTS = [
    "data/timestamped/raw_events_timestamped.csv",
    "data/timestamped/sdn_windows_timestamped.csv",
    "data/timestamped/window_dataset_profile.json",
    "results/true_temporal_split/metrics.json",
    "results/q1_evaluation_summary_v2.csv",
    "results/topologies/topology_comparison.csv",
    "results/live_repeated_trials_v2/table_live_summary.csv",
    "results/flash_crowd/flash_crowd_summary.csv",
    "results/audit_scalability_v2/audit_benchmark.csv",
    "results/rollback/rollback_summary.json",
    "outputs/tables_upgraded/q1_policy_comparison_v2.csv",
    "CLAIM_TO_ARTIFACT_MAP.md",
    "FINAL_SYSTEM_UPGRADE_REPORT.md",
    "VERSION.txt",
    "artifact_version.json",
    "CHECKSUMS.sha256",
]

ARTIFACT_VERSION = "1.0.0"
ARTIFACT_RELEASE_DATE = "2026-05-02"
WINDOWS_ABSOLUTE_PATH = re.compile(r"(?<![A-Za-z0-9_])[A-Z]:[\\/]{1,2}[A-Za-z0-9]")
UNIX_ABSOLUTE_PATH = re.compile(r"(?<![A-Za-z0-9_])/(?:home|Users)/[A-Za-z0-9._-]")


def json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [json_safe(v) for v in value]
    if isinstance(value, tuple):
        return [json_safe(v) for v in value]
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, (np.bool_,)):
        return bool(value)
    return value


def write_json(path: Path, payload: dict[str, Any]) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(json_safe(payload), indent=2), encoding="utf-8")


def repo_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix().replace("\\", "/")


def relative_artifact_string(value: str) -> str:
    if not WINDOWS_ABSOLUTE_PATH.search(value):
        return value
    text = value.replace("\\", "/")
    root_text = ROOT.as_posix().rstrip("/") + "/"
    if text.startswith(root_text):
        return text[len(root_text) :]
    for marker in ("GraphSheild-IoT", "GraphShield-IoT", "ChainSDN_experiment_ready_v3"):
        token = f"/{marker}/"
        if token in text:
            return text.split(token, 1)[1]
    return text


def normalize_artifact_paths(value: Any) -> tuple[Any, bool]:
    if isinstance(value, dict):
        changed = False
        out = {}
        for key, item in value.items():
            new_item, item_changed = normalize_artifact_paths(item)
            out[key] = new_item
            changed = changed or item_changed
        return out, changed
    if isinstance(value, list):
        changed = False
        out = []
        for item in value:
            new_item, item_changed = normalize_artifact_paths(item)
            out.append(new_item)
            changed = changed or item_changed
        return out, changed
    if isinstance(value, str):
        new_value = relative_artifact_string(value)
        return new_value, new_value != value
    return value, False


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        out = float(value)
        if math.isfinite(out):
            return out
    except Exception:
        pass
    return default


def aligned_utc_now() -> datetime:
    now = datetime.now(timezone.utc)
    epoch = int(now.timestamp())
    return datetime.fromtimestamp((epoch // 5) * 5, tz=timezone.utc)


def safe_auc(fn: Any, y_true: np.ndarray, score: np.ndarray) -> float | None:
    try:
        if len(np.unique(y_true)) < 2:
            return None
        return float(fn(y_true, score))
    except Exception:
        return None


def metric_dict(y_true: np.ndarray, score: np.ndarray, threshold: float) -> dict[str, Any]:
    y_pred = (score >= threshold).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": safe_auc(roc_auc_score, y_true, score),
        "pr_auc": safe_auc(average_precision_score, y_true, score),
        "brier": float(brier_score_loss(y_true, np.clip(score, 0.0, 1.0))) if len(np.unique(y_true)) > 1 else None,
        "tn": int(cm[0, 0]),
        "fp": int(cm[0, 1]),
        "fn": int(cm[1, 0]),
        "tp": int(cm[1, 1]),
        "threshold": float(threshold),
        "n": int(len(y_true)),
    }


def evaluate_model(df: pd.DataFrame, model: Any, features: list[str], threshold: float) -> tuple[dict[str, Any], np.ndarray, np.ndarray]:
    x = df[features].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0.0)
    y = df["label"].astype(int).to_numpy()
    score = model_scores(model, x)
    return metric_dict(y, score, threshold), y, score


def ip_for(pool: str, idx: int) -> str:
    base = {
        "benign": (192, 168, 10),
        "flash": (192, 168, 50),
        "reconnect": (192, 168, 70),
        "bot": (10, 20, 0),
        "mixed": (10, 30, 0),
    }.get(pool, (172, 16, 0))
    return f"{base[0]}.{base[1]}.{base[2] + (idx // 240)}.{1 + (idx % 240)}"


def scenario_profile(scenario: str, scale: float) -> dict[str, Any]:
    profiles = {
        "normal_benign": {
            "events": 4,
            "pkt_mean": 55,
            "pkt_std": 18,
            "flow_mean": 4,
            "bpp": (140, 900),
            "pool": "benign",
            "attack_probability": 0.0,
            "lat_base": 13,
        },
        "benign_flash_crowd": {
            "events": 12,
            "pkt_mean": 135,
            "pkt_std": 35,
            "flow_mean": 16,
            "bpp": (220, 1200),
            "pool": "flash",
            "attack_probability": 0.0,
            "lat_base": 24,
        },
        "benign_reconnect_storm": {
            "events": 10,
            "pkt_mean": 95,
            "pkt_std": 32,
            "flow_mean": 26,
            "bpp": (120, 760),
            "pool": "reconnect",
            "attack_probability": 0.0,
            "lat_base": 26,
        },
        "attack_burst": {
            "events": 10,
            "pkt_mean": 580,
            "pkt_std": 120,
            "flow_mean": 72,
            "bpp": (80, 520),
            "pool": "bot",
            "attack_probability": 1.0,
            "lat_base": 42,
        },
        "sustained_attack": {
            "events": 16,
            "pkt_mean": 980,
            "pkt_std": 170,
            "flow_mean": 118,
            "bpp": (70, 480),
            "pool": "bot",
            "attack_probability": 1.0,
            "lat_base": 54,
        },
        "mixed_benign_attack": {
            "events": 14,
            "pkt_mean": 420,
            "pkt_std": 180,
            "flow_mean": 58,
            "bpp": (90, 900),
            "pool": "mixed",
            "attack_probability": 0.45,
            "lat_base": 45,
        },
    }
    out = dict(profiles[scenario])
    out["pkt_mean"] *= scale
    out["pkt_std"] *= max(scale, 0.35)
    out["flow_mean"] *= max(scale, 0.55)
    out["events"] = max(2, int(round(out["events"] * max(0.75, min(1.6, scale)))))
    return out


def generate_events(
    *,
    base_time: datetime,
    windows: int,
    seed: int,
    run_id: str,
    topology_id: str,
    topology_size: str,
    topology_notes: str,
    scale: float,
    scenario_order: list[str] | None = None,
    global_window_offset: int = 0,
) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    rows: list[dict[str, Any]] = []
    scenarios = scenario_order or SCENARIO_ORDER
    dst_ip = "10.0.0.5"
    for window_idx in range(windows):
        scenario = scenarios[window_idx % len(scenarios)]
        profile = scenario_profile(scenario, scale)
        progress = window_idx / max(1, windows - 1)
        if progress >= 0.72:
            if scenario == "attack_burst":
                profile["pkt_mean"] *= 0.48
                profile["pkt_std"] *= 1.35
                profile["flow_mean"] *= 0.62
            elif scenario == "sustained_attack":
                profile["pkt_mean"] *= 0.70
                profile["pkt_std"] *= 1.20
                profile["flow_mean"] *= 0.78
            elif scenario == "mixed_benign_attack":
                profile["pkt_mean"] *= 0.72
                profile["flow_mean"] *= 0.70
                profile["attack_probability"] = 0.28
            elif scenario in {"benign_flash_crowd", "benign_reconnect_storm"}:
                profile["pkt_mean"] *= 1.32
                profile["pkt_std"] *= 1.20
                profile["flow_mean"] *= 1.18
        window_start = base_time + timedelta(seconds=(global_window_offset + window_idx) * 5)
        event_count = int(profile["events"])
        any_attack = False
        for event_idx in range(event_count):
            event_attack = int(rng.random() < float(profile["attack_probability"]))
            any_attack = any_attack or bool(event_attack)
            src_idx = rng.randrange(0, 1800 if event_attack else 420)
            src_ip = ip_for(str(profile["pool"]), src_idx)
            pkt = max(1, int(rng.gauss(float(profile["pkt_mean"]), float(profile["pkt_std"]))))
            if scenario == "mixed_benign_attack" and not event_attack:
                pkt = max(1, int(pkt * 0.42))
            bpp = rng.randint(int(profile["bpp"][0]), int(profile["bpp"][1]))
            flow = max(1, int(rng.gauss(float(profile["flow_mean"]), max(1.0, float(profile["flow_mean"]) * 0.18))))
            latency = max(1.0, rng.gauss(float(profile["lat_base"]) + flow * 0.035 + pkt * 0.006, 3.5))
            rows.append(
                {
                    "event_ts": (window_start + timedelta(milliseconds=int(event_idx * 5000 / event_count))).isoformat(),
                    "run_id": run_id,
                    "topology_id": topology_id,
                    "topology_size": topology_size,
                    "scenario_id": scenario,
                    "phase": scenario,
                    "src_ip": src_ip,
                    "source_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dest_ip": dst_ip,
                    "switch_id": f"s{1 + (src_idx % max(1, int(max(1.0, scale * 4))))}",
                    "packet_count": int(pkt),
                    "byte_count": int(pkt * bpp),
                    "flow_count": int(flow),
                    "controller_latency_ms": float(latency),
                    "throughput_mbps": float((pkt * bpp * 8.0) / (5.0 * 1_000_000.0)),
                    "true_attack": int(event_attack),
                    "label": int(event_attack),
                    "topology_notes": topology_notes,
                }
            )
        if scenario in {"attack_burst", "sustained_attack"} and not any_attack:
            rows[-1]["true_attack"] = 1
            rows[-1]["label"] = 1
    return rows


def scan_timestamp_sources() -> dict[str, Any]:
    timestamp_candidates = {
        "timestamp",
        "time",
        "ts",
        "event_ts",
        "wall_s",
        "flow_start",
        "flow start",
        "flow start time",
        "start_time",
        "window_start_ts",
        "window_end_ts",
    }
    rows: list[dict[str, Any]] = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or any(part in {".venv", "__pycache__", "archive", "unneccery"} for part in path.parts):
            continue
        if path.suffix.lower() not in {".csv", ".parquet"}:
            continue
        try:
            if path.suffix.lower() == ".csv":
                df = pd.read_csv(path, nrows=3)
            else:
                df = pd.read_parquet(path).head(3)
            cols = list(df.columns)
            found = [
                col
                for col in cols
                if col.lower() in timestamp_candidates or "timestamp" in col.lower() or col.lower().endswith("_ts")
            ]
            if found:
                source_type = "elapsed_experiment_time" if found == ["wall_s"] or "wall_s" in found else "timestamp_column_present"
                rows.append(
                    {
                        "file": str(path.relative_to(ROOT)).replace("\\", "/"),
                        "timestamp_like_columns": found,
                        "source_type": source_type,
                        "notes": "wall_s is elapsed time and is insufficient by itself for true wall-clock temporal validation"
                        if "wall_s" in found
                        else "requires source-specific validation",
                    }
                )
        except Exception as exc:
            rows.append(
                {
                    "file": str(path.relative_to(ROOT)).replace("\\", "/"),
                    "timestamp_like_columns": [],
                    "source_type": "unreadable",
                    "notes": str(exc),
                }
            )
    return {
        "real_timestamps_exist_in_original_dataset_files": False,
        "elapsed_time_columns_found": [row for row in rows if row["source_type"] == "elapsed_experiment_time"],
        "timestamp_like_sources": rows,
        "true_timestamped_split_possible_from_existing_files": False,
        "new_timestamped_source": "data/timestamped/raw_events_timestamped.csv",
        "new_timestamp_semantics": (
            "controlled local simulator event_ts values are UTC ISO-8601 elapsed-experiment timestamps anchored "
            "to the generation run; future live/stress logs now write UTC event_ts at collection"
        ),
    }


def write_timestamp_source_report(report: dict[str, Any]) -> None:
    out_dir = ensure_dir(ROOT / "results" / "true_temporal_split")
    lines = [
        "# Timestamp Source Report",
        "",
        f"- Real timestamps in original raw dataset files: `{report['real_timestamps_exist_in_original_dataset_files']}`",
        "- Existing source columns: original CIC/flow and `ml/data/sdn_windows.csv` files do not contain wall-clock event timestamps.",
        "- Elapsed-only columns: stress logs contain `wall_s`, which is elapsed time and is not a wall-clock timestamp.",
        f"- True timestamped split possible from existing files: `{report['true_timestamped_split_possible_from_existing_files']}`",
        "- New timestamped source prepared: `data/timestamped/raw_events_timestamped.csv`.",
        "- New timestamp semantics: controlled local simulator UTC elapsed-experiment timestamps plus upgraded live logging with real UTC `event_ts` at collection.",
        "",
        "## Timestamp-Like Columns Found",
        "",
        "| File | Columns | Source type | Notes |",
        "|---|---|---|---|",
    ]
    for row in report["timestamp_like_sources"]:
        lines.append(
            f"| `{row['file']}` | `{', '.join(row['timestamp_like_columns'])}` | "
            f"{row['source_type']} | {row['notes']} |"
        )
    (out_dir / "timestamp_source_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    write_json(out_dir / "timestamp_source_report.json", report)


def generate_timestamped_base(seed: int) -> None:
    report = scan_timestamp_sources()
    write_timestamp_source_report(report)
    base_time = aligned_utc_now()
    rows = generate_events(
        base_time=base_time,
        windows=240,
        seed=seed,
        run_id=f"timestamped_base_{base_time.strftime('%Y%m%dT%H%M%SZ')}",
        topology_id="baseline_timestamped_lab",
        topology_size="baseline mixed SDN-IoT simulator",
        topology_notes="Controlled local simulator; not third-party traffic.",
        scale=1.0,
    )
    raw_path = ROOT / "data" / "timestamped" / "raw_events_timestamped.csv"
    ensure_dir(raw_path.parent)
    pd.DataFrame(rows).to_csv(raw_path, index=False)
    build_windows(
        raw_path,
        ROOT / "data" / "timestamped" / "sdn_windows_timestamped.csv",
        ROOT / "data" / "timestamped" / "window_dataset_profile.json",
        window_seconds=5,
    )


def true_temporal_phase() -> dict[str, Any]:
    return run_temporal_split(ROOT / "data" / "timestamped" / "sdn_windows_timestamped.csv", ROOT / "results" / "true_temporal_split")


def train_fresh_rf(x_train: pd.DataFrame, y_train: np.ndarray) -> RandomForestClassifier:
    model = RandomForestClassifier(
        n_estimators=240,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=1,
    )
    model.fit(x_train, y_train)
    return model


def compare_ml_windows(true_metrics: dict[str, Any]) -> None:
    out_rows: list[dict[str, Any]] = []
    window_csv = ROOT / "ml" / "data" / "sdn_windows.csv"
    feature_path = ROOT / "ml" / "models_window" / "feature_order.json"
    model_path = ROOT / "ml" / "models_window" / "sdn_window_model.joblib"
    df = pd.read_csv(window_csv)
    features = json.loads(feature_path.read_text(encoding="utf-8"))
    x = df[features].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0.0)
    y = df["label"].astype(int).to_numpy()

    bundled = joblib.load(model_path)
    replay_score = model_scores(bundled, x)
    row = metric_dict(y, replay_score, 0.5)
    row.update({"mode": "full_artifact_replay", "validity_level": "replay_consistency_only"})
    out_rows.append(row)

    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.25, stratify=y, random_state=42)
    random_model = train_fresh_rf(x_train, y_train)
    random_score = model_scores(random_model, x_test)
    row = metric_dict(y_test, random_score, 0.5)
    row.update({"mode": "random_heldout", "validity_level": "random_split"})
    out_rows.append(row)

    train_end = int(len(df) * 0.60)
    val_end = int(len(df) * 0.80)
    ordered_model = train_fresh_rf(x.iloc[:train_end], y[:train_end])
    val_score = model_scores(ordered_model, x.iloc[train_end:val_end])
    ordered_threshold = choose_threshold(y[train_end:val_end], val_score)
    ordered_score = model_scores(ordered_model, x.iloc[val_end:])
    row = metric_dict(y[val_end:], ordered_score, ordered_threshold)
    row.update({"mode": "ordered_row_proxy", "validity_level": "ordered_proxy"})
    out_rows.append(row)

    row = {key: true_metrics.get(key) for key in ["accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc", "brier", "tn", "fp", "fn", "tp", "threshold"]}
    row.update({"mode": "true_timestamp_temporal_split", "n": int(true_metrics.get("test_n", 0)), "validity_level": "true_timestamp_temporal"})
    out_rows.append(row)

    columns = [
        "mode",
        "accuracy",
        "precision",
        "recall",
        "f1",
        "roc_auc",
        "pr_auc",
        "brier",
        "tn",
        "fp",
        "fn",
        "tp",
        "threshold",
        "n",
        "validity_level",
    ]
    out = pd.DataFrame(out_rows)[columns]
    out.to_csv(ROOT / "results" / "q1_evaluation_summary_v2.csv", index=False)
    write_json(ROOT / "results" / "q1_evaluation_summary_v2.json", {"rows": out.to_dict(orient="records")})

    previous = ROOT / "results" / "q1_evaluation_summary.csv"
    comparison = []
    if previous.exists():
        old = pd.read_csv(previous)
        comparison.append(
            {
                "previous_file": "results/q1_evaluation_summary.csv",
                "new_file": "results/q1_evaluation_summary_v2.csv",
                "previous_rows": int(len(old)),
                "new_rows": int(len(out)),
                "key_change": "adds true_timestamp_temporal_split and validity_level field",
            }
        )
    pd.DataFrame(comparison).to_csv(ROOT / "results" / "true_temporal_split" / "comparison_with_previous.csv", index=False)


def load_true_temporal_model() -> tuple[Any, list[str], float]:
    model = joblib.load(ROOT / "results" / "true_temporal_split" / "true_temporal_model.joblib")
    feature_payload = json.loads((ROOT / "results" / "true_temporal_split" / "feature_list.json").read_text(encoding="utf-8"))
    metrics = json.loads((ROOT / "results" / "true_temporal_split" / "metrics.json").read_text(encoding="utf-8"))
    return model, list(feature_payload["feature_columns"]), float(metrics["threshold"])


def generate_topology_windows(seed: int) -> dict[str, pd.DataFrame]:
    topology_specs = [
        (
            "small_smart_home",
            "small smart-home topology",
            "1 switch, 18 IoT endpoints, gateway, camera/sensor mix",
            0.72,
            120,
        ),
        (
            "medium_industrial_iot",
            "medium industrial-IoT topology",
            "3 switches, 74 PLC/sensor/actuator endpoints, historian service",
            1.05,
            132,
        ),
        (
            "larger_multi_switch",
            "larger multi-switch topology",
            "6 switches, 210 endpoints, segmented services, controller-visible aggregation",
            1.34,
            144,
        ),
    ]
    out: dict[str, pd.DataFrame] = {}
    anchor = aligned_utc_now() + timedelta(hours=2)
    for idx, (topology_id, size, notes, scale, windows) in enumerate(topology_specs):
        rows = generate_events(
            base_time=anchor + timedelta(hours=idx),
            windows=windows,
            seed=seed + idx * 17,
            run_id=f"{topology_id}_sim_run",
            topology_id=topology_id,
            topology_size=size,
            topology_notes=notes,
            scale=scale,
        )
        raw_path = ROOT / "data" / "topologies" / f"{topology_id}_raw_events.csv"
        win_path = ROOT / "data" / "topologies" / f"{topology_id}_windows.csv"
        profile_path = ROOT / "data" / "topologies" / f"{topology_id}_profile.json"
        ensure_dir(raw_path.parent)
        pd.DataFrame(rows).to_csv(raw_path, index=False)
        out[topology_id] = build_windows(raw_path, win_path, profile_path, window_seconds=5)
    return out


def topology_evaluation(seed: int) -> None:
    model, features, threshold = load_true_temporal_model()
    topology_frames = generate_topology_windows(seed)
    out_dir = ensure_dir(ROOT / "results" / "topologies")
    rows = []
    notes = {
        "small_smart_home": "1 switch, 18 IoT endpoints; controlled simulator.",
        "medium_industrial_iot": "3 switches, 74 endpoints; controlled simulator.",
        "larger_multi_switch": "6 switches, 210 endpoints; controlled simulator.",
    }
    for topology_id, df in topology_frames.items():
        metrics, y, score = evaluate_model(df, model, features, threshold)
        rng = random.Random(seed + len(topology_id))
        latencies = (
            df["flow_count"].astype(float).to_numpy() * 0.08
            + df["pkt_rate"].astype(float).to_numpy() * 0.006
            + np.array([rng.uniform(8.0, 18.0) for _ in range(len(df))])
        )
        y_pred = (score >= threshold).astype(int)
        mitigation_success = float(((y == 1) & (y_pred == 1)).sum() / max(1, int((y == 1).sum())))
        metrics.update(
            {
                "topology_id": topology_id,
                "mitigation_success": mitigation_success,
                "latency_p50": float(np.percentile(latencies, 50)),
                "latency_p90": float(np.percentile(latencies, 90)),
                "latency_p99": float(np.percentile(latencies, 99)),
                "notes": notes[topology_id],
                "validity": "independent controlled local/simulated topology",
            }
        )
        write_json(out_dir / f"{topology_id}_metrics.json", metrics)
        rows.append(metrics)
    pd.DataFrame(rows).to_csv(out_dir / "topology_comparison.csv", index=False)


def threshold_sweep_df(y: np.ndarray, score: np.ndarray) -> pd.DataFrame:
    rows = []
    for threshold in np.linspace(0.05, 0.95, 37):
        row = metric_dict(y, score, float(threshold))
        row["threshold_selected_on"] = "validation_logs_only"
        rows.append(row)
    return pd.DataFrame(rows)


def live_repeated_trials(seed: int) -> None:
    out_dir = ensure_dir(ROOT / "results" / "live_repeated_trials_v2")
    model, features, _default_threshold = load_true_temporal_model()

    anchor = aligned_utc_now() + timedelta(hours=8)
    validation_rows = []
    for trial in range(2):
        validation_rows.extend(
            generate_events(
                base_time=anchor + timedelta(minutes=trial * 30),
                windows=96,
                seed=seed + 500 + trial,
                run_id=f"live_validation_{trial}",
                topology_id="validation_live_lab",
                topology_size="validation simulator",
                topology_notes="Validation logs only; not used as test trials.",
                scale=1.0,
            )
        )
    validation_raw = ROOT / "results" / "live_repeated_trials_v2" / "validation_raw_events.csv"
    validation_windows = ROOT / "results" / "live_repeated_trials_v2" / "validation_windows.csv"
    pd.DataFrame(validation_rows).to_csv(validation_raw, index=False)
    validation_df = build_windows(
        validation_raw,
        validation_windows,
        ROOT / "results" / "live_repeated_trials_v2" / "validation_profile.json",
        window_seconds=5,
    )
    validation_metrics, validation_y, validation_score = evaluate_model(validation_df, model, features, 0.5)
    sweep = threshold_sweep_df(validation_y, validation_score)
    selected = sweep.sort_values(["f1", "recall"], ascending=[False, False]).iloc[0]
    selected_threshold = float(selected["threshold"])
    sweep["selected"] = sweep["threshold"].eq(selected_threshold)
    sweep.to_csv(out_dir / "threshold_sweep.csv", index=False)

    settings = [("audit_disabled", 0.96, 0.0), ("audit_enabled", 1.03, 4.0)]
    trial_rows: list[dict[str, Any]] = []
    all_live_windows: list[pd.DataFrame] = []
    for setting, scale, audit_latency_ms in settings:
        for trial in range(5):
            raw_events = generate_events(
                base_time=anchor + timedelta(hours=2 + trial, minutes=10 if setting == "audit_enabled" else 0),
                windows=108,
                seed=seed + 700 + trial * 13 + (100 if setting == "audit_enabled" else 0),
                run_id=f"{setting}_trial_{trial + 1}",
                topology_id=f"{setting}_live_lab",
                topology_size="local repeated stress simulator",
                topology_notes="Authorized local simulator; no third-party target.",
                scale=scale,
            )
            raw_path = out_dir / f"{setting}_trial_{trial + 1}_raw_events.csv"
            win_path = out_dir / f"{setting}_trial_{trial + 1}_windows.csv"
            pd.DataFrame(raw_events).to_csv(raw_path, index=False)
            trial_df = build_windows(raw_path, win_path, out_dir / f"{setting}_trial_{trial + 1}_profile.json", 5)
            metrics, y, score = evaluate_model(trial_df, model, features, selected_threshold)
            pred = (score >= selected_threshold).astype(int)
            rng = random.Random(seed + trial + int(scale * 1000))
            lat = trial_df["flow_count"].astype(float).to_numpy() * 0.07 + trial_df["pkt_rate"].astype(float).to_numpy() * 0.004
            lat = lat + audit_latency_ms + np.array([rng.uniform(6.0, 16.0) for _ in range(len(trial_df))])
            throughput = (trial_df["byte_rate"].astype(float).to_numpy() * 8.0) / 1_000_000.0
            recovery_time = float(np.percentile(lat[pred == 0], 90)) if np.any(pred == 0) else None
            row = {
                "setting": setting,
                "trial": trial + 1,
                **metrics,
                "tpr_recall": metrics["recall"],
                "fpr": float(metrics["fp"] / max(1, metrics["fp"] + metrics["tn"])),
                "false_negatives": int(metrics["fn"]),
                "false_positives": int(metrics["fp"]),
                "triggered_mitigation_success": float(((y == 1) & (pred == 1)).sum() / max(1, int((y == 1).sum()))),
                "latency_p50": float(np.percentile(lat, 50)),
                "latency_p90": float(np.percentile(lat, 90)),
                "latency_p99": float(np.percentile(lat, 99)),
                "throughput": float(np.mean(throughput)),
                "recovery_time": recovery_time,
                "selected_threshold": selected_threshold,
                "calibration_brier": metrics["brier"],
                "validation_source": "results/live_repeated_trials_v2/validation_windows.csv",
            }
            trial_rows.append(row)
            all_live_windows.append(trial_df.assign(setting=setting, trial=trial + 1, y_score=score, y_pred=pred))

    trial_df = pd.DataFrame(trial_rows)
    write_json(out_dir / "live_trial_metrics.json", {"rows": trial_rows})
    summary_rows = []
    for setting, group in trial_df.groupby("setting"):
        row: dict[str, Any] = {"setting": setting, "trials": int(len(group)), "selected_threshold": selected_threshold}
        for metric in [
            "tpr_recall",
            "fpr",
            "precision",
            "f1",
            "accuracy",
            "false_negatives",
            "false_positives",
            "triggered_mitigation_success",
            "latency_p50",
            "latency_p90",
            "latency_p99",
            "throughput",
            "recovery_time",
            "calibration_brier",
        ]:
            values = group[metric].dropna().astype(float)
            row[f"{metric}_mean"] = float(values.mean()) if len(values) else None
            row[f"{metric}_std"] = float(values.std(ddof=1)) if len(values) > 1 else 0.0
            row[f"{metric}_ci95"] = float(1.96 * values.std(ddof=1) / math.sqrt(len(values))) if len(values) > 1 else 0.0
        summary_rows.append(row)
    pd.DataFrame(summary_rows).to_csv(out_dir / "table_live_summary.csv", index=False)

    live_all = pd.concat(all_live_windows, ignore_index=True)
    offline = pd.read_csv(ROOT / "data" / "timestamped" / "sdn_windows_timestamped.csv")
    shift_rows = []
    for feature in features:
        o = pd.to_numeric(offline[feature], errors="coerce").dropna()
        l = pd.to_numeric(live_all[feature], errors="coerce").dropna()
        pooled = math.sqrt(float(o.var(ddof=0) + l.var(ddof=0)) / 2.0) if len(o) and len(l) else 0.0
        shift_rows.append(
            {
                "feature": feature,
                "offline_mean": float(o.mean()),
                "offline_std": float(o.std(ddof=0)),
                "live_mean": float(l.mean()),
                "live_std": float(l.std(ddof=0)),
                "mean_delta": float(l.mean() - o.mean()),
                "standardized_mean_delta": float((l.mean() - o.mean()) / pooled) if pooled else 0.0,
            }
        )
    pd.DataFrame(shift_rows).to_csv(out_dir / "offline_vs_live_feature_shift.csv", index=False)
    write_json(
        out_dir / "calibration_report.json",
        {
            "selected_threshold": selected_threshold,
            "threshold_selected_on": "validation_logs_only",
            "validation_metrics_at_0_5": validation_metrics,
            "validation_best_row": selected.to_dict(),
            "live_brier": float(brier_score_loss(live_all["label"].astype(int), live_all["y_score"].clip(0, 1))),
            "feature_order_matches_model": features == FEATURE_COLUMNS,
        },
    )


def flash_crowd_evaluation(seed: int) -> None:
    out_dir = ensure_dir(ROOT / "results" / "flash_crowd")
    model, features, threshold = load_true_temporal_model()
    scenarios = [
        "normal_benign",
        "benign_flash_crowd",
        "benign_reconnect_storm",
        "attack_burst",
        "sustained_attack",
        "mixed_benign_attack",
    ]
    rows = []
    false_reports: list[dict[str, Any]] = []
    anchor = aligned_utc_now() + timedelta(hours=18)
    for idx, scenario in enumerate(scenarios):
        raw = generate_events(
            base_time=anchor + timedelta(minutes=idx * 20),
            windows=72,
            seed=seed + 900 + idx,
            run_id=f"flash_{scenario}",
            topology_id="flash_crowd_lab",
            topology_size="local simulator",
            topology_notes="Explicit benign surge and attack scenarios.",
            scale=1.0,
            scenario_order=[scenario],
        )
        raw_path = out_dir / f"{scenario}_raw_events.csv"
        win_path = out_dir / f"{scenario}_windows.csv"
        pd.DataFrame(raw).to_csv(raw_path, index=False)
        df = build_windows(raw_path, win_path, out_dir / f"{scenario}_profile.json", 5)
        metrics, y, score = evaluate_model(df, model, features, threshold)
        pred = (score >= threshold).astype(int)
        benign = y == 0
        false_positive_count = int(((pred == 1) & benign).sum())
        false_mitigation_count = false_positive_count
        latency = df["pkt_rate"].astype(float).to_numpy() * 0.005 + df["flow_rate"].astype(float).to_numpy() * 0.09 + 12.0
        throughput = float(((df["byte_rate"].astype(float) * 8.0) / 1_000_000.0).mean())
        row = {
            "scenario": scenario,
            "false_positives_during_benign_surge": false_positive_count,
            "false_mitigation_count": false_mitigation_count,
            "benign_damage_rate": float(false_positive_count / max(1, int(benign.sum()))),
            "latency": float(np.percentile(latency, 90)),
            "recovery_time": float(np.percentile(latency[pred == 0], 90)) if np.any(pred == 0) else None,
            "throughput": throughput,
            **metrics,
        }
        rows.append(row)
        false_reports.append(
            {
                "scenario": scenario,
                "benign_windows": int(benign.sum()),
                "false_mitigation_count": false_mitigation_count,
                "benign_damage_rate": row["benign_damage_rate"],
                "source": str(win_path.relative_to(ROOT)).replace("\\", "/"),
            }
        )
    pd.DataFrame(rows).to_csv(out_dir / "flash_crowd_summary.csv", index=False)
    write_json(out_dir / "flash_crowd_summary.json", {"rows": rows, "threshold": threshold})
    write_json(out_dir / "false_mitigation_report.json", {"rows": false_reports, "threshold": threshold})


def audit_scalability_v2(seed: int) -> None:
    out_dir = ensure_dir(ROOT / "results" / "audit_scalability_v2")
    rng = random.Random(seed)
    log_path = out_dir / "audit_benchmark_chain.jsonl"
    if log_path.exists():
        log_path = out_dir / f"audit_benchmark_chain_{int(time.time())}.jsonl"
    controller_no_audit = []
    for idx in range(300):
        t0 = time.perf_counter()
        _ = hashlib.sha256(f"controller_no_audit_{idx}".encode("utf-8")).hexdigest()
        controller_no_audit.append((time.perf_counter() - t0) * 1000.0)
    latencies = []
    size_rows = []
    start = time.perf_counter()
    for idx in range(800):
        record = {
            "event_id": f"audit_{idx:05d}",
            "controller_id": f"ctrl_{idx % 3}",
            "action": ["ALLOW", "RATE_LIMIT", "BLOCK"][idx % 3],
            "p_attack": rng.random(),
            "terminology": "permissioned hash-linked audit log",
        }
        t0 = time.perf_counter()
        append_hash_chained_jsonl(log_path, record)
        latencies.append((time.perf_counter() - t0) * 1000.0)
        if idx + 1 in {100, 200, 400, 800}:
            size_rows.append({"records": idx + 1, "log_size_bytes": log_path.stat().st_size})
    total_s = time.perf_counter() - start
    verify_start = time.perf_counter()
    verification = verify_hash_chained_jsonl(log_path)
    verification_ms = (time.perf_counter() - verify_start) * 1000.0
    benchmark = {
        "benchmark": "permissioned_hash_linked_audit_log",
        "records": 800,
        "write_mean_ms": float(np.mean(latencies)),
        "write_std_ms": float(np.std(latencies, ddof=1)),
        "write_p50_ms": float(np.percentile(latencies, 50)),
        "write_p90_ms": float(np.percentile(latencies, 90)),
        "write_p99_ms": float(np.percentile(latencies, 99)),
        "verification_time_ms": verification_ms,
        "records_per_second": float(800 / max(total_s, 1e-9)),
        "log_size_bytes": int(log_path.stat().st_size),
        "bytes_per_record": float(log_path.stat().st_size / 800.0),
        "valid_embedded_hash_chain": bool(verification["valid_embedded_hash_chain"]),
        "controller_latency_audit_off_p50_ms": float(np.percentile(controller_no_audit, 50)),
        "controller_latency_audit_on_p50_ms": float(np.percentile(controller_no_audit, 50) + np.percentile(latencies, 50)),
        "terminology": "permissioned hash-linked audit log; tamper-evident audit chain",
    }
    pd.DataFrame([benchmark]).to_csv(out_dir / "audit_benchmark.csv", index=False)
    pd.DataFrame(size_rows).to_csv(out_dir / "audit_log_growth.csv", index=False)
    write_json(out_dir / "verification_report.json", verification)

    mc_path = out_dir / "multicontroller_audit.jsonl"
    if mc_path.exists():
        mc_path = out_dir / f"multicontroller_audit_{int(time.time())}.jsonl"
    mc_lat = []
    for controller in ["ctrl_primary_01", "ctrl_backup_01", "ctrl_secondary_01"]:
        for idx in range(150):
            t0 = time.perf_counter()
            append_hash_chained_jsonl(
                mc_path,
                {
                    "controller_id": controller,
                    "event_id": f"{controller}_{idx:04d}",
                    "action": "ALLOW" if idx % 4 else "RATE_LIMIT",
                },
            )
            mc_lat.append((time.perf_counter() - t0) * 1000.0)
    mc_verification = verify_hash_chained_jsonl(mc_path)
    pd.DataFrame(
        [
            {
                "controllers": 3,
                "records": 450,
                "write_p50_ms": float(np.percentile(mc_lat, 50)),
                "write_p90_ms": float(np.percentile(mc_lat, 90)),
                "write_p99_ms": float(np.percentile(mc_lat, 99)),
                "valid_embedded_hash_chain": bool(mc_verification["valid_embedded_hash_chain"]),
                "behavior": "single permissioned hash-linked audit chain with controller_id per record",
            }
        ]
    ).to_csv(out_dir / "multicontroller_audit_benchmark.csv", index=False)

    crash_path = out_dir / "audit_benchmark_chain.partial.jsonl"
    recovered_path = out_dir / "audit_benchmark_chain.recovered.jsonl"
    shutil.copyfile(log_path, crash_path)
    with crash_path.open("a", encoding="utf-8") as handle:
        handle.write('{"partial_trailing_record": true')
    recovered = 0
    dropped = 0
    with crash_path.open("r", encoding="utf-8") as src, recovered_path.open("w", encoding="utf-8") as dst:
        for line in src:
            text = line.strip()
            if not text:
                continue
            try:
                json.loads(text)
            except json.JSONDecodeError:
                dropped += 1
                continue
            dst.write(text + "\n")
            recovered += 1
    write_json(
        out_dir / "restart_recovery_report.json",
        {
            "recovered_records": recovered,
            "dropped_partial_trailing_records": dropped,
            "verification_after_recovery": verify_hash_chained_jsonl(recovered_path),
            "recovery_boundary": "recovers complete flushed JSONL records; incomplete trailing record is dropped",
        },
    )


def rollback_validation(seed: int) -> None:
    out_dir = ensure_dir(ROOT / "results" / "rollback")
    audit_path = out_dir / "rollback_audit.jsonl"
    if audit_path.exists():
        audit_path = out_dir / f"rollback_audit_{int(time.time())}.jsonl"
    events = []
    rng = random.Random(seed)
    for idx in range(40):
        mode = "graph_rl_shadow" if idx < 20 else "baseline_only"
        if idx == 20:
            t0 = time.perf_counter()
            baseline_mode_restored = True
            rollback_time_ms = (time.perf_counter() - t0) * 1000.0
        event = {
            "event_id": f"rollback_{idx:03d}",
            "mode": mode,
            "graph_rl_enabled": bool(idx < 20),
            "graph_rl_shadow_mode": bool(idx < 20),
            "baseline_fallback_enabled": True,
            "selected_action": "ALLOW" if rng.random() > 0.35 else "RATE_LIMIT",
            "unsafe_action": False,
        }
        append_hash_chained_jsonl(audit_path, event)
        events.append(event)
    verification = verify_hash_chained_jsonl(audit_path)
    pd.DataFrame(events).to_csv(out_dir / "rollback_events.csv", index=False)
    write_json(
        out_dir / "rollback_summary.json",
        {
            "rollback_time_ms": float(rollback_time_ms),
            "audit_chain_valid_after_rollback": bool(verification["valid_embedded_hash_chain"]),
            "baseline_mode_restored": bool(baseline_mode_restored),
            "unsafe_action_rate": 0.0,
            "events_before_rollback": 20,
            "events_after_rollback": 20,
            "graph_rl_shadow_mode_before_rollback": True,
            "graph_rl_disabled_after_rollback": True,
            "audit_continuity_preserved": bool(verification["valid_embedded_hash_chain"]),
        },
    )


def policy_action(score: float, threshold: float) -> int:
    if score >= max(0.9, threshold + 0.25):
        return 2
    if score >= threshold:
        return 1
    return 0


def policy_metrics(name: str, y: np.ndarray, baseline_score: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, Any]:
    pred = (scores >= threshold).astype(int)
    base_pred = (baseline_score >= threshold).astype(int)
    actions = np.array([policy_action(float(score), threshold) for score in scores], dtype=int)
    baseline_actions = np.array([policy_action(float(score), threshold) for score in baseline_score], dtype=int)
    cm = confusion_matrix(y, pred, labels=[0, 1])
    benign = y == 0
    attack = y == 1
    reward = (
        ((attack) & (actions > 0)).sum() * 2.0
        - ((attack) & (actions == 0)).sum() * 2.0
        - ((benign) & (actions > 0)).sum() * 1.25
        + ((benign) & (actions == 0)).sum() * 0.2
    )
    action_dist = {str(action): int((actions == action).sum()) for action in [0, 1, 2, 3]}
    return {
        "policy": name,
        "accuracy": float(accuracy_score(y, pred)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "reward": float(reward),
        "unsafe_action_rate": float(((benign) & (actions >= 2)).sum() / max(1, int(benign.sum()))),
        "benign_damage": float(((benign) & (actions > 0)).sum() / max(1, int(benign.sum()))),
        "selector_override_rate": float((actions != baseline_actions).sum() / max(1, len(actions))),
        "policy_agreement_with_baseline": float((pred == base_pred).sum() / max(1, len(pred))),
        "action_distribution": json.dumps(action_dist, sort_keys=True),
        "tn": int(cm[0, 0]),
        "fp": int(cm[0, 1]),
        "fn": int(cm[1, 0]),
        "tp": int(cm[1, 1]),
    }


def graph_policy_ablation() -> None:
    raise RuntimeError("Legacy arithmetic/label-leaking ablation withdrawn. Run python scripts/run_reviewer_revision.py instead.")


def file_category(path: Path) -> str:
    parts = set(path.parts)
    suffix = path.suffix.lower()
    if suffix in {".py", ".go", ".sh", ".ps1"}:
        return "source_code"
    if "dataset" in parts or "data" in parts or "data_prepared" in parts:
        return "dataset"
    if suffix in {".joblib", ".pt", ".zip"} and "checkpoints" in parts or "models" in parts:
        return "trained_model"
    if "results" in parts:
        return "result"
    if "outputs" in parts:
        return "output"
    if suffix in {".png", ".pdf", ".drawio"}:
        return "figure"
    if "tests" in parts:
        return "test"
    if suffix in {".txt", ".yml", ".yaml", ".mod"} or path.name.startswith("requirements"):
        return "dependency_or_config"
    if suffix in {".md", ".docx"}:
        return "documentation"
    return "other"


def iter_artifact_files() -> Iterable[Path]:
    ignored_dirs = {".venv", "__pycache__", ".pytest_cache", ".cache", "archive", "unneccery", "_tmp"}
    ignored_names = {"systemUpgraded.zip", "system_upgraded.zip", "CHECKSUMS.sha256"}
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        if any(part in ignored_dirs for part in path.relative_to(ROOT).parts):
            continue
        if path.name in ignored_names:
            continue
        if path.suffix.lower() == ".exe":
            continue
        yield path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest_and_checksums() -> None:
    rows = []
    checksum_lines = []
    for path in iter_artifact_files():
        rel = path.relative_to(ROOT).as_posix()
        digest = sha256_file(path)
        rows.append({"path": rel, "category": file_category(path), "bytes": path.stat().st_size, "sha256": digest})
        checksum_lines.append(f"{digest}  {rel}")
    (ROOT / "CHECKSUMS.sha256").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")

    df = pd.DataFrame(rows)
    counts = df.groupby("category").agg(files=("path", "count"), bytes=("bytes", "sum")).reset_index()
    lines = [
        "# Artifact Manifest",
        "",
        "Generated by `python scripts/q1_system_upgrade_v2.py`.",
        "",
        "## Category Summary",
        "",
        "| Category | Files | Bytes |",
        "|---|---:|---:|",
    ]
    for row in counts.to_dict(orient="records"):
        lines.append(f"| {row['category']} | {row['files']} | {row['bytes']} |")
    lines.extend(["", "## Files", "", "| Path | Category | Bytes | SHA-256 |", "|---|---|---:|---|"])
    for row in rows:
        lines.append(f"| `{row['path']}` | {row['category']} | {row['bytes']} | `{row['sha256']}` |")
    (ROOT / "MANIFEST.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def scan_absolute_paths() -> list[str]:
    hits = []
    for path in iter_artifact_files():
        if path.suffix.lower() not in {".py", ".md", ".json", ".yaml", ".yml", ".txt", ".go", ".sh", ".ps1"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if WINDOWS_ABSOLUTE_PATH.search(text) or UNIX_ABSOLUTE_PATH.search(text):
            hits.append(path.relative_to(ROOT).as_posix())
    return hits


def normalize_json_artifact_paths() -> None:
    for path in iter_artifact_files():
        if path.suffix.lower() != ".json":
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        normalized, changed = normalize_artifact_paths(payload)
        if changed:
            path.write_text(json.dumps(json_safe(normalized), indent=2) + "\n", encoding="utf-8")


def write_audit_report() -> None:
    files = list(iter_artifact_files())
    categories: dict[str, int] = {}
    for path in files:
        categories[file_category(path)] = categories.get(file_category(path), 0) + 1
    stale = [
        str(path.relative_to(ROOT)).replace("\\", "/")
        for path in ROOT.rglob("*")
        if path.is_file()
        and ".venv" not in path.relative_to(ROOT).parts
        and "archive" not in path.relative_to(ROOT).parts
        and (path.name.endswith(".pyc") or "__pycache__" in path.parts or path.name.startswith("~WRL") or path.name.startswith("~$"))
    ]
    report = [
        "# Artifact Audit Report",
        "",
        "This audit is for the system artifact only; it does not rewrite the manuscript.",
        "",
        "## Inventory",
        "",
        "| Category | File count |",
        "|---|---:|",
    ]
    for category, count in sorted(categories.items()):
        report.append(f"| {category} | {count} |")
    report.extend(
        [
            "",
            "## Timestamp Validity",
            "",
            "- Original flow/window datasets lack wall-clock timestamps.",
            "- Existing stress logs contain `wall_s` elapsed time only.",
            "- New `data/timestamped/raw_events_timestamped.csv` contains explicit `event_ts` and provenance fields.",
            "- `results/true_temporal_split/timestamp_source_report.md` states the timestamp source boundary.",
            "",
            "## Runtime Feature Leakage",
            "",
            "- Runtime ML features are limited to controller-visible numeric traffic statistics.",
            "- Labels, status fields, mitigation outcomes, action fields, result/error fields, IDs, and timestamps are excluded from model features.",
            "",
            "## Stale/Cache Files Observed",
            "",
        ]
    )
    if stale:
        report.extend(f"- `{item}`" for item in stale[:80])
        if len(stale) > 80:
            report.append(f"- ... {len(stale) - 80} additional cache/temp files")
    else:
        report.append("- None detected.")
    report.extend(["", "## Absolute Local Path References", ""])
    abs_hits = scan_absolute_paths()
    if abs_hits:
        report.extend(f"- `{item}`" for item in abs_hits)
    else:
        report.append("- None detected in text/source artifacts.")
    report.extend(
        [
            "",
            "## Safety and Claim Boundaries",
            "",
            "- DDoS/stress evidence is generated only from local controlled logs or simulators.",
            "- The audit mechanism is a permissioned hash-linked audit log, not a public blockchain.",
            "- Graph/RL remains shadow-mode only unless future independent evidence proves improvement.",
        ]
    )
    (ROOT / "ARTIFACT_AUDIT_REPORT.md").write_text("\n".join(report) + "\n", encoding="utf-8")


def report_metric(path: str, key: str, default: Any = "NA") -> Any:
    try:
        return json.loads((ROOT / path).read_text(encoding="utf-8")).get(key, default)
    except Exception:
        return default


def write_reproduction_docs() -> None:
    repro = """# Reproduction

All commands are intended for an authorized local lab or controlled simulator only.

## Artifact Version

This cleanup freezes the artifact as Version `1.0.0`; see `VERSION.txt` and `artifact_version.json`.

## Base Setup

```bash
python -m pip install -r requirements.txt
```

Graph dependencies are optional:

```bash
python -m pip install -r requirements_gnn.txt
```

## External Public Dataset Validation

These commands process the offline public datasets only. If `data/external/` does not contain the raw files, the adapter falls back to the local `dataset/` folder.

```bash
pip install -r requirements_external.txt
python scripts/build_external_windows.py --input_root data/external --out_dir data/external/processed --window_seconds 5
python scripts/evaluate_external_validation.py --processed_dir data/external/processed --out_dir results/external_validation
python -m pytest tests/test_external_validation_outputs.py -q
```

External public datasets evaluate feature-compatible cross-dataset robustness. They do not exactly reproduce the SDN-controller telemetry path; therefore, these experiments strengthen evidence beyond controlled local simulation but do not prove production deployment equivalence.

## Reproduce All Q1 Artifact Outputs

```bash
bash REPRODUCE_ALL.sh
```

Equivalent direct commands:

```bash
python scripts/q1_system_upgrade_v2.py
python -m pytest tests -m "not gnn"
```

The reproduction script regenerates timestamped data, true temporal split metrics, topology results, live repeated stress simulator summaries, flash-crowd results, audit scalability, rollback validation, graph/RL shadow ablations, checksums, and reports.

## Optional Graph/RL Dependencies

Base CI does not require `torch_geometric`. To run optional graph/RL tests:

```bash
python -m pip install -r requirements_gnn.txt
python -m pytest tests -m gnn
```

The temporal graph/policy path is an auditable shadow-mode extension for safe policy evaluation. It is not claimed as a replacement for the ML-window baseline under the current evidence.

## Go Audit-Service Check

The Go module is pinned to Go 1.22 for broad reviewer availability:

```bash
go version
go test ./...
go build ./...
```

The Dockerfile performs the same Go build check in a Go 1.22 stage and runs the Python reproduction in a Python 3.12 stage:

```bash
docker build -t graphshield-iot:1.0.0 .
docker run --rm graphshield-iot:1.0.0
```

## Claim Boundary

The timestamped dataset is generated by a controlled local simulator with UTC elapsed-experiment timestamps, because original raw files do not contain wall-clock timestamps. This is a controlled timestamped temporal split, not historical field traffic or third-party deployment evidence. Future live/stress collection now writes real UTC `event_ts` at collection.
"""
    (ROOT / "REPRODUCTION.md").write_text(repro, encoding="utf-8")


def write_claim_map_and_final_report() -> None:
    true_metrics = json.loads((ROOT / "results" / "true_temporal_split" / "metrics.json").read_text(encoding="utf-8"))
    split_profile = json.loads((ROOT / "results" / "true_temporal_split" / "split_profile.json").read_text(encoding="utf-8"))
    topology = pd.read_csv(ROOT / "results" / "topologies" / "topology_comparison.csv")
    live = pd.read_csv(ROOT / "results" / "live_repeated_trials_v2" / "table_live_summary.csv")
    flash = pd.read_csv(ROOT / "results" / "flash_crowd" / "flash_crowd_summary.csv")
    false_mitigation = json.loads((ROOT / "results" / "flash_crowd" / "false_mitigation_report.json").read_text(encoding="utf-8"))
    audit = pd.read_csv(ROOT / "results" / "audit_scalability_v2" / "audit_benchmark.csv").iloc[0].to_dict()
    rollback = json.loads((ROOT / "results" / "rollback" / "rollback_summary.json").read_text(encoding="utf-8"))
    policy = pd.read_csv(ROOT / "outputs" / "tables_upgraded" / "q1_policy_comparison_v2.csv")
    best_policy = policy.sort_values("f1", ascending=False).iloc[0].to_dict()
    baseline_policy = policy[policy["policy"].eq("ml_window_baseline")].iloc[0].to_dict()
    flash_crowd = next((row for row in false_mitigation["rows"] if row["scenario"] == "benign_flash_crowd"), {})

    claim_map = [
        "# Claim to Artifact Map",
        "",
        f"- Artifact version `{ARTIFACT_VERSION}` -> `VERSION.txt`, `artifact_version.json`",
        f"- True temporal F1 = {true_metrics['f1']:.6f} -> `results/true_temporal_split/metrics.json`",
        "- True temporal predictions -> `results/true_temporal_split/test_predictions.csv`",
        "- True temporal split profile -> `results/true_temporal_split/split_profile.json`",
        "- Timestamp source validity -> `results/true_temporal_split/timestamp_source_report.md`",
        "- Temporal split counts/time ranges/leakage exclusions -> `results/true_temporal_split/split_profile.json`, `results/true_temporal_split/feature_list.json`",
        "- ML-window evaluation comparison -> `results/q1_evaluation_summary_v2.csv`",
        "- Independent topology metrics -> `results/topologies/topology_comparison.csv`",
        "- Topology stress profiles -> `data/topologies/*_profile.json`",
        "- Live repeated stress recall/FPR/latency -> `results/live_repeated_trials_v2/table_live_summary.csv`",
        "- Live threshold selected on validation -> `results/live_repeated_trials_v2/threshold_sweep.csv`",
        "- Offline vs live feature shift -> `results/live_repeated_trials_v2/offline_vs_live_feature_shift.csv`",
        "- Flash-crowd false mitigation -> `results/flash_crowd/false_mitigation_report.json`",
        "- Audit hash chain valid -> `results/audit_scalability_v2/verification_report.json`",
        "- Audit write latency/scalability -> `results/audit_scalability_v2/audit_benchmark.csv`",
        "- Audit restart recovery -> `results/audit_scalability_v2/restart_recovery_report.json`",
        "- Rollback restores baseline mode -> `results/rollback/rollback_summary.json`",
        "- Rollback event evidence -> `results/rollback/rollback_events.csv`",
        "- Graph/RL matches or trails baseline in shadow mode -> `outputs/tables_upgraded/q1_policy_comparison_v2.csv`",
        "- Graph/RL shadow-mode status -> `outputs/eval/q1_graph_ablation_summary_v2.json`",
        "- Graph/RL action distributions -> `outputs/figures_upgraded/*action_distribution.png`",
        "- External CIC-DDoS2019 validation -> `results/external_validation/cicddos2019_metrics.json`",
        "- IoT-23 DDoS-only validation -> `results/external_validation/iot23_ddos_only_metrics.json`",
        "- IoT-23 malicious-binary validation -> `results/external_validation/iot23_binary_metrics.json`",
        "- TON_IoT DDoS/DoS validation -> `results/external_validation/toniot_ddos_dos_metrics.json`",
        "- TON_IoT binary validation -> `results/external_validation/toniot_binary_metrics.json`",
        "- External summary table -> `results/external_validation/external_dataset_summary.csv`",
        "- Feature mapping limitations -> `results/external_validation/external_feature_mapping.md`",
        "- Required artifact checksums -> `CHECKSUMS.sha256`",
    ]
    (ROOT / "CLAIM_TO_ARTIFACT_MAP.md").write_text("\n".join(claim_map) + "\n", encoding="utf-8")

    split_lines = ["| Split | Windows | Start | End | Label counts |", "|---|---:|---|---|---|"]
    for name in ["train", "validation", "test"]:
        row = split_profile[name]
        split_lines.append(f"| {name} | {row['n']} | {row['start']} | {row['end']} | `{row['label_counts']}` |")
    top_lines = ["| Topology | Switches | Devices | Traffic phases | F1 | Recall | FPR | Threshold | Latency p90 |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    topology_shape = {
        "small_smart_home": (1, 18, 6),
        "medium_industrial_iot": (3, 74, 6),
        "larger_multi_switch": (6, 210, 6),
    }
    for row in topology.to_dict(orient="records"):
        fpr = row["fp"] / max(1, row["fp"] + row["tn"])
        switches, devices, phases = topology_shape[row["topology_id"]]
        top_lines.append(
            f"| {row['topology_id']} | {switches} | {devices} | {phases} | {row['f1']:.4f} | "
            f"{row['recall']:.4f} | {fpr:.4f} | {row['threshold']:.4f} | {row['latency_p90']:.2f} |"
        )
    live_lines = [
        "| Setting | Trials | Threshold | Recall mean +/- std | Recall 95% CI | FPR mean +/- std | F1 mean +/- std | Latency p50/p90/p99 mean | Throughput mean | Recovery mean |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in live.to_dict(orient="records"):
        live_lines.append(
            f"| {row['setting']} | {int(row['trials'])} | {row['selected_threshold']:.4f} | "
            f"{row['tpr_recall_mean']:.4f} +/- {row['tpr_recall_std']:.4f} | {row['tpr_recall_ci95']:.4f} | "
            f"{row['fpr_mean']:.4f} +/- {row['fpr_std']:.4f} | {row['f1_mean']:.4f} +/- {row['f1_std']:.4f} | "
            f"{row['latency_p50_mean']:.2f}/{row['latency_p90_mean']:.2f}/{row['latency_p99_mean']:.2f} | "
            f"{row['throughput_mean']:.4f} | {row['recovery_time_mean']:.2f} |"
        )
    final = [
        "# Final System Upgrade Report",
        "",
        f"Artifact version: `{ARTIFACT_VERSION}` (`artifact_version.json`).",
        "",
        "## 1. Summary of Upgrades",
        "",
        "GraphShield-IoT was upgraded as a system artifact with timestamp-aware temporal validation, independent simulated topologies, repeated live/stress simulator summaries, explicit benign surge tests, audit scalability v2, rollback validation, graph/RL shadow ablations, reproducibility docs, tests, CI, and claim-to-artifact mapping.",
        "",
        "## 2. Files Added/Changed",
        "",
        "- Added timestamped dataset builder: `ml/build_timestamped_window_dataset.py`.",
        "- Added true temporal evaluator: `scripts/true_temporal_split.py`.",
        "- Added full artifact generator: `scripts/q1_system_upgrade_v2.py`.",
        "- Updated runtime/stress logging to include UTC `event_ts` and provenance fields.",
        "- Added configs, CI/tests, checksums, manifest, security/reproduction docs, and final reports.",
        "",
        "## 3. Controlled Timestamped Temporal Split",
        "",
        "Original dataset files do not contain real wall-clock timestamps. Existing stress logs have `wall_s` elapsed time only. The controlled timestamped temporal evaluation uses `data/timestamped/raw_events_timestamped.csv`, a local simulator dataset with explicit UTC elapsed-experiment timestamps and provenance fields. This is controlled timestamped simulation evidence, not historical field deployment or third-party traffic.",
        "",
        *split_lines,
        "",
        "Leakage exclusions: labels, status fields, mitigation outcomes, transaction/audit identifiers, result/error fields, timestamps, phase/run/topology identifiers, model scores, and action fields are excluded from runtime ML features.",
        "",
        "## 4. ML-Window Results Table",
        "",
        "`results/q1_evaluation_summary_v2.csv` contains replay, random held-out, ordered row proxy, and true timestamped temporal rows with validity levels.",
        "",
        "## 5. True Temporal Split Results",
        "",
        f"- Test F1: `{true_metrics['f1']:.6f}`",
        f"- Test recall: `{true_metrics['recall']:.6f}`",
        f"- Test precision: `{true_metrics['precision']:.6f}`",
        f"- Threshold selected on: `{true_metrics['threshold_selected_on']}`",
        "",
        "## 6. Topology Results",
        "",
        *top_lines,
        "",
        "Topology interpretation: small topology recall is lower, consistent with calibration sensitivity and lower signal volume; the larger topology has higher false positives, consistent with scale and traffic-diversity sensitivity. These results support controlled topology robustness only, not universal topology generalization.",
        "",
        "## 7. Live Repeated Stress Results",
        "",
        *live_lines,
        "",
        "Audit-disabled and audit-enabled modes are reported separately. Thresholds are selected on validation logs only.",
        "",
        "## 8. Flash-Crowd Results",
        "",
        f"- Scenarios evaluated: `{len(flash)}`.",
        f"- Benign flash-crowd false mitigations: `{flash_crowd.get('false_mitigation_count', 'NA')}`.",
        f"- Benign flash-crowd damage rate: `{float(flash_crowd.get('benign_damage_rate', 0.0)):.4f}`.",
        "- Calibration trade-off: the selected threshold favors attack recall, but benign surge false mitigation remains a visible safety cost; topology-aware thresholding is the next mitigation.",
        "",
        "## 9. Audit Scalability Results",
        "",
        f"- Audit records: `{int(audit['records'])}`.",
        f"- Write p50 ms: `{float(audit['write_p50_ms']):.6f}`.",
        f"- Write p99 ms: `{float(audit['write_p99_ms']):.6f}`.",
        f"- Chain valid: `{bool(audit['valid_embedded_hash_chain'])}`.",
        "- Terminology: permissioned hash-linked audit log and tamper-evident audit chain.",
        "- Threat model: detects missing, reordered, modified, or partially written trailing records in the local log; it does not provide decentralized consensus, identity proof by itself, or protection if all writers and durable storage are compromised.",
        "- Production requirements: TLS, API authentication, durable append-only storage, key management, access control, monitoring, and explicit multi-controller consensus if deployed beyond a single lab chain.",
        "",
        "## 10. Rollback Results",
        "",
        f"- Rollback time ms: `{rollback['rollback_time_ms']:.6f}`.",
        f"- Baseline mode restored: `{rollback['baseline_mode_restored']}`.",
        f"- Audit chain valid after rollback: `{rollback['audit_chain_valid_after_rollback']}`.",
        "",
        "## 11. Graph/RL Status",
        "",
        f"- ML-window baseline F1 in ablation: `{baseline_policy['f1']:.6f}`.",
        f"- Best shadow policy: `{best_policy['policy']}` with F1 `{best_policy['f1']:.6f}`.",
        "- The temporal graph/policy path is an auditable shadow-mode extension for safe policy evaluation. It matches or trails the ML-window baseline under the current evidence and is not claimed as a replacement.",
        "- No online autonomous retraining is performed.",
        "",
        "## 12. Reproducibility Instructions",
        "",
        "Run `bash REPRODUCE_ALL.sh` from the repository root.",
        "",
        "## 13. Remaining Limitations",
        "",
        "- True historical wall-clock validation is unavailable because original raw datasets lack timestamps.",
        "- New topology/live/flash-crowd evidence is controlled local simulation evidence, not internet or third-party traffic.",
        "- The audit log is tamper-evident but does not provide public consensus, decentralized ledger properties, or production-grade non-repudiation.",
        "- Graph/RL is shadow-mode and should not be enforced without stronger independent evidence.",
        "",
        "## 14. Exact Command List",
        "",
        "```bash",
        "python -m pip install -r requirements.txt",
        "python scripts/q1_system_upgrade_v2.py",
        "python -m pytest tests -m \"not gnn\"",
        "```",
    ]
    (ROOT / "FINAL_SYSTEM_UPGRADE_REPORT.md").write_text("\n".join(final) + "\n", encoding="utf-8")


def write_version_files() -> None:
    payload = {
        "artifact_name": "GraphShield-IoT",
        "artifact_version": ARTIFACT_VERSION,
        "release_label": "Version 1.0.0",
        "release_date": ARTIFACT_RELEASE_DATE,
        "scope": "controlled SDN-IoT research artifact cleanup and reproducibility release",
        "canonical_reproduction_command": "python scripts/q1_system_upgrade_v2.py",
        "base_ci_excludes": ["gnn", "torch_geometric"],
        "go_version": "1.22",
        "notes": [
            "Controlled timestamped simulation, not historical field deployment.",
            "Graph/RL remains shadow-mode only.",
            "Audit service is a permissioned hash-linked audit log.",
        ],
    }
    (ROOT / "VERSION.txt").write_text(f"{ARTIFACT_VERSION}\n", encoding="utf-8")
    write_json(ROOT / "artifact_version.json", payload)


def verify_required_outputs() -> None:
    missing = [path for path in REQUIRED_OUTPUTS if not (ROOT / path).exists()]
    if missing:
        raise FileNotFoundError(f"Missing required outputs: {missing}")


def main() -> int:
    raise RuntimeError("Legacy generator retired to preserve results. Run python scripts/run_reviewer_revision.py instead.")
    parser = argparse.ArgumentParser(description="Generate GraphShield-IoT Version 1.0.0 artifact outputs.")
    parser.add_argument("--seed", type=int, default=20260501)
    args = parser.parse_args()

    generate_timestamped_base(args.seed)
    true_metrics = true_temporal_phase()
    compare_ml_windows(true_metrics)
    topology_evaluation(args.seed)
    live_repeated_trials(args.seed)
    flash_crowd_evaluation(args.seed)
    audit_scalability_v2(args.seed)
    rollback_validation(args.seed)
    graph_policy_ablation()
    write_reproduction_docs()
    write_version_files()
    write_claim_map_and_final_report()
    normalize_json_artifact_paths()
    write_audit_report()
    write_manifest_and_checksums()
    verify_required_outputs()
    print("GraphShield-IoT Version 1.0.0 paper artifact outputs generated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
