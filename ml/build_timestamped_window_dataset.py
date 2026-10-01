#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


LEAKAGE_EXCLUDED_FIELDS = [
    "label",
    "true_attack",
    "status",
    "detected_api",
    "mitigation_rule_id",
    "mitigation_success",
    "error",
    "result",
    "transaction_id",
    "enforced_action",
    "baseline_action",
    "rl_action",
    "safe_action",
    "shadow_action_applied",
    "p_attack",
    "p_attack_raw",
]


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.as_posix().replace("\\", "/")


def entropy(values: pd.Series) -> float:
    clean = values.dropna().astype(str)
    if clean.empty:
        return 0.0
    counts = clean.value_counts()
    total = float(counts.sum())
    return float(-sum((count / total) * math.log2(count / total) for count in counts if count > 0))


def binary_label(series: pd.Series) -> pd.Series:
    def one(value: Any) -> int:
        if pd.isna(value):
            return 0
        text = str(value).strip().lower()
        if text in {"0", "0.0", "false", "benign", "normal", "none", "no"}:
            return 0
        try:
            return int(float(text) > 0.0)
        except ValueError:
            return 1

    return series.map(one).astype(int)


def first_existing(df: pd.DataFrame, candidates: list[str], required: bool = False) -> str | None:
    for name in candidates:
        if name in df.columns:
            return name
    if required:
        raise ValueError(f"Missing required column; expected one of: {', '.join(candidates)}")
    return None


def build_windows(input_csv: Path, output_csv: Path, profile_json: Path, window_seconds: int = 5) -> pd.DataFrame:
    if not input_csv.exists():
        raise FileNotFoundError(input_csv)
    df = pd.read_csv(input_csv)
    if "event_ts" not in df.columns:
        raise ValueError("timestamp column is missing: event_ts")

    ts = pd.to_datetime(df["event_ts"], utc=True, errors="coerce", format="mixed")
    if ts.isna().any():
        bad = int(ts.isna().sum())
        raise ValueError(f"event_ts contains {bad} unparsable timestamps")
    df = df.copy()
    df["_event_ts"] = ts

    pkt_col = first_existing(df, ["packet_count", "pkt_count", "packets", "pkt_sum"], required=True)
    byte_col = first_existing(df, ["byte_count", "bytes", "byte_sum"], required=False)
    flow_col = first_existing(df, ["flow_count", "flows"], required=False)
    src_col = first_existing(df, ["src_ip", "source_ip"], required=False)
    label_col = first_existing(df, ["label", "true_attack"], required=True)

    for col, default in [
        ("run_id", "run_unknown"),
        ("topology_id", "topology_unknown"),
        ("scenario_id", "scenario_unknown"),
        ("phase", "phase_unknown"),
    ]:
        if col not in df.columns:
            df[col] = default

    df["_label"] = binary_label(df[label_col])
    df["_packets"] = pd.to_numeric(df[pkt_col], errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0.0)
    df["_bytes"] = (
        pd.to_numeric(df[byte_col], errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0.0)
        if byte_col
        else 0.0
    )
    df["_flows"] = (
        pd.to_numeric(df[flow_col], errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0.0)
        if flow_col
        else 1.0
    )
    df["_src"] = df[src_col].astype(str) if src_col else "unknown"

    epoch = pd.Timestamp("1970-01-01T00:00:00Z")
    epoch_s = ((df["_event_ts"] - epoch).dt.total_seconds()).astype("int64")
    start_epoch = (epoch_s // int(window_seconds)) * int(window_seconds)
    df["_window_start"] = pd.to_datetime(start_epoch, unit="s", utc=True)
    df["_window_end"] = df["_window_start"] + pd.to_timedelta(int(window_seconds), unit="s")

    rows: list[dict[str, Any]] = []
    group_cols = ["run_id", "topology_id", "scenario_id", "phase", "_window_start", "_window_end"]
    for keys, group in df.sort_values("_event_ts").groupby(group_cols, sort=True, dropna=False):
        run_id, topology_id, scenario_id, phase, window_start, window_end = keys
        pkt_sum = float(group["_packets"].sum())
        byte_sum = float(group["_bytes"].sum())
        flow_count = float(group["_flows"].sum())
        rows.append(
            {
                "window_start_ts": window_start.isoformat(),
                "window_end_ts": window_end.isoformat(),
                "run_id": str(run_id),
                "topology_id": str(topology_id),
                "scenario_id": str(scenario_id),
                "phase": str(phase),
                "pkt_rate": pkt_sum / float(window_seconds),
                "byte_rate": byte_sum / float(window_seconds),
                "pkt_sum": pkt_sum,
                "events": int(len(group)),
                "unique_src": int(group["_src"].nunique()),
                "src_ip_entropy": entropy(group["_src"]),
                "flow_count": flow_count,
                "flow_rate": flow_count / float(window_seconds),
                "label": int(group["_label"].max()),
            }
        )

    out = pd.DataFrame(rows).sort_values(["window_start_ts", "run_id", "topology_id", "scenario_id", "phase"])
    if out.empty:
        raise ValueError("No windows produced from timestamped events")

    features = [
        "pkt_rate",
        "byte_rate",
        "pkt_sum",
        "events",
        "unique_src",
        "src_ip_entropy",
        "flow_count",
        "flow_rate",
    ]
    profile = {
        "source_file": display_path(input_csv),
        "output_file": display_path(output_csv),
        "window_seconds": int(window_seconds),
        "number_of_windows": int(len(out)),
        "time_range": {
            "start": str(out["window_start_ts"].min()),
            "end": str(out["window_end_ts"].max()),
        },
        "label_counts": {str(k): int(v) for k, v in out["label"].value_counts().sort_index().items()},
        "run_counts": {str(k): int(v) for k, v in out["run_id"].value_counts().sort_index().items()},
        "topology_counts": {str(k): int(v) for k, v in out["topology_id"].value_counts().sort_index().items()},
        "scenario_counts": {str(k): int(v) for k, v in out["scenario_id"].value_counts().sort_index().items()},
        "phase_counts": {str(k): int(v) for k, v in out["phase"].value_counts().sort_index().items()},
        "feature_list": features,
        "timestamp_columns": ["event_ts", "window_start_ts", "window_end_ts"],
        "leakage_excluded_fields": LEAKAGE_EXCLUDED_FIELDS,
        "label_rule": "label = 1 if any attack event occurs in the window, else 0",
    }

    ensure_parent(output_csv)
    out.to_csv(output_csv, index=False)
    ensure_parent(profile_json)
    profile_json.write_text(json.dumps(profile, indent=2), encoding="utf-8")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Build fixed-window dataset from timestamped SDN-IoT events.")
    parser.add_argument("--input", default="data/timestamped/raw_events_timestamped.csv")
    parser.add_argument("--output", default="data/timestamped/sdn_windows_timestamped.csv")
    parser.add_argument("--profile", default="data/timestamped/window_dataset_profile.json")
    parser.add_argument("--window-seconds", type=int, default=5)
    args = parser.parse_args()

    build_windows(Path(args.input), Path(args.output), Path(args.profile), window_seconds=args.window_seconds)
    print(f"saved -> {args.output}")
    print(f"saved -> {args.profile}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
