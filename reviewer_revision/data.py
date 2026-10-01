"""Causal feature construction from the existing controlled event simulator."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

from reviewer_revision.core import FEATURES, Partition
from scripts.q1_system_upgrade_v2 import generate_events

OBSERVABLE = ["event_ts", "run_id", "src_ip", "dst_ip", "switch_id", "packet_count", "byte_count", "flow_count"]
BIPARTITE = ["ss_edges", "sources", "services", "source_degree_mean", "service_degree_max", "edge_packets_mean", "edge_packets_max"]
SWITCH = BIPARTITE + ["switch_nodes", "source_switch_edges", "switch_service_edges", "switch_degree_max", "path_count", "local_switch_packet_share"]
CONTEXT = SWITCH + ["arrival_gap_mean", "arrival_gap_std", "event_flow_std", "active_switches"]
TEMPORAL = BIPARTITE + ["historical_edges", "new_edge_fraction", "decayed_packets", "returning_edge_fraction"]
NORMALIZED = ["ss_edges", "sources", "services", "source_degree_mean", "service_degree_max", "edge_weight_share_max", "edge_weight_share_entropy", "edge_packet_rate_mean"]
GRAPH_FEATURES = list(dict.fromkeys(CONTEXT + TEMPORAL + NORMALIZED))


def entropy(values):
    _, counts = np.unique(values, return_counts=True)
    p = counts / counts.sum()
    return float(-(p * np.log2(p)).sum())


def generate_run(config, run_index, seed, *, scale=1., windows=None, base_time=None):
    anchor = datetime.fromisoformat(config["anchor_timestamp"])
    # A one-day gap makes runs independent simulation episodes, not adjacent data fragments.
    return pd.DataFrame(generate_events(base_time=base_time or anchor + timedelta(days=run_index),
        windows=windows or config["windows_per_run"], seed=seed, run_id=f"run_{run_index:04d}",
        topology_id=f"scale_{scale}", topology_size="controlled simulator",
        topology_notes="Fresh pseudorandom events; timestamps are synthetic experiment time, not collection wall clock.", scale=scale))


def prepare_windows(raw):
    raw = raw.copy()
    raw["start"] = pd.to_datetime(raw.event_ts, utc=True, format="mixed").dt.floor("5s")
    rows = []
    for (run, start, switch, service), g in raw.groupby(["run_id", "start", "switch_id", "dst_ip"], sort=True):
        pkt, byte, flow = float(g.packet_count.sum()), float(g.byte_count.sum()), float(g.flow_count.sum())
        rows.append({"row_id": f"{run}|{start.isoformat()}|{switch}|{service}", "run_id": run,
            "window_start_ts": start.isoformat(), "window_end_ts": (start + pd.Timedelta(seconds=5)).isoformat(),
            "switch_id": switch, "dst_ip": service, "scenario_id": "|".join(sorted(g.scenario_id.unique())),
            "label": int(g.label.max()), "pkt_rate": pkt / 5, "byte_rate": byte / 5,
            "pkt_sum": pkt, "events": len(g), "unique_src": g.src_ip.nunique(),
            "src_ip_entropy": entropy(g.src_ip.to_numpy()), "flow_count": flow if flow > 0 else len(g),
            "flow_rate": (flow if flow > 0 else len(g)) / 5})
    return pd.DataFrame(rows).sort_values(["window_start_ts", "run_id", "switch_id", "dst_ip"]).reset_index(drop=True)


def graph_features(observations, windows, history_seconds=30, decay_seconds=15):
    """Strict allowlist: labels, scenario IDs and simulated latency never reach the graph builder.

    At a window close, all edges with event_ts < window_end are available. Past state resets
    at an independent run. No future score ranges or fitted normalization are used.
    """
    if list(observations.columns) != OBSERVABLE:
        raise ValueError("Graph builder accepts only ordered observable event columns")
    if list(windows.columns) != ["row_id", "run_id", "window_start_ts", "switch_id", "dst_ip"]:
        raise ValueError("Graph query metadata must not contain labels or future outcomes")
    raw = observations.copy()
    raw["start"] = pd.to_datetime(raw.event_ts, utc=True, format="mixed").dt.floor("5s")
    raw["epoch"] = pd.to_datetime(raw.event_ts, utc=True, format="mixed").astype("int64") / 1e9
    result = {}
    query = windows.copy()
    query["start"] = pd.to_datetime(query.window_start_ts, utc=True)
    for run, run_data in raw.groupby("run_id", sort=False):
        history = []
        query_run = query[query.run_id == run]
        for start, batch in run_data.sort_values("epoch").groupby("start", sort=True):
            end = start.timestamp() + 5
            history = [edge for edge in history if edge[0] >= end - history_seconds]
            historical_pairs = {(edge[1], edge[2]) for edge in history}
            source_services, service_sources, switch_neighbors = defaultdict(set), defaultdict(set), defaultdict(set)
            weights = defaultdict(float)
            for r in batch.itertuples():
                source_services[r.src_ip].add(r.dst_ip)
                service_sources[r.dst_ip].add(r.src_ip)
                switch_neighbors[r.switch_id].update([("source", r.src_ip), ("service", r.dst_ip)])
                weights[(r.src_ip, r.dst_ip)] += r.packet_count
            weight_values = np.array(list(weights.values()), dtype=float)
            shares = weight_values / weight_values.sum()
            edges = set(weights)
            degree = [len(x) for x in source_services.values()]
            gaps = np.diff(np.sort(batch.epoch.to_numpy()))
            common = {"ss_edges": len(edges), "sources": len(source_services), "services": len(service_sources),
                "source_degree_mean": float(np.mean(degree)), "service_degree_max": max(map(len, service_sources.values())),
                "edge_packets_mean": float(weight_values.mean()), "edge_packets_max": float(weight_values.max()),
                "switch_nodes": batch.switch_id.nunique(), "source_switch_edges": len(batch[["src_ip", "switch_id"]].drop_duplicates()),
                "switch_service_edges": len(batch[["switch_id", "dst_ip"]].drop_duplicates()),
                "switch_degree_max": max(map(len, switch_neighbors.values())),
                "path_count": len(batch[["src_ip", "switch_id", "dst_ip"]].drop_duplicates()),
                "arrival_gap_mean": float(gaps.mean()) if len(gaps) else 0.,
                "arrival_gap_std": float(gaps.std()) if len(gaps) else 0.,
                "event_flow_std": float(batch.flow_count.std(ddof=0)), "active_switches": batch.switch_id.nunique(),
                "historical_edges": len(historical_pairs), "new_edge_fraction": len(edges - historical_pairs) / len(edges),
                "returning_edge_fraction": len(edges & historical_pairs) / len(edges),
                "decayed_packets": float(sum(e[3] * np.exp(-(end - e[0]) / decay_seconds) for e in history)),
                "edge_weight_share_max": float(shares.max()), "edge_weight_share_entropy": float(-(shares * np.log2(shares)).sum()),
                "edge_packet_rate_mean": float(weight_values.mean() / 5)}
            for r in query_run[query_run.start == start].itertuples():
                local_share = batch.loc[batch.switch_id == r.switch_id, "packet_count"].sum() / batch.packet_count.sum()
                result[r.row_id] = {**common, "local_switch_packet_share": float(local_share)}
            history.extend((r.epoch, r.src_ip, r.dst_ip, r.packet_count) for r in batch.itertuples())
    return pd.DataFrame([result[r] for r in windows.row_id], columns=GRAPH_FEATURES, index=windows.index)


def make_folds(windows, config):
    required = ["row_id", "run_id", "window_start_ts", "window_end_ts"]
    if windows[required].isna().any().any() or windows.row_id.duplicated().any():
        raise ValueError("Missing IDs/timestamps or duplicate windows")
    times = pd.to_datetime(windows.window_start_ts, utc=True)
    if not times.is_monotonic_increasing:
        raise ValueError("Temporal input must already be ordered; no shuffling")
    runs = windows.groupby("run_id").agg(start=("window_start_ts", "min"), end=("window_end_ts", "max")).sort_values("start")
    if any(pd.Timestamp(runs.iloc[i].end) > pd.Timestamp(runs.iloc[i + 1].start) for i in range(len(runs) - 1)):
        raise ValueError("Independent run time ranges overlap")
    first, val, size = config["initial_train_runs"], config["validation_runs"], config["test_runs_per_fold"]
    if min(first, val, size) < 1:
        raise ValueError("Positive partition sizes required")
    available = (len(runs) - first - val) // size
    requested = available if config["fold_count"] == "auto" else int(config["fold_count"])
    if requested < 2 or requested > available:
        raise ValueError(f"Requested {requested} folds; at most {available} whole-run folds available (at least two required)")
    folds, definitions = [], []
    used = set()
    for fold in range(requested):
        train_end = first + fold * size
        names = {"train": runs.index[:train_end], "validation": runs.index[train_end:train_end + val],
                 "test": runs.index[train_end + val:train_end + val + size]}
        indices = {role: windows.index[windows.run_id.isin(ids)].to_numpy() for role, ids in names.items()}
        test_ids = set(windows.loc[indices["test"], "row_id"])
        if used & test_ids:
            raise ValueError("Test windows reused across folds")
        used |= test_ids
        for role, idx in indices.items():
            d = windows.loc[idx]
            definitions.append({"fold": fold, "split": role, "n": len(d), "benign": int((d.label == 0).sum()),
                "attack": int((d.label == 1).sum()), "start": d.window_start_ts.min(), "end": d.window_end_ts.max(),
                "run_ids": ";".join(names[role]), "scenario_counts": d.scenario_id.value_counts().to_json()})
        folds.append(indices)
    return folds, pd.DataFrame(definitions)


def partition(windows, features, indices, role):
    return Partition(role, features.loc[indices].copy(), windows.loc[indices, "label"].to_numpy(), windows.loc[indices].copy())
