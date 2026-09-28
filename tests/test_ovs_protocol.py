import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from reviewer_revision.core import FEATURES, Partition, select_threshold


ROOT = Path(__file__).resolve().parents[1]


def test_preregistered_seed_ranges_are_disjoint():
    protocol = json.loads((ROOT / "configs/ovs_experiment_protocol_v2.json").read_text(encoding="utf-8"))
    ranges = []
    for name in ["calibration_train", "calibration_validation", "confirmatory_kali", "confirmatory_ubuntu"]:
        item = protocol[name]
        seeds = set(range(item["seed_start"], item["seed_start"] + item["runs"]))
        assert all(not seeds.intersection(previous) for previous in ranges)
        ranges.append(seeds)
    pilot = set(range(protocol["excluded_pilot"]["seed_start"],
                      protocol["excluded_pilot"]["seed_end"] + 1))
    assert all(not pilot.intersection(seeds) for seeds in ranges)


def test_threshold_selection_rejects_test_partition():
    records = pd.DataFrame({
        "run_id": ["test_run", "test_run"],
        "window_start_ts": pd.to_datetime(["2026-01-01T00:00:00Z", "2026-01-01T00:00:05Z"]),
        "window_end_ts": pd.to_datetime(["2026-01-01T00:00:05Z", "2026-01-01T00:00:10Z"]),
    })
    x = pd.DataFrame(np.zeros((2, len(FEATURES))), columns=FEATURES)
    test = Partition("test", x, np.array([0, 1]), records)
    registry = json.loads((ROOT / "configs/threshold_registry_ovs_v2.json").read_text(encoding="utf-8"))
    with pytest.raises(ValueError, match="validation partition"):
        select_threshold(test, np.array([0.1, 0.9]), registry)


def test_detector_features_exclude_labels_and_scenario_metadata():
    forbidden = {"label", "phase", "seed", "window_index", "scheduled_attack_mbps",
                 "scheduled_benign_mbps", "scheduled_attackers"}
    assert forbidden.isdisjoint(FEATURES)
