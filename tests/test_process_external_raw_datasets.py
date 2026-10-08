from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path

import pandas as pd

from scripts.process_external_raw_datasets import WindowState, entropy, parse_zeek_tail


def test_window_features_do_not_use_labels() -> None:
    base = pd.DataFrame({
        "_packets": [2.0, 3.0], "_bytes": [20.0, 30.0], "_src": ["a", "b"],
        "_binary": [0, 1], "_target": [0, 1], "_other": [0, 0],
        "_label_text": ["benign", "ddos"],
    })
    changed = base.copy(); changed[["_binary", "_target"]] = 0
    one, two = WindowState(0), WindowState(0)
    one.add_frame(base); two.add_frame(changed)
    assert (one.packets, one.bytes_, one.rows, one.sources) == (two.packets, two.bytes_, two.rows, two.sources)


def test_entropy_is_flow_occurrence_weighted() -> None:
    assert entropy(Counter({"a": 2, "b": 2})) == 1.0


def test_iot23_tail_parser() -> None:
    assert parse_zeek_tail("-   Malicious   DDoS") == ("-", "Malicious", "DDoS")
