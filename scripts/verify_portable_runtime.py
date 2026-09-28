#!/usr/bin/env python3
"""Verify immutable model/schema/threshold and controller inference parity."""
from __future__ import annotations

import hashlib
import json
import platform
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from reviewer_revision.core import FEATURES, RuntimeDetector  # noqa: E402
from sdn import CompletedWindowController  # noqa: E402


def sha(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def main():
    if sys.version_info[:2] != (3, 13):
        raise RuntimeError("Portable runtime requires Python 3.13")
    selection = json.loads((ROOT / "deployment/threshold_selection.json").read_text())
    assert sha(ROOT / "deployment/model.joblib") == selection["model_hash"]
    # Git may normalize CRLF to LF on Linux.  The schema content is unchanged,
    # so accept the raw checkout hash or either newline-normalized byte hash.
    schema_path = ROOT / "deployment/feature_schema.json"
    schema_bytes = schema_path.read_bytes()
    schema_lf = schema_bytes.replace(b"\r\n", b"\n")
    schema_crlf = schema_lf.replace(b"\n", b"\r\n")
    schema_hashes = {
        hashlib.sha256(schema_bytes).hexdigest(),
        hashlib.sha256(schema_lf).hexdigest(),
        hashlib.sha256(schema_crlf).hexdigest(),
    }
    assert selection["feature_schema_hash"] in schema_hashes
    detector = RuntimeDetector(directory=ROOT / "deployment", registry_path=ROOT / "configs/threshold_registry.json")
    zero = {name: 0.0 for name in FEATURES}
    response = CompletedWindowController(detector=detector, audit_enabled=False).detect_completed_window(zero, "parity-zero")
    assert np.isfinite(response["probability"])
    assert response["prediction"] == int(response["probability"] >= detector.threshold)
    try:
        detector.predict_proba_1({**zero, "label": 1})
    except ValueError:
        pass
    else:
        raise AssertionError("Runtime accepted a label")
    frame = pd.DataFrame([zero], columns=FEATURES)
    assert np.isfinite(detector.predict_proba_or_action(frame)).all()
    print(json.dumps({"passed": True, "python": platform.python_version(),
                      "threshold": detector.threshold, "model_sha256": selection["model_hash"],
                      "feature_order": FEATURES, "label_rejection": True}, indent=2))


if __name__ == "__main__":
    main()
