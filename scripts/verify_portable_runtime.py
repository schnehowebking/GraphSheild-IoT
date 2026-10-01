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
from reviewer_revision.core import FEATURES, RuntimeDetector, matches_text_sha  # noqa: E402
from sdn import CompletedWindowController  # noqa: E402


def sha(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def main():
    if sys.version_info[:2] != (3, 13):
        raise RuntimeError("Portable runtime requires Python 3.13")
    deployment = ROOT / "deployment_ovs_v2"
    selection = json.loads((deployment / "threshold_selection.json").read_text())
    assert sha(deployment / "model.joblib") == selection["model_hash"]
    assert matches_text_sha(deployment / "feature_schema.json", selection["feature_schema_hash"])
    detector = RuntimeDetector(directory=deployment, registry_path=ROOT / "configs/threshold_registry_ovs_v2.json")
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
