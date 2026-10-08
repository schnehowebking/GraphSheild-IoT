#!/usr/bin/env python3
"""Recompute external metrics from saved row-level predictions."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

try:
    from scripts.evaluate_external_raw_transfer import confusion, from_counts, evaluate
except ModuleNotFoundError:
    from evaluate_external_raw_transfer import confusion, from_counts, evaluate


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify(root):
    root = Path(root).resolve()
    # Exact round-trip parsing preserves extremely close forest probabilities;
    # the default fast parser can collapse ties and slightly alter ROC-AUC.
    frame = pd.read_csv(root / "external_predictions.csv", float_precision="round_trip")
    metrics = pd.read_csv(root / "external_metrics.csv", float_precision="round_trip")
    manifest = json.loads((root / "evaluation_manifest.json").read_text(encoding="utf-8"))
    checks = []
    intervals = []
    for row in metrics.to_dict("records"):
        full = frame.loc[frame["dataset"].eq(row["dataset"])].copy()
        part = full.copy()
        label = "label"
        if row["label_mode"] in {"ddos_only", "ddos_dos"}:
            part = part.loc[part["target_eligible"].eq(1)]
            label = "target_label"
        y = part[label].to_numpy(dtype=int)
        pred = part["prediction"].to_numpy(dtype=int)
        proba = part["probability"].to_numpy(dtype=float)
        if not np.isfinite(proba).all() or not np.all((proba >= 0) & (proba <= 1)):
            raise ValueError('Invalid saved probability')
        tn, fp, fn, tp = confusion(y, pred)
        values = {"n": len(y), "tn": tn, "fp": fp, "fn": fn, "tp": tp,
                  **from_counts(tn, fp, fn, tp)}
        values["roc_auc"] = float(roc_auc_score(y, proba)) if len(np.unique(y)) == 2 else np.nan
        values["pr_auc"] = float(average_precision_score(y, proba)) if len(np.unique(y)) == 2 else np.nan
        for key, value in values.items():
            saved = row[key]
            if (pd.isna(saved) and pd.isna(value)) or np.isclose(float(saved), float(value), rtol=0, atol=1e-12):
                continue
            raise AssertionError(f"Metric mismatch {row['dataset']} {row['label_mode']} {key}: {saved} != {value}")
        if not np.array_equal(pred, (proba >= float(row["threshold"])).astype(int)):
            raise AssertionError("Saved threshold was not used for inference")
        if float(row['threshold']) != float(manifest['threshold']):
            raise AssertionError('Threshold disagrees with frozen manifest')
        eligible = full['target_eligible'].eq(1).to_numpy() if label == 'target_label' else np.ones(len(full), dtype=bool)
        _, ci = evaluate(full, label, eligible)
        intervals.extend(dict(dataset=row['dataset'], label_mode=row['label_mode'], **entry) for entry in ci)
        checks.append({"dataset": row["dataset"], "label_mode": row["label_mode"], "rows": len(y)})

    checksum_count = 0
    for line in (root / "CHECKSUMS.sha256").read_text(encoding="utf-8").splitlines():
        expected, name = line.split("  ", 1)
        if sha256(root / name) != expected:
            raise AssertionError(f"Checksum mismatch: {name}")
        checksum_count += 1
    pd.testing.assert_frame_equal(pd.DataFrame(intervals),
        pd.read_csv(root/'external_confidence_intervals.csv', float_precision='round_trip'),
        check_dtype=False, check_like=True, rtol=1e-10, atol=1e-12)
    report = {
        "passed": True, "metric_sets_recomputed": checks,
        "checksums_verified": checksum_count, "threshold": manifest["threshold"],
        "external_labels_used_for_inference": False,
        "confidence_intervals_recomputed": True,
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output')
    parser.add_argument('--report', type=Path, help='Optional NEW report path; source artifacts remain read-only')
    args = parser.parse_args()
    report = verify(args.output)
    if args.report:
        with args.report.open('x', encoding='utf-8') as handle:
            json.dump(report, handle, indent=2)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
