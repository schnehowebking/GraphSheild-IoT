#!/usr/bin/env python3
"""Build publication-facing external diagnostic tables from generated metrics."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pandas as pd


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evaluation", default="results/external_raw_transfer_v1")
    parser.add_argument("--output", default="results/external_final_tables_v1")
    args = parser.parse_args()
    source, output = Path(args.evaluation).resolve(), Path(args.output).resolve()
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite existing output: {output}")
    output.mkdir(parents=True)
    metrics = pd.read_csv(source / "external_metrics.csv", float_precision="round_trip")
    ci = pd.read_csv(source / "external_confidence_intervals.csv", float_precision="round_trip")
    wide = ci.pivot(index=["dataset", "label_mode"], columns="metric", values=["lower_95", "upper_95"])
    wide.columns = [f"{metric}_ci_{'lower' if bound == 'lower_95' else 'upper'}" for bound, metric in wide.columns]
    final = metrics.merge(wide.reset_index(), on=["dataset", "label_mode"], how="left", validate="one_to_one")
    final.to_csv(output / "external_metrics_with_ci.csv", index=False)
    selected = [
        "dataset", "label_mode", "n", "tn", "fp", "fn", "tp", "accuracy",
        "precision", "recall", "f1", "f1_ci_lower", "f1_ci_upper", "roc_auc",
        "pr_auc", "fpr", "fnr", "benign_damage", "threshold", "threshold_source",
        "measurement_type",
    ]
    final[selected].to_csv(output / "external_table_publication.csv", index=False)
    manifest = {
        "source_evaluation": source.as_posix(),
        "source_metrics_sha256": sha256(source / "external_metrics.csv"),
        "source_ci_sha256": sha256(source / "external_confidence_intervals.csv"),
        "rows": len(final), "canonical_controller_equivalence_claimed": False,
    }
    (output / "table_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    files = sorted(output.iterdir())
    (output / "CHECKSUMS.sha256").write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in files), encoding="utf-8")
    print(final[selected].to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
