"""Canonical training utility; temporal evaluation uses the same FittedDetector."""
import argparse
from pathlib import Path
import pandas as pd
from reviewer_revision.core import ROOT, FEATURES, FittedDetector, read_json
from reviewer_revision.data import make_folds, partition


def main():
    parser = argparse.ArgumentParser(description="Train canonical detector on timestamped independent-run windows")
    parser.add_argument("--csv_path", required=True)
    parser.add_argument("--out_dir", required=True)
    parser.add_argument("--config", default=str(ROOT / "configs/reviewer_revision.json"))
    args = parser.parse_args()
    output = Path(args.out_dir)
    if output.exists():
        raise FileExistsError("Use a new output directory; old models are preserved")
    windows = pd.read_csv(args.csv_path)
    config = read_json(args.config)
    folds, definitions = make_folds(windows, config)
    idx = folds[-1]
    train = partition(windows, windows[FEATURES], idx["train"], "train")
    validation = partition(windows, windows[FEATURES], idx["validation"], "validation")
    model = FittedDetector().fit(train, validation, read_json(ROOT / "configs/threshold_registry.json"))
    model.save(output)
    definitions.to_csv(output / "fold_definitions.csv", index=False)
    print(f"Canonical model and validation threshold saved to {output}; test labels were not used for fitting")
