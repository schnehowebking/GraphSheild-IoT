"""Strict schemas, validation-only threshold selection and saved-model inference."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


CONFIG = read_json(ROOT / "configs/canonical_detector.json")
FEATURES = CONFIG["features"]


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def sha(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def matches_text_sha(path, expected):
    """Match a text artifact across Git CRLF/LF checkout normalization."""
    raw = Path(path).read_bytes()
    lf = raw.replace(b"\r\n", b"\n")
    crlf = lf.replace(b"\n", b"\r\n")
    return expected in {
        hashlib.sha256(raw).hexdigest(),
        hashlib.sha256(lf).hexdigest(),
        hashlib.sha256(crlf).hexdigest(),
    }


def object_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False).encode()).hexdigest()


def frame_hash(frame):
    return hashlib.sha256(frame.to_csv(index=False, float_format="%.17g").encode()).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


def versions():
    import platform
    return {"python": platform.python_version(), "platform": platform.platform(), **{
        name: importlib.metadata.version(name)
        for name in ["numpy", "pandas", "scikit-learn", "scipy", "joblib", "pytest", "aiohttp"]}}


def strict_features(x, names):
    if not isinstance(x, pd.DataFrame) or list(x.columns) != list(names):
        raise ValueError("Inference accepts exactly the declared ordered feature columns; labels/metadata forbidden")
    values = x.to_numpy(dtype=float)
    if not np.isfinite(values).all():
        raise ValueError("Nonfinite/missing feature values are not permitted")
    return x.astype(float)


def validate_binary(y):
    y = np.asarray(y)
    if y.ndim != 1 or len(y) == 0 or not np.isin(y, [0, 1]).all():
        raise ValueError("Expected nonempty binary labels/actions")
    return y.astype(int)


def metrics(y, p, a=None):
    y = validate_binary(y)
    p = np.asarray(p, dtype=float)
    if p.shape != y.shape or not np.isfinite(p).all() or ((p < 0) | (p > 1)).any():
        raise ValueError("Invalid probability vector")
    a = validate_binary(a)
    if a.shape != y.shape:
        raise ValueError("Output length mismatch")
    tn, fp, fn, tp = [int(v.sum()) for v in [(y == 0) & (a == 0), (y == 0) & (a == 1), (y == 1) & (a == 0), (y == 1) & (a == 1)]]
    undefined = []

    def ratio(n, d, name):
        if not d:
            undefined.append(name + ": zero denominator")
            return None
        return float(n / d)

    result = {"n": len(y), "tn": tn, "fp": fp, "fn": fn, "tp": tp,
              "accuracy": (tn + tp) / len(y), "precision": ratio(tp, tp + fp, "precision"),
              "recall": ratio(tp, tp + fn, "recall"), "f1": ratio(2 * tp, 2 * tp + fp + fn, "f1"),
              "fpr": ratio(fp, fp + tn, "fpr"), "fnr": ratio(fn, fn + tp, "fnr"),
              "benign_damage": ratio(fp, fp + tn, "benign_damage"),
              "roc_auc": float(roc_auc_score(y, p)) if len(np.unique(y)) == 2 else None,
              "pr_auc": float(average_precision_score(y, p)) if y.sum() else None,
              "reward": float(rewards(y, a).sum()), "reward_mean": float(rewards(y, a).mean()),
              "mitigation_count": int(a.sum()), "no_action_count": int((a == 0).sum())}
    if result["roc_auc"] is None:
        undefined.append("roc_auc: single-class sample")
    if result["pr_auc"] is None:
        undefined.append("pr_auc: no positive class")
    result["undefined_metrics"] = "; ".join(undefined)
    return result


def rewards(y, a):
    """Declared classification utility, not measured mitigation benefit."""
    y, a = np.asarray(y), np.asarray(a)
    return np.where(y == 1, np.where(a == 1, 2., -2.), np.where(a == 1, -1.25, .2))


@dataclass(frozen=True)
class Partition:
    role: str
    x: pd.DataFrame
    y: np.ndarray
    records: pd.DataFrame

    def __post_init__(self):
        if self.role not in {"train", "validation", "test"}:
            raise ValueError("Unknown partition role")
        if not (len(self.x) == len(self.y) == len(self.records)) or not len(self.x):
            raise ValueError("Invalid partition sizes")
        validate_binary(self.y)


def validate_fit(train, validation):
    if train.role != "train" or validation.role != "validation":
        raise ValueError("Only train and validation partitions may enter fit")
    if pd.to_datetime(train.records.window_end_ts, utc=True).max() > pd.to_datetime(validation.records.window_start_ts, utc=True).min():
        raise ValueError("Training extends into validation")
    if set(train.records.run_id) & set(validation.records.run_id):
        raise ValueError("Episode/run leakage")
    if len(np.unique(train.y)) != 2 or len(np.unique(validation.y)) != 2:
        raise ValueError("Training and threshold validation require both classes")


def select_threshold(validation, probabilities, registry):
    if validation.role != "validation":
        raise ValueError("Threshold selection requires a validation partition, never test")
    y, p = validate_binary(validation.y), np.asarray(probabilities, dtype=float)
    if p.shape != y.shape or not np.isfinite(p).all() or ((p < 0) | (p > 1)).any():
        raise ValueError("Invalid validation probabilities")
    if len(np.unique(y)) != 2:
        raise ValueError("Both validation classes are required")
    candidates = np.unique(np.r_[0., p, np.nextafter(1., np.inf)])
    rows = []
    # Confusion-only curve avoids repeatedly calculating AUC while sweeping.
    for t in candidates:
        a = p >= t
        tp, fp = int(((y == 1) & a).sum()), int(((y == 0) & a).sum())
        fn, tn = int((y == 1).sum()) - tp, int((y == 0).sum()) - fp
        rows.append({"threshold": float(t), "tn": tn, "fp": fp, "fn": fn, "tp": tp,
                     "f1": 2 * tp / (2 * tp + fp + fn), "recall": tp / (tp + fn),
                     "fpr": fp / (fp + tn)})
    curve = pd.DataFrame(rows)
    allowed = curve[curve.fpr <= registry["operating"]["max_false_positive_rate"]]
    best = allowed.sort_values(["f1", "recall", "fpr", "threshold"], ascending=[False, False, True, False]).iloc[0]
    threshold = float(best.threshold)
    curve["selected"] = curve.threshold == threshold
    return threshold, curve


class FittedDetector:
    def __init__(self, config=None):
        self.config = config or CONFIG
        self.features = self.config["features"]

    def fit(self, train, validation, registry):
        validate_fit(train, validation)
        self.model = RandomForestClassifier(**self.config["hyperparameters"])
        self.model.fit(strict_features(train.x, self.features), train.y)
        self.threshold, self.curve = select_threshold(validation, self.predict_proba_or_action(validation.x), registry)
        self.train, self.validation = train, validation
        self.registry = registry
        return self

    def predict_proba_or_action(self, observations):
        return self.model.predict_proba(strict_features(observations, self.features))[:, list(self.model.classes_).index(1)].copy()

    def actions(self, observations):
        return (self.predict_proba_or_action(observations) >= self.threshold).astype(int)

    def get_metadata(self):
        return {"model_family": "RandomForestClassifier", "features": self.features,
                "hyperparameters": self.model.get_params() if hasattr(self.model, "get_params") else self.config["hyperparameters"], "threshold": self.threshold,
                "train_rows": len(self.train.x), "validation_rows": len(self.validation.x),
                "training_episodes": int(self.train.records.run_id.nunique()), "validation_episodes": int(self.validation.records.run_id.nunique())}

    def save(self, directory, evaluation_paths=None, test_rows=0):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, directory / "model.joblib")
        write_json(directory / "feature_schema.json", {"features": self.features, "units": self.config.get("units"),
                   "missing_values": "reject", "scaling": "none", "calibration": "none"})
        self.curve.to_csv(directory / "validation_threshold_curve.csv", index=False)
        selection = {"selected_value": self.threshold, "selection_split": "validation",
                     "selection_dataset_hash": frame_hash(self.validation.records),
                     "selection_run_ids": sorted(set(self.validation.records.run_id)),
                     "objective": self.registry["operating"]["objective"],
                     "constraints": {"max_fpr": self.registry["operating"]["max_false_positive_rate"]},
                     "tie_break": self.registry["operating"]["tie_break"], "selection_timestamp": now(),
                     "model_hash": sha(directory / "model.joblib"),
                     "feature_schema_hash": sha(directory / "feature_schema.json"),
                     "registry_hash": object_hash(self.registry)}
        write_json(directory / "threshold_selection.json", selection)
        write_json(directory / "model_metadata.json", {**self.get_metadata(),
                   "training_data_hash": frame_hash(pd.concat([self.train.records.reset_index(drop=True), self.train.x.reset_index(drop=True)], axis=1)),
                   "configuration_hash": object_hash(self.config), "code_version": "no git metadata available; source SHA256 in manifest",
                   "created_at": now(), "library_versions": versions(), "selection": selection,
                   "evaluation_artifact_paths": evaluation_paths or [], "test_rows": int(test_rows)})


class RuntimeDetector:
    """The controller and offline replay use this exact saved model and selection."""
    def __init__(self, directory=None, registry_path=None):
        self.registry_path = Path(registry_path or ROOT / CONFIG["threshold_registry"])
        self.registry = read_json(self.registry_path)
        if directory is None:
            selection_path = ROOT / self.registry["operating"]["selection_file"]
            directory = selection_path.parent
        self.directory = Path(directory)
        self.selection = read_json(self.directory / "threshold_selection.json")
        if self.selection["model_hash"] != sha(self.directory / "model.joblib"):
            raise ValueError("Model/threshold hash mismatch")
        if not matches_text_sha(self.directory / "feature_schema.json", self.selection["feature_schema_hash"]):
            raise ValueError("Feature schema hash mismatch")
        self.features = read_json(self.directory / "feature_schema.json")["features"]
        if self.features != FEATURES:
            raise ValueError("Runtime detector must use the canonical eight-feature schema")
        self.model = joblib.load(self.directory / "model.joblib")
        if list(self.model.feature_names_in_) != self.features:
            raise ValueError("Model feature order differs from schema")
        self.threshold = float(self.selection["selected_value"])
        if not np.isfinite(self.threshold) or not 0 <= self.threshold <= np.nextafter(1., np.inf):
            raise ValueError("Invalid operating threshold")
        self.enabled, self.name, self.error = True, "canonical_window", None
        self.feature_order = self.features
        self.model_path = self.directory / "model.joblib"

    def predict_proba_or_action(self, x):
        return self.model.predict_proba(strict_features(x, self.features))[:, list(self.model.classes_).index(1)].copy()

    def predict_proba_1(self, features):
        if set(features) != set(self.features):
            raise ValueError("Unexpected or missing runtime features")
        return float(self.predict_proba_or_action(pd.DataFrame([{k: features[k] for k in self.features}]))[0])

    def decide(self, features):
        p = self.predict_proba_1(features)
        return {"probability": p, "prediction": int(p >= self.threshold), "threshold": self.threshold,
                "action": "RATE_LIMIT" if p >= self.threshold else "NONE",
                "model_hash": self.selection["model_hash"], "threshold_selection_file": str(self.directory / "threshold_selection.json")}


def preservation_status():
    """Resolve repository artifacts relative to this checkout, including after relocation."""
    snapshot = read_json(ROOT / "reviewer_revision/preservation_snapshot.json")
    changed, unavailable_external, checked = [], [], 0
    for original, digest in snapshot.items():
        normalized = original.replace(chr(92), "/")
        marker = "/GraphSheild-IoT/"
        if marker in normalized:
            path = ROOT / normalized.split(marker, 1)[1]
        else:
            path = Path(original)
            if not path.exists():
                unavailable_external.append(original)
                continue
        checked += 1
        if not path.is_file() or sha(path) != digest:
            changed.append(str(path))
    if changed:
        raise AssertionError(f"Protected artifacts changed or missing: {changed}")
    return {"checked_files": checked, "changed_files": [], "unavailable_external_references": unavailable_external}
