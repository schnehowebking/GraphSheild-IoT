"""Export metadata from serialized estimators and seal generated artifacts."""
from pathlib import Path
import joblib
from reviewer_revision.core import read_json, write_json, sha


def export_estimator_metadata(output):
    """Describe preprocessing inside the estimator separately from input schema checks.

    Numeric results and selected operating values are not changed by this exporter.
    It reads the actual serialized model, including fitted distillation scaler state.
    """
    output = Path(output)
    for model_path in sorted(output.glob("models/*/*/model.joblib")) + [output / "deployment/model.joblib"]:
        directory = model_path.parent
        model = joblib.load(model_path)
        schema = read_json(directory / "feature_schema.json")
        internal = {"method": "none"}
        if hasattr(model, "scaler"):
            internal = {"method": "StandardScaler", "fit_split": "train",
                        "mean": model.scaler.mean_.tolist(), "scale": model.scaler.scale_.tolist()}
        schema["input_scaling"] = "none"
        schema["scaling"] = "training-fitted StandardScaler inside estimator" if hasattr(model, "scaler") else "none"
        schema["estimator_preprocessing"] = internal
        write_json(directory / "feature_schema.json", schema)
        selection = read_json(directory / "threshold_selection.json")
        selection["feature_schema_hash"] = sha(directory / "feature_schema.json")
        write_json(directory / "threshold_selection.json", selection)
        metadata = read_json(directory / "model_metadata.json")
        metadata["feature_schema"] = schema
        metadata["selection"] = selection
        write_json(directory / "model_metadata.json", metadata)
    import shutil
    for name in ["feature_schema.json", "threshold_selection.json", "model_metadata.json"]:
        shutil.copyfile(output / "deployment" / name, output / name)


def seal(output):
    output = Path(output)
    manifest = read_json(output / "experiment_manifest.json")
    manifest["outputs"] = sorted(str(p.relative_to(output)) for p in output.rglob("*") if p.is_file() and p.name != "CHECKSUMS.sha256")
    write_json(output / "experiment_manifest.json", manifest)
    (output / "CHECKSUMS.sha256").write_text("\n".join(
        f"{sha(p)}  {p.relative_to(output).as_posix()}" for p in sorted(output.rglob("*"))
        if p.is_file() and p.name != "CHECKSUMS.sha256") + "\n", encoding="utf-8")
