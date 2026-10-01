"""Read-only service/targeting evaluation, separate from classification."""
import csv
import hashlib
import json
from pathlib import Path
import numpy as np


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def receiver_metrics(path):
    """Use receiver measurements only; do not substitute sender offered load."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if data.get("error"):
            raise ValueError(data["error"])
        record = data["end"]["sum_received"]
        rate, loss = float(record["bits_per_second"]), float(record["lost_percent"])
        if not np.isfinite([rate, loss]).all() or rate < 0 or not 0 <= loss <= 100:
            raise ValueError("Invalid receiver rate/loss")
        return {"receiver_mbps": rate / 1e6, "loss_percent": loss, "status": "ok"}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return {"receiver_mbps": None, "loss_percent": None,
                "status": f"unavailable: {type(exc).__name__}: {exc}"}


def read_rows(root, dataset):
    root = Path(root)
    rows, inputs = [], {}
    files = sorted(root.rglob("window_results.csv"))
    if not files:
        raise ValueError(f"No trial records under {root}")
    for path in files:
        inputs[str(path.resolve())] = sha(path)
        records = list(csv.DictReader(path.open(encoding="utf-8")))
        previous_target = ""
        truth_path = path.parent / "source_truth.json"
        if truth_path.exists():
            truth = json.loads(truth_path.read_text())
            benign_ips = {ip for ip, label in truth.items() if label == 0}
            inputs[str(truth_path.resolve())] = sha(truth_path)
        else:
            benign_ips = {"10.253.0.1"}  # historical testbed EVALUATION mapping only
        for expected, row in enumerate(records):
            index = int(row["window_index"])
            if index != expected:
                raise ValueError("Nonconsecutive window records")
            folder = path.parent / f"window_{index:03d}"
            benign_path = folder / "iperf_benign.json"
            benign = receiver_metrics(benign_path)
            if benign_path.exists(): inputs[str(benign_path.resolve())] = sha(benign_path)
            attack_paths = sorted(folder.glob("iperf_attack*.json"))
            attacks = [receiver_metrics(p) for p in attack_paths]
            for p in attack_paths: inputs[str(p.resolve())] = sha(p)
            attack_ok = bool(attacks) and all(a["status"] == "ok" for a in attacks)
            target = row.get("rate_limited_source_for_next_window", "")
            rows.append({"dataset": dataset, "seed": int(row["seed"]), "setting": row["setting"],
                "window_index": index, "phase": row["phase"], "label": int(row["label"]),
                "prediction": int(row["prediction"]), "selected_action": row["action"],
                "next_target": target, "benign_target_selected": int(target in benign_ips),
                "preceding_target": previous_target,
                "follows_benign_target_selection": int(previous_target in benign_ips),
                "scheduled_benign_mbps": float(row["scheduled_benign_mbps"]),
                "scheduled_attack_mbps": float(row["scheduled_attack_mbps"]),
                "scheduled_attackers": int(row.get("scheduled_attackers", bool(int(row["label"])))),
                "benign_receiver_mbps": benign["receiver_mbps"], "benign_loss_percent": benign["loss_percent"],
                "benign_measurement_status": benign["status"],
                "attack_receiver_mbps": sum(a["receiver_mbps"] for a in attacks) if attack_ok else
                    0.0 if not float(row["scheduled_attack_mbps"]) else None,
                "attack_measurement_status": "ok" if attack_ok else "no_attack_scheduled" if not float(row["scheduled_attack_mbps"]) else "unavailable",
                "record_path": str(path.resolve())})
            previous_target = target
    return rows, inputs


def mean_ci(values, rng, count=2000):
    values = np.asarray(values, dtype=float)
    if not len(values):
        return dict(n=0, mean=None, std=None, median=None, minimum=None, maximum=None, ci_lower_95=None, ci_upper_95=None)
    boot = values[rng.integers(0, len(values), (count, len(values)))].mean(axis=1)
    return dict(n=len(values), mean=float(values.mean()), std=float(values.std(ddof=1)) if len(values)>1 else None,
                median=float(np.median(values)), minimum=float(values.min()), maximum=float(values.max()),
                ci_lower_95=float(np.quantile(boot,.025)) if len(values)>1 else None,
                ci_upper_95=float(np.quantile(boot,.975)) if len(values)>1 else None)
