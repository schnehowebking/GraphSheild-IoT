#!/usr/bin/env python3
"""Stream official external flow sources into auditable five-second windows.

The produced features are diagnostic, feature-compatible proxies. They are not
declared semantically identical to controller switch-destination telemetry.
Labels are accumulated separately and attached only after feature aggregation.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import sqlite3
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, TextIO

import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
FEATURES = [
    "pkt_rate", "byte_rate", "pkt_sum", "events", "unique_src",
    "src_ip_entropy", "flow_count", "flow_rate",
]
WINDOW_COLUMNS = [
    "dataset_id", "scenario_id", "source_file", "segment_id",
    "window_start_epoch", "window_start_ts", "window_end_ts", *FEATURES,
    "label", "target_label", "target_eligible", "attack_fraction",
    "raw_rows", "label_types", "timestamp_basis", "measurement_type",
]


def json_dump(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256(path: Path, block: int = 8 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for data in iter(lambda: handle.read(block), b""):
            digest.update(data)
    return digest.hexdigest()


def entropy(counts: Counter[str]) -> float:
    total = sum(counts.values())
    if not total:
        return 0.0
    # Round-off can otherwise yield tiny negatives (about -1e-15).
    return max(0.0, -sum((n / total) * math.log2(n / total) for n in counts.values() if n))


def iso_time(epoch: int, basis: str) -> str:
    value = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return value if basis == "unix_utc" else value.removesuffix("Z") + "[timezone_unspecified]"


@dataclass
class WindowState:
    epoch: int
    rows: int = 0
    packets: float = 0.0
    bytes_: float = 0.0
    binary_attack_rows: int = 0
    target_attack_rows: int = 0
    other_attack_rows: int = 0
    sources: Counter[str] = field(default_factory=Counter)
    label_types: set[str] = field(default_factory=set)

    def add_frame(self, frame: pd.DataFrame) -> None:
        self.rows += len(frame)
        self.packets += float(frame["_packets"].sum())
        self.bytes_ += float(frame["_bytes"].sum())
        self.binary_attack_rows += int(frame["_binary"].sum())
        self.target_attack_rows += int(frame["_target"].sum())
        self.other_attack_rows += int(frame["_other"].sum())
        values = frame["_src"].astype(str)
        self.sources.update(values[values.ne("") & values.ne("-")].value_counts().to_dict())
        self.label_types.update(str(v) for v in frame["_label_text"].dropna().unique())

    def add_values(
        self, src: str, packets: float, bytes_: float, binary: int,
        target: int, other: int, label_text: str,
    ) -> None:
        self.rows += 1
        self.packets += packets
        self.bytes_ += bytes_
        self.binary_attack_rows += binary
        self.target_attack_rows += target
        self.other_attack_rows += other
        if src and src != "-":
            self.sources[src] += 1
        if label_text:
            self.label_types.add(label_text)


class WindowWriter:
    def __init__(self, path: Path, dataset: str, window_seconds: int = 5) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = path.open("w", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(self.handle, fieldnames=WINDOW_COLUMNS)
        self.writer.writeheader()
        self.dataset = dataset
        self.window_seconds = window_seconds
        self.state: WindowState | None = None
        self.scenario = ""
        self.source_file = ""
        self.segment = 0
        self.basis = "unix_utc"
        self.windows = 0
        self.label_counts = Counter()
        self.target_counts = Counter()

    def start_source(self, scenario: str, source_file: str, basis: str) -> None:
        self.flush()
        self.scenario, self.source_file, self.basis = scenario, source_file, basis
        self.segment = 0

    def new_segment(self) -> None:
        self.flush()
        self.segment += 1

    def add_frame(self, epoch: int, frame: pd.DataFrame) -> None:
        if self.state is None:
            self.state = WindowState(epoch)
        elif epoch != self.state.epoch:
            if epoch < self.state.epoch:
                raise ValueError("Non-monotonic window reached without a segment reset")
            self.flush()
            self.state = WindowState(epoch)
        self.state.add_frame(frame)

    def add_values(self, epoch: int, *values: object) -> None:
        if self.state is None:
            self.state = WindowState(epoch)
        elif epoch != self.state.epoch:
            if epoch < self.state.epoch:
                raise ValueError("Non-monotonic window reached without a segment reset")
            self.flush()
            self.state = WindowState(epoch)
        self.state.add_values(*values)  # type: ignore[arg-type]

    def flush(self) -> None:
        state = self.state
        if state is None:
            return
        label = int(state.binary_attack_rows > 0)
        target = int(state.target_attack_rows > 0)
        self.writer.writerow({
            "dataset_id": self.dataset,
            "scenario_id": f"{self.scenario}__segment_{self.segment}",
            "source_file": self.source_file,
            "segment_id": self.segment,
            "window_start_epoch": state.epoch,
            "window_start_ts": iso_time(state.epoch, self.basis),
            "window_end_ts": iso_time(state.epoch + self.window_seconds, self.basis),
            "pkt_rate": state.packets / self.window_seconds,
            "byte_rate": state.bytes_ / self.window_seconds,
            "pkt_sum": state.packets,
            "events": state.rows,
            "unique_src": len(state.sources),
            "src_ip_entropy": entropy(state.sources),
            "flow_count": state.rows,
            "flow_rate": state.rows / self.window_seconds,
            "label": label,
            "target_label": target,
            "target_eligible": int(state.other_attack_rows == 0),
            "attack_fraction": state.binary_attack_rows / state.rows,
            "raw_rows": state.rows,
            "label_types": ";".join(sorted(state.label_types)),
            "timestamp_basis": self.basis,
            "measurement_type": "offline_flow_derived_diagnostic",
        })
        self.windows += 1
        self.label_counts[label] += 1
        if state.other_attack_rows == 0:
            self.target_counts[target] += 1
        self.state = None

    def write_aggregate(
        self, scenario: str, epoch: int, rows: int, packets: float, bytes_: float,
        binary_rows: int, target_rows: int, other_rows: int, unique_src: int,
        source_entropy: float, label_types: str,
    ) -> None:
        self.flush()
        label, target = int(binary_rows > 0), int(target_rows > 0)
        self.writer.writerow({
            "dataset_id": self.dataset, "scenario_id": scenario,
            "source_file": self.source_file, "segment_id": 0,
            "window_start_epoch": epoch, "window_start_ts": iso_time(epoch, self.basis),
            "window_end_ts": iso_time(epoch + self.window_seconds, self.basis),
            "pkt_rate": packets / self.window_seconds,
            "byte_rate": bytes_ / self.window_seconds, "pkt_sum": packets,
            "events": rows, "unique_src": unique_src,
            "src_ip_entropy": source_entropy, "flow_count": rows,
            "flow_rate": rows / self.window_seconds, "label": label,
            "target_label": target, "target_eligible": int(other_rows == 0),
            "attack_fraction": binary_rows / rows, "raw_rows": rows,
            "label_types": label_types, "timestamp_basis": self.basis,
            "measurement_type": "offline_flow_derived_diagnostic",
        })
        self.windows += 1
        self.label_counts[label] += 1
        if other_rows == 0:
            self.target_counts[target] += 1

    def close(self) -> None:
        self.flush()
        self.handle.close()


def safe_numeric(series: pd.Series) -> tuple[pd.Series, int]:
    values = pd.to_numeric(series, errors="coerce")
    values = values.replace([np.inf, -np.inf], np.nan)
    invalid = int((series.notna() & values.isna()).sum())
    return values.fillna(0.0).clip(lower=0.0), invalid


def process_monotonic_frame(frame: pd.DataFrame, writer: WindowWriter, stats: dict) -> None:
    if frame.empty:
        return
    frame = frame.sort_index()
    times = frame["_ts"].to_numpy(dtype="float64")
    cuts = (np.flatnonzero(np.diff(times) < 0) + 1).tolist()
    starts = [0, *cuts]
    ends = [*cuts, len(frame)]
    for position, (start, end) in enumerate(zip(starts, ends)):
        part = frame.iloc[start:end]
        if position or (stats.get("last_ts") is not None and float(part["_ts"].iloc[0]) < stats["last_ts"]):
            writer.new_segment()
            stats["out_of_order_resets"] += 1
        part = part.copy()
        part["_window"] = (np.floor(part["_ts"] / 5.0) * 5).astype("int64")
        for epoch, group in part.groupby("_window", sort=False):
            writer.add_frame(int(epoch), group)
        stats["last_ts"] = float(part["_ts"].iloc[-1])


def cic_files(root: Path) -> list[Path]:
    return sorted((root / "CIC-DDoS2019" / "CSVs").rglob("*.csv"))


def process_cic(root: Path, output: Path, max_rows: int | None, chunksize: int) -> dict:
    files = cic_files(root)
    writer = WindowWriter(output, "cicddos2019")
    stats: dict[str, object] = {
        "files": len(files), "raw_rows": 0, "dropped_bad_timestamps": 0,
        "numeric_coercions": 0, "out_of_order_resets": 0, "last_ts": None,
    }
    wanted = {
        "Timestamp", "Source IP", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Label",
    }
    try:
        for path in files:
            relative = path.relative_to(root).as_posix()
            scenario = re.sub(r"\W+", "_", f"{path.parent.name}_{path.stem}").strip("_").lower()
            writer.start_source(scenario, relative, "local_time_timezone_unspecified")
            stats["last_ts"] = None
            read_rows = 0
            for chunk in pd.read_csv(
                path, usecols=lambda name: name.strip() in wanted, chunksize=chunksize,
                low_memory=False,
            ):
                chunk.rename(columns=lambda name: name.strip(), inplace=True)
                if max_rows is not None:
                    chunk = chunk.head(max_rows - read_rows)
                if chunk.empty:
                    break
                read_rows += len(chunk)
                stats["raw_rows"] = int(stats["raw_rows"]) + len(chunk)
                ts = pd.to_datetime(
                    chunk["Timestamp"].astype(str).str.strip(), format="mixed",
                    dayfirst=True, errors="coerce",
                )
                bad = ts.isna()
                stats["dropped_bad_timestamps"] = int(stats["dropped_bad_timestamps"]) + int(bad.sum())
                chunk = chunk.loc[~bad].copy()
                ts = ts.loc[~bad]
                if chunk.empty:
                    continue
                chunk["_ts"] = ts.astype("int64") / 1_000_000_000
                fwd_pkt, bad1 = safe_numeric(chunk["Total Fwd Packets"])
                bwd_pkt, bad2 = safe_numeric(chunk["Total Backward Packets"])
                fwd_b, bad3 = safe_numeric(chunk["Total Length of Fwd Packets"])
                bwd_b, bad4 = safe_numeric(chunk["Total Length of Bwd Packets"])
                stats["numeric_coercions"] = int(stats["numeric_coercions"]) + bad1 + bad2 + bad3 + bad4
                labels = chunk["Label"].astype(str).str.strip()
                binary = ~labels.str.lower().isin({"benign", "normal", "0"})
                chunk["_packets"] = fwd_pkt + bwd_pkt
                chunk["_bytes"] = fwd_b + bwd_b
                chunk["_src"] = chunk["Source IP"].fillna("").astype(str).str.strip()
                chunk["_binary"] = binary.astype("int8")
                chunk["_target"] = chunk["_binary"]
                chunk["_other"] = 0
                chunk["_label_text"] = labels
                process_monotonic_frame(chunk, writer, stats)
                if max_rows is not None and read_rows >= max_rows:
                    break
    finally:
        writer.close()
    stats.pop("last_ts", None)
    stats.update({"windows": writer.windows, "window_label_counts": dict(writer.label_counts)})
    return stats


def parse_zeek_tail(value: str) -> tuple[str, str, str]:
    parts = re.split(r"\s{2,}", value.strip(), maxsplit=2)
    while len(parts) < 3:
        parts.append("")
    return parts[0], parts[1], parts[2]


def number(value: str) -> tuple[float, int]:
    if value in {"", "-", "(empty)"}:
        return 0.0, 0
    try:
        result = float(value)
        if not math.isfinite(result) or result < 0:
            return 0.0, 1
        return result, 0
    except ValueError:
        return 0.0, 1


def process_iot23(root: Path, output: Path, max_rows: int | None) -> dict:
    files = sorted((root / "IoT23").rglob("*.labeled"))
    writer = WindowWriter(output, "iot23")
    work_db = output.with_suffix(".work.sqlite")
    connection = sqlite3.connect(work_db)
    connection.executescript("""
        PRAGMA journal_mode=OFF;
        PRAGMA synchronous=OFF;
        PRAGMA temp_store=MEMORY;
        CREATE TABLE windows (
          scenario TEXT NOT NULL, epoch INTEGER NOT NULL, rows INTEGER NOT NULL,
          packets REAL NOT NULL, bytes REAL NOT NULL, binary_rows INTEGER NOT NULL,
          target_rows INTEGER NOT NULL, other_rows INTEGER NOT NULL,
          PRIMARY KEY (scenario, epoch));
        CREATE TABLE sources (
          scenario TEXT NOT NULL, epoch INTEGER NOT NULL, src TEXT NOT NULL, n INTEGER NOT NULL,
          PRIMARY KEY (scenario, epoch, src));
        CREATE TABLE labels (
          scenario TEXT NOT NULL, epoch INTEGER NOT NULL, label TEXT NOT NULL,
          PRIMARY KEY (scenario, epoch, label));
    """)
    stats = {
        "files": len(files), "raw_rows": 0, "dropped_bad_timestamps": 0,
        "numeric_coercions": 0, "out_of_order_resets": 0,
        "aggregation_engine": "sqlite_exact_arbitrary_order",
    }
    window_batch: dict[tuple[str, int], list[float]] = {}
    source_batch: Counter[tuple[str, int, str]] = Counter()
    label_batch: set[tuple[str, int, str]] = set()

    def flush_batch() -> None:
        if not window_batch:
            return
        connection.executemany(
            """INSERT INTO windows VALUES (?,?,?,?,?,?,?,?)
            ON CONFLICT(scenario,epoch) DO UPDATE SET
              rows=rows+excluded.rows, packets=packets+excluded.packets,
              bytes=bytes+excluded.bytes, binary_rows=binary_rows+excluded.binary_rows,
              target_rows=target_rows+excluded.target_rows,
              other_rows=other_rows+excluded.other_rows""",
            [(s, e, int(v[0]), v[1], v[2], int(v[3]), int(v[4]), int(v[5]))
             for (s, e), v in window_batch.items()],
        )
        connection.executemany(
            """INSERT INTO sources VALUES (?,?,?,?)
            ON CONFLICT(scenario,epoch,src) DO UPDATE SET n=n+excluded.n""",
            [(s, e, src, n) for (s, e, src), n in source_batch.items()],
        )
        connection.executemany("INSERT OR IGNORE INTO labels VALUES (?,?,?)", list(label_batch))
        connection.commit(); window_batch.clear(); source_batch.clear(); label_batch.clear()

    try:
        for path in files:
            relative = path.relative_to(root).as_posix()
            scenario = path.parent.parent.name
            writer.start_source(scenario, relative, "unix_utc")
            read_rows = 0
            with path.open("r", encoding="utf-8", errors="strict", newline="") as handle:
                for line in handle:
                    if not line or line.startswith("#"):
                        continue
                    if max_rows is not None and read_rows >= max_rows:
                        break
                    read_rows += 1
                    stats["raw_rows"] += 1
                    values = line.rstrip("\r\n").split("\t")
                    if len(values) < 21:
                        raise ValueError(f"Malformed IoT-23 row in {path}: expected >=21 tab fields")
                    try:
                        ts = float(values[0])
                    except ValueError:
                        stats["dropped_bad_timestamps"] += 1
                        continue
                    tunnel, label, detail = parse_zeek_tail(values[20])
                    del tunnel
                    orig_pkts, b1 = number(values[16]); resp_pkts, b2 = number(values[18])
                    orig_ip, b3 = number(values[17]); resp_ip, b4 = number(values[19])
                    orig_b, b5 = number(values[9]); resp_b, b6 = number(values[10])
                    stats["numeric_coercions"] += b1 + b2 + b3 + b4 + b5 + b6
                    packets = orig_pkts + resp_pkts
                    bytes_ = orig_ip + resp_ip
                    if bytes_ <= 0:
                        bytes_ = orig_b + resp_b
                    normalized = label.strip().lower()
                    binary = int(normalized not in {"benign", "normal", "0"})
                    target = int("ddos" in detail.lower())
                    other = int(binary and not target)
                    epoch = int(math.floor(ts / 5.0) * 5)
                    label_text = label.strip() + (":" + detail.strip() if detail.strip() not in {"", "-"} else "")
                    key = (scenario, epoch)
                    rec = window_batch.setdefault(key, [0.0] * 6)
                    rec[0] += 1; rec[1] += packets; rec[2] += bytes_
                    rec[3] += binary; rec[4] += target; rec[5] += other
                    src = values[2].strip()
                    if src and src != "-": source_batch[(scenario, epoch, src)] += 1
                    if label_text: label_batch.add((scenario, epoch, label_text))
                    if len(window_batch) >= 10_000 or len(source_batch) >= 250_000:
                        flush_batch()
        flush_batch()
        source_summary = {
            (row[0], row[1]): (int(row[2]), int(row[3]), float(row[4]))
            for row in connection.execute(
                """SELECT scenario, epoch, SUM(n), COUNT(*),
                   (ln(SUM(n)) - SUM(n * ln(n)) / SUM(n)) / ln(2.0)
                   FROM sources GROUP BY scenario, epoch"""
            )
        }
        labels = {
            (row[0], row[1]): row[2]
            for row in connection.execute(
                "SELECT scenario, epoch, group_concat(label, ';') FROM labels GROUP BY scenario, epoch"
            )
        }
        writer.source_file = "multiple_scenario_logs; see source_files.csv"
        writer.basis = "unix_utc"
        for row in connection.execute(
            "SELECT scenario,epoch,rows,packets,bytes,binary_rows,target_rows,other_rows FROM windows ORDER BY scenario,epoch"
        ):
            key = (row[0], row[1]); total, unique, ent = source_summary.get(key, (0, 0, 0.0))
            del total
            writer.write_aggregate(
                row[0], int(row[1]), int(row[2]), float(row[3]), float(row[4]),
                int(row[5]), int(row[6]), int(row[7]), unique, ent, labels.get(key, ""),
            )
    finally:
        connection.close()
        writer.close()
        if work_db.exists():
            work_db.unlink()
    stats.update({
        "windows": writer.windows, "window_label_counts": dict(writer.label_counts),
        "eligible_ddos_window_counts": dict(writer.target_counts),
    })
    return stats


def toniot_files(root: Path) -> list[Path]:
    folder = root / "TON_IoT_datasets" / "Processed_datasets" / "Processed_Network_dataset"
    return sorted(folder.glob("Network_dataset_*.csv"), key=lambda p: int(p.stem.rsplit("_", 1)[1]))


def process_toniot(root: Path, output: Path, max_rows: int | None, chunksize: int) -> dict:
    files = toniot_files(root)
    writer = WindowWriter(output, "toniot")
    stats: dict[str, object] = {
        "files": len(files), "raw_rows": 0, "dropped_bad_timestamps": 0,
        "numeric_coercions": 0, "out_of_order_resets": 0, "last_ts": None,
    }
    wanted = {
        "ts", "src_ip", "src_pkts", "dst_pkts", "src_ip_bytes", "dst_ip_bytes",
        "src_bytes", "dst_bytes", "label", "type",
    }
    try:
        for path in files:
            relative = path.relative_to(root).as_posix()
            writer.start_source(path.stem.lower(), relative, "unix_utc")
            stats["last_ts"] = None
            read_rows = 0
            for chunk in pd.read_csv(
                path, usecols=lambda name: name.strip() in wanted, chunksize=chunksize,
                low_memory=False,
            ):
                chunk.rename(columns=lambda name: name.strip(), inplace=True)
                if max_rows is not None:
                    chunk = chunk.head(max_rows - read_rows)
                if chunk.empty:
                    break
                read_rows += len(chunk)
                stats["raw_rows"] = int(stats["raw_rows"]) + len(chunk)
                ts = pd.to_numeric(chunk["ts"], errors="coerce")
                bad = ts.isna() | ~np.isfinite(ts)
                stats["dropped_bad_timestamps"] = int(stats["dropped_bad_timestamps"]) + int(bad.sum())
                chunk = chunk.loc[~bad].copy(); ts = ts.loc[~bad]
                if chunk.empty:
                    continue
                chunk["_ts"] = ts.astype(float)
                sp, b1 = safe_numeric(chunk["src_pkts"]); dp, b2 = safe_numeric(chunk["dst_pkts"])
                sib, b3 = safe_numeric(chunk["src_ip_bytes"]); dib, b4 = safe_numeric(chunk["dst_ip_bytes"])
                sb, b5 = safe_numeric(chunk["src_bytes"]); db, b6 = safe_numeric(chunk["dst_bytes"])
                stats["numeric_coercions"] = int(stats["numeric_coercions"]) + b1+b2+b3+b4+b5+b6
                ip_bytes = sib + dib; fallback = sb + db
                labels = pd.to_numeric(chunk["label"], errors="coerce").fillna(0).gt(0)
                types = chunk["type"].fillna("").astype(str).str.strip().str.lower()
                target = types.str.contains(r"(?:^|[^a-z])d?dos(?:[^a-z]|$)", regex=True)
                chunk["_packets"] = sp + dp
                chunk["_bytes"] = ip_bytes.where(ip_bytes.gt(0), fallback)
                chunk["_src"] = chunk["src_ip"].fillna("").astype(str).str.strip()
                chunk["_binary"] = labels.astype("int8")
                chunk["_target"] = target.astype("int8")
                chunk["_other"] = (labels & ~target).astype("int8")
                chunk["_label_text"] = types
                process_monotonic_frame(chunk, writer, stats)
                if max_rows is not None and read_rows >= max_rows:
                    break
    finally:
        writer.close()
    stats.pop("last_ts", None)
    stats.update({
        "windows": writer.windows, "window_label_counts": dict(writer.label_counts),
        "eligible_ddos_dos_window_counts": dict(writer.target_counts),
    })
    return stats


def feature_semantics_rows() -> list[dict[str, str]]:
    definitions = {
        "pkt_sum": ("sum of flow-record packet totals in each 5-second source window", "conditional_proxy"),
        "pkt_rate": ("pkt_sum / 5 seconds", "conditional_proxy"),
        "byte_rate": ("sum of flow-record IP-byte totals / 5 seconds", "conditional_proxy"),
        "events": ("number of flow records", "not_equivalent_to_controller_updates"),
        "unique_src": ("distinct flow source addresses", "conditional_proxy"),
        "src_ip_entropy": ("Shannon entropy weighted by flow-record occurrence", "not_equivalent_to_controller_event_weighting"),
        "flow_count": ("number of completed flow records", "not_equivalent_to_flow_table_occupancy"),
        "flow_rate": ("flow_count / 5 seconds", "not_equivalent_to_controller_flow_rate"),
    }
    return [
        {"feature": name, "external_definition": definitions[name][0], "equivalence": definitions[name][1]}
        for name in FEATURES
    ]


def source_records(root: Path, selected: Iterable[Path]) -> list[dict[str, object]]:
    rows = []
    for path in selected:
        stat = path.stat()
        rows.append({
            "relative_path": path.relative_to(root).as_posix(), "bytes": stat.st_size,
            "modified_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
            "sha256": "deferred_to_final_hash_pass",
        })
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-root", default=str(ROOT / "dataset" / "datasetsforexternalaudit"))
    parser.add_argument("--output", default=str(ROOT / "results" / "external_raw_processing_v1"))
    parser.add_argument("--datasets", nargs="+", choices=["cic", "iot23", "toniot"], default=["cic", "iot23", "toniot"])
    parser.add_argument("--chunksize", type=int, default=200_000)
    parser.add_argument("--max-rows-per-file", type=int)
    args = parser.parse_args()

    root, output = Path(args.input_root).resolve(), Path(args.output).resolve()
    if not root.is_dir():
        raise FileNotFoundError(root)
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite existing output: {output}")
    available = {'cic': cic_files(root), 'iot23': sorted((root/'IoT23').rglob('*.labeled')),
                 'toniot': toniot_files(root)}
    for name in args.datasets:
        if not available[name]:
            raise FileNotFoundError(f'No source files for {name}; see docs/EXTERNAL_REPRODUCTION.md')
    (output / "windows").mkdir(parents=True)
    started = time.time()
    results: dict[str, object] = {}
    selected: list[Path] = []
    if "cic" in args.datasets:
        selected += cic_files(root)
        results["CIC-DDoS2019"] = process_cic(root, output / "windows" / "cicddos2019_windows.csv", args.max_rows_per_file, args.chunksize)
    if "iot23" in args.datasets:
        paths = sorted((root / "IoT23").rglob("*.labeled")); selected += paths
        results["IoT-23"] = process_iot23(root, output / "windows" / "iot23_windows.csv", args.max_rows_per_file)
    if "toniot" in args.datasets:
        selected += toniot_files(root)
        results["TON_IoT"] = process_toniot(root, output / "windows" / "toniot_windows.csv", args.max_rows_per_file, args.chunksize)

    with (output / "source_files.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["relative_path", "bytes", "modified_utc", "sha256"])
        writer.writeheader(); writer.writerows(source_records(root, selected))
    with (output / "feature_semantics.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["feature", "external_definition", "equivalence"])
        writer.writeheader(); writer.writerows(feature_semantics_rows())
    manifest = {
        "version": "external_raw_processing_v1", "created_at": datetime.now(timezone.utc).isoformat(),
        "input_root": root.as_posix(), "window_seconds": 5, "chunksize": args.chunksize,
        "max_rows_per_file": args.max_rows_per_file, "datasets": results,
        "label_policy": "features aggregated without labels; window label attached afterward as any attack row",
        "target_policy": "DDoS/DoS target uses only eligible benign-or-target windows; other-malicious windows are excluded after aggregation",
        "measurement_type": "offline flow-derived diagnostic; not controller-telemetry equivalent",
        "runtime_seconds": time.time() - started,
    }
    json_dump(output / "processing_manifest.json", manifest)
    generated = [p for p in output.rglob("*") if p.is_file() and p.name != "CHECKSUMS.sha256"]
    (output / "CHECKSUMS.sha256").write_text(
        "".join(f"{sha256(p)}  {p.relative_to(output).as_posix()}\n" for p in sorted(generated)),
        encoding="utf-8",
    )
    (output / "README.md").write_text(
        "# External raw processing v1\n\n"
        "Generated by `scripts/process_external_raw_datasets.py`. Source files are read-only. "
        "Outputs are five-second offline flow-derived diagnostic windows and are not claimed "
        "semantically identical to GraphShield controller telemetry. Labels are attached after "
        "feature aggregation. See `feature_semantics.csv` and `processing_manifest.json`.\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
