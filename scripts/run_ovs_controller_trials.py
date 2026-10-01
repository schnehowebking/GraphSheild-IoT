#!/usr/bin/env python3
"""Run paired model-driven trials through real Linux namespaces and Open vSwitch.

Run as root on an authorized Kali or Ubuntu lab host. Ground-truth phases are
used only after controller inference for evaluation.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import time
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reviewer_revision.core import FEATURES, RuntimeDetector  # noqa: E402
from sdn import CompletedWindowController  # noqa: E402

COOKIE_TRACK = "0x475401"
COOKIE_METER = "0x475402"
SERVER_IP = "10.253.0.3"
DEFAULT_BENIGN_RATES = (0.5, 1.0, 1.5, 2.0, 3.0, 5.0, 8.0)
DEFAULT_ATTACK_RATES = (5.0, 10.0, 20.0, 35.0, 50.0, 70.0)


def command(args, *, check=True, text=True):
    return subprocess.run(args, check=check, capture_output=True, text=text)


def version(command_args):
    try:
        result = command(command_args)
        return (result.stdout or result.stderr).splitlines()[0]
    except Exception as exc:
        return f"unavailable: {exc}"


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def entropy(items):
    counts = Counter(items)
    total = sum(counts.values())
    return 0.0 if not total else -sum((n / total) * math.log2(n / total) for n in counts.values())


def parse_flow_counters(text, server_ip=SERVER_IP):
    """Return source -> (packets, bytes) for installed tracking flows."""
    result = {}
    for line in text.splitlines():
        if not any(f"cookie={cookie}" in line for cookie in [COOKIE_TRACK, COOKIE_METER]) or f"nw_dst={server_ip}" not in line:
            continue
        src = re.search(r"nw_src=([0-9.]+)", line)
        packets = re.search(r"n_packets=(\d+)", line)
        bytes_ = re.search(r"n_bytes=(\d+)", line)
        if src and packets and bytes_:
            key = src.group(1)
            old_packets, old_bytes = result.get(key, (0, 0))
            result[key] = (old_packets + int(packets.group(1)), old_bytes + int(bytes_.group(1)))
    return result


def binary_metrics(labels, predictions):
    y, p = np.asarray(labels, dtype=int), np.asarray(predictions, dtype=int)
    tn = int(((y == 0) & (p == 0)).sum()); fp = int(((y == 0) & (p == 1)).sum())
    fn = int(((y == 1) & (p == 0)).sum()); tp = int(((y == 1) & (p == 1)).sum())
    ratio = lambda a, b: float(a / b) if b else None
    precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    # The confusion-count definition is zero when TP=0 and FP+FN>0.  It is
    # undefined only for an all-negative set with no positive prediction.
    f1 = ratio(2 * tp, 2 * tp + fp + fn)
    undefined = []
    if precision is None: undefined.append("precision: zero predicted positives")
    if recall is None: undefined.append("recall: zero actual positives")
    if f1 is None: undefined.append("f1: zero denominator")
    return {"n": len(y), "tn": tn, "fp": fp, "fn": fn, "tp": tp,
            "accuracy": float((tn + tp) / len(y)), "precision": precision, "recall": recall,
            "f1": f1, "fpr": ratio(fp, fp + tn), "fnr": ratio(fn, fn + tp),
            "benign_damage": ratio(fp, fp + tn), "undefined_metrics": "; ".join(undefined)}


class OvsLab:
    def __init__(self, token, meter_rate_kbps, max_attackers=1):
        if not 1 <= int(max_attackers) <= 8:
            raise ValueError("max_attackers must be between 1 and 8")
        self.bridge = f"gs{token}"[:15]
        self.attackers = [f"attacker_{index}" for index in range(1, int(max_attackers) + 1)]
        self.namespaces = {"benign": f"{token}b", "server": f"{token}s"}
        self.namespaces.update({role: f"{token}a{index}" for index, role in enumerate(self.attackers, start=1)})
        self.hosts = {"benign": "10.253.0.1", "server": SERVER_IP}
        self.hosts.update({role: f"10.253.0.{10 + index}" for index, role in enumerate(self.attackers, start=1)})
        self.meter_rate_kbps = int(meter_rate_kbps)
        self.servers = []

    def setup(self):
        command(["ovs-vsctl", "add-br", self.bridge])
        command(["ovs-vsctl", "set", "bridge", self.bridge, "protocols=OpenFlow13", "fail_mode=standalone"])
        for index, role in enumerate(["benign", *self.attackers, "server"], start=1):
            ns, outer, inner = self.namespaces[role], f"o{self.bridge}{index}"[:15], f"i{self.bridge}{index}"[:15]
            command(["ip", "netns", "add", ns])
            command(["ip", "link", "add", outer, "type", "veth", "peer", "name", inner])
            command(["ip", "link", "set", inner, "netns", ns])
            command(["ip", "link", "set", outer, "up"])
            command(["ovs-vsctl", "add-port", self.bridge, outer])
            command(["ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"])
            command(["ip", "netns", "exec", ns, "ip", "addr", "add", f"{self.hosts[role]}/24", "dev", inner])
            command(["ip", "netns", "exec", ns, "ip", "link", "set", inner, "up"])
        command(["ovs-ofctl", "-O", "OpenFlow13", "add-flow", self.bridge, "priority=0,actions=NORMAL"])
        for src in [self.hosts["benign"], *[self.hosts[role] for role in self.attackers]]:
            flow = f"cookie={COOKIE_TRACK},priority=100,ip,nw_src={src},nw_dst={SERVER_IP},actions=NORMAL"
            command(["ovs-ofctl", "-O", "OpenFlow13", "add-flow", self.bridge, flow])
        for port in [5201, *[5201 + index for index in range(1, len(self.attackers) + 1)]]:
            self.servers.append(subprocess.Popen(
                ["ip", "netns", "exec", self.namespaces["server"], "iperf3", "-s", "-p", str(port)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        time.sleep(0.5)
        command(["ip", "netns", "exec", self.namespaces["benign"], "ping", "-c", "1", "-W", "2", SERVER_IP])

    def dump_flows(self):
        return command(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", self.bridge]).stdout

    def clear_meter(self):
        command(["ovs-ofctl", "-O", "OpenFlow13", "del-flows", self.bridge,
                 f"cookie={COOKIE_METER}/0xffffffffffffffff"], check=False)
        command(["ovs-ofctl", "-O", "OpenFlow13", "del-meters", self.bridge], check=False)

    def set_rate_limit(self, source_ip, ttl_seconds=15):
        if not 1 <= int(ttl_seconds) <= 30:
            raise ValueError("Meter rule TTL must be 1..30 seconds")
        self.clear_meter()
        meter = f"meter=1,kbps,band=type=drop,rate={self.meter_rate_kbps}"
        command(["ovs-ofctl", "-O", "OpenFlow13", "add-meter", self.bridge, meter])
        flow = (f"cookie={COOKIE_METER},hard_timeout={int(ttl_seconds)},priority=300,ip,nw_src={source_ip},nw_dst={SERVER_IP},"
                "actions=meter:1,NORMAL")
        command(["ovs-ofctl", "-O", "OpenFlow13", "add-flow", self.bridge, flow])
        evidence = self.dump_flows() + "\n" + command(
            ["ovs-ofctl", "-O", "OpenFlow13", "dump-meters", self.bridge]).stdout
        if COOKIE_METER not in evidence or "meter=1" not in evidence:
            raise RuntimeError("Model-driven OpenFlow meter was not observable after installation")

    def start_traffic(self, benign_mbps, attack_mbps, active_attackers, duration, log_dir):
        processes = []
        active_attackers = int(active_attackers)
        if not 0 <= active_attackers <= len(self.attackers):
            raise ValueError("active_attackers exceeds configured attacker namespaces")
        specifications = [("benign", 5201, benign_mbps, "benign")]
        if attack_mbps > 0:
            if not active_attackers:
                raise ValueError("Positive attack traffic requires at least one active attacker")
            per_attacker = float(attack_mbps) / active_attackers
            specifications.extend((role, 5201 + index, per_attacker, f"attack_{index:02d}")
                                  for index, role in enumerate(self.attackers[:active_attackers], start=1))
        for role, port, rate, name in specifications:
            handle = (log_dir / f"iperf_{name}.json").open("w", encoding="utf-8")
            process = subprocess.Popen([
                "ip", "netns", "exec", self.namespaces[role], "iperf3", "-c", SERVER_IP,
                "-p", str(port), "-u", "-b", f"{rate:.3f}M", "-t", str(duration), "-J"],
                stdout=handle, stderr=subprocess.STDOUT, text=True)
            processes.append((process, handle))
        return processes

    def close(self):
        self.clear_meter()
        for process in self.servers:
            process.terminate()
            try: process.wait(timeout=2)
            except subprocess.TimeoutExpired: process.kill()
        for ns in self.namespaces.values():
            command(["ip", "netns", "del", ns], check=False)
        command(["ovs-vsctl", "--if-exists", "del-br", self.bridge], check=False)


@contextmanager
def ovs_lab(token, meter_rate, max_attackers=1):
    lab = OvsLab(token, meter_rate, max_attackers=max_attackers)
    try:
        lab.setup()
        yield lab
    finally:
        lab.close()


def schedule(seed, benign_windows, attack_windows, recovery_windows, max_attackers=1,
             benign_rates=DEFAULT_BENIGN_RATES, attack_rates=DEFAULT_ATTACK_RATES):
    rng = np.random.default_rng(seed)
    rows = []
    attacker_choices = sorted(set([1, min(2, int(max_attackers)), int(max_attackers)]))
    for phase, count in [("benign", benign_windows), ("attack", attack_windows), ("recovery", recovery_windows)]:
        for _ in range(count):
            rows.append({"phase": phase, "label": int(phase == "attack"),
                         "benign_mbps": float(rng.choice(benign_rates)),
                         "attack_mbps": float(rng.choice(attack_rates)) if phase == "attack" else 0.0,
                         "active_attackers": int(rng.choice(attacker_choices)) if phase == "attack" else 0})
    return rows


def collect_window(lab, item, seconds, poll_seconds, log_dir):
    previous = parse_flow_counters(lab.dump_flows())
    traffic = lab.start_traffic(item["benign_mbps"], item["attack_mbps"], item["active_attackers"], seconds, log_dir)
    packet_sum = byte_sum = flow_sum = events = 0
    sources, source_packets, source_bytes = [], Counter(), Counter()
    deadline = time.monotonic() + seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0: break
        time.sleep(min(poll_seconds, remaining))
        current = parse_flow_counters(lab.dump_flows())
        poll_had_traffic = False
        for src, (packets, bytes_) in current.items():
            old_packets, old_bytes = previous.get(src, (0, 0))
            dp, db = max(0, packets - old_packets), max(0, bytes_ - old_bytes)
            if dp or db:
                packet_sum += dp; byte_sum += db; flow_sum += 1; poll_had_traffic = True
                sources.append(src); source_packets[src] += dp; source_bytes[src] += db
        if poll_had_traffic:
            events += 1
        previous = current
    for process, handle in traffic:
        try: process.wait(timeout=3)
        except subprocess.TimeoutExpired: process.kill(); process.wait()
        handle.close()
        if process.returncode != 0:
            raise RuntimeError(f"iperf3 client failed with exit code {process.returncode}")
    features = {
        "pkt_rate": packet_sum / seconds, "byte_rate": byte_sum / seconds,
        "pkt_sum": float(packet_sum), "events": float(events),
        "unique_src": float(len(set(sources))), "src_ip_entropy": float(entropy(sources)),
        "flow_count": float(flow_sum if flow_sum else events),
        "flow_rate": float((flow_sum if flow_sum else events) / seconds),
    }
    assert list(features) == FEATURES and all(math.isfinite(v) and v >= 0 for v in features.values())
    observations = [{"source_ip": ip, "packets": int(source_packets[ip]),
                     "bytes": int(source_bytes[ip]), "duration_seconds": float(seconds)}
                    for ip in sorted(source_packets)]
    (log_dir / "source_observations.json").write_text(json.dumps(observations, indent=2) + "\n", encoding="utf-8")
    dominant = source_packets.most_common(1)[0][0] if source_packets else None
    return features, dominant, byte_sum * 8 / seconds / 1_000_000


def run_trial(output, seed, setting, args):
    trial = output / f"seed_{seed:08d}_{setting}"
    trial.mkdir()
    audit_enabled = setting == "audit_enabled"
    from reviewer_revision.source_selector import SourceSelector
    safety_policy = getattr(args, "source_policy", None)
    selector = SourceSelector(safety_policy) if safety_policy else None
    enforcement_enabled = setting != "mitigation_disabled"
    controller = CompletedWindowController(
        detector=RuntimeDetector(directory=Path(args.deployment_dir).resolve(),
                                 registry_path=Path(args.threshold_registry).resolve()),
        audit_path=trial / "audit.jsonl", audit_enabled=audit_enabled, source_selector=selector)
    rows, active_source = [], None
    token = f"g{os.getpid()%1000:03d}{seed%100:02d}{int(audit_enabled)}"
    with ovs_lab(token, args.meter_rate_kbps, args.max_attackers) as lab:
        capture = subprocess.Popen(
            ["tcpdump", "-i", "any", "-c", "2000", "-w", str(trial / "traffic_sample.pcap"),
             "net", "10.253.0.0/24"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        lab.servers.append(capture)
        (trial / "ovs_initial.txt").write_text(lab.dump_flows(), encoding="utf-8")
        # Ground-truth mapping is evaluation metadata; never passed to controller.
        (trial / "source_truth.json").write_text(json.dumps(
            {ip: int(role in lab.attackers) for role, ip in lab.hosts.items() if role != "server"}, indent=2), encoding="utf-8")
        for index, item in enumerate(schedule(seed, args.benign_windows, args.attack_windows,
                                              args.recovery_windows, args.max_attackers,
                                              getattr(args, "benign_rates", DEFAULT_BENIGN_RATES),
                                              getattr(args, "attack_rates", DEFAULT_ATTACK_RATES))):
            window_dir = trial / f"window_{index:03d}"; window_dir.mkdir()
            # Keep ground truth outside both feature extraction and inference.
            # It is joined to the saved record only after the controller returns.
            traffic_only = {key: item[key]
                            for key in ["benign_mbps", "attack_mbps", "active_attackers"]}
            features, dominant, throughput = collect_window(
                lab, traffic_only, args.window_seconds, args.poll_seconds, window_dir)
            started = time.perf_counter_ns()
            observations = json.loads((window_dir / "source_observations.json").read_text())
            response = controller.detect_completed_window(features, f"{platform.system()}-{seed}-{setting}-{index}",
                       source_observations=observations, window_index=index, enforcement_enabled=enforcement_enabled)
            inference_ms = (time.perf_counter_ns() - started) / 1e6
            enforcement_started = time.perf_counter_ns()
            if response["action"] == "RATE_LIMIT":
                lab.set_rate_limit(response["target_source"], response["rule_ttl_seconds"]); active_source = response["target_source"]
            else:
                lab.clear_meter(); active_source = None
            enforcement_ms = (time.perf_counter_ns() - enforcement_started) / 1e6
            enforcement_record = {"window_index": index, "selected_action": response["action"],
                "target_source": active_source, "applies_to_window": index + 1,
                "rule_ttl_seconds": response["rule_ttl_seconds"], "observed_flows": lab.dump_flows()}
            if response["action"] == "NONE" and COOKIE_METER in enforcement_record["observed_flows"]:
                raise RuntimeError("NONE action failed to remove active meter flow")
            (window_dir / "enforcement.json").write_text(json.dumps(enforcement_record, indent=2), encoding="utf-8")
            controller.record_enforcement(enforcement_record)
            rows.append({
                "seed": seed, "setting": setting, "window_index": index,
                "phase": item["phase"], "label": item["label"],
                "scheduled_benign_mbps": item["benign_mbps"], "scheduled_attack_mbps": item["attack_mbps"],
                "scheduled_attackers": item["active_attackers"],
                **features, "probability": response["probability"], "threshold": response["threshold"],
                "prediction": response["prediction"], "action": response["action"],
                "baseline_action": response["baseline_action"], "proposed_action": response["proposed_action"],
                "proposed_target": response["proposed_target"], "safety_reason": response["safety_reason"],
                "input_feature_hash": response["input_feature_hash"],
                "source_observations_hash": response["source_observations_hash"],
                "source_policy_hash": response["source_policy_hash"],
                "dominant_source": dominant, "rate_limited_source_for_next_window": active_source or "",
                "observed_throughput_mbps": throughput, "inference_latency_ms": inference_ms,
                "enforcement_latency_ms": enforcement_ms,
                "measurement_type": "actual_single_host_ovs_runtime",
                "ground_truth_use": "evaluation_only_after_inference",
                "model_hash": response["model_hash"],
                "threshold_selection_file": response["threshold_selection_file"],
            })
        controller.rollback_to_baseline()
        lab.clear_meter()
        final_evidence = lab.dump_flows() + "\n" + command(
            ["ovs-ofctl", "-O", "OpenFlow13", "dump-meters", lab.bridge]).stdout
        (trial / "ovs_final_after_rollback.txt").write_text(final_evidence, encoding="utf-8")
        rollback_ok = COOKIE_METER not in final_evidence and "meter=1" not in final_evidence
        if capture.poll() is None:
            capture.terminate()
            try: capture.wait(timeout=3)
            except subprocess.TimeoutExpired: capture.kill(); capture.wait()
    pd.DataFrame(rows).to_csv(trial / "window_results.csv", index=False)
    metric = binary_metrics([r["label"] for r in rows], [r["prediction"] for r in rows])
    if getattr(args, "safety_v3", False):
        metric["window_false_positive_rate"] = metric.pop("benign_damage")
    metric.update({"seed": seed, "setting": setting, "windows": len(rows),
                   "inference_p50_ms": float(np.percentile([r["inference_latency_ms"] for r in rows], 50)),
                   "inference_p90_ms": float(np.percentile([r["inference_latency_ms"] for r in rows], 90)),
                   "inference_p99_ms": float(np.percentile([r["inference_latency_ms"] for r in rows], 99)),
                   "enforcement_p50_ms": float(np.percentile([r["enforcement_latency_ms"] for r in rows], 50)),
                   "throughput_mean_mbps": float(np.mean([r["observed_throughput_mbps"] for r in rows])),
                   "audit_bytes": (trial / "audit.jsonl").stat().st_size if (trial / "audit.jsonl").exists() else 0,
                   "rollback_verified": rollback_ok})
    (trial / "trial_metrics.json").write_text(json.dumps(metric, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return metric


def summaries(trials, output, bootstrap_seed):
    frame = pd.DataFrame(trials)
    frame.to_csv(output / "trial_level_results.csv", index=False)
    numeric = ["accuracy", "precision", "recall", "f1", "fpr", "fnr", "benign_damage",
               "inference_p50_ms", "inference_p90_ms", "inference_p99_ms", "enforcement_p50_ms",
               "throughput_mean_mbps", "audit_bytes"]
    rng = np.random.default_rng(bootstrap_seed); rows = []
    for setting, group in frame.groupby("setting", sort=True):
        for metric in numeric:
            values = group[metric].dropna().to_numpy(float)
            means = (np.mean(values[rng.integers(0, len(values), size=(5000, len(values)))], axis=1)
                     if len(values) else np.array([]))
            rows.append({"setting": setting, "metric": metric, "n": len(values),
                         "undefined_trials": len(group) - len(values),
                         "mean": float(values.mean()) if len(values) else None,
                         "std": float(values.std(ddof=1)) if len(values) > 1 else None,
                         "median": float(np.median(values)) if len(values) else None,
                         "minimum": float(values.min()) if len(values) else None,
                         "maximum": float(values.max()) if len(values) else None,
                         "ci_lower_95": float(np.quantile(means, .025)) if len(values) else None,
                         "ci_upper_95": float(np.quantile(means, .975)) if len(values) else None,
                         "ci_method": "trial-level bootstrap", "bootstrap_seed": bootstrap_seed})
    pd.DataFrame(rows).to_csv(output / "trial_summary_with_ci.csv", index=False)
    wide = frame.pivot(index="seed", columns="setting", values=numeric)
    paired = []
    for metric in numeric:
        difference = wide[(metric, "audit_enabled")] - wide[(metric, "audit_disabled")]
        diff = difference.dropna().to_numpy(float)
        means = (np.mean(diff[rng.integers(0, len(diff), size=(5000, len(diff)))], axis=1)
                 if len(diff) else np.array([]))
        paired.append({"metric": metric, "pairs": len(diff), "undefined_pairs": len(difference) - len(diff),
                       "mean_enabled_minus_disabled": float(diff.mean()) if len(diff) else None,
                       "ci_lower_95": float(np.quantile(means, .025)) if len(diff) else None,
                       "ci_upper_95": float(np.quantile(means, .975)) if len(diff) else None,
                       "bootstrap_seed": bootstrap_seed})
    pd.DataFrame(paired).to_csv(output / "paired_audit_differences.csv", index=False)


def preflight():
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise RuntimeError("Run on Linux as root (for example: sudo .venv/bin/python ...)")
    if sys.version_info[:2] != (3, 13):
        raise RuntimeError("Canonical runtime requires Python 3.13")
    missing = [name for name in ["ip", "ovs-vsctl", "ovs-ofctl", "iperf3", "tcpdump"] if shutil.which(name) is None]
    if missing: raise RuntimeError(f"Missing system commands: {missing}")
    if command(["systemctl", "is-active", "openvswitch-switch"], check=False).returncode != 0:
        raise RuntimeError("openvswitch-switch is not active")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--trials", type=int, default=30)
    parser.add_argument("--base-seed", type=int, default=42000)
    parser.add_argument("--bootstrap-seed", type=int, default=20261010)
    parser.add_argument("--window-seconds", type=int, default=5)
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    parser.add_argument("--benign-windows", type=int, default=3)
    parser.add_argument("--attack-windows", type=int, default=6)
    parser.add_argument("--recovery-windows", type=int, default=3)
    parser.add_argument("--meter-rate-kbps", type=int, default=1000)
    parser.add_argument("--max-attackers", type=int, default=1)
    parser.add_argument("--deployment-dir", default=str(ROOT / "deployment"))
    parser.add_argument("--threshold-registry", default=str(ROOT / "configs/threshold_registry.json"))
    parser.add_argument("--protocol-role", choices=["diagnostic", "confirmatory"], default="diagnostic")
    parser.add_argument("--protocol", default=str(ROOT / "configs/ovs_experiment_protocol_v2.json"))
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    raise RuntimeError("Legacy dominant-source protocol retired. Use scripts/run_ovs_safety.py; see docs/OVS_SAFETY_V3.md")
    preflight()
    if not 1 <= args.max_attackers <= 8:
        raise ValueError("--max-attackers must be between 1 and 8")
    deployment_dir = Path(args.deployment_dir).resolve()
    threshold_registry = Path(args.threshold_registry).resolve()
    detector = RuntimeDetector(directory=deployment_dir, registry_path=threshold_registry)
    protocol_path = Path(args.protocol).resolve()
    protocol_hash = None
    if args.protocol_role == "confirmatory":
        protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
        protocol_hash = sha256(protocol_path)
        if args.max_attackers != int(protocol["traffic"]["maximum_attacker_namespaces"]):
            raise ValueError("Confirmatory attacker count differs from the preregistered protocol")
        if not args.smoke:
            allowed = {(int(protocol[name]["seed_start"]), int(protocol[name]["runs"]))
                       for name in ["confirmatory_kali", "confirmatory_ubuntu"]}
            if (args.base_seed, args.trials) not in allowed:
                raise ValueError("Confirmatory seed range differs from the preregistered protocol")
        training_verification = deployment_dir / "training_verification.json"
        if not training_verification.is_file() or not json.loads(training_verification.read_text())["passed"]:
            raise ValueError("Confirmatory execution requires a verified OVS-trained deployment")
    output = Path(args.output).resolve()
    if output.exists(): raise FileExistsError(f"Refusing to overwrite {output}")
    output.mkdir(parents=True)
    if args.smoke:
        args.trials = 1; args.benign_windows = args.attack_windows = args.recovery_windows = 1
    configuration = vars(args).copy(); configuration.update({
        "measurement_type": "actual_single_host_ovs_runtime", "paired_condition": "audit logging only",
        "canonical_features": FEATURES, "positive_action": "RATE_LIMIT",
        "ground_truth_policy": "predeclared phase label is withheld from inference",
        "resolved_deployment_dir": str(deployment_dir), "resolved_threshold_registry": str(threshold_registry),
        "model_hash": detector.selection["model_hash"], "operating_threshold": detector.threshold,
        "metrics_definition": "confusion_count_f1_v2",
        "protocol_sha256": protocol_hash,
    })
    (output / "experiment_configuration.json").write_text(json.dumps(configuration, indent=2) + "\n", encoding="utf-8")
    environment = {"created_at": datetime.now(timezone.utc).isoformat(), "os_release": platform.freedesktop_os_release(),
                   "platform": platform.platform(), "python": platform.python_version(),
                   "ovs": version(["ovs-vsctl", "--version"]), "iperf3": version(["iperf3", "--version"]),
                   "kernel": platform.release(), "model_sha256": sha256(deployment_dir / "model.joblib"),
                   "threshold_selection_sha256": sha256(deployment_dir / "threshold_selection.json"),
                   "feature_schema_sha256": sha256(deployment_dir / "feature_schema.json"),
                   "threshold_registry_sha256": sha256(threshold_registry)}
    (output / "environment.json").write_text(json.dumps(environment, indent=2) + "\n", encoding="utf-8")
    trials = []
    for trial_index in range(args.trials):
        seed = args.base_seed + trial_index
        order = ["audit_disabled", "audit_enabled"] if trial_index % 2 == 0 else ["audit_enabled", "audit_disabled"]
        for setting in order:
            print(f"trial {trial_index + 1}/{args.trials}: seed={seed} {setting}", flush=True)
            trials.append(run_trial(output, seed, setting, args))
    summaries(trials, output, args.bootstrap_seed)
    files = sorted(p for p in output.rglob("*") if p.is_file())
    (output / "CHECKSUMS.sha256").write_text("".join(
        f"{sha256(path)}  {path.relative_to(output).as_posix()}\n" for path in files), encoding="utf-8")
    print(json.dumps({"status": "complete", "paired_trials": args.trials,
                      "executions": len(trials), "output": str(output)}, indent=2))


if __name__ == "__main__":
    main()
