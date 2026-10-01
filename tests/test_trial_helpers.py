import json
from pathlib import Path

import pytest

from scripts.run_ovs_controller_trials import FEATURES, OvsLab, binary_metrics, parse_flow_counters, schedule
from reviewer_revision.core import RuntimeDetector, matches_text_sha


def test_parse_tracking_flows():
    text = """
 cookie=0x475401, duration=1.0s, table=0, n_packets=12, n_bytes=900, priority=100,ip,nw_src=10.253.0.1,nw_dst=10.253.0.3 actions=NORMAL
 cookie=0x475401, duration=1.0s, table=0, n_packets=20, n_bytes=1500, priority=100,ip,nw_src=10.253.0.2,nw_dst=10.253.0.3 actions=NORMAL
 cookie=0x475402, duration=1.0s, table=0, n_packets=5, n_bytes=400, priority=300,ip,nw_src=10.253.0.2,nw_dst=10.253.0.3 actions=meter:1,NORMAL
 cookie=0x0, duration=1.0s, table=0, n_packets=99, n_bytes=9999, priority=0 actions=NORMAL
 """
    assert parse_flow_counters(text) == {"10.253.0.1": (12, 900), "10.253.0.2": (25, 1900)}


def test_schedule_is_deterministic_and_balanced():
    first, second = schedule(42, 3, 6, 3), schedule(42, 3, 6, 3)
    assert first == second
    assert sum(row["label"] for row in first) == 6
    assert all(set(row) == {"phase", "label", "benign_mbps", "attack_mbps", "active_attackers"}
               for row in first)


def test_metrics_recompute():
    result = binary_metrics([0, 0, 1, 1], [0, 1, 0, 1])
    assert (result["tn"], result["fp"], result["fn"], result["tp"]) == (1, 1, 1, 1)
    assert result["f1"] == 0.5


def test_undefined_precision_is_explicit():
    result = binary_metrics([0, 1], [0, 0])
    assert result["precision"] is None and result["f1"] == 0.0
    assert "zero predicted positives" in result["undefined_metrics"]


def test_f1_is_undefined_only_for_all_negative_no_action():
    result = binary_metrics([0, 0], [0, 0])
    assert result["f1"] is None
    assert "f1: zero denominator" in result["undefined_metrics"]


def test_multisource_schedule_stays_within_declared_attacker_count():
    rows = schedule(51000, 3, 30, 3, max_attackers=4)
    attack_counts = {row["active_attackers"] for row in rows if row["label"] == 1}
    assert attack_counts.issubset({1, 2, 4}) and len(attack_counts) >= 2
    assert all(row["active_attackers"] == 0 for row in rows if row["label"] == 0)
    lab = OvsLab("test", 1000, max_attackers=4)
    assert len(lab.attackers) == len({lab.hosts[role] for role in lab.attackers}) == 4


def test_canonical_feature_order_is_fixed():
    assert FEATURES == ["pkt_rate", "byte_rate", "pkt_sum", "events", "unique_src",
                        "src_ip_entropy", "flow_count", "flow_rate"]


def test_text_hash_accepts_git_newline_normalization(tmp_path):
    lf = b'{\n  "features": []\n}\n'
    crlf = lf.replace(b"\n", b"\r\n")
    path = tmp_path / "schema.json"
    path.write_bytes(lf)
    expected = __import__("hashlib").sha256(crlf).hexdigest()
    assert matches_text_sha(path, expected)


def test_runtime_rejects_threshold_registry_mismatch(tmp_path):
    root = Path(__file__).resolve().parents[1]
    registry = json.loads((root / "configs/threshold_registry_ovs_v2.json").read_text(encoding="utf-8"))
    registry["operating"]["max_false_positive_rate"] = 0.123
    changed = tmp_path / "registry.json"
    changed.write_text(json.dumps(registry), encoding="utf-8")
    with pytest.raises(ValueError, match="registry hash"):
        RuntimeDetector(directory=root / "deployment_ovs_v2", registry_path=changed)
