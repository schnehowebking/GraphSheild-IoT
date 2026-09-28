from scripts.run_ovs_controller_trials import FEATURES, binary_metrics, parse_flow_counters, schedule


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
    assert all(set(row) == {"phase", "label", "benign_mbps", "attack_mbps"} for row in first)


def test_metrics_recompute():
    result = binary_metrics([0, 0, 1, 1], [0, 1, 0, 1])
    assert (result["tn"], result["fp"], result["fn"], result["tp"]) == (1, 1, 1, 1)
    assert result["f1"] == 0.5


def test_undefined_precision_is_explicit():
    result = binary_metrics([0, 1], [0, 0])
    assert result["precision"] is None and result["f1"] is None
    assert "zero predicted positives" in result["undefined_metrics"]


def test_canonical_feature_order_is_fixed():
    assert FEATURES == ["pkt_rate", "byte_rate", "pkt_sum", "events", "unique_src",
                        "src_ip_entropy", "flow_count", "flow_rate"]
