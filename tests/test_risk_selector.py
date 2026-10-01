from __future__ import annotations

import unittest
from pathlib import Path

try:
    import pytest

    pytestmark = pytest.mark.gnn
except Exception:
    pytestmark = []

try:
    import torch

    from integration.graph_state_builder import build_temporal_graph
    from integration.risk_selector import ALLOW, BLOCK, ISOLATE_SUBNET, RiskBound, RiskBoundedSelector
    from rl.sdn_graph_env import SDNGraphEnv

    HAS_GRAPH_DEPS = True
except Exception:
    HAS_GRAPH_DEPS = False


@unittest.skipUnless(HAS_GRAPH_DEPS, "optional graph/RL dependencies are not installed")
class RiskSelectorTests(unittest.TestCase):
    def test_selector_rejects_risky_action(self) -> None:
        selector = RiskBoundedSelector(RiskBound(0.3, 100.0, 0.7), live_mode=False, allow_isolate_live=True)
        decision = selector.select(
            predictions={
                "q_value": [0.1, 0.5, 0.9, 0.8],
                "predicted_attack_reduction": [0.0, 0.4, 0.8, 0.9],
                "predicted_benign_loss": [0.0, 0.1, 0.6, 0.2],
                "predicted_controller_cost": [10.0, 50.0, 150.0, 80.0],
                "predicted_next_risk": [0.5, 0.4, 0.3, 0.2],
                "risk_upper": [0.5, 0.4, 0.9, 0.6],
            },
            fallback_action=ALLOW,
            action_mask=[True, True, True, True],
        )
        self.assertEqual(decision["selected_action_id"], ISOLATE_SUBNET)
        self.assertTrue(any(item["action_id"] == BLOCK for item in decision["rejected_actions"]))

    def test_env_observation_is_non_leaky(self) -> None:
        rows = [
            {
                "source_ip": "192.168.1.10",
                "packet_count": 40,
                "byte_count": 4000,
                "flow_count": 3,
                "p_attack": 0.2,
                "detected_api": 0.0,
                "prev_action": 0,
                "controller_rtt_ms": 20.0,
            },
            {
                "source_ip": "192.168.1.11",
                "packet_count": 300,
                "byte_count": 30000,
                "flow_count": 8,
                "p_attack": 0.8,
                "detected_api": 1.0,
                "prev_action": 1,
                "controller_rtt_ms": 35.0,
            },
        ]
        graph, _ = build_temporal_graph(rows, window_size=4)
        graph.y_graph = torch.tensor([1], dtype=torch.long)
        temp_dir = Path(__file__).resolve().parent / "_tmp"
        temp_dir.mkdir(exist_ok=True)
        dataset_path = temp_dir / "graphs.pt"
        env = None
        try:
            torch.save([graph, graph], dataset_path)
            env = SDNGraphEnv(str(dataset_path), embedding_mode="raw_mean")
            obs, _ = env.reset()
            self.assertEqual(obs["global_stats"].shape[0], 8)
            self.assertNotEqual(float(obs["global_stats"][0]), float(graph.y_graph.item()))
        finally:
            if env is not None:
                env.close()
            if dataset_path.exists():
                try:
                    dataset_path.unlink()
                except PermissionError:
                    pass


if __name__ == "__main__":
    unittest.main()
