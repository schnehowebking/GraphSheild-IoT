#!/usr/bin/env python3
"""
GraphShield-IoT - SDN + optional permissioned audit service + hybrid DDoS detection.

This file is designed to be COPY/PASTE ready.

What it supports:
- Threshold detection (packet_count > threshold)
- ML-Flow detection (requires 65-feature dict in request: ml_features)
- ML-Window detection (deployable 8-feature window computed online)
- Autonomous mitigation action decisions: NONE / RATE_LIMIT / BLOCK
- Optional permissioned hash-linked audit logging + flow-rule submission if the audit service is running.

API:
  GET  /health
  GET  /status
  GET  /controllers
  GET  /ml/features
  GET  /ml/template
  GET  /ml/window-template
  POST /detect
  POST /benchmark

Environment variables (optional):
  GRAPHSHIELD_CONFIG=config/graphshield_config.json
  API_PORT=8888
  BLOCKCHAIN_HOST=localhost   # legacy env name for the audit service host
  BLOCKCHAIN_PORT=9090        # legacy env name for the audit service port

  ML_WINDOW_SEC=5
  GRAPHSHIELD_THRESHOLD_REGISTRY=configs/threshold_registry.json

  Legacy FLOW mode only: DEFAULT_ML_DETECT_THRESHOLD=0.50
  Legacy FLOW mode only: DEFAULT_ML_BLOCK_THRESHOLD=0.90
"""

import asyncio
import argparse
import json
import logging
import math
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import aiohttp
from aiohttp import web
import numpy as np
from integration.audit_hash_chain import append_hash_chained_jsonl
from reviewer_revision.core import RuntimeDetector
from upgrade_common import ensure_dir, ensure_repo_root_on_path

ROOT = ensure_repo_root_on_path(__file__, levels_up=0)


def _load_runtime_config() -> Dict[str, Any]:
    config_name = os.getenv("GRAPHSHIELD_CONFIG") or os.getenv("GRAPHSHEILD_CONFIG")
    config_path = Path(config_name) if config_name else ROOT / "config" / "graphshield_config.json"
    if not config_path.is_absolute():
        config_path = ROOT / config_path
    if not config_path.exists():
        return {}
    try:
        return json.loads(config_path.read_text(encoding="utf-8"))
    except Exception as exc:
        logging.getLogger("SDN").warning(f"Unable to load runtime config {config_path}: {exc}")
        return {}


RUNTIME_CONFIG = _load_runtime_config()


def cfg(path: str, default: Any) -> Any:
    current: Any = RUNTIME_CONFIG
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current

# ---------------- Logging ----------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - SDN - %(levelname)s - %(message)s",
)
logger = logging.getLogger("SDN")

# ---------------- Defaults ----------------
DEFAULT_API_PORT = int(os.getenv("API_PORT", str(cfg("sdn.api_port", 8888))))
DEFAULT_BC_HOST = os.getenv("BLOCKCHAIN_HOST", str(cfg("audit.host", "localhost")))
DEFAULT_BC_PORT = int(os.getenv("BLOCKCHAIN_PORT", str(cfg("audit.port", 9090))))

DEFAULT_WINDOW_SEC = int(os.getenv("ML_WINDOW_SEC", str(cfg("ml.window_sec", 5))))
DEFAULT_ML_DETECT_THRESHOLD = float(os.getenv("DEFAULT_ML_DETECT_THRESHOLD", str(cfg("ml.detect_threshold", 0.50))))
DEFAULT_ML_BLOCK_THRESHOLD = float(os.getenv("DEFAULT_ML_BLOCK_THRESHOLD", str(cfg("ml.block_threshold", 0.90))))


# ---------------- Types ----------------
class ControllerRole(Enum):
    PRIMARY = "primary"
    BACKUP = "backup"
    SECONDARY = "secondary"


@dataclass
class DDoSAlert:
    alert_id: str
    timestamp: float
    switch_id: str
    source_ip: str
    dest_ip: str
    packet_count: int
    severity: int
    attack_type: str
    detected_by: str
    mitigated: bool = False
    mitigation_rule_id: Optional[str] = None
    transaction_id: Optional[str] = None


# ---------------- Helpers ----------------
def now_ts() -> float:
    return time.time()


def utc_event_ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def shannon_entropy(items: List[str]) -> float:
    if not items:
        return 0.0
    counts: Dict[str, int] = {}
    for x in items:
        counts[x] = counts.get(x, 0) + 1
    total = sum(counts.values())
    ent = 0.0
    for c in counts.values():
        p = c / total
        if p > 0:
            ent -= p * math.log2(p)
    return float(ent)


def clamp01(x: float) -> float:
    return float(max(0.0, min(1.0, x)))


# ---------------- ML Detector ----------------
class MLDetector:
    """
    Loads a joblib model + feature_order.json
    - feature_order.json: JSON list of feature names (strings)
    """

    def __init__(self, name: str, model_path: Path, feature_order_path: Path):
        self.name = name
        self.model_path = model_path
        self.feature_order_path = feature_order_path

        self.enabled: bool = False
        self.error: Optional[str] = None
        self.model = None
        self.feature_order: List[str] = []

        try:
            import joblib  # noqa: F401
        except Exception as e:
            self.error = f"Missing joblib: {e}"
            return

        if not model_path.exists():
            self.error = f"Model not found: {model_path}"
            return
        if not feature_order_path.exists():
            self.error = f"Feature order not found: {feature_order_path}"
            return

        try:
            import joblib

            self.model = joblib.load(str(model_path))
            self.feature_order = json.loads(feature_order_path.read_text(encoding="utf-8"))
            if not isinstance(self.feature_order, list) or not all(isinstance(x, str) for x in self.feature_order):
                raise ValueError("feature_order.json must be a JSON list of strings")
            self.enabled = True
        except Exception as e:
            self.error = f"Failed to load ML assets: {e}"
            self.enabled = False

    def predict_proba_1(self, features: Dict[str, Any]) -> float:
        """
        Returns P(class=1). Missing keys -> 0.0

        Also avoids sklearn warning about missing feature names by using a DataFrame when possible.
        """
        if not self.enabled or self.model is None:
            raise RuntimeError("MLDetector disabled")

        import warnings

        warnings.filterwarnings(
            "ignore",
            message=r"X does not have valid feature names, but.*was fitted with feature names",
            category=UserWarning,
        )

        row: List[float] = []
        for k in self.feature_order:
            v = features.get(k, 0.0)
            try:
                row.append(float(v))
            except Exception:
                row.append(0.0)

        # Prefer a DataFrame with column names (best for sklearn models trained with feature names)
        try:
            import pandas as pd  # optional dependency at runtime

            X = pd.DataFrame([row], columns=self.feature_order)
        except Exception:
            import numpy as np

            X = np.array([row], dtype=float)

        if hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(X)
            if getattr(proba, "shape", (0, 0))[1] < 2:
                return 0.0

            classes = getattr(self.model, "classes_", None)
            if classes is not None:
                cls = list(classes)
                idx = cls.index(1) if 1 in cls else 1
            else:
                idx = 1

            return clamp01(float(proba[0, idx]))

        if hasattr(self.model, "decision_function"):
            import numpy as np

            s = float(self.model.decision_function(X)[0])
            p = 1.0 / (1.0 + np.exp(-s))
            return clamp01(float(p))

        raise RuntimeError("Model must support predict_proba or decision_function")


# ---------------- Window Feature Builder ----------------
class WindowFeatureBuilder:
    """
    Online SDN window features (8 deployable features):

      pkt_rate, byte_rate, pkt_sum, events,
      unique_src, src_ip_entropy, flow_count, flow_rate

    Windows are keyed by (switch_id, dest_ip) and aligned to fixed window_sec boundaries.
    """

    def __init__(self, window_sec: int = 5):
        self.window_sec = int(window_sec)
        self.state: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def _window_start(self, t: float) -> int:
        return int(t // self.window_sec) * self.window_sec

    def update(
        self,
        switch_id: str,
        dest_ip: str,
        source_ip: str,
        packet_count: int,
        byte_count: Optional[int],
        flow_count: Optional[int],
    ) -> Dict[str, float]:
        t = now_ts()
        ws = self._window_start(t)
        key = (switch_id, dest_ip)

        st = self.state.get(key)
        if st is None or st.get("ws") != ws:
            st = {"ws": ws, "events": 0, "pkt_sum": 0, "byte_sum": 0, "flow_sum": 0, "sources": []}
            self.state[key] = st

        st["events"] += 1
        st["pkt_sum"] += int(packet_count) if packet_count is not None else 0
        if byte_count is not None:
            st["byte_sum"] += int(byte_count)
        if flow_count is not None:
            st["flow_sum"] += int(flow_count)

        st["sources"].append(str(source_ip))

        win = float(self.window_sec)
        pkt_sum = float(st["pkt_sum"])
        byte_sum = float(st["byte_sum"])
        events = float(st["events"])
        unique_src = float(len(set(st["sources"])))
        ent = float(shannon_entropy(st["sources"]))

        pkt_rate = pkt_sum / win
        byte_rate = byte_sum / win

        # If flow_sum isn't provided, approximate flow_count using events
        fc = float(st["flow_sum"] if st["flow_sum"] > 0 else st["events"])
        flow_rate = fc / win

        return {
            "pkt_rate": float(pkt_rate),
            "byte_rate": float(byte_rate),
            "pkt_sum": float(pkt_sum),
            "events": float(events),
            "unique_src": float(unique_src),
            "src_ip_entropy": float(ent),
            "flow_count": float(fc),
            "flow_rate": float(flow_rate),
        }


# ---------------- Blockchain Client ----------------
class BlockchainClient:
    """
    Optional external service. SDN will work without it (degraded mode).
    """

    def __init__(self, host: str, port: int):
        self.base = f"http://{host}:{port}"
        self.session: Optional[aiohttp.ClientSession] = None

    async def initialize(self):
        if self.session is None:
            self.session = aiohttp.ClientSession()

    async def close(self):
        if self.session is not None:
            await self.session.close()
            self.session = None

    async def check_health(self) -> bool:
        if self.session is None:
            return False
        try:
            async with self.session.get(f"{self.base}/health", timeout=aiohttp.ClientTimeout(total=3)) as r:
                return r.status == 200
        except Exception:
            return False

    async def get_blockchain_status(self) -> Dict[str, Any]:
        if self.session is None:
            return {}
        try:
            async with self.session.get(f"{self.base}/blockchain", timeout=aiohttp.ClientTimeout(total=5)) as r:
                if r.status == 200:
                    return await r.json()
        except Exception:
            pass
        return {}

    async def register_controller(self, controller_id: str, role: str) -> bool:
        if self.session is None:
            return False
        payload = {
            "controller_id": controller_id,
            "address": "localhost",
            "role": role,
            "version": "1.0",
            "load": 0.5,
        }
        try:
            async with self.session.post(
                f"{self.base}/api/controller/register",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=5),
            ) as r:
                return r.status in (200, 201)
        except Exception:
            return False

    async def submit_transaction(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        if self.session is None:
            return {"success": False, "error": "client_not_initialized"}
        try:
            async with self.session.post(
                f"{self.base}/transaction",
                json=tx,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as r:
                if r.status in (200, 201):
                    return {"success": True, "data": await r.json()}
                return {"success": False, "error": await r.text()}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def submit_flow_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        if self.session is None:
            return {"success": False, "error": "client_not_initialized"}
        try:
            async with self.session.post(
                f"{self.base}/flowrule",
                json=rule,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as r:
                if r.status in (200, 201):
                    return {"success": True, "data": await r.json()}
                return {"success": False, "error": await r.text()}
        except Exception as e:
            return {"success": False, "error": str(e)}


# ---------------- SDN Controller ----------------
class CompletedWindowController:
    """Canonical completed-window decision and audit path, exposed at /detect-window.

    Local software execution is measurable; OpenFlow enforcement is not implied.
    """
    def __init__(self, detector=None, audit_path=None, audit_enabled=True, source_selector=None):
        self.detector = detector or RuntimeDetector()
        self.audit_path = Path(audit_path or ROOT / "results/reviewer_revision_v1/runtime_audit.jsonl")
        self.audit_enabled = bool(audit_enabled)
        self.source_selector = source_selector
        self.shadow_policy = None
        self.mode = "baseline_only"

    def detect_completed_window(self, features, row_id, *, source_observations=None,
                                window_index=None, enforcement_enabled=True):
        from reviewer_revision.source_selector import canonical_hash
        decision = self.detector.decide(features)
        decision["baseline_action"] = decision["action"]
        decision["input_feature_hash"] = canonical_hash(features)
        decision["source_observations_hash"] = canonical_hash(source_observations)
        if self.source_selector is None:
            decision.update(action="NONE", target_source=None,
                            safety_reason="source_selector_unavailable", candidate_sources=[],
                            source_policy_hash=None, rule_ttl_seconds=0)
        else:
            decision.update(self.source_selector.select(source_observations,
                            prediction=decision["prediction"], window_index=window_index))
        decision["proposed_action"] = decision["action"]
        decision["proposed_target"] = decision["target_source"]
        if not enforcement_enabled:
            decision.update(action="NONE", target_source=None)
        decision["enforcement_enabled"] = bool(enforcement_enabled)
        decision.update({"row_id": str(row_id), "mode": self.mode, "shadow_action": None})
        if self.shadow_policy is not None and self.mode == "shadow":
            decision["shadow_action"] = self.shadow_policy(dict(features))
        if self.audit_enabled:
            append_hash_chained_jsonl(self.audit_path, decision)
        return decision

    def record_enforcement(self, record):
        """Record observed enforcement separately from the decision/proposal."""
        if self.audit_enabled:
            append_hash_chained_jsonl(self.audit_path, {"event": "enforcement_observation", **record})

    def rollback_to_baseline(self):
        self.shadow_policy = None
        self.mode = "baseline_only"
        event = {"event": "rollback_to_baseline", "mode": self.mode, "shadow_policy_loaded": False}
        if self.audit_enabled:
            append_hash_chained_jsonl(self.audit_path, event)
        return event


class SDNController:
    def __init__(self, controller_id: str, role: ControllerRole, port: int, bc: BlockchainClient, window_sec: int):
        self.controller_id = controller_id
        self.role = role
        self.port = port
        self.bc = bc

        self.switches: Set[str] = set()
        self.alerts: List[DDoSAlert] = []

        self.win_builder = WindowFeatureBuilder(window_sec=window_sec)
        self.prev_action: int = 0

        base = Path(__file__).resolve().parent

        self.flow_ml = MLDetector(
            "flow",
            base / "ml" / "models" / "ddos_model.joblib",
            base / "ml" / "models" / "feature_order.json",
        )

        # Missing or mismatched canonical assets stop startup rather than silently
        # loading the historical calibrated HGB detector under the same name.
        self.window_ml = RuntimeDetector(registry_path=os.getenv("GRAPHSHIELD_THRESHOLD_REGISTRY"))
        self.completed_window_controller = CompletedWindowController(self.window_ml)

        if self.flow_ml.enabled:
            logger.info(f"[{controller_id}] FLOW-ML enabled ({len(self.flow_ml.feature_order)} features)")
        else:
            logger.info(f"[{controller_id}] FLOW-ML disabled: {self.flow_ml.error}")

        if self.window_ml.enabled:
            logger.info(f"[{controller_id}] WINDOW-ML enabled ({len(self.window_ml.feature_order)} features)")
            logger.info(f"[{controller_id}] Canonical saved operating threshold={self.window_ml.threshold}")
        else:
            logger.info(f"[{controller_id}] WINDOW-ML disabled: {self.window_ml.error}")

        # ---- Temporal graph + counterfactual policy integration ----
        policy_mode = str(os.getenv("POLICY_MODE", str(cfg("policy.mode", "baseline_only")))).strip().lower()
        self.rollback_baseline_only = policy_mode in ("baseline", "baseline_only", "rollback")
        configured_rl_enable = str(os.getenv("RL_ENABLE", str(cfg("policy.rl_enable", False)))).strip().lower() in (
            "1",
            "true",
            "yes",
            "on",
        )
        self.rl_enabled = bool(configured_rl_enable and not self.rollback_baseline_only)
        self.rl_shadow_mode = str(os.getenv("RL_SHADOW_MODE", str(cfg("policy.shadow_mode", True)))).strip().lower() in ("1", "true", "yes", "on")
        self.rl_graph_window = int(os.getenv("RL_GRAPH_WINDOW", str(cfg("policy.graph_window", 10))))
        self.rl_policy_path = os.getenv("RL_POLICY_PATH", str(cfg("paths.rl_policy_path", "outputs/checkpoints/cstg_policy.pt")))
        self.rl_policy_meta = os.getenv("RL_POLICY_META", str(cfg("paths.rl_policy_meta", "outputs/checkpoints/cstg_policy_meta.json")))
        self.rl_controller_rtt_ms = float(os.getenv("RL_CONTROLLER_RTT_MS", "80.0"))
        self.rl_allow_isolate_live = str(os.getenv("RL_ALLOW_ISOLATE_LIVE", "false")).strip().lower() in ("1", "true", "yes", "on")
        self.rl_policy = None
        self.graph_builder = None
        self.rl_error: Optional[str] = None
        self.graph_emb_source = "raw_mean_fallback"
        self.gnn_checkpoint_loaded = False
        self.rl_audit_log_path = ensure_dir(ROOT / "outputs" / "eval") / "rl_runtime_audit.jsonl"

        try:
            from integration.graph_state_builder import GraphStateBuilder

            self.graph_builder = GraphStateBuilder(window_size=self.rl_graph_window)
        except Exception as e:
            self.rl_error = f"GraphStateBuilder unavailable: {e}"

        if self.rl_enabled and self.graph_builder is not None:
            try:
                from integration.adaptive_policy import AdaptivePolicy

                model_path = Path(self.rl_policy_path)
                meta_path = Path(self.rl_policy_meta)
                if not model_path.is_absolute():
                    model_path = (Path(__file__).resolve().parent / model_path).resolve()
                if not meta_path.is_absolute():
                    meta_path = (Path(__file__).resolve().parent / meta_path).resolve()
                self.rl_policy = AdaptivePolicy(
                    str(model_path),
                    meta_path=str(meta_path),
                    live_mode=not self.rl_shadow_mode,
                    allow_isolate_live=self.rl_allow_isolate_live,
                )
                self.gnn_checkpoint_loaded = bool(self.rl_policy.loaded)
                logger.info(
                    f"[{controller_id}] RL policy loaded (shadow_mode={self.rl_shadow_mode}) from {model_path}"
                )
            except Exception as e:
                self.rl_error = f"RL policy unavailable: {e}"
                self.rl_policy = None
                logger.warning(f"[{controller_id}] RL disabled at runtime: {self.rl_error}")
        elif self.rl_enabled and self.graph_builder is None:
            logger.warning(f"[{controller_id}] RL requested but graph builder missing: {self.rl_error}")

    def _append_rl_audit(self, payload: Dict[str, Any]) -> None:
        try:
            append_hash_chained_jsonl(self.rl_audit_log_path, payload)
        except Exception as exc:
            logger.warning(f"[{self.controller_id}] Unable to append RL audit log: {exc}")

    def add_switch(self, switch_id: str):
        self.switches.add(switch_id)

    def _severity_threshold(self, pkt: int, thr: int) -> int:
        if pkt <= thr:
            return 0
        ratio = min(pkt / max(thr, 1), 10.0)
        return max(1, min(10, int(ratio)))

    def _severity_prob(self, p: float, is_attack: bool) -> int:
        if not is_attack:
            return 0
        return max(1, min(10, int(round(p * 10))))

    async def detect(
        self,
        switch_id: str,
        source_ip: str,
        dest_ip: str,
        packet_count: int,
        threshold: int,
        attack_type: str,
        byte_count: Optional[int],
        flow_count: Optional[int],
        ml_features: Optional[Dict[str, Any]],
        ml_detect_threshold: float,
        ml_block_threshold: float,
        decision_mode: str,
        use_blockchain: bool,
    ) -> Dict[str, Any]:
        decision_mode = (decision_mode or "auto").lower().strip()

        # default outputs
        method = "threshold"
        p_attack: Optional[float] = None
        p_attack_raw: Optional[float] = None
        window_features: Optional[Dict[str, float]] = None

        # ----- choose method -----
        if decision_mode == "threshold":
            method = "threshold"
        else:
            # Prefer FLOW if features provided and enabled
            if decision_mode in ("auto", "ml_flow") and self.flow_ml.enabled and isinstance(ml_features, dict) and ml_features:
                try:
                    p_attack = self.flow_ml.predict_proba_1(ml_features)
                    method = "ml_flow"
                except Exception as e:
                    logger.warning(f"[{self.controller_id}] FLOW-ML failed -> fallback: {e}")
                    method = "threshold"
                    p_attack = None

            # Otherwise try WINDOW if enabled
            if method == "threshold" and decision_mode in ("auto", "ml_window") and self.window_ml.enabled:
                try:
                    window_features = self.win_builder.update(
                        switch_id, dest_ip, source_ip, packet_count, byte_count, flow_count
                    )

                    # Raw model probability
                    p_raw = float(self.window_ml.predict_proba_1(window_features))
                    p_attack_raw = p_raw

                    # Same probability and threshold as completed-window evaluation.
                    p_attack = p_raw
                    method = "ml_window"

                except Exception as e:
                    logger.warning(f"[{self.controller_id}] WINDOW-ML failed -> fallback: {e}")
                    method = "threshold"
                    p_attack = None
                    p_attack_raw = None
                    window_features = None

        # ----- decision -----
        if method.startswith("ml") and p_attack is not None:
            if method == "ml_window":
                ml_detect_threshold = self.window_ml.threshold
            detected = bool(p_attack >= float(ml_detect_threshold))
            severity = self._severity_prob(p_attack, detected)

            action = "NONE"
            if detected:
                action = "RATE_LIMIT" if method == "ml_window" else ("BLOCK" if p_attack >= float(ml_block_threshold) else "RATE_LIMIT")

            if method == "ml_window":
                reason = (
                    f"canonical_ml_window(p={p_attack:.4f}, detect>={ml_detect_threshold}; "
                    "partial-window request; completed-window evaluation uses /detect-window)"
                )
            else:
                reason = f"{method}(p={p_attack:.4f}, detect>={ml_detect_threshold}, block>={ml_block_threshold})"

        else:
            detected = bool(packet_count > threshold)
            severity = self._severity_threshold(packet_count, threshold)
            action = "BLOCK" if severity >= 7 else ("RATE_LIMIT" if severity >= 1 else "NONE")
            reason = f"threshold(pkt={packet_count}, thr={threshold})"

        # ----- adaptive RL action path (keeps baseline fallback) -----
        baseline_action = action
        rl_action_name = "ALLOW"
        safe_action_name = baseline_action
        safe_reason = "baseline_only"
        shadow_action_applied = False
        counterfactual_predictions: Dict[str, Any] = {}
        risk_bounds: Dict[str, Any] = {}
        rejected_actions: List[Dict[str, Any]] = []
        feasible_actions: List[Dict[str, Any]] = []
        if self.rl_enabled and self.graph_builder is not None and self.rl_policy is not None:
            try:
                from integration.risk_selector import ACTION_TO_ID, action_mask_from_context

                row = {
                    "source_ip": source_ip,
                    "dest_ip": dest_ip,
                    "packet_count": int(packet_count),
                    "byte_count": int(byte_count or 0),
                    "flow_count": int(flow_count or 0),
                    "p_attack": float(p_attack or 0.0),
                    "detected_api": float(detected),
                    "prev_action": float(self.prev_action),
                    "controller_rtt_ms": float(self.rl_controller_rtt_ms),
                    "threshold": float(threshold),
                }
                graph = self.graph_builder.update(row)
                controller_load = float(getattr(graph, "controller_load", torch.tensor([0.0]))[0].item())
                service_health = float(getattr(graph, "service_health", torch.tensor([1.0]))[0].item())
                action_mask = action_mask_from_context(
                    controller_load=controller_load,
                    service_health=service_health,
                    live_mode=not self.rl_shadow_mode,
                    allow_isolate_live=self.rl_allow_isolate_live,
                )
                decision = self.rl_policy.choose_action(
                    graph,
                    action_mask=action_mask,
                    fallback_action=ACTION_TO_ID.get(baseline_action.replace("NONE", "ALLOW"), 0),
                )
                self.graph_emb_source = str(decision.get("embedding_source", "counterfactual_temporal_model"))
                self.gnn_checkpoint_loaded = bool(decision.get("runtime_loaded", False))
                self.rl_error = decision.get("runtime_error") or self.rl_error
                counterfactual_predictions = {
                    key: [float(x) for x in value]
                    for key, value in decision.get("predictions", {}).items()
                    if key != "graph_embedding"
                }
                risk_bounds = dict(decision.get("bounds", {}))
                rejected_actions = list(decision.get("rejected_actions", []))
                feasible_actions = list(decision.get("feasible_actions", []))
                rl_action_name = str(decision.get("selected_action_name", "ALLOW"))
                safe_action_name = str(decision.get("live_action_name", baseline_action))
                safe_reason = str(decision.get("selection_reason", "risk_bounded_selector"))
                self.prev_action = int(decision.get("selected_action_id", ACTION_TO_ID.get(baseline_action.replace("NONE", "ALLOW"), 0)))

                if not self.rl_shadow_mode:
                    action = safe_action_name
                    reason = f"{reason} + rl({safe_reason})"
                else:
                    shadow_action_applied = True
            except Exception as e:
                self.rl_error = f"RL inference error: {e}"
                self.prev_action = {"NONE": 0, "ALLOW": 0, "RATE_LIMIT": 1, "BLOCK": 2, "ISOLATE_SUBNET": 3}.get(baseline_action, 0)
        else:
            self.prev_action = {"NONE": 0, "ALLOW": 0, "RATE_LIMIT": 1, "BLOCK": 2, "ISOLATE_SUBNET": 3}.get(baseline_action, 0)

        event_ts = utc_event_ts()
        result: Dict[str, Any] = {
            "detected": detected,
            "event_ts": event_ts,
            "timestamp": event_ts,
            "controller_id": self.controller_id,
            "switch_id": switch_id,
            "source_ip": source_ip,
            "src_ip": source_ip,
            "dest_ip": dest_ip,
            "dst_ip": dest_ip,
            "packet_count": int(packet_count),
            "byte_count": int(byte_count) if byte_count is not None else None,
            "flow_count": int(flow_count) if flow_count is not None else None,
            "threshold": int(threshold),
            "severity": int(severity),
            "attack_type": str(attack_type),
            "ml_used": method.startswith("ml"),
            "ml_method": method,
            "p_attack": p_attack,  # adjusted probability
            "p_attack_raw": p_attack_raw if method == "ml_window" else None,
            "operating_threshold": self.window_ml.threshold if method == "ml_window" else ml_detect_threshold,
            "threshold_selection_file": str(self.window_ml.directory / "threshold_selection.json") if method == "ml_window" else None,
            "model_hash": self.window_ml.selection["model_hash"] if method == "ml_window" else None,
            "window_features": window_features if method == "ml_window" else None,
            "decision_reason": reason,
            "baseline_action": baseline_action,
            "graph_emb_source": self.graph_emb_source,
            "gnn_checkpoint_loaded": bool(self.gnn_checkpoint_loaded),
            "rl_policy_loaded": bool(self.rl_policy is not None),
            "rl_enabled": bool(self.rl_enabled),
            "rl_shadow_mode": bool(self.rl_shadow_mode),
            "rl_action": rl_action_name,
            "safe_action": safe_action_name,
            "shadow_action_applied": bool(shadow_action_applied),
            "safe_reason": safe_reason,
            "per_action_effects": counterfactual_predictions,
            "risk_bounds": risk_bounds,
            "rejected_actions": rejected_actions,
            "feasible_actions": feasible_actions,
            "enforced_action": action,
            "rl_error": self.rl_error,
            "runtime_audit_log": str(self.rl_audit_log_path),
            "transaction_id": None,
            "mitigation_rule_id": None,
            "status": "normal",
        }

        if not detected:
            self._append_rl_audit(
                {
                    "timestamp": result["timestamp"],
                    "event_ts": result["event_ts"],
                    "controller_id": self.controller_id,
                    "switch_id": switch_id,
                    "source_ip": source_ip,
                    "src_ip": source_ip,
                    "dest_ip": dest_ip,
                    "dst_ip": dest_ip,
                    "detected": bool(detected),
                    "method": method,
                    "p_attack": float(p_attack or 0.0),
                    "packet_count": int(packet_count),
                    "byte_count": int(byte_count) if byte_count is not None else None,
                    "flow_count": int(flow_count) if flow_count is not None else None,
                    "threshold": int(threshold),
                    "baseline_action": baseline_action,
                    "rl_enabled": bool(self.rl_enabled),
                    "rl_policy_loaded": bool(self.rl_policy is not None),
                    "graph_emb_source": self.graph_emb_source,
                    "gnn_checkpoint_loaded": bool(self.gnn_checkpoint_loaded),
                    "rl_action": rl_action_name,
                    "safe_action": safe_action_name,
                    "shadow_action_applied": bool(shadow_action_applied),
                    "enforced_action": action,
                    "safe_reason": safe_reason,
                    "per_action_effects": counterfactual_predictions,
                    "risk_bounds": risk_bounds,
                    "rejected_actions": rejected_actions,
                    "rl_error": self.rl_error,
                    "transaction_id": result["transaction_id"],
                    "mitigation_rule_id": result["mitigation_rule_id"],
                    "status": result["status"],
                }
            )
            return result

        # ----- record alert -----
        alert_id = f"alert_{uuid.uuid4().hex[:8]}"
        alert = DDoSAlert(
            alert_id=alert_id,
            timestamp=now_ts(),
            switch_id=switch_id,
            source_ip=source_ip,
            dest_ip=dest_ip,
            packet_count=int(packet_count),
            severity=int(severity),
            attack_type=str(attack_type),
            detected_by=self.controller_id,
        )
        self.alerts.append(alert)

        # ----- mitigation artifacts -----
        tx_id = f"tx_{uuid.uuid4().hex[:8]}"
        rule_id = f"rule_{uuid.uuid4().hex[:8]}"

        tx = {
            "id": tx_id,
            "type": "attack_report",
            "source_ip": source_ip,
            "target_ip": dest_ip,
            "attack_type": str(attack_type),
            "severity": int(severity),
            "timestamp": int(now_ts()),
            "reporter_id": self.controller_id,
            "signature": f"sig_{uuid.uuid4().hex[:8]}",
            "evidence": json.dumps(
                {
                    "method": method,
                    "p_attack": p_attack,
                    "p_attack_raw": p_attack_raw,
                    "packet_count": int(packet_count),
                    "threshold": int(threshold),
                    "window_features": window_features if method == "ml_window" else None,
                },
                separators=(",", ":"),
            ),
        }

        rule = {
            "id": rule_id,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "action": action,
            "priority": 150 + int(severity),
            "expiry": int(now_ts()) + 3600,
            "created_by": self.controller_id,
            "validated": False,
        }

        # ----- blockchain optional -----
        if use_blockchain:
            txr = await self.bc.submit_transaction(tx)
            if txr.get("success"):
                result["transaction_id"] = tx_id
                alert.transaction_id = tx_id

            rr = await self.bc.submit_flow_rule(rule)
            if rr.get("success"):
                result["mitigation_rule_id"] = rule_id
                alert.mitigated = True
                alert.mitigation_rule_id = rule_id
                result["status"] = "mitigated"
            else:
                result["status"] = "detection_only"
        else:
            # No blockchain: still show mitigation ID if action is applied
            if action != "NONE":
                result["mitigation_rule_id"] = rule_id
                alert.mitigated = True
                alert.mitigation_rule_id = rule_id
                result["status"] = "mitigated"
            else:
                result["status"] = "detection_only"

        self._append_rl_audit(
            {
                "timestamp": result["timestamp"],
                "event_ts": result["event_ts"],
                "controller_id": self.controller_id,
                "switch_id": switch_id,
                "source_ip": source_ip,
                "src_ip": source_ip,
                "dest_ip": dest_ip,
                "dst_ip": dest_ip,
                "detected": bool(detected),
                "method": method,
                "p_attack": float(p_attack or 0.0),
                "packet_count": int(packet_count),
                "byte_count": int(byte_count) if byte_count is not None else None,
                "flow_count": int(flow_count) if flow_count is not None else None,
                "threshold": int(threshold),
                "baseline_action": baseline_action,
                "rl_enabled": bool(self.rl_enabled),
                "rl_policy_loaded": bool(self.rl_policy is not None),
                "graph_emb_source": self.graph_emb_source,
                "gnn_checkpoint_loaded": bool(self.gnn_checkpoint_loaded),
                "rl_action": rl_action_name,
                "safe_action": safe_action_name,
                "shadow_action_applied": bool(shadow_action_applied),
                "enforced_action": action,
                "safe_reason": safe_reason,
                "per_action_effects": counterfactual_predictions,
                "risk_bounds": risk_bounds,
                "rejected_actions": rejected_actions,
                "rl_error": self.rl_error,
                "transaction_id": result["transaction_id"],
                "mitigation_rule_id": result["mitigation_rule_id"],
                "status": result["status"],
            }
        )
        return result

    def stats(self) -> Dict[str, Any]:
        return {
            "controller_id": self.controller_id,
            "role": self.role.value,
            "switches_managed": len(self.switches),
            "total_alerts": len(self.alerts),
            "mitigated_attacks": sum(1 for a in self.alerts if a.mitigated),
            "ml_flow_enabled": bool(self.flow_ml.enabled),
            "ml_flow_error": self.flow_ml.error,
            "ml_window_enabled": bool(self.window_ml.enabled),
            "ml_window_error": self.window_ml.error,
            "window_sec": self.win_builder.window_sec,
            "ml_window_min_pkt_rate": 0.0,  # compatibility status field; canonical score gate disabled
            "ml_window_min_events": 0,
            "rl_enabled": bool(self.rl_enabled),
            "rl_shadow_mode": bool(self.rl_shadow_mode),
            "gnn_checkpoint_loaded": bool(self.gnn_checkpoint_loaded),
            "rl_policy_loaded": bool(self.rl_policy is not None),
            "graph_emb_source": self.graph_emb_source,
            "rl_error": self.rl_error,
            "runtime_audit_log": str(self.rl_audit_log_path),
        }


# ---------------- Multi-controller Manager ----------------
class MultiControllerManager:
    def __init__(self, bc_host: str, bc_port: int, window_sec: int):
        self.bc = BlockchainClient(bc_host, bc_port)
        self.controllers: Dict[str, SDNController] = {}
        self.window_sec = window_sec

    async def initialize(self):
        await self.bc.initialize()
        ok = await self.bc.check_health()
        logger.info("Connected to blockchain successfully" if ok else "Blockchain not reachable (degraded mode)")

    async def close(self):
        await self.bc.close()

    def add_controller(self, cid: str, role: ControllerRole, port: int) -> SDNController:
        c = SDNController(cid, role, port, self.bc, window_sec=self.window_sec)
        self.controllers[cid] = c
        return c

    async def register_all(self):
        for c in self.controllers.values():
            ok = await self.bc.register_controller(c.controller_id, c.role.value)
            logger.info(f"Registered {c.controller_id} with blockchain" if ok else f"Could not register {c.controller_id}")

    def get(self, cid: str) -> Optional[SDNController]:
        return self.controllers.get(cid)

    def all_stats(self) -> List[Dict[str, Any]]:
        return [c.stats() for c in self.controllers.values()]


# ---------------- API Server ----------------
class IntegrationAPIServer:
    def __init__(self, mgr: MultiControllerManager, port: int):
        self.mgr = mgr
        self.port = int(port)
        self.app = web.Application(middlewares=[self._cors])
        self._routes()
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None

    @web.middleware
    async def _cors(self, request, handler):
        if request.method == "OPTIONS":
            resp = web.Response(status=200)
        else:
            resp = await handler(request)
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return resp

    def _pick_any_controller(self) -> SDNController:
        c = self.mgr.get("ctrl_primary_01")
        return c if c else next(iter(self.mgr.controllers.values()))

    def _routes(self):
        self.app.router.add_get("/health", self.handle_health)
        self.app.router.add_get("/status", self.handle_status)
        self.app.router.add_get("/controllers", self.handle_controllers)

        self.app.router.add_get("/ml/features", self.handle_ml_features)
        self.app.router.add_get("/ml/template", self.handle_ml_template)
        self.app.router.add_get("/ml/window-template", self.handle_ml_window_template)

        self.app.router.add_post("/detect", self.handle_detect)
        self.app.router.add_post("/detect-window", self.handle_detect_window)
        self.app.router.add_post("/benchmark", self.handle_benchmark)

    async def handle_health(self, request):
        ok = await self.mgr.bc.check_health()
        return web.json_response(
            {
                "status": "healthy" if ok else "degraded",
                "blockchain_connected": bool(ok),
                "controllers_active": len(self.mgr.controllers),
                "timestamp": datetime.now().isoformat(),
            }
        )

    async def handle_controllers(self, request):
        return web.json_response({"controllers": self.mgr.all_stats()})

    async def handle_status(self, request):
        bc = await self.mgr.bc.get_blockchain_status()
        total_det = 0
        total_mit = 0
        alerts: List[DDoSAlert] = []
        for c in self.mgr.controllers.values():
            alerts.extend(c.alerts)
            total_det += len(c.alerts)
            total_mit += sum(1 for a in c.alerts if a.mitigated)

        recent = sorted(alerts, key=lambda a: a.timestamp, reverse=True)[:10]
        recent_out = [
            {
                "source_ip": a.source_ip,
                "dest_ip": a.dest_ip,
                "severity": a.severity,
                "attack_type": a.attack_type,
                "mitigated": a.mitigated,
                "timestamp": datetime.fromtimestamp(a.timestamp).isoformat(),
            }
            for a in recent
        ]

        return web.json_response(
            {
                "total_detections": total_det,
                "total_mitigations": total_mit,
                "controllers": self.mgr.all_stats(),
                "blockchain_status": bc,
                "network_metrics": bc.get("network_state", {}),
                "recent_attacks": recent_out,
            }
        )

    async def handle_ml_features(self, request):
        c = self._pick_any_controller()
        return web.json_response(
            {
                "flow_ml": {
                    "enabled": bool(c.flow_ml.enabled),
                    "feature_count": len(c.flow_ml.feature_order) if c.flow_ml.enabled else 0,
                    "feature_order": c.flow_ml.feature_order if c.flow_ml.enabled else [],
                    "error": c.flow_ml.error,
                    "model_path": str(c.flow_ml.model_path),
                },
                "window_ml": {
                    "enabled": bool(c.window_ml.enabled),
                    "feature_count": len(c.window_ml.feature_order) if c.window_ml.enabled else 0,
                    "feature_order": c.window_ml.feature_order if c.window_ml.enabled else [],
                    "error": c.window_ml.error,
                    "model_path": str(c.window_ml.model_path),
                    "window_sec": c.win_builder.window_sec,
                    "min_pkt_rate_gate": 0.0,
                    "min_events_gate": 0,
                },
            }
        )

    async def handle_ml_template(self, request):
        c = self._pick_any_controller()
        if not c.flow_ml.enabled:
            return web.json_response({"ml_enabled": False, "ml_error": c.flow_ml.error, "ml_features": {}})

        t = {k: 0.0 for k in c.flow_ml.feature_order}
        # populate a few typical keys (if present)
        for k, v in [
            ("Flow Duration", 1000.0),
            ("Flow Packets/s", 1200.0),
            ("Flow Bytes/s", 900000.0),
            ("Total Fwd Packets", 6000.0),
        ]:
            if k in t:
                t[k] = v
        return web.json_response(
            {"ml_enabled": True, "model": "flow", "feature_count": len(c.flow_ml.feature_order), "ml_features": t}
        )

    async def handle_ml_window_template(self, request):
        c = self._pick_any_controller()
        if not c.window_ml.enabled:
            return web.json_response({"ml_enabled": False, "ml_error": c.window_ml.error, "ml_features": {}})

        t = {k: 0.0 for k in c.window_ml.feature_order}
        for k, v in [
            ("pkt_rate", 1500.0),
            ("byte_rate", 120000.0),
            ("pkt_sum", 7000.0),
            ("events", 5.0),
            ("unique_src", 50.0),
            ("src_ip_entropy", 4.5),
            ("flow_count", 25.0),
            ("flow_rate", 5.0),
        ]:
            if k in t:
                t[k] = v
        return web.json_response(
            {"ml_enabled": True, "model": "window", "feature_count": len(c.window_ml.feature_order), "ml_features": t}
        )

    async def handle_detect_window(self, request):
        data = await request.json()
        if set(data) - {"features", "row_id", "controller_id"}:
            return web.json_response({"error": "Unexpected input: labels and threshold overrides forbidden"}, status=400)
        c = self.mgr.get(data.get("controller_id", "ctrl_primary_01"))
        if c is None:
            return web.json_response({"error": "Unknown controller"}, status=404)
        try:
            result = c.completed_window_controller.detect_completed_window(data["features"], data["row_id"])
        except (KeyError, TypeError, ValueError) as exc:
            return web.json_response({"error": str(exc)}, status=400)
        return web.json_response(result)

    async def handle_detect(self, request):
        data = await request.json()

        cid = data.get("controller_id", "ctrl_primary_01")
        c = self.mgr.get(cid)
        if not c:
            return web.json_response({"error": f"Controller not found: {cid}"}, status=404)

        # optional ints
        byte_count = data.get("byte_count", None)
        flow_count = data.get("flow_count", None)

        res = await c.detect(
            switch_id=str(data.get("switch_id", "s1")),
            source_ip=str(data.get("source_ip", "0.0.0.0")),
            dest_ip=str(data.get("dest_ip", "0.0.0.0")),
            packet_count=int(data.get("packet_count", 0)),
            threshold=int(data.get("threshold", 1000)),
            attack_type=str(data.get("attack_type", "traffic_spike")),
            byte_count=int(byte_count) if byte_count is not None else None,
            flow_count=int(flow_count) if flow_count is not None else None,
            ml_features=data.get("ml_features") if isinstance(data.get("ml_features"), dict) else None,
            ml_detect_threshold=float(data.get("ml_detect_threshold", DEFAULT_ML_DETECT_THRESHOLD)),
            ml_block_threshold=float(data.get("ml_block_threshold", DEFAULT_ML_BLOCK_THRESHOLD)),
            decision_mode=str(data.get("decision_mode", "auto")),
            use_blockchain=bool(data.get("use_blockchain", True)),
        )
        return web.json_response(res)

    async def handle_benchmark(self, request):
        """
        End-to-end benchmark of detect() including optional blockchain calls.

        Example:
          curl -s -X POST http://localhost:8888/benchmark -H "Content-Type: application/json" \
            -d '{"n":300,"decision_mode":"ml_window","use_blockchain":false,"packet_count":5000,"threshold":1000}' | jq
        """
        try:
            import numpy as np
        except Exception as e:
            return web.json_response({"error": f"numpy missing: {e}"}, status=500)

        data = await request.json()
        n = int(data.get("n", 200))

        cid = data.get("controller_id", "ctrl_primary_01")
        c = self.mgr.get(cid)
        if not c:
            return web.json_response({"error": f"Controller not found: {cid}"}, status=404)

        decision_mode = str(data.get("decision_mode", "auto"))
        use_blockchain = bool(data.get("use_blockchain", True))
        pkt = int(data.get("packet_count", 5000))
        thr = int(data.get("threshold", 1000))

        ml_features = data.get("ml_features", None) if decision_mode.strip().lower() == "ml_flow" else None

        # warm-up
        for _ in range(5):
            await c.detect(
                "s1",
                "192.168.1.10",
                "10.0.0.5",
                pkt,
                thr,
                "traffic_spike",
                None,
                None,
                ml_features if isinstance(ml_features, dict) else None,
                float(data.get("ml_detect_threshold", DEFAULT_ML_DETECT_THRESHOLD)),
                float(data.get("ml_block_threshold", DEFAULT_ML_BLOCK_THRESHOLD)),
                decision_mode,
                use_blockchain,
            )

        lat_ms: List[float] = []
        methods: Dict[str, int] = {}
        detected_count = 0

        t0 = time.perf_counter()
        for i in range(n):
            s = time.perf_counter()
            r = await c.detect(
                "s1",
                f"192.168.1.{10 + (i % 200)}",
                "10.0.0.5",
                pkt,
                thr,
                "traffic_spike",
                None,
                None,
                ml_features if isinstance(ml_features, dict) else None,
                float(data.get("ml_detect_threshold", DEFAULT_ML_DETECT_THRESHOLD)),
                float(data.get("ml_block_threshold", DEFAULT_ML_BLOCK_THRESHOLD)),
                decision_mode,
                use_blockchain,
            )
            e = time.perf_counter()
            lat_ms.append((e - s) * 1000.0)

            m = r.get("ml_method", "unknown")
            methods[m] = methods.get(m, 0) + 1
            if r.get("detected"):
                detected_count += 1
        t1 = time.perf_counter()

        arr = np.array(lat_ms, dtype=float)
        out = {
            "n": n,
            "controller_id": cid,
            "decision_mode": decision_mode.strip().lower(),
            "use_blockchain": use_blockchain,
            "packet_count": pkt,
            "threshold": thr,
            "total_time_s": float(t1 - t0),
            "mean_ms": float(arr.mean()),
            "p50_ms": float(np.percentile(arr, 50)),
            "p90_ms": float(np.percentile(arr, 90)),
            "p99_ms": float(np.percentile(arr, 99)),
            "min_ms": float(arr.min()),
            "max_ms": float(arr.max()),
            "detected_count": int(detected_count),
            "methods": methods,
        }
        return web.json_response(out)

    async def start(self):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()

        last_err: Optional[Exception] = None
        for off in range(0, 8):
            try_port = self.port + off
            try:
                self.site = web.TCPSite(self.runner, "127.0.0.1", try_port)
                await self.site.start()
                self.port = try_port
                logger.info(f"Integration API started on http://localhost:{self.port}")
                return
            except OSError as e:
                last_err = e
                if getattr(e, "errno", None) == 98:  # address in use
                    continue
                raise
        if last_err:
            raise last_err
        raise RuntimeError("Failed to bind API port")

    async def stop(self):
        if self.runner is not None:
            await self.runner.cleanup()
            self.runner = None
            self.site = None


# ---------------- Main ----------------
def parse_args():
    ap = argparse.ArgumentParser(description="Run GraphShield-IoT SDN API")
    ap.add_argument("--api_port", type=int, default=DEFAULT_API_PORT)
    ap.add_argument("--blockchain_host", default=DEFAULT_BC_HOST)
    ap.add_argument("--blockchain_port", type=int, default=DEFAULT_BC_PORT)
    ap.add_argument("--window_sec", type=int, default=DEFAULT_WINDOW_SEC)
    return ap.parse_args()


async def main(args):
    print("============================================================")
    print("GraphShield-IoT - SDN + permissioned audit service (optional) + ML DDoS")
    print("============================================================\n")

    mgr = MultiControllerManager(args.blockchain_host, args.blockchain_port, window_sec=args.window_sec)
    api: Optional[IntegrationAPIServer] = None

    try:
        await mgr.initialize()

        # Controllers
        primary = mgr.add_controller("ctrl_primary_01", ControllerRole.PRIMARY, 8001)
        backup = mgr.add_controller("ctrl_backup_01", ControllerRole.BACKUP, 8002)
        secondary = mgr.add_controller("ctrl_secondary_01", ControllerRole.SECONDARY, 8003)

        # Example switch assignment
        primary.add_switch("s1")
        primary.add_switch("s2")
        backup.add_switch("s3")
        secondary.add_switch("s4")

        # Register controllers in the audit service if it is reachable.
        await mgr.register_all()

        # API server
        api = IntegrationAPIServer(mgr, port=args.api_port)
        await api.start()

        print("Ready!")
        print(f"Audit base:       http://{args.blockchain_host}:{args.blockchain_port}")
        print(f"API base:         http://localhost:{api.port}")
        print(
            f"Window gate:      min_pkt_rate={os.getenv('ML_WINDOW_MIN_PKT_RATE','600')}, "
            f"min_events={os.getenv('ML_WINDOW_MIN_EVENTS','3')}"
        )
        print()

        # keep running
        await asyncio.Event().wait()

    finally:
        print("\nShutting down...")
        try:
            if api is not None:
                await api.stop()
        finally:
            await mgr.close()
        print("Goodbye")


if __name__ == "__main__":
    asyncio.run(main(parse_args()))
