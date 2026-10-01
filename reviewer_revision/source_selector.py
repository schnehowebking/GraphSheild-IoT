"""Conservative empirical source-rate gate; NOT a calibrated risk bound.

Only observed byte rates enter selection. Labels/IP roles belong in evaluation.
A candidate must exceed a development-derived benign envelope for consecutive
completed windows. Multiple candidates cause abstention, never arbitrary ranking.
"""
import hashlib
import ipaddress
import json
import math


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    allow_nan=False).encode()).hexdigest()


class SourceSelector:
    def __init__(self, policy):
        self.policy = dict(policy)
        required = {"version", "byte_rate_threshold", "consecutive_windows", "rule_ttl_seconds"}
        if not required <= self.policy.keys():
            raise ValueError("Incomplete source policy")
        threshold = policy["byte_rate_threshold"]
        if threshold is not None and (not math.isfinite(threshold) or threshold < 0):
            raise ValueError("Invalid source threshold")
        if policy["consecutive_windows"] not in (1, 2, 3):
            raise ValueError("Invalid persistence")
        if not 1 <= policy["rule_ttl_seconds"] <= 30:
            raise ValueError("Invalid rule TTL")
        self.hash = canonical_hash(self.policy)
        self.streaks = {}
        self.last_index = -1

    def select(self, observations, *, prediction, window_index):
        if window_index != self.last_index + 1:
            raise ValueError("Source windows must be consecutive and ordered")
        validated = []
        seen = set()
        for obs in observations:
            if set(obs) != {"source_ip", "packets", "bytes", "duration_seconds"}:
                raise ValueError("Only source telemetry allowed; labels/roles forbidden")
            ipaddress.IPv4Address(obs["source_ip"])
            if obs["source_ip"] in seen:
                raise ValueError("Duplicate source")
            seen.add(obs["source_ip"])
            if any(not math.isfinite(float(obs[k])) or float(obs[k]) < 0
                   for k in ("packets", "bytes", "duration_seconds")) or obs["duration_seconds"] <= 0:
                raise ValueError("Invalid source telemetry")
            validated.append((obs["source_ip"], obs["bytes"] / obs["duration_seconds"]))
        threshold = self.policy["byte_rate_threshold"]
        self.streaks = {ip: self.streaks.get(ip, 0) + 1 if threshold is not None and rate > threshold else 0
                        for ip, rate in validated}
        self.last_index = window_index
        candidates = sorted(ip for ip, streak in self.streaks.items()
                            if streak >= self.policy["consecutive_windows"])
        target = candidates[0] if prediction and len(candidates) == 1 else None
        reason = ("unique_persistent_rate_exceedance" if target else
                  "negative_window_prediction" if not prediction else
                  "policy_abstains" if threshold is None else
                  "ambiguous_sources" if len(candidates) > 1 else "insufficient_source_evidence")
        return {"action": "RATE_LIMIT" if target else "NONE", "target_source": target,
                "safety_reason": reason, "candidate_sources": candidates,
                "source_policy_hash": self.hash, "rule_ttl_seconds": self.policy["rule_ttl_seconds"]}
