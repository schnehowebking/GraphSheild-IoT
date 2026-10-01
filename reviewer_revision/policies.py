"""Separately trained graph summaries; no prediction API receives target labels."""
from __future__ import annotations

import numpy as np
import pandas as pd
from scipy.optimize import minimize
from scipy.special import expit
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from reviewer_revision.core import FittedDetector, Partition, select_threshold, strict_features, validate_fit
from reviewer_revision.data import BIPARTITE, SWITCH, CONTEXT, TEMPORAL, NORMALIZED

POLICIES = {
    "source_service_bipartite_graph": BIPARTITE,
    "source_switch_service_graph": SWITCH,
    "controller_context_graph": CONTEXT,
    "temporal_edge_graph": TEMPORAL,
    "normalized_edge_weight_graph": NORMALIZED,
    "imitation_regularized_classifier": TEMPORAL,
    "temporal_graph_with_risk_selector": TEMPORAL,
}
UNSUPPORTED = {
    "contextual_bandit": "Not evaluated: logs lack action propensities, exploration support and defensible action-conditioned rewards. A classification utility is not a logged-bandit outcome.",
    "conservative_offline_rl": "Claim withdrawn: stored transitions overlap across split boundaries; next-row probability changes and packet drops are proxies, not identified action outcomes. No defensible off-policy evaluation or causal trajectories.",
}


class SoftTargetLogistic:
    """CE(y,p) + lambda CE(teacher_probability,p) + 1e-3 ||w||^2.

    Teacher is the train-only canonical RF. No policy reward or RL claim is made.
    """
    def __init__(self, strength):
        self.strength = strength

    def fit(self, x, y, teacher):
        self.scaler = StandardScaler().fit(x)
        design = np.c_[np.ones(len(x)), self.scaler.transform(x)]
        target = (np.asarray(y) + self.strength * np.asarray(teacher)) / (1 + self.strength)

        def objective(w):
            z = design @ w
            loss = np.mean(np.logaddexp(0, z) - target * z) + .001 * (w[1:] ** 2).sum()
            gradient = design.T @ (expit(z) - target) / len(z)
            gradient[1:] += .002 * w[1:]
            return loss, gradient

        result = minimize(objective, np.zeros(design.shape[1]), jac=True, method="L-BFGS-B", options={"maxiter": 1500})
        if not result.success:
            raise RuntimeError(f"Imitation optimization failed: {result.message}")
        self.coef = result.x
        self.classes_, self.feature_names_in_ = np.array([0, 1]), np.array(x.columns)
        return self

    def predict_proba(self, x):
        p = expit(np.c_[np.ones(len(x)), self.scaler.transform(x)] @ self.coef)
        return np.c_[1 - p, p]


class GraphPolicy(FittedDetector):
    def __init__(self, name, experiment):
        self.name, self.features = name, POLICIES[name]
        self.experiment = experiment
        self.config = {"features": self.features, "hyperparameters": {
            "n_estimators": experiment["graph_forest_trees"], "min_samples_leaf": 2,
            "class_weight": "balanced", "random_state": 42, "n_jobs": 1}}

    def fit(self, train, validation, registry, teacher_train=None):
        validate_fit(train, validation)
        x = strict_features(train.x, self.features)
        if self.name == "imitation_regularized_classifier":
            if teacher_train is None:
                raise ValueError("Imitation teacher probabilities required for training only")
            self.model = SoftTargetLogistic(self.experiment["imitation_lambda"]).fit(x, train.y, teacher_train)
        else:
            self.model = RandomForestClassifier(**self.config["hyperparameters"]).fit(x, train.y)
        self.threshold, self.curve = select_threshold(validation, self.predict_proba_or_action(validation.x), registry)
        self.train, self.validation, self.registry = train, validation, registry
        return self

    def actions(self, observations):
        return self.actions_from_probabilities(self.predict_proba_or_action(observations))

    def actions_from_probabilities(self, p):
        p = np.asarray(p, dtype=float)
        if p.ndim != 1 or not np.isfinite(p).all() or ((p < 0) | (p > 1)).any():
            raise ValueError("Invalid policy probabilities")
        proposed = p >= self.threshold
        if self.name == "temporal_graph_with_risk_selector":
            # Probability gate only; explicitly not a calibrated/conformal risk guarantee.
            proposed &= (1 - p) <= self.registry["policy_action"]["risk_selector_max_benign_probability"]
        return proposed.astype(int)

    def get_metadata(self):
        result = super().get_metadata()
        result.update({"name": self.name, "graph_schema": self.name, "model_version": "reviewer_revision_v1",
            "action_rule": "p >= validation threshold; risk selector additionally requires 1-p <= configured limit" if "selector" in self.name else "p >= validation threshold",
            "training_episodes": self.train.records.run_id.nunique(), "validation_episodes": self.validation.records.run_id.nunique(),
            "teacher": "train-only canonical RF probabilities" if "imitation" in self.name else None,
            "regularization": {"imitation_lambda": self.experiment["imitation_lambda"], "l2": .001} if "imitation" in self.name else None})
        if "imitation" in self.name:
            result["model_family"] = "standardized soft-target logistic classifier"
            result["hyperparameters"] = {"lambda": self.experiment["imitation_lambda"], "l2": .001, "maxiter": 1500}
        return result
