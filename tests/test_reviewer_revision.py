from __future__ import annotations

import inspect
import json
from dataclasses import replace
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from reviewer_revision.core import CONFIG, FEATURES, ROOT, FittedDetector, RuntimeDetector, metrics, object_hash, read_json, select_threshold, write_json
from reviewer_revision.data import OBSERVABLE, generate_run, graph_features, make_folds, partition, prepare_windows
from reviewer_revision.policies import GraphPolicy, POLICIES
from reviewer_revision.verify import verify_results


@pytest.fixture(scope="module")
def data():
    config = read_json(ROOT / "configs/reviewer_revision.json")
    config.update(simulation_runs=8, windows_per_run=12, stress_trials=2, stress_windows=6,
                  bootstrap_replicates=30, graph_forest_trees=12)
    raw = pd.concat([generate_run(config, i, config["seed"] + i) for i in range(8)], ignore_index=True)
    windows = prepare_windows(raw)
    graphs = graph_features(raw[OBSERVABLE], windows[["row_id", "run_id", "window_start_ts", "switch_id", "dst_ip"]])
    folds, _ = make_folds(windows, config)
    parts = {role: partition(windows, windows[FEATURES], idx, role) for role, idx in folds[0].items()}
    registry = read_json(ROOT / "configs/threshold_registry.json")
    baseline = FittedDetector().fit(parts["train"], parts["validation"], registry)
    return config, raw, windows, graphs, folds, parts, registry, baseline


def test_temporal_runs_and_test_windows_never_overlap(data):
    config, _, windows, _, folds, _, _, _ = data
    seen = set()
    for idx in folds:
        tr, va, te = [windows.loc[idx[role]] for role in ["train", "validation", "test"]]
        assert pd.Timestamp(tr.window_end_ts.max()) <= pd.Timestamp(va.window_start_ts.min())
        assert pd.Timestamp(va.window_end_ts.max()) <= pd.Timestamp(te.window_start_ts.min())
        assert not set(tr.run_id) & set(va.run_id)
        assert not set(te.run_id) & set(va.run_id)
        assert not seen & set(te.row_id)
        seen |= set(te.row_id)
    with pytest.raises(ValueError):
        make_folds(windows.iloc[::-1], config)
    with pytest.raises(ValueError):
        make_folds(windows, {**config, "fold_count": 100})


def test_fit_and_threshold_reject_test_partition(data):
    _, _, _, _, _, parts, registry, baseline = data
    with pytest.raises(ValueError):
        FittedDetector().fit(parts["train"], parts["test"], registry)
    with pytest.raises(ValueError):
        select_threshold(parts["test"], baseline.predict_proba_or_action(parts["test"].x), registry)
    bad_validation = replace(parts["validation"], records=parts["train"].records.iloc[:len(parts["validation"].x)].copy())
    with pytest.raises(ValueError):
        FittedDetector().fit(parts["train"], bad_validation, registry)


def test_test_labels_cannot_change_predictions_or_threshold(data):
    _, _, _, _, _, parts, registry, baseline = data
    changed = replace(parts["test"], y=1 - parts["test"].y)
    p1 = baseline.predict_proba_or_action(parts["test"].x)
    p2 = baseline.predict_proba_or_action(changed.x)
    assert np.array_equal(p1, p2)
    t1, curve1 = select_threshold(parts["validation"], baseline.predict_proba_or_action(parts["validation"].x), registry)
    assert t1 == baseline.threshold
    assert curve1.loc[curve1.selected, "fpr"].iloc[0] <= registry["operating"]["max_false_positive_rate"]
    assert "test" not in inspect.signature(select_threshold).parameters
    with pytest.raises(TypeError):
        baseline.predict_proba_or_action(parts["test"].x, changed.y)


@pytest.mark.parametrize("extra", ["label", "y", "true_attack", "future_outcome", "scenario_id"])
def test_inference_rejects_labels_and_metadata(data, extra):
    baseline, test = data[-1], data[5]["test"]
    with pytest.raises(ValueError):
        baseline.predict_proba_or_action(test.x.assign(**{extra: test.y}))


def test_schema_order_and_nonfinite_values_rejected(data):
    baseline, test = data[-1], data[5]["test"]
    with pytest.raises(ValueError):
        baseline.predict_proba_or_action(test.x[test.x.columns[::-1]])
    for value in [np.nan, np.inf]:
        x = test.x.copy(); x.iloc[0, 0] = value
        with pytest.raises(ValueError):
            baseline.predict_proba_or_action(x)


def test_graph_features_respond_to_edges_and_ignore_future(data):
    _, raw, windows, original, _, _, _, _ = data
    queries = windows[["row_id", "run_id", "window_start_ts", "switch_id", "dst_ip"]]
    changed = raw[OBSERVABLE].copy()
    changed.loc[changed.index[::2], "dst_ip"] = "service_changed"
    revised = graph_features(changed, queries)
    assert (original.services != revised.services).any()
    assert not np.array_equal(original.to_numpy(), revised.to_numpy())
    cutoff = pd.Timestamp(windows.window_start_ts.iloc[len(windows) // 2])
    early = queries[pd.to_datetime(queries.window_start_ts, utc=True) < cutoff]
    subset = raw.loc[pd.to_datetime(raw.event_ts, utc=True, format="mixed") < cutoff, OBSERVABLE]
    past_only = graph_features(subset, early)
    pd.testing.assert_frame_equal(original.loc[early.index], past_only)
    with pytest.raises(ValueError):
        graph_features(raw[OBSERVABLE + ["label"]], queries)


@pytest.mark.parametrize("name", list(POLICIES))
def test_policies_have_separate_fits_and_label_free_inference(data, name):
    config, _, windows, graphs, folds, parts, registry, baseline = data
    gp = {role: partition(windows, graphs[POLICIES[name]], idx, role) for role, idx in folds[0].items()}
    p = GraphPolicy(name, config).fit(gp["train"], gp["validation"], registry,
                                   teacher_train=baseline.predict_proba_or_action(parts["train"].x))
    predictions = p.predict_proba_or_action(gp["test"].x)
    assert len(predictions) == len(parts["test"].x)
    assert p.model is not baseline.model
    assert not np.shares_memory(predictions, baseline.predict_proba_or_action(parts["test"].x))
    with pytest.raises(ValueError):
        p.predict_proba_or_action(gp["test"].x.assign(label=gp["test"].y))
    with pytest.raises(TypeError):
        p.predict_proba_or_action(gp["test"].x, y=gp["test"].y)


def test_saved_model_threshold_runtime_parity_and_registry_routing(data, tmp_path):
    baseline, test = data[-1], data[5]["test"]
    directory = tmp_path / "model"
    baseline.save(directory)
    runtime = RuntimeDetector(directory)
    assert runtime.threshold == baseline.threshold
    p = runtime.predict_proba_or_action(test.x)
    assert np.array_equal(p, baseline.predict_proba_or_action(test.x))
    from sdn import CompletedWindowController
    controller = CompletedWindowController(runtime, tmp_path / "audit.jsonl", audit_enabled=False)
    for i in range(5):
        decision = controller.detect_completed_window(test.x.iloc[i].to_dict(), str(i))
        assert decision["probability"] == p[i]
        assert decision["prediction"] == int(p[i] >= runtime.threshold)
    # Redirect a registry to a second valid serialized operating selection fixture.
    import shutil
    alternate = tmp_path / "alternate"
    shutil.copytree(directory, alternate)
    registry = read_json(ROOT / "configs/threshold_registry.json")
    registry["operating"]["selection_file"] = str(alternate / "threshold_selection.json")
    selection = read_json(alternate / "threshold_selection.json")
    selection["selected_value"] = float(np.nextafter(1., np.inf))
    selection["registry_hash"] = object_hash(registry)
    write_json(alternate / "threshold_selection.json", selection)
    registry_path = tmp_path / "registry.json"; write_json(registry_path, registry)
    alternate_runtime = RuntimeDetector(registry_path=registry_path)
    assert alternate_runtime.threshold != runtime.threshold
    assert all(alternate_runtime.decide(row)["prediction"] == 0 for row in test.x.to_dict("records"))
    assert np.any(p >= runtime.threshold)


def test_undefined_metrics_are_explicit():
    result = metrics(np.array([0, 0]), np.array([.1, .2]), np.array([0, 0]))
    assert result["recall"] is None and result["precision"] is None and result["roc_auc"] is None
    assert "zero denominator" in result["undefined_metrics"]
    with pytest.raises(ValueError):
        metrics([0, 1], [np.nan, .2], [0, 0])


def test_legacy_label_leaking_generator_removed():
    from scripts.q1_system_upgrade_v2 import graph_policy_ablation
    with pytest.raises(RuntimeError, match="withdrawn"):
        graph_policy_ablation()
    assert "y ==" not in inspect.getsource(graph_policy_ablation)


def test_clean_output_reproducibility_smoke(data, tmp_path):
    from reviewer_revision.pipeline import run
    output = tmp_path / "fresh_revision"
    assert not output.exists()
    run(data[0], output)
    assert verify_results(output)["passed"]
    for name in ["temporal_fold_definitions.csv", "temporal_confidence_intervals.csv", "policy_pairwise_statistics.csv",
                 "validation_threshold_curve.csv", "experiment_manifest.json", "CHECKSUMS.sha256", "tables/table_9.csv"]:
        assert (output / name).is_file()
    with pytest.raises(FileExistsError):
        run(data[0], output)


def test_runtime_feature_builder_matches_offline_completed_window(data, monkeypatch):
    import sdn
    _, raw, windows, _, _, _, _, _ = data
    first = windows.iloc[0]
    instant = pd.Timestamp(first.window_start_ts).timestamp()
    monkeypatch.setattr(sdn, "now_ts", lambda: instant + 1)
    events = raw[(raw.run_id == first.run_id) & (raw.switch_id == first.switch_id) &
                 (raw.dst_ip == first.dst_ip) &
                 (pd.to_datetime(raw.event_ts, utc=True, format="mixed").dt.floor("5s") == pd.Timestamp(first.window_start_ts))]
    builder = sdn.WindowFeatureBuilder(window_sec=5)
    for row in events.itertuples():
        got = builder.update(row.switch_id, row.dst_ip, row.src_ip, row.packet_count, row.byte_count, row.flow_count)
    assert list(got) == FEATURES
    assert np.allclose([got[name] for name in FEATURES], first[FEATURES].to_numpy(dtype=float))


def test_actual_http_completed_window_endpoint_and_controller_status(data, tmp_path, monkeypatch):
    import asyncio
    import sdn
    from aiohttp.test_utils import TestClient, TestServer
    baseline = data[-1]
    directory = tmp_path / "model_http"
    baseline.save(directory)
    registry = read_json(ROOT / "configs/threshold_registry.json")
    registry["operating"]["selection_file"] = str(directory / "threshold_selection.json")
    selection = read_json(directory / "threshold_selection.json")
    selection["registry_hash"] = object_hash(registry)
    write_json(directory / "threshold_selection.json", selection)
    registry_path = tmp_path / "registry_http.json"
    write_json(registry_path, registry)
    monkeypatch.setenv("GRAPHSHIELD_THRESHOLD_REGISTRY", str(registry_path))
    monkeypatch.setenv("POLICY_MODE", "baseline_only")
    mgr = sdn.MultiControllerManager("127.0.0.1", 9, 5)
    c = mgr.add_controller("ctrl_primary_01", sdn.ControllerRole.PRIMARY, 0)
    c.completed_window_controller.audit_path = tmp_path / "http_audit.jsonl"
    server = sdn.IntegrationAPIServer(mgr, 0)
    features = data[5]["test"].x.iloc[0].to_dict()
    expected = c.window_ml.decide(features)

    async def check():
        async with TestClient(TestServer(server.app)) as client:
            response = await client.post("/detect-window", json={"features": features, "row_id": "http_test"})
            assert response.status == 200
            result = await response.json()
            assert result["probability"] == expected["probability"]
            assert result["prediction"] == expected["prediction"]
            assert result["threshold"] == baseline.threshold
            assert (await client.get("/controllers")).status == 200
            assert (await client.get("/ml/features")).status == 200
            for forbidden in ["label", "threshold"]:
                response = await client.post("/detect-window", json={"features": features, "row_id": "bad", forbidden: 1})
                assert response.status == 400
    asyncio.run(check())
