#!/usr/bin/env python3
"""Replay model/source decisions, service metrics and audit evidence independently."""
import argparse
import json
import sys
import tempfile
from pathlib import Path
import numpy as np
import pandas as pd
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/"scripts"))
from reviewer_revision.core import RuntimeDetector, FEATURES
from reviewer_revision.source_selector import SourceSelector, canonical_hash
from reviewer_revision.ovs_safety import sha, write_json
from integration.audit_hash_chain import verify_hash_chained_jsonl
from run_ovs_controller_trials import binary_metrics
from analyze_ovs_safety import analyze


def verify(output, deployment, registry):
    out=Path(output)
    config=json.loads((out/"run_configuration.json").read_text())
    protocol=config["protocol"]
    if canonical_hash(protocol)!=config["protocol_hash"]: raise ValueError("Protocol hash mismatch")
    policy=config["source_policy"]
    if canonical_hash(policy)!=config["source_policy_hash"]: raise ValueError("Policy hash mismatch")
    detector=RuntimeDetector(directory=Path(deployment),registry_path=Path(registry))
    if detector.selection["model_hash"]!=config["detector_model_hash"] or detector.threshold!=config["detector_threshold"]:
        raise ValueError("Detector configuration mismatch")
    definition=protocol[config["stage"]]
    confirmation=config["stage"].startswith("confirmatory_")
    if confirmation:
        from run_ovs_safety import validate_policy
        validate_policy(policy,protocol,detector)
    elif policy is not None: raise ValueError("Calibration with source policy")
    expected_conditions=protocol["confirmatory_conditions"] if confirmation else ["mitigation_disabled"]
    if config["conditions"]!=expected_conditions: raise ValueError("Wrong conditions")
    expected_folders={f"seed_{seed:08d}_{condition}" for seed in range(definition["seed_start"],definition["seed_start"]+definition["runs"])
                      for condition in expected_conditions}
    folders={p.parent.name for p in out.glob("seed_*/window_results.csv")}
    if folders!=expected_folders: raise ValueError("Missing/extra trials")
    covered=set()
    for line in (out/"CHECKSUMS.sha256").read_text().splitlines():
        digest,relative=line.split("  ",1); path=(out/relative).resolve()
        if not path.is_relative_to(out.resolve()) or sha(path)!=digest: raise ValueError(f"Checksum mismatch: {relative}")
        covered.add(relative)
    actual={p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file() and p.name not in ["verification_v3.json"]}
    actual.remove("CHECKSUMS.sha256")
    if actual!=covered: raise ValueError("Checksum coverage differs from artifact files")
    checked=chains=0; metrics_all=json.loads((out/"trial_metrics_all.json").read_text())
    for folder_name in sorted(folders):
        folder=out/folder_name
        frame=pd.read_csv(folder/"window_results.csv",float_precision="round_trip",keep_default_na=False)
        expected_n=sum(protocol["traffic"][k] for k in ["benign_windows","attack_windows","recovery_windows"])
        if len(frame)!=expected_n or list(frame.window_index)!=list(range(expected_n)): raise ValueError("Incomplete windows")
        probabilities=detector.predict_proba_or_action(frame[FEATURES])
        if not np.array_equal(probabilities,frame.probability.to_numpy(float)): raise ValueError("Model replay mismatch")
        if not np.all(frame.threshold.to_numpy(float)==detector.threshold): raise ValueError("Threshold mismatch")
        predictions=(probabilities>=detector.threshold).astype(int)
        if not np.array_equal(predictions,frame.prediction.to_numpy(int)): raise ValueError("Classification mismatch")
        selector=SourceSelector(policy) if policy else None
        condition=frame.setting.iloc[0]; records=[]
        audit=folder/"audit.jsonl"
        if condition=="audit_enabled":
            if not verify_hash_chained_jsonl(audit)["valid_embedded_hash_chain"]: raise ValueError("Invalid chain")
            records=[json.loads(line) for line in audit.read_text().splitlines()]
            if len(records)!=2*len(frame)+1: raise ValueError("Missing decision/enforcement audit records")
            if records[-1].get("event")!="rollback_to_baseline": raise ValueError("Missing mode rollback record")
            chains+=1
        elif audit.exists(): raise ValueError("Unexpected audit records")
        for index,row in frame.iterrows():
            window=folder/f"window_{index:03d}"
            observations=json.loads((window/"source_observations.json").read_text())
            result=selector.select(observations,prediction=int(row.prediction),window_index=index) if selector else dict(
                action="NONE",target_source=None,safety_reason="source_selector_unavailable",source_policy_hash=None)
            action=result["action"] if condition!="mitigation_disabled" else "NONE"
            target=result["target_source"] if action=="RATE_LIMIT" else None
            if row.action!=action or row.rate_limited_source_for_next_window!=(target or ""): raise ValueError("Source/action replay mismatch")
            if row.safety_reason!=result["safety_reason"]: raise ValueError("Reason mismatch")
            feature_hash=canonical_hash({key:float(row[key]) for key in FEATURES})
            if row.input_feature_hash!=feature_hash or row.source_observations_hash!=canonical_hash(observations):
                raise ValueError("Observation hash mismatch")
            if row.source_policy_hash!=(result["source_policy_hash"] or ""): raise ValueError("Row policy hash mismatch")
            enforcement=json.loads((window/"enforcement.json").read_text())
            if enforcement["selected_action"]!=action or enforcement["target_source"]!=target or enforcement["applies_to_window"]!=index+1:
                raise ValueError("Enforcement record mismatch")
            flow=enforcement["observed_flows"]
            if target:
                matching=[line for line in flow.splitlines() if "cookie=0x475402" in line]
                if len(matching)!=1 or f"nw_src={target}," not in matching[0] or "actions=meter:1,NORMAL" not in matching[0]:
                    raise ValueError("Enforcement flow evidence mismatch")
                if f"hard_timeout={policy['rule_ttl_seconds']}" not in matching[0]: raise ValueError("Rule is not bounded")
            elif "cookie=0x475402" in flow: raise ValueError("NONE left an active meter flow")
            if records:
                event,observed=records[index*2:index*2+2]
                for key,value in {"action":action,"target_source":target,"input_feature_hash":feature_hash,
                                  "source_observations_hash":canonical_hash(observations),"safety_reason":result["safety_reason"]}.items():
                    if event.get(key)!=value: raise ValueError(f"Audit decision mismatch: {key}")
                for key,value in enforcement.items():
                    if observed.get(key)!=value: raise ValueError(f"Audit enforcement mismatch: {key}")
        final=(folder/"ovs_final_after_rollback.txt").read_text()
        if "cookie=0x475402" in final or "meter=1" in final: raise ValueError("Cleanup failed")
        metrics=binary_metrics(frame.label,frame.prediction)
        metrics["window_false_positive_rate"]=metrics.pop("benign_damage")
        saved=json.loads((folder/"trial_metrics.json").read_text())
        for key,value in metrics.items():
            if saved[key]!=value: raise ValueError(f"Classification metric mismatch: {key}")
        indexed=[m for m in metrics_all if m["seed"]==saved["seed"] and m["setting"]==saved["setting"]]
        if indexed!=[saved]: raise ValueError("Combined metrics mismatch")
        for field,column,quantile in [("inference_p50_ms","inference_latency_ms",50),("inference_p90_ms","inference_latency_ms",90),
                ("inference_p99_ms","inference_latency_ms",99),("enforcement_p50_ms","enforcement_latency_ms",50)]:
            if not np.isclose(saved[field],np.percentile(frame[column],quantile),rtol=0,atol=1e-10): raise ValueError("Timing summary mismatch")
        checked+=len(frame)
    with tempfile.TemporaryDirectory() as tmp:
        target=Path(tmp)/"analysis"
        analyze({config["stage"]:out},target,protocol["bootstrap_seed"])
        for path in target.glob("*.csv"):
            # Recompute service/target metrics and their trial CIs from original receiver logs.
            if path.stat().st_size<=2:
                if (out/"safety_analysis"/path.name).read_bytes()!=path.read_bytes(): raise ValueError("Empty summary mismatch")
            else:
                pd.testing.assert_frame_equal(pd.read_csv(path),pd.read_csv(out/"safety_analysis"/path.name))
    return dict(passed=True,stage=config["stage"],executions=len(folders),windows_verified=checked,
        audit_chains_verified=chains,checksums_verified=len(covered),matched_schedules_verified=True,
        realized_inputs_identical="not assumed",safety_claim="Replay integrity only; inspect measured harm and effectiveness separately")

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("output")
    p.add_argument("--deployment-dir",default=str(ROOT/"deployment_ovs_v2"))
    p.add_argument("--threshold-registry",default=str(ROOT/"configs/threshold_registry_ovs_v2.json"))
    a=p.parse_args(); report=verify(a.output,a.deployment_dir,a.threshold_registry)
    write_json(Path(a.output)/"verification_v3.json",report); print(json.dumps(report,indent=2))
