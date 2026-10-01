#!/usr/bin/env python3
"""Fit a transparent source-rate envelope using DEVELOPMENT/VALIDATION ONLY."""
import argparse
import csv
import json
import sys
from pathlib import Path
from datetime import datetime, timezone
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from reviewer_revision.source_selector import SourceSelector, canonical_hash
from reviewer_revision.ovs_safety import write_json, sha


def load_collection(directory, stage, protocol):
    directory=Path(directory)
    config=json.loads((directory/"run_configuration.json").read_text())
    if config["stage"] != stage or config["protocol_hash"] != canonical_hash(protocol):
        raise ValueError("Wrong split/protocol; test data forbidden during fitting")
    if not (directory / "verification_v3.json").exists():
        raise ValueError("Verify the source collection before fitting")
    report=json.loads((directory/"verification_v3.json").read_text())
    if not report.get("passed") or report.get("stage")!=stage:
        raise ValueError("Invalid collection verification")
    # Recheck byte integrity, rather than relying on a stored passed flag.
    for line in (directory/"CHECKSUMS.sha256").read_text().splitlines():
        digest,relative=line.split("  ",1)
        candidate=(directory/relative).resolve()
        if not candidate.is_relative_to(directory.resolve()) or sha(candidate)!=digest:
            raise ValueError("Collection changed after verification")
    definition=protocol[stage]
    rows=[]; hashes={str((directory/"run_configuration.json").resolve()):sha(directory/"run_configuration.json")}
    for seed in range(definition["seed_start"],definition["seed_start"]+definition["runs"]):
        folder=directory/f"seed_{seed:08d}_mitigation_disabled"
        paths=[folder/"source_truth.json",folder/"window_results.csv"]
        truth=json.loads(paths[0].read_text())
        windows=list(csv.DictReader(paths[1].open()))
        expected=sum(protocol["traffic"][k] for k in ["benign_windows","attack_windows","recovery_windows"])
        if len(windows)!=expected: raise ValueError("Incomplete calibration trial")
        for index,row in enumerate(windows):
            if int(row["window_index"])!=index or row["action"]!="NONE":
                raise ValueError("Calibration must be ordered and unenforced")
            path=folder/f"window_{index:03d}"/"source_observations.json"; paths.append(path)
            rows.append((seed,index,int(row["prediction"]),json.loads(path.read_text()),truth))
        hashes.update({str(path.resolve()):sha(path) for path in paths})
    return config,rows,hashes


def evaluate(policy, rows):
    selector=None; last_seed=None; benign=attack=benign_opportunities=attack_opportunities=0
    for seed,index,prediction,observations,truth in rows:
        if seed!=last_seed: selector=SourceSelector(policy); last_seed=seed
        result=selector.select(observations,prediction=prediction,window_index=index)
        benign_opportunities += int(any(truth[o["source_ip"]]==0 and o["bytes"]>0 for o in observations))
        attack_opportunities += int(any(truth[o["source_ip"]]==1 and o["bytes"]>0 for o in observations))
        target=result["target_source"]
        if target is not None:
            benign+=int(truth[target]==0); attack+=int(truth[target]==1)
    return dict(benign_targets=benign,attack_targets=attack,benign_opportunities=benign_opportunities,
                attack_opportunities=attack_opportunities,
                benign_target_rate=benign/benign_opportunities if benign_opportunities else None)


def fit(train, validation, output, protocol):
    output=Path(output)
    if output.exists(): raise FileExistsError(output)
    tc,tr,th=load_collection(train,"development",protocol)
    vc,vr,vh=load_collection(validation,"validation",protocol)
    if {r[0] for r in tr}&{r[0] for r in vr}: raise ValueError("Overlapping seeds")
    if max(r[0] for r in tr)>=min(r[0] for r in vr): raise ValueError("Invalid split ordering")
    if tc["detector_model_hash"]!=vc["detector_model_hash"]: raise ValueError("Detector mismatch")
    rates=[o["bytes"]/o["duration_seconds"] for _,_,_,obs,truth in tr for o in obs if truth[o["source_ip"]]==0]
    if not rates or max(rates)<=0: raise ValueError("No benign calibration observations")
    search=protocol["selector_search"]; candidates=[]
    for multiplier in search["threshold_multipliers"]:
        for persistence in search["persistence_candidates"]:
            policy=dict(version="source_rate_envelope_v3",byte_rate_threshold=max(rates)*multiplier,
                        consecutive_windows=persistence,rule_ttl_seconds=protocol["rule_ttl_seconds"])
            result=evaluate(policy,vr)
            if result["benign_target_rate"] is None: raise ValueError("Validation lacks benign traffic")
            candidates.append(dict(**policy,**result,multiplier=multiplier))
    feasible=[c for c in candidates if c["benign_target_rate"]<=search["max_validation_benign_target_rate"] and c["attack_targets"]>0]
    if feasible:
        chosen=max(feasible,key=lambda c:(c["attack_targets"],-c["benign_targets"],c["byte_rate_threshold"],c["consecutive_windows"]))
        policy={k:chosen[k] for k in ["version","byte_rate_threshold","consecutive_windows","rule_ttl_seconds"]}
        result=evaluate(policy,vr)
    else:
        policy=dict(version="source_rate_envelope_v3",byte_rate_threshold=None,consecutive_windows=2,rule_ttl_seconds=protocol["rule_ttl_seconds"])
        result=evaluate(policy,vr)
    for candidate in candidates:
        candidate["selected"] = candidate["byte_rate_threshold"]==policy["byte_rate_threshold"] and candidate["consecutive_windows"]==policy["consecutive_windows"]
    policy.update(status="validation_selected",protocol_hash=canonical_hash(protocol),
        detector_model_hash=tc["detector_model_hash"],validation_attack_targets=result["attack_targets"],
        validation_metrics=result,training_rows=len(tr),validation_rows=len(vr),
        training_input_hash=canonical_hash(th),validation_input_hash=canonical_hash(vh),
        created_at=datetime.now(timezone.utc).isoformat(),
        limitations="Empirical rate gate only; cannot distinguish observationally identical benign/attack sources. Not a risk guarantee.")
    output.mkdir(parents=True)
    write_json(output/"source_policy.json",policy); write_json(output/"input_checksums.json",dict(training=th,validation=vh))
    with (output/"validation_source_threshold_curve.csv").open("w",newline="") as f:
        writer=csv.DictWriter(f,fieldnames=list(candidates[0])); writer.writeheader(); writer.writerows(candidates)
    write_json(output/"selection.json",dict(policy_hash=canonical_hash(policy),objective=search,
        result=result,confirmatory_execution_allowed=result["attack_targets"]>0))
    return policy

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ["train","validation","output"]: p.add_argument("--"+name,required=True)
    p.add_argument("--protocol",default=str(ROOT/"configs/ovs_experiment_protocol_v3.json"))
    a=p.parse_args()
    print(json.dumps(fit(a.train,a.validation,a.output,json.loads(Path(a.protocol).read_text())),indent=2))
