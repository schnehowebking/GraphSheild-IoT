#!/usr/bin/env python3
"""Collect v3 source calibration or run frozen, three-condition safety trials."""
import argparse
import itertools
import json
import platform
import sys
from pathlib import Path
from datetime import datetime, timezone
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT / "scripts"))
from run_ovs_controller_trials import preflight, run_trial, version
from reviewer_revision.core import RuntimeDetector
from reviewer_revision.source_selector import canonical_hash
from reviewer_revision.ovs_safety import write_json, sha
from analyze_ovs_safety import analyze


def validate_policy(policy, protocol, detector):
    if policy.get("protocol_hash") != canonical_hash(protocol):
        raise ValueError("Source policy/protocol mismatch")
    if policy.get("detector_model_hash") != detector.selection["model_hash"]:
        raise ValueError("Source policy/detector mismatch")
    if policy.get("status") != "validation_selected":
        raise ValueError("Source policy needs disjoint development/validation selection")
    if policy.get("validation_attack_targets",0) <= 0:
        raise ValueError("No demonstrated source attribution: do not launch mitigation confirmation")


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--stage",required=True,choices=["development","validation","confirmatory_kali","confirmatory_ubuntu"])
    p.add_argument("--output",required=True)
    p.add_argument("--protocol",default=str(ROOT/"configs/ovs_experiment_protocol_v3.json"))
    p.add_argument("--deployment-dir",default=str(ROOT/"deployment_ovs_v2"))
    p.add_argument("--threshold-registry",default=str(ROOT/"configs/threshold_registry_ovs_v2.json"))
    p.add_argument("--source-policy",help="validation-selected source_policy.json, required for confirmation")
    args=p.parse_args()
    preflight()
    protocol=json.loads(Path(args.protocol).read_text(encoding="utf-8"))
    detector=RuntimeDetector(directory=Path(args.deployment_dir),registry_path=Path(args.threshold_registry))
    confirmation=args.stage.startswith("confirmatory_")
    if confirmation and platform.freedesktop_os_release().get("ID") != args.stage.split("_")[1]:
        raise ValueError("Host OS does not match confirmatory stage")
    policy=json.loads(Path(args.source_policy).read_text()) if args.source_policy else None
    if policy is not None:
        selection_file=Path(args.source_policy).parent/"selection.json"
        selection=json.loads(selection_file.read_text())
        if selection.get("policy_hash")!=canonical_hash(policy):
            raise ValueError("Frozen source policy differs from its saved validation selection")
    if confirmation:
        if policy is None: raise ValueError("Fit source selector on development/validation first")
        validate_policy(policy,protocol,detector)
    elif policy is not None:
        raise ValueError("Calibration must be collected without a source policy or enforcement")
    stage=protocol[args.stage]; traffic=protocol["traffic"]
    for key in ["window_seconds","poll_seconds","benign_windows","attack_windows","recovery_windows"]:
        setattr(args,key,traffic[key])
    args.max_attackers=traffic["maximum_attacker_namespaces"]
    args.benign_rates=traffic["benign_rates_mbps"]; args.attack_rates=traffic["attack_rates_mbps"]
    args.meter_rate_kbps=protocol["meter_rate_kbps"]; args.source_policy=policy; args.safety_v3=True
    out=Path(args.output).resolve()
    if out.exists(): raise FileExistsError(out)
    out.mkdir(parents=True)
    conditions=protocol["confirmatory_conditions"] if confirmation else ["mitigation_disabled"]
    permutations=list(itertools.permutations(conditions))
    configuration={"stage":args.stage,"protocol":protocol,"protocol_hash":canonical_hash(protocol),
       "source_policy":policy,"source_policy_hash":canonical_hash(policy),"conditions":conditions,
       "detector_model_hash":detector.selection["model_hash"],"detector_threshold":detector.threshold,
       "deployment_dir":str(Path(args.deployment_dir).resolve()),"measurement_type":"actual_single_host_ovs_runtime",
       "created_at":datetime.now(timezone.utc).isoformat(),"os_release":platform.freedesktop_os_release(),
       "python":platform.python_version(),"ovs":version(["ovs-vsctl","--version"]),
       "source_checksums":{str(p.relative_to(ROOT)):sha(p) for p in sorted(ROOT.rglob("*.py"))
                           if not any(x in p.parts for x in (".venv","results","__pycache__"))}}
    write_json(out/"run_configuration.json",configuration)
    trials=[]
    for offset in range(stage["runs"]):
        seed=stage["seed_start"]+offset
        for condition in permutations[offset % len(permutations)]:
            print(f"{args.stage} {offset+1}/{stage['runs']}: seed={seed} {condition}",flush=True)
            trials.append(run_trial(out,seed,condition,args))
    write_json(out/"trial_metrics_all.json",trials)
    analyze({args.stage:out},out/"safety_analysis",protocol["bootstrap_seed"])
    files=sorted(p for p in out.rglob("*") if p.is_file())
    (out/"CHECKSUMS.sha256").write_text("".join(f"{sha(p)}  {p.relative_to(out).as_posix()}\n" for p in files),encoding="utf-8")
    print(json.dumps({"status":"collection_complete","stage":args.stage,"executions":len(trials),
                      "next":"run verify_ovs_safety.py; collection does not establish safety"},indent=2))

if __name__=="__main__": main()
