#!/usr/bin/env python3
"""Generate new safety artifacts from saved rows/receiver logs; never edit inputs."""
import argparse
import json
import sys
from pathlib import Path
import numpy as np
import pandas as pd
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from reviewer_revision.ovs_safety import read_rows, mean_ci, write_json, sha


def analyze(sources, output, seed=20261002):
    output = Path(output)
    if output.exists(): raise FileExistsError(output)
    all_rows, inputs = [], {}
    for name, directory in sources.items():
        rows, hashes = read_rows(directory, name)
        all_rows.extend(rows); inputs.update(hashes)
    frame = pd.DataFrame(all_rows)
    if frame.duplicated(["dataset", "seed", "setting", "window_index"]).any():
        raise ValueError("Duplicate trial windows")
    output.mkdir(parents=True)
    frame.to_csv(output / "safety_window_records.csv", index=False)
    frame[frame.benign_target_selected == 1].to_csv(output / "benign_targeting_events.csv", index=False)
    trials = []
    for (dataset, trial_seed, setting), group in frame.groupby(["dataset", "seed", "setting"]):
        benign_windows = group[group.label == 0]
        targeted = group[group.follows_benign_target_selection == 1]
        tn=int(((group.label==0)&(group.prediction==0)).sum())
        fp=int(((group.label==0)&(group.prediction==1)).sum())
        fn=int(((group.label==1)&(group.prediction==0)).sum())
        tp=int(((group.label==1)&(group.prediction==1)).sum())
        trials.append(dict(dataset=dataset, seed=int(trial_seed), setting=setting, windows=len(group),
            tn=tn,fp=fp,fn=fn,tp=tp,accuracy=(tn+tp)/len(group),
            precision=tp/(tp+fp) if tp+fp else None,recall=tp/(tp+fn) if tp+fn else None,
            f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None,
            window_false_positive_rate=float(benign_windows.prediction.mean()) if len(benign_windows) else None,
            benign_target_selections=int(group.benign_target_selected.sum()),
            benign_target_selection_rate=float(group.benign_target_selected.mean()),
            following_windows=int(len(targeted)),
            following_windows_with_measured_loss=int((targeted.benign_loss_percent > 0).sum()),
            missing_benign_measurements=int(group.benign_receiver_mbps.isna().sum()),
            mean_benign_receiver_mbps=float(group.benign_receiver_mbps.mean()) if group.benign_receiver_mbps.notna().any() else None,
            mean_benign_loss_percent=float(group.benign_loss_percent.mean()) if group.benign_loss_percent.notna().any() else None,
            mean_attack_receiver_mbps=float(group.loc[group.label == 1, "attack_receiver_mbps"].mean()) if group.loc[group.label == 1, "attack_receiver_mbps"].notna().any() else None,
            recovery_benign_loss_percent=float(group.loc[group.phase == "recovery", "benign_loss_percent"].mean()) if group.loc[group.phase == "recovery", "benign_loss_percent"].notna().any() else None))
    trial_frame = pd.DataFrame(trials)
    trial_frame.to_csv(output / "safety_trial_metrics.csv", index=False)
    rng = np.random.default_rng(seed)
    metrics = ["accuracy", "precision", "recall", "f1", "window_false_positive_rate", "benign_target_selection_rate", "mean_benign_receiver_mbps",
               "mean_benign_loss_percent", "mean_attack_receiver_mbps", "recovery_benign_loss_percent"]
    summaries = []
    for (dataset, setting), group in trial_frame.groupby(["dataset", "setting"]):
        for metric in metrics:
            summaries.append(dict(dataset=dataset, setting=setting, metric=metric,
                **mean_ci(group[metric].dropna(), rng), undefined_trials=int(group[metric].isna().sum()),
                bootstrap_seed=seed, bootstrap_replicates=2000, unit="complete trial"))
    pd.DataFrame(summaries).to_csv(output / "safety_summary_with_ci.csv", index=False)
    paired = []
    for dataset, group in frame.groupby("dataset"):
        settings = set(group.setting)
        for left,right in [("audit_enabled","audit_disabled"), ("audit_disabled","mitigation_disabled"), ("audit_enabled","mitigation_disabled")]:
            if not {left,right} <= settings: continue
            a=group[group.setting==left].set_index(["seed","window_index"])
            b=group[group.setting==right].set_index(["seed","window_index"])
            cols=["phase","label","scheduled_benign_mbps","scheduled_attack_mbps","scheduled_attackers"]
            pd.testing.assert_frame_equal(a[cols].sort_index(),b[cols].sort_index())
            for metric in metrics:
                t = trial_frame[trial_frame.dataset==dataset].pivot(index="seed",columns="setting",values=metric)
                delta = t[left]-t[right]
                paired.append(dict(dataset=dataset, comparison=left+" minus "+right,metric=metric,
                    **mean_ci(delta.dropna(),rng),undefined_pairs=int(delta.isna().sum()),bootstrap_seed=seed))
    pd.DataFrame(paired).to_csv(output / "paired_service_differences.csv",index=False)
    totals=[]
    for dataset,g in frame.groupby("dataset"):
        totals.append(dict(dataset=dataset,windows=len(g),benign_target_selections=int(g.benign_target_selected.sum()),
          subsequent_windows_with_loss=int(((g.follows_benign_target_selection==1)&(g.benign_loss_percent>0)).sum()),
          unavailable_benign_measurements=int(g.benign_receiver_mbps.isna().sum()),
          has_no_mitigation_reference="mitigation_disabled" in set(g.setting)))
    report={"totals":totals,"bootstrap_seed":seed,"bootstrap_replicates":2000,
      "analysis_code_hash":sha(Path(__file__)),"limitations":["Target identity comes from testbed ground truth for evaluation only.",
      "Historical follow-on windows indicate association; they do not isolate meter-caused loss.",
      "Receiver loss/throughput are observed measurements, not a zero-harm guarantee.",
      "Same schedules do not imply identical realized telemetry; single-host trials are correlated within runs.",
      "Rate-based source attribution cannot distinguish benign and attack sources with indistinguishable traffic."]}
    write_json(output / "safety_analysis.json",report)
    write_json(output / "input_checksums.json",inputs)
    (output / "methodology.md").write_text("# OVS safety analysis\n\nReceiver `end.sum_received` fields only; missing measurements stay undefined. "
      "Classification FPR is not benign-service damage. Target selected in window t is associated with service in t+1; "
      "the last selection has no subsequent measured window. Means are means of complete-trial means; CIs resample trials "
      "(2000 draws, fixed seed). Paired differences resample within-seed trial differences. "
      "No mitigation reference permits schedule-matched contrasts, not identical-packet counterfactuals.\n",encoding="utf-8")
    (output / "CHECKSUMS.sha256").write_text("".join(f"{sha(p)}  {p.name}\n" for p in sorted(output.iterdir()) if p.is_file()),encoding="utf-8")
    return report


if __name__ == "__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", action="append", required=True, help="name=directory")
    p.add_argument("--output",required=True)
    args=p.parse_args()
    print(json.dumps(analyze(dict(x.split("=",1) for x in args.source),args.output),indent=2))
