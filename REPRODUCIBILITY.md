# Reviewer reproduction guide

Archived release: [GraphShield-IoT v1.0.0 on Zenodo](https://doi.org/10.5281/zenodo.23084542).

## Claims and verification commands

| Claim area | Evidence | Verification |
|---|---|---|
| Repeated non-overlapping temporal folds | `reviewer_revision_v1_evidence.zip` | `python scripts/verify_release_archives.py` |
| Confidence intervals and saved row-level predictions | same archive | same command |
| Label-free, distinct graph policies | `policy_predictions.csv`, policy metadata and tests | archive verifier plus `pytest tests/test_reviewer_revision.py -q` |
| Canonical detector and threshold governance | `configs/`, `deployment_ovs_v2/` | `python scripts/verify_portable_runtime.py` |
| Actual paired OVS trials | Kali and Ubuntu ZIP archives | `python scripts/verify_release_archives.py` |
| Full controlled regeneration | executable pipeline | `python scripts/run_reviewer_revision.py --output results/reviewer_reproduction_v1` |

## Evidence boundaries

- Controlled temporal, topology, flash-crowd and graph-policy results are
  controlled simulation measurements.
- The Kali and Ubuntu confirmatory archives are actual single-host OVS/runtime
  measurements.
- External results use one frozen transfer threshold and are diagnostic because
  public feature meanings differ from controller-window telemetry.
- Contextual-bandit and conservative offline-RL claims are excluded because the
  available logs lack action propensities and supported counterfactual outcomes.

## Independent metric recomputation

`scripts/verify_release_archives.py` extracts the evidence in a temporary
directory and recalculates confusion matrices, accuracy, precision, recall, F1,
ROC-AUC, PR-AUC, false-positive and false-negative rates, benign damage, rewards,
agreement, action counts, bootstrap confidence intervals, McNemar comparisons,
stress summaries and paired audit differences. Undefined metrics remain explicit
rather than being silently replaced.

## Determinism

The controlled pipeline records seed `41000`, bootstrap seed `9127`, all run
seeds, fold boundaries and configuration hashes. The OVS protocol reserves
`51000-51039` for fitting, `52000-52019` for validation, `53000-53029` for Kali
confirmation and `63000-63029` for Ubuntu confirmation. Thread counts and the
RandomForest seed are fixed.

## Expected limitations

Wall-clock and audit timing values vary across hosts. OVS reproduction requires
Linux root privileges because it creates namespaces, bridges and meters. The
testbed does not establish multi-controller, hardware-switch, WAN or production
performance.
