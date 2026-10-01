# OVS safety revision v3 — development required before confirmation

Status: software safeguards and offline analysis are implemented. No v3 physical OVS
calibration, validation, or confirmatory results have been collected here. Do not
claim zero harm, a formal risk bound, or successful mitigation based on passing tests.
The archived v2 results and model/threshold remain unchanged. The unsafe v2 execution
entrypoint is retired. The legacy general-purpose `/detect` route is outside this
completed-window OVS protocol; this revision does not validate its safety.

## Scientific change

The window detector stays the frozen OVS v2 RF model and threshold. Its positive
prediction is a baseline proposal, not source attribution. CompletedWindowController
now defaults to NONE when no source selector is supplied. It hashes the exact window
features and source observations and records proposals, selected targets and reasons.
Actual flow installation evidence is a separate audit event. Mode rollback and OVS
rule removal remain separate operations; neither alone proves service recovery.

The experimental selector uses source bytes/duration observed in completed windows,
with no labels, source role, scenario, port-based identity, known benign IP list or
traffic schedule at inference. Development data sets a maximum observed benign-rate
envelope. Validation chooses a multiplier (1, 1.25, 1.5, 2) and persistence (1 or 2
consecutive windows) to maximize correctly targeted attack-source windows subject to
benign targeting <= 0.01 per benign-present window. Ties prefer fewer benign targets,
a larger threshold, then longer persistence. This is an empirical operating constraint,
NOT a confidence bound or calibrated risk probability. Multiple eligible sources cause
abstention, rather than choosing the largest sender. No eligible validated candidate
produces a NONE-only policy and blocks confirmatory mitigation runs.

This deliberately simple baseline is falsifiable: high-rate benign traffic can exceed
the envelope; distributed/low-rate attacks may be missed; traffic can change before
next-window enforcement. Indistinguishable benign/attack traffic cannot be separated
by this rule. An ineffective selector requires further development or narrower claims,
not tuning on confirmatory runs. After inspecting a failed confirmatory run, reserve
new seeds/protocol versions for any further confirmation.

Each selected flow gets a 15-second OVS hard timeout, is reconsidered after the next
5-second completed window, and is removed on NONE and cleanup. The meter object itself
is cleaned explicitly. TTL limits intervention duration; it does not guarantee harmlessness.
Source counter observations are pre-decision but may be affected by a previous action;
this is a closed-loop evaluation. The receiver service measurements never enter inference.

## New experimental stages

- Development: 40 no-mitigation runs, seeds 71000–71039.
- Validation: 20 no-mitigation runs, seeds 72000–72019.
- Kali confirmation: 30 schedules, seeds 73000–73029, three conditions (90 executions).
- Ubuntu confirmation: 30 schedules, seeds 83000–83029, same frozen source policy,
  three conditions (90 executions). Hardware and OS effects remain confounded.

Conditions are mitigation_disabled, audit_disabled, and audit_enabled. The last two
form the 30 audit pairs. All three use matching schedules/seeds; realized observations
and decisions may differ. Six execution-order permutations are rotated. The reference
runs enable paired service contrasts. Matching schedules is not identical packet replay.
Benign offered rates include 12 and 20 Mbps challenges in addition to v2 rates; this is
a new evaluation, not a paired improvement comparison against the v2 historical runs.
The schedule still covers a limited synthetic UDP workload, not arbitrary DDoS attacks.

## On Kali first

After pushing the changed source and pulling it onto Kali, from the repository root:

```bash
source .venv/bin/activate
python scripts/verify_manifest.py
python -m pytest tests -q
python scripts/verify_portable_runtime.py
sudo .venv/bin/python scripts/check_ovs_safety_lab.py
sudo .venv/bin/python scripts/run_ovs_safety.py --stage development --output results/ovs_safety_development_v3
sudo .venv/bin/python scripts/verify_ovs_safety.py results/ovs_safety_development_v3
sudo .venv/bin/python scripts/run_ovs_safety.py --stage validation --output results/ovs_safety_validation_v3
sudo .venv/bin/python scripts/verify_ovs_safety.py results/ovs_safety_validation_v3
python scripts/fit_ovs_source_selector.py --train results/ovs_safety_development_v3 --validation results/ovs_safety_validation_v3 --output deployment_source_v3
```

STOP and inspect `deployment_source_v3/selection.json` and the full validation curve.
No live v3 calibration data are bundled yet; do not create source_policy.json manually.
If confirmatory_execution_allowed is false, do not change thresholds merely to pass.
Review the failed attribution evidence and narrow the contribution or design a new
separately validated selector. Even a true flag does not establish harm-free mitigation.
Archive the frozen source policy and input manifests before proceeding.

## After reviewing validation, confirm on Kali

```bash
sudo .venv/bin/python scripts/run_ovs_safety.py --stage confirmatory_kali --source-policy deployment_source_v3/source_policy.json --output results/actual_ovs_kali_safety_v3
sudo .venv/bin/python scripts/verify_ovs_safety.py results/actual_ovs_kali_safety_v3
```

Transfer the exact `deployment_source_v3/` to Ubuntu with the same updated code,
existing deployment_ovs_v2 and registry. Do not refit using Ubuntu confirmatory data.

```bash
source .venv/bin/activate
sudo .venv/bin/python scripts/check_ovs_safety_lab.py
sudo .venv/bin/python scripts/run_ovs_safety.py --stage confirmatory_ubuntu --source-policy deployment_source_v3/source_policy.json --output results/actual_ovs_ubuntu_safety_v3
sudo .venv/bin/python scripts/verify_ovs_safety.py results/actual_ovs_ubuntu_safety_v3
```

All output directories must be new. No global `mn -c`, bridge reset, physical NIC,
Wi-Fi route, or router configuration is used. Lab cleanup operates on its own bridge
and namespaces. Python 3.13, existing locked dependencies, OVS, iperf3, tcpdump and root
permissions are required for live collection.

## Metrics and evidence

`window_false_positive_rate` is classification FPR, not service damage. New trial
metrics omit the misleading benign_damage alias. Safety analysis saves every targeting
selection, preceding-window target, receiver throughput/loss, and missing-measurement
status. Only iperf `end.sum_received` is read; sender throughput is not delivery.
Historical target-to-next-window associations do not isolate causal damage without
a no-mitigation reference. No missing/invalid measurement is replaced with zero.

Summary CIs resample whole trials (2000 draws, seed 20261002), or within-seed differences
for paired contrasts. Trial mean F1 is distinct from pooled-window F1. Degenerate zero-event
bootstrap intervals do not prove zero population risk. Service recovery losses are
reported separately. Performance inference timing includes decision-audit logging when
enabled; enforcement timing covers rule commands/verification, not complete network
response, and excludes the subsequent enforcement-audit append.

The verifier recomputes frozen model scores, source decisions, feature hashes, classification
metrics and timing quantiles; verifies chains, recorded flow targets/TTL and final removal;
and regenerates service summaries/CIs from receiver logs. Passing means artifact consistency,
not satisfactory safety/effectiveness. Mocked software fixtures are never real OVS results.

## Historical reanalysis

```bash
python scripts/analyze_ovs_safety.py --source kali=PATH_TO_KALI_V2 --source ubuntu=PATH_TO_UBUNTU_V2 --output results/historical_safety_analysis_NEW
```

Keep the original v2 archives. This command creates new results and source checksums;
it does not repair past measurements or change their model predictions. Full raw external
adapter/release/manuscript issues from the broader AI audit are separate work.
