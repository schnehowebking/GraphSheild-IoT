# GraphShield IoT actual OVS controller trials

This repository runs the frozen GraphShield-IoT canonical detector through real
Linux network namespaces, Open vSwitch counters, `iperf3` traffic, model-driven
OpenFlow rate limiting, audit logging and rollback. It supports Kali Linux and
Ubuntu on an authorized single-host lab.

The bundled `deployment/` model is retained only to reproduce the excluded
42000-series pilot runs. Those pilots exposed a simulator-to-OVS feature-domain
mismatch and are not efficacy evidence. The v2 workflow collects
enforcement-free actual-OVS fitting and validation runs, freezes a new
`RandomForestClassifier` and validation-only threshold in `deployment_ovs_v2/`,
then evaluates untouched Kali and Ubuntu seeds. Labels never enter feature
extraction or runtime inference.

## Included

- `deployment/`: model, feature schema, metadata, validation curve and threshold selection.
- `configs/`: unchanged canonical detector and threshold registry for provenance; the portable runner supplies `deployment/` explicitly.
- `reviewer_revision/`: strict saved-model loader and feature validation.
- `sdn.py`: `CompletedWindowController` inference and audit path.
- `integration/`: hash-linked JSONL audit implementation.
- `scripts/run_ovs_controller_trials.py`: real traffic, OVS telemetry, inference, meter enforcement and rollback.
- `scripts/collect_ovs_calibration.py`: enforcement-free actual-OVS fitting/validation collection.
- `scripts/train_ovs_detector.py`: whole-run fitting and validation-only threshold selection.
- `scripts/verify_ovs_detector.py`: split, source, model and threshold provenance verification.
- `scripts/run_ovs_confirmatory.sh`: fixed fresh seed ranges for Kali and Ubuntu confirmation.
- `scripts/verify_ovs_controller_trials.py`: independent row-level, pairing, threshold, rollback and checksum verification.
- `tests/`: platform-independent helper tests.

Raw datasets, manuscript files, old results and Python virtual environments are
intentionally excluded.

## Kali and Ubuntu installation

```bash
git clone YOUR_GITHUB_REPOSITORY_URL GraphShield-IoT
cd GraphShield-IoT
chmod +x scripts/*.sh
bash scripts/setup_linux.sh --install-system
bash scripts/verify_environment.sh
```

Python 3.13 is required for saved-model parity. If the distribution does not
provide it, install a Python 3.13 release with `pyenv`, then run:

```bash
PYTHON_BIN="$(pyenv prefix 3.13)/bin/python" bash scripts/setup_linux.sh
```

No repartitioning, container runtime or Mininet installation is required.

## Pilot boundary

Seeds `42000–42029`, the bundled `deployment/` model and threshold
`0.48702094063328466` are diagnostic pilot evidence only. Never use those
windows for v2 fitting, threshold selection or confirmatory evaluation.

## Step 1: calibration collector smoke test

Run once on Kali. The smoke output is environment evidence only.

```bash
sudo .venv/bin/python scripts/collect_ovs_calibration.py \
  --role train --smoke --output results/ovs_calibration_smoke
sudo chown -R "$(id -u):$(id -g)" results/ovs_calibration_smoke
```

## Step 2: collect fitting and validation runs on Kali

The protocol fixes 40 fitting seeds (`51000–51039`) and 20 later validation
seeds (`52000–52019`). Collection applies no inference or mitigation.

```bash
sudo .venv/bin/python scripts/collect_ovs_calibration.py \
  --role train --output results/ovs_calibration_train_v2
sudo chown -R "$(id -u):$(id -g)" results/ovs_calibration_train_v2

sudo .venv/bin/python scripts/collect_ovs_calibration.py \
  --role validation --output results/ovs_calibration_validation_v2
sudo chown -R "$(id -u):$(id -g)" results/ovs_calibration_validation_v2
```

## Step 3: freeze and verify the OVS detector

```bash
.venv/bin/python scripts/train_ovs_detector.py \
  --train results/ovs_calibration_train_v2 \
  --validation results/ovs_calibration_validation_v2 \
  --output deployment_ovs_v2

.venv/bin/python scripts/verify_ovs_detector.py \
  --train results/ovs_calibration_train_v2 \
  --validation results/ovs_calibration_validation_v2 \
  --deployment deployment_ovs_v2
```

The verifier must report `test_rows_seen: 0`, disjoint seeds, chronological
ordering, label-column rejection and the reproduced validation threshold.

## Step 4: confirmatory smoke test

```bash
sudo .venv/bin/python scripts/run_ovs_controller_trials.py \
  --smoke --base-seed 52999 --max-attackers 4 \
  --deployment-dir deployment_ovs_v2 \
  --threshold-registry configs/threshold_registry_ovs_v2.json \
  --protocol-role confirmatory \
  --output results/actual_ovs_kali_confirmatory_smoke
sudo chown -R "$(id -u):$(id -g)" results/actual_ovs_kali_confirmatory_smoke
.venv/bin/python scripts/verify_ovs_controller_trials.py \
  results/actual_ovs_kali_confirmatory_smoke \
  --deployment-dir deployment_ovs_v2 \
  --threshold-registry configs/threshold_registry_ovs_v2.json
```

## Step 5: full confirmatory experiments

Kali uses untouched seeds `53000–53029`. Commit the frozen deployment artifacts,
clone that exact commit on Ubuntu, then use Ubuntu seeds `63000–63029`.

```bash
bash scripts/run_ovs_confirmatory.sh kali
# After Kali verification succeeds, on Ubuntu:
bash scripts/run_ovs_confirmatory.sh ubuntu
```

Each OS produces 30 paired seeds and 60 executions. Up to four isolated attack
namespaces generate multiple controller-observable sources. Audit-disabled and
audit-enabled executions use identical schedules. Trial order is counterbalanced;
the only configured condition change is audit logging.

Do not pool OS results without first reporting OS-stratified results and testing
the cross-platform difference. These experiments are actual single-host OVS lab
measurements, not Internet-scale or production deployment evidence.

## Expected outputs

- `trial_level_results.csv`
- `trial_summary_with_ci.csv`
- `paired_audit_differences.csv`
- per-window features, probabilities, actions and latencies
- `traffic_sample.pcap`, OVS initial/final snapshots and audit JSONL per execution
- `environment.json`, `experiment_configuration.json`, `CHECKSUMS.sha256`
- `verification_report.json` after independent verification

See [the experiment protocol](docs/EXPERIMENT_PROTOCOL.md) and
[the GitHub upload list](docs/GITHUB_UPLOAD_LIST.md).

## Safety boundary

Run only on systems and traffic namespaces you own or are explicitly authorized
to test. The runner creates isolated namespaces and an ephemeral OVS bridge. Its
model-driven action is `RATE_LIMIT`; it does not attack or scan external hosts.

## Licensing

No license is granted merely by publication of this folder. The authors must
select and add an explicit open-source license before public release.
