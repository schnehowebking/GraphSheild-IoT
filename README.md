# GraphShield IoT actual OVS controller trials

This repository runs the frozen GraphShield-IoT canonical detector through real
Linux network namespaces, Open vSwitch counters, `iperf3` traffic, model-driven
OpenFlow rate limiting, audit logging and rollback. It supports Kali Linux and
Ubuntu on an authorized single-host lab.

The canonical model is the unchanged `RandomForestClassifier` deployment
artifact. Its eight-feature order and validation-selected operating threshold
are verified by SHA-256 before use. External labels and trial phase labels never
enter inference.

## Included

- `deployment/`: model, feature schema, metadata, validation curve and threshold selection.
- `configs/`: unchanged canonical detector and threshold registry for provenance; the portable runner supplies `deployment/` explicitly.
- `reviewer_revision/`: strict saved-model loader and feature validation.
- `sdn.py`: `CompletedWindowController` inference and audit path.
- `integration/`: hash-linked JSONL audit implementation.
- `scripts/run_ovs_controller_trials.py`: real traffic, OVS telemetry, inference, meter enforcement and rollback.
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

## Smoke trial

The smoke run verifies connectivity and one paired execution. It is not a
publication result.

```bash
sudo .venv/bin/python scripts/run_ovs_controller_trials.py \
  --smoke --output results/actual_ovs_smoke
sudo chown -R "$(id -u):$(id -g)" results/actual_ovs_smoke
.venv/bin/python scripts/verify_ovs_controller_trials.py results/actual_ovs_smoke
```

## Full paired experiment

Run separately on Kali and Ubuntu. Both systems must use the same commit and
default seeds/configuration.

```bash
bash scripts/run_trials.sh results/actual_ovs_kali_v1 30
# On Ubuntu use:
bash scripts/run_trials.sh results/actual_ovs_ubuntu_v1 30
```

Each OS produces 30 paired seeds and 60 executions. Audit-disabled and
audit-enabled conditions use identical phase schedules and traffic rates. Trial
order is counterbalanced. The only configured condition change is audit logging.

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
