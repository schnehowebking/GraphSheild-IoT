# GraphShield-IoT reproducibility repository

This repository contains the executable code, frozen configurations, trained
detectors, row-level evidence, automated checks and actual Open vSwitch (OVS)
measurements used for the revised GraphShield-IoT evaluation. It addresses the
reviewer's concerns about temporal reliability, graph-policy validity, detector
identity, threshold governance and reproducibility.

The evidence has two deliberately separate scopes:

1. `reviewer_revision_v1_evidence.zip` contains controlled timestamped
   simulation, non-overlapping forward-chaining folds, validation-only threshold
   selection, graph-policy predictions, external fixed-threshold diagnostic
   transfer and row-level metric evidence.
2. `actual_ovs_kali_confirmatory_v2.zip` and
   `actual_ovs_ubuntu_confirmatory_v2.zip` contain actual single-host OVS trials:
   30 paired seeds, 60 executions and 720 completed windows per operating system.

The frozen OVS detector is `deployment_ovs_v2/model.joblib`. Its operating
threshold is `0.9639583333333334`, selected only from the 20 validation runs in
`deployment_ovs_v2/threshold_selection.json`. Labels never enter runtime feature
construction or inference.

## Five-minute reviewer verification

Python 3.13 is required for serialized-model parity. On Linux or macOS:

```bash
git clone https://github.com/schnehowebking/GraphSheild-IoT.git
cd GraphSheild-IoT
python3.13 -m venv .venv
.venv/bin/python -m pip install --only-binary=:all: -r requirements-lock.txt
.venv/bin/python scripts/verify_manifest.py
.venv/bin/python scripts/verify_release_archives.py
.venv/bin/python -m pytest tests -q
```

On Windows, replace `.venv/bin/python` with `.venv\Scripts\python.exe`.
The archive verifier checks every embedded SHA-256 checksum, validates both OVS
verification reports and independently recomputes temporal, policy, stress,
topology, external, confidence-interval and paired-comparison results from the
saved row-level records.

## Rebuild the controlled reviewer evaluation

The five processed feature-compatible external inputs are included under
`data/external/processed/`; their provenance and diagnostic limitations are
documented in `data/README.md`. Generate a fresh versioned directory with:

```bash
.venv/bin/python scripts/run_reviewer_revision.py \
  --output results/reviewer_reproduction_v1
.venv/bin/python -m reviewer_revision.verify \
  results/reviewer_reproduction_v1
```

The pipeline refuses to overwrite an existing output directory. It records all
seeds, input/source hashes, environment versions, thresholds, fold boundaries,
row-level predictions, uncertainty estimates and table files. Timing values can
vary by host; deterministic predictions and aggregate classification metrics are
the reproducibility targets.

## Reproduce the actual OVS experiment

Use an authorized Kali or Ubuntu host. The runner creates only isolated network
namespaces and an ephemeral OVS bridge in `10.253.0.0/24`.

```bash
chmod +x scripts/*.sh
bash scripts/setup_linux.sh --install-system
bash scripts/verify_environment.sh
```

The enforcement-free calibration source is preserved in
`ovs_calibration_v2.zip`. To collect new fitting and validation runs and refit
the frozen OVS detector, follow `docs/EXPERIMENT_PROTOCOL.md`. To repeat the
confirmatory trials with the preregistered seed ranges:

```bash
bash scripts/run_ovs_confirmatory.sh kali
# On the separate Ubuntu installation:
bash scripts/run_ovs_confirmatory.sh ubuntu
```

Each command runs 30 paired audit-disabled/audit-enabled trials. Audit logging is
the intended condition difference. Results are reported separately by operating
system and are actual single-host OVS evidence, not production or Internet-scale
deployment evidence.

## Repository map

- `reviewer_revision/`: detector, temporal-fold, policy, statistics, reporting
  and independent recomputation code.
- `scripts/run_reviewer_revision.py`: controlled one-command experiment entrypoint.
- `scripts/verify_release_archives.py`: public evidence and checksum verifier.
- `scripts/run_ovs_controller_trials.py`: actual traffic, OVS counters,
  inference, enforcement, audit logging and rollback.
- `configs/`: canonical detector, deterministic seeds, protocol and threshold
  registries.
- `deployment_ovs_v2/`: frozen OVS model, feature schema, threshold curve and
  provenance metadata.
- `tests/`: label-leakage, temporal-ordering, graph-feature, threshold,
  runtime-parity, audit and OVS protocol tests.
- `MANIFEST.sha256`: checksum manifest for the public repository bundle.
- `REPRODUCIBILITY.md`: detailed claim-to-command instructions.

Raw CIC-DDoS2019, IoT-23 and TON_IoT archives, manuscript files, private account
information, virtual environments and superseded pilot results are excluded.

## Citation and rights

Use `CITATION.cff` to cite this exact software release. The current
research-evaluation license permits non-commercial peer-review and reproducibility
verification while reserving redistribution and commercial rights. See `LICENSE`.
The release DOI will be added to the manuscript after Zenodo archives tag
`v1.0.0`.
