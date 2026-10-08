# GraphShield-IoT reviewer reproduction bundle

This source-available research bundle separates controlled simulation, offline
external diagnostics and actual single-host OVS measurements. Successful artifact
verification establishes consistency of saved evidence, not a formal risk bound
or universal mitigation safety.

## Current reviewer evidence

- `release_assets/reviewer_revision_v1_complete_v2.zip`: complete original
  controlled reviewer evidence, including fold models, audit logs and stress inputs
  omitted from the older compact ZIP. Original bytes and metrics are preserved.
- `release_assets/ovs_safety_confirmatory_v3_evidence_v1.zip`: Kali and Ubuntu v3,
  each with 30 schedules x 3 conditions = 90 executions and 1,080 windows.
- `release_assets/external_raw_diagnostic_evidence_v1.zip`: raw-derived external
  windows, saved predictions, tables, feature semantics and consumed-source hashes.
- `ovs_calibration_v2.zip`: original OVS detector fitting/validation evidence.
- `release_assets/ovs_source_calibration_v3_evidence_v1.zip`: original 40 development
  and 20 validation runs for the source selector; all candidate thresholds and the
  frozen choice are independently replayed by the public verifier.

Superseded v2 confirmatory and duplicate compact ZIPs are excluded from this public
bundle. The v2 detector and calibration archive remain required by the v3 protocol.
Do not interpret window false-positive rate as benign-service harm.

## Verify from a clean clone

Use Python 3.13 and the pinned dependencies. No raw datasets, root access, OVS
installation or network traffic generation is needed for offline replay.

```bash
git clone https://github.com/schnehowebking/GraphSheild-IoT.git
cd GraphSheild-IoT
python3.13 -m venv --copies .venv
.venv/bin/python -m pip install --only-binary=:all: -r requirements-lock.txt
.venv/bin/python scripts/verify_manifest.py
.venv/bin/python -m pytest tests -q
.venv/bin/python scripts/verify_portable_runtime.py
.venv/bin/python scripts/verify_public_release.py --output results/public_check_v1
```

On Windows use `.venv\Scripts\python.exe`. The output directory must not exist.
The final command extracts fresh files, checks complete archive coverage, recomputes
controlled statistics and external diagnostic confidence intervals, replays external
model predictions, and replays both OVS model/source-policy decisions, observed rule
and cleanup evidence, receiver measurements and audit chains. Read
`results/public_check_v1/verification.json` for exact checks and limitations.

## Generate fresh controlled experiments

```bash
.venv/bin/python scripts/run_reviewer_revision.py --output results/reviewer_reproduction_v2
.venv/bin/python -m reviewer_revision.verify results/reviewer_reproduction_v2
```

For a short integration run add `--smoke`. The pipeline refuses overwrites.
This command generates controlled experiments, not real OVS trials or raw-dataset
processing. Timing varies by host. See [external reproduction](docs/EXTERNAL_REPRODUCTION.md)
for the separate raw-source processing command and diagnostic limitations.

## Actual OVS v3 replication

On an authorized Ubuntu or Kali host with Python 3.13:

```bash
bash scripts/setup_linux.sh --install-system
bash scripts/verify_environment.sh
sudo .venv/bin/python scripts/check_ovs_safety_lab.py
sudo .venv/bin/python scripts/run_ovs_safety.py \
  --stage confirmatory_ubuntu \
  --source-policy deployment_source_v3/source_policy.json \
  --output results/actual_ovs_ubuntu_safety_v3
sudo .venv/bin/python scripts/verify_ovs_safety.py results/actual_ovs_ubuntu_safety_v3
```

For Kali use `confirmatory_kali` and a new Kali output path. Do not retune the
model, threshold or source policy using confirmatory results. Do not rerun into
existing result directories. This uses isolated namespaces and an ephemeral OVS
bridge; it does not need physical Wi-Fi traffic. See [v3 protocol](docs/OVS_SAFETY_V3.md).

Frozen runtime model: `deployment_ovs_v2/model.joblib`; validation threshold:
`0.9639583333333334`. Frozen source policy: `deployment_source_v3/source_policy.json`.
The selector is an empirical byte-rate gate, not calibrated attack attribution.
Audit conditions share scheduled inputs/seeds; realized telemetry may differ.

## Provenance and remaining limitations

Original source-selector development/validation raw runs (40+20) are now included.
The public verifier replays both collections, compares every consumed file with
the frozen input fingerprints, refits into a separate directory and compares the
full validation curve and selected policy. Only the new creation timestamp and
path-derived provenance hashes differ after relocation; deployed policy files
remain unchanged. Do not use confirmatory runs as replacement training data.

Native Linux verification of this updated bundle still needs CI or a Linux host;
local WSL cannot start with virtualization disabled. The Ubuntu/Kali OVS artifacts
are actual recorded measurements, independent of this packaging limitation.

Manuscript claims, release metadata/license consistency and third-party data
redistribution terms require separate final review. This bundle is not a claim
that all reviewer concerns or scientific limitations have disappeared.

## Citation and rights

See `CITATION.cff` and `LICENSE` (research-evaluation, not OSI open source).
This working tree is an unreleased revision. The previous DOI does not identify
these updated files. Publish and verify a new version before adding its DOI, version
and release date to CITATION.cff. Cite the exact Git commit until then.
Raw third-party datasets are not bundled.
