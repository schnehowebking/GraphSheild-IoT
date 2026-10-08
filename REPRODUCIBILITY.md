# Claim-to-command map

| Evidence | Command / source | Interpretation |
|---|---|---|
| Complete controlled temporal folds, policies, uncertainty | `verify_public_release.py`, complete controlled ZIP | Controlled simulation; folds and policy result statistics recomputed |
| Actual OVS v3 confirmation | same verifier, v3 evidence ZIP | 90 executions per OS; classification, source choice, service and audit replay |
| External raw-derived diagnostic | same verifier, external ZIP | Frozen controlled model and threshold; feature proxies, not live deployment equivalence |
| Frozen runtime schema/threshold | `verify_portable_runtime.py` | Serialized OVS model parity |
| Raw external processing | `reproduce_external.py` | Publisher sources needed; see `docs/EXTERNAL_REPRODUCTION.md` |
| Fresh controlled regeneration | `run_reviewer_revision.py --output NEW_DIRECTORY` | Excludes actual OVS traffic and raw-source processing |
| Source-policy selection | `verify_source_policy.py` (also called by public verifier) | Original 40+20 runs, all 8 candidates and frozen selection independently replayed |

Commands above are under `scripts/`. Full invocations are in README.md.

Controlled seeds: simulation 41000, bootstrap 9127. OVS detector calibration:
51000-51039 fitting, 52000-52019 validation. V3 source selection: 71000-71039
and 72000-72019. V3 confirmation: Kali 73000-73029, Ubuntu 83000-83029.
V3 bootstrap seed: 20261002. External bootstrap seed: 20260928.

Superseded v2 confirmation artifacts are excluded from this public bundle.
Finite single-host runs cannot establish WAN, hardware-switch or production safety.
Classification F1, source-selection coverage and actual mitigation effectiveness
are separate measures. Hash-linked local audit is tamper evidence, not distributed
consensus or authenticated proof of data collection. RL/bandit learning claims
remain unsupported without suitable logged action/reward/propensity trajectories.

Complete evidence preserves historical files byte-for-byte. Hashes prove consistency
against the included manifest, not independent authenticity. A new release must
publish the source bundle, all release_assets ZIPs and the source manifest together.
Do not claim the current local bundle already exists at the historical Zenodo DOI.
