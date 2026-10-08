# Current evidence assets

These new archives supplement the historical root-level ZIPs. They preserve the
original saved records and include byte-level manifests; no reported metric was
hand-edited during packaging. Run `scripts/verify_public_release.py --output NEW_DIRECTORY`
from the repository root to extract and independently replay them.

- `reviewer_revision_v1_complete_v2.zip`: complete controlled evidence.
- `ovs_safety_confirmatory_v3_evidence_v1.zip`: both actual OVS v3 confirmations.
- `external_raw_diagnostic_evidence_v1.zip`: raw-derived diagnostic evidence and source fingerprints.
- `ovs_source_calibration_v3_evidence_v1.zip`: original source-selector development/validation runs.

All four should accompany the corrected source release. `MANIFEST.sha256` covers
these ZIP bytes. Original v3 source-selection inputs are now included and replayed; see `docs/PUBLIC_REPRODUCTION_STATUS.txt`. These local assets have
not been published to GitHub or Zenodo by this revision task.
