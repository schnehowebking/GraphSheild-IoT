# Public repository contents

The public reviewer release must include:

- source: `reviewer_revision/`, `integration/`, `scripts/`, `sdn.py`, `ml/`;
- tests: `tests/` and `.github/workflows/ci.yml`;
- machine-readable configuration: `configs/`, `deployment_ovs_v2/`;
- reviewer evidence: `reviewer_revision_v1_evidence.zip`;
- actual OVS evidence: the Kali and Ubuntu confirmatory ZIP archives;
- calibration provenance: `ovs_calibration_v2.zip`;
- documentation: `README.md`, `REPRODUCIBILITY.md`, `docs/`, `data/README.md`;
- citation and rights: `CITATION.cff`, `LICENSE`;
- integrity: `MANIFEST.sha256` and the embedded archive manifests.

Do not publish raw third-party dataset archives, manuscripts, reviewer files,
credentials, virtual environments, caches, private packet captures or superseded
pilot results. Processed external window inputs must retain source attribution and
must be described only as diagnostic feature-compatible transfer.

Before tagging, run every command in `docs/RELEASE_CHECKLIST.md`. Attach or archive
larger future evidence through a versioned research repository and record its
SHA-256 checksum and DOI; never replace generated metrics manually.
