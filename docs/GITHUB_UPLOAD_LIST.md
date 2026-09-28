# GitHub upload list

Upload the complete contents of this folder:

- `.github/workflows/ci.yml`
- `.gitignore`
- `README.md`
- `requirements-lock.txt`
- `sdn.py`
- `upgrade_common.py`
- `configs/`
- `deployment/`
- `deployment_ovs_v2/` after the verified train/validation workflow creates it;
- `integration/`
- `reviewer_revision/`
- `scripts/`
- `tests/`
- `docs/`
- `MANIFEST.sha256`

Do not upload:

- manuscript or reviewer DOCX files;
- raw CIC-DDoS2019, IoT-23 or TON_IoT datasets;
- `.venv`, caches or credentials;
- prior unverified result directories;
- packet captures containing traffic outside the isolated experiment network;
- API tokens, SSH keys or account information.

Before publishing, add an author-approved license, repository URL, release tag
and archival DOI. Record the release commit in the manuscript and response letter.

Archive the verified calibration and confirmatory result directories with their
checksums in a release or research repository. Large PCAP files may use Zenodo;
do not omit their hashes or replace them with manually edited summaries.
