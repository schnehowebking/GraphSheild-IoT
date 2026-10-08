# Public reviewer bundle contents

Include source, tests, configs, pinned requirements, deployment_ovs_v2,
deployment_source_v3, compact controlled-pipeline inputs, documentation,
MANIFEST.sha256, ovs_calibration_v2.zip and all four ZIPs under release_assets/.
The root calibration ZIP is active provenance, despite its v2 filename.

The release_assets ZIPs provide complete controlled evidence, both v3 OVS
confirmations, external diagnostics and source-selector development/validation.
Use `python scripts/verify_public_release.py --output results/public_check_NEW`
to verify them. See README.md for the full setup and reproduction sequence.

Do not upload .venv, caches, ignored local results, raw third-party datasets,
manuscripts, obsolete v2 confirmation ZIPs or duplicate compact evidence ZIPs.
The legacy summary CSV and simulator helper modules are retained because the
current pipeline imports them or uses them for traceable old-versus-new comparison.

Before publishing, inspect `git status --short`, stage the intended files and
removals, inspect the staged diff, and follow RELEASE_CHECKLIST.md. This document
does not imply a push, release or native Linux CI run has already succeeded.
