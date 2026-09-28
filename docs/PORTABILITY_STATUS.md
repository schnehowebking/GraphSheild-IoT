# Portability validation status

Completed before publication of this folder:

- Python syntax checks passed for runtime, OVS runner and verifiers.
- Five platform-independent unit tests passed.
- Canonical model and feature-schema SHA-256 matched threshold metadata.
- Original detector configuration and threshold-registry hashes were preserved.
- Saved threshold `0.48702094063328466` loaded successfully under Python 3.13.3.
- Strict eight-feature order and label rejection passed.
- Bash syntax checks passed for setup, environment and trial wrappers.

Still required on each Linux host:

- run `scripts/verify_environment.sh`;
- run and verify the smoke experiment;
- run 30 paired trials;
- preserve the generated verification report and checksums;
- report Kali and Ubuntu results separately.

Windows validation does not claim that OpenFlow meters or namespace traffic have
already executed. Only a passing Linux smoke/full verification can establish that.
