# Portability validation status

Completed before publication of this folder:

- Python syntax checks passed for runtime, OVS runner and verifiers.
- Thirteen platform-independent tests passed, including an end-to-end synthetic
  OVS train/validation/model/threshold verification workflow.
- Canonical model and feature-schema SHA-256 matched threshold metadata.
- Original detector configuration and threshold-registry hashes were preserved.
- Saved threshold `0.48702094063328466` loaded successfully under Python 3.13.3.
- Strict eight-feature order and label rejection passed.
- Bash syntax checks passed for setup, environment and trial wrappers.

Still required on each Linux host:

- run `scripts/verify_environment.sh`;
- collect the fixed Kali training and later validation seed ranges;
- train and verify `deployment_ovs_v2/` with zero test rows seen;
- run the confirmatory smoke experiment;
- run Kali's 30 fresh paired trials;
- clone the frozen-model commit and run Ubuntu's separate 30 fresh paired trials;
- preserve the generated verification report and checksums;
- report Kali and Ubuntu results separately.

Windows validation does not claim that OpenFlow meters or namespace traffic have
already executed. Only a passing Linux smoke/full verification can establish that.
