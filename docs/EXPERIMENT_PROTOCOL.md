# Experiment entrypoints and scope

The current actual-runtime protocol is [OVS safety v3](OVS_SAFETY_V3.md).
Use `scripts/run_ovs_safety.py` for collection and `scripts/verify_ovs_safety.py`
for replay. The retired dominant-source v2 confirmation procedure is not a
supported reproduction target.

## Frozen detector provenance

`deployment_ovs_v2/` and `ovs_calibration_v2.zip` remain necessary: v3 uses that
fitted detector, feature schema and validation threshold (0.9639583333333334).
Detector fitting used enforcement-free seeds 51000-51039; validation used
52000-52019, collected after fitting data. The controlled-simulation detector
is separately fitted and is not interchangeable with the OVS detector.

`collect_ovs_calibration.py`, `train_ovs_detector.py`, `verify_ovs_detector.py`
and `configs/ovs_experiment_protocol_v2.json` retain the detector reproduction
procedure. Inspect their `--help` before collecting a new dataset. Any refitting
is a new experiment: use new output paths, never replace the frozen deployment
or tune it on confirmation results. The public verifier checks the bundled
calibration checksums and replays the deployed detector.

## Current confirmation

Source selection uses development seeds 71000-71039 and validation seeds
72000-72019. The frozen policy is `deployment_source_v3/source_policy.json`.
Kali uses 73000-73029; Ubuntu uses 83000-83029. Each confirmation has 30
schedules and three conditions (90 executions). Matched schedules do not imply
identical realized traffic. Report each host separately; hardware and OS effects
cannot be separated with these hosts.

Replay integrity, classification accuracy, attack-source targeting and measured
service harm/effectiveness are separate outcomes. These finite experiments do
not establish a formal risk bound, production safety or learned RL mitigation.
