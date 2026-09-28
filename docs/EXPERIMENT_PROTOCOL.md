# Actual OVS paired trial protocol

## Objective

Fit, select and measure one frozen GraphShield-IoT detector using semantically
identical actual OpenFlow-counter features. Measure its audit path and rollback
on Kali and Ubuntu without reusing pilot or test labels.

## Testbed

Every execution creates a fresh OVS bridge, one benign client, one server and up
to four attack-client Linux namespaces. `iperf3` generates traffic only inside
`10.253.0.0/24`. OVS tracking-flow counters are sampled once per second and
aggregated into completed five-second switch-destination windows.

The eight inputs are packet rate, byte rate, packet sum, telemetry-event count,
distinct source count, source-edge-observation Shannon entropy, nonzero
source-service edge-observation count and its rate. `events` counts polling
intervals with any traffic; `flow_count` counts active source-service edge
observations across polls. The phase label is never passed to feature extraction
or `detect_completed_window`.

## Preregistered partitions

- Seeds `42000–42029`: excluded pilot diagnostics; never reused.
- Seeds `51000–51039`: enforcement-free model fitting.
- Seeds `52000–52019`: later enforcement-free threshold validation.
- Seeds `53000–53029`: untouched paired Kali confirmation.
- Seeds `63000–63029`: untouched paired Ubuntu confirmation.

Training and validation are whole-run partitions with disjoint seeds. Training
must finish before validation starts. The threshold maximizes validation F1
subject to the registered maximum FPR and deterministic tie-breaking. Test
windows never enter fitting, feature selection or threshold selection.

## Paired design

For each confirmatory set of 30 seeds, audit-disabled and audit-enabled executions receive
the same ordered phases and requested traffic rates. Execution order alternates
by seed to reduce order bias. Each default execution has three benign windows,
six attack windows and three recovery windows. Audit logging is the configured
condition difference.

The smoke mode uses one window per phase and cannot support publication claims.

## Runtime decision and enforcement

The frozen validation threshold selects `NONE` or `RATE_LIMIT`. When rate limiting
is selected, an OpenFlow meter is installed for the controller-observable dominant
source in the completed window and affects the next window. Meter and rule evidence
is read back from OVS. Rollback removes all experiment meter rules and verifies
that none remains.

## Statistics

Each execution records TN, FP, FN, TP, accuracy, precision, recall, F1, FPR,
FNR, benign damage, inference latency, enforcement latency, throughput and audit
bytes. Summaries include mean, sample standard deviation, median, 95% trial-level
bootstrap CI, minimum, maximum and trial count. Paired audit differences use the
same seeds and a fixed bootstrap seed.

F1 uses `2TP/(2TP+FP+FN)`. It is zero when TP is zero and FP+FN is positive;
it is undefined only when that denominator is zero.

Kali and Ubuntu are reported separately. Cross-platform results are compared as
an OS factor; they are not silently pooled as extra independent replications.

## Required evidence

Publication results require a passing verification report, complete per-window
records, nonempty packet-capture evidence, OVS snapshots, audit-count checks,
verified rollback and artifact checksums. Failed or interrupted executions must
remain failed and must not be manually repaired in CSV or JSON files.

## Claim boundary

This is an actual single-host OVS/controller-runtime experiment. It does not
establish multi-controller, hardware-switch, WAN, adversarial-controller or
production-scale performance.
