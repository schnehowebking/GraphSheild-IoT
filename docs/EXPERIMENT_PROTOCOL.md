# Actual OVS paired trial protocol

## Objective

Measure the frozen GraphShield-IoT detector, audit path and rollback against
real packet traffic and OpenFlow 1.3 counters on Kali and Ubuntu.

## Testbed

Every execution creates a fresh OVS bridge and three Linux namespaces: one
benign client, one attack client and one server. `iperf3` generates only traffic
inside `10.253.0.0/24`. OVS tracking-flow counters are sampled once per second
and aggregated into completed five-second switch-destination windows.

The eight inputs are packet rate, byte rate, packet sum, telemetry-event count,
distinct source count, source-event Shannon entropy, observed-flow count and
flow rate. The feature dictionary is checked against the canonical order before
inference. The phase label is stored only after `detect_completed_window` returns.

## Paired design

For each of 30 seeds, the audit-disabled and audit-enabled executions receive
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
