"""Reports derive numeric statements from executable experiment outputs."""
from pathlib import Path
import pandas as pd
from reviewer_revision.core import read_json, ROOT


STATISTICS = """# Statistical methodology

The sampling unit is an independently seeded controlled simulation run. Within a run,
five-second decision windows are grouped by switch and destination. Windows on different
switches at the same time are correlated and are never counted as independent bootstrap units.
Whole runs are ordered in synthetic event time. Each fold uses expanding past training runs,
the next validation runs and subsequent test runs. Test runs never overlap between folds.
Earlier test runs may enter a later model's training set, as in forward chaining, but never
influence the model evaluating those runs. No temporal shuffle is used. All scenarios recur
within each run; this evaluates future runs of known scenarios, NOT unseen scenario classes.
Entire scenario episodes stay in a run. Scenario/phase IDs and raw address identities are
excluded from fitted features; graph node identities are used only for structural counts.

The default uses every permissible whole-run fold given the declared minimum training,
validation and test sizes. Fold count may be reduced explicitly; requesting unavailable folds
fails. The final chronological fold model is chosen for deployment before evaluating test scores.
Aggregate metrics pool disjoint out-of-sample predictions from the fold-specific models.

The 95% percentile bootstrap resamples whole (fold, test-run) clusters, preserving every window
within each sampled cluster. It does not resample duplicated windows as independent evidence
or mix a block across temporal boundaries. Seed and replicate count appear in every CI row.
Class-stratified window bootstrap is deliberately not used: it would break within-run dependence.
Both classes occur within the generated mixed-scenario runs. Shared training induces remaining
dependence between fold models; intervals are conditional on the fitted models and simulator,
not a full retraining bootstrap or a guarantee for field deployments. Few clusters and simulator
design limit inference even when the number of windows is large. Degenerate CIs are retained.

Precision with no predicted positives, recall/FNR with no attacks, FPR/benign damage with no
benign windows, and ROC-AUC with one class are undefined. PR-AUC means average precision
(stepwise area), and is undefined with no positives. Undefined values are null in JSON / blank
in CSV with an explicit reason; no NaN/Infinity JSON is emitted. F1 is computed as
2TP/(2TP+FP+FN) when its denominator is nonzero.

Benign damage is FP/(TN+FP), a false-mitigation decision rate; actual lost benign traffic is
not measured. Reward is a declared classification utility: TP +2, FN -2, FP -1.25, TN +0.2.
It is not measured packet recovery or a counterfactual action effect.

Policy comparisons pair the exact same test windows and resample the same whole-run clusters
for both policies. The reward difference uses mean per-window utility. Exact McNemar p-values
are provided only as diagnostics: their window-independence assumption fails here. Cluster CIs
are primary. No multiplicity-adjusted superiority claim is made.

Stress trials use independent seeds, and audit-on/off share the same saved input, seed, model,
threshold and warmup. Execution order alternates to reduce order effects. Trial-level summaries
include sample SD, mean, median, min, max, n and Student-t intervals. Paired differences use
Student-t intervals across per-trial differences. Timings are perf_counter measurements of
sdn.CompletedWindowController, including local audit append when enabled. These are controlled
simulation inputs executing actual local controller code, not live traffic, HTTP latency,
OpenFlow rule installation or Go audit consensus. Historical simulated controller_latency_ms
and throughput_mbps columns from the event generator are NEVER used as measured outcomes.
"""

GRAPH = """# Graph schema and causal construction

The existing simulator supplies source IP, destination IP, switch ID, packets, bytes, flows
and event timestamps. Destination IP is a service proxy: transport ports/service identity are
unavailable, and the default simulator has one destination. No extra topology links are invented.
These experiments fit classifiers to explicit graph summaries; they are not trained GNNs.

At the end of each 5-second window, all events with timestamp < window end are observable.
The current graph contains typed source and service nodes joined by observed interactions.
Edges aggregate packet counts. Bipartite features include edge count, node counts, source/service
degrees and edge packet weights. The switch variant additionally constructs observed
source-switch and switch-service edges and counts observed three-node paths. These are observed
attachments, not verified physical network routes. A local switch packet-share feature locates
the decision window within the global graph at that window close.

Controller context adds event arrival gaps, flow-count variation and active-switch count, all
computed from the input event stream. It excludes the old simulator's label-dependent latency
formula. CPU load and real controller RTT are unavailable and are not invented.

Temporal edges keep only past events within a 30-second history, reset at each independent run.
Features include historical edge count, new/returning edge fractions and sum of packet weights
times exp(-(decision_time-event_time)/15 seconds). Current edges are added to history only after
that timestamp batch is scored. No future event or future normalization statistic is inspected.
Normalized edge weights use packet_count_on_edge / total_packets_in_current_window; their max
and entropy are features. Edge packet rate uses count/5 seconds. This normalization is local
and causal, not a min/max fit across the test set.

Exact input feature lists are in policy_feature_manifest.json; per-fold hyperparameters, seeds,
training/validation/test sizes, thresholds, model hashes and inference time are in
policy_configuration.json and the model directories. Graph construction time is distinct from
classifier inference time; the reported batch inference time does not include graph building.
"""

POLICY = """# Policy ablation methodology

The old Table 9 generator transformed a baseline probability for multiple named graph/RL
policies, used full test-set ranges for normalization, evaluated the last 96 windows (including
the old validation set), and consulted y==0 inside risk selection. That generator has been
retired; its results are preserved solely as historical evidence.

Each new graph classifier is fitted independently to its documented graph features using
training labels only; its operating threshold is chosen on validation only. The ML-window
baseline uses only the eight canonical features. Inference rejects extra columns (including
labels). Graph preprocessing receives an explicit observable allowlist, with neither labels nor
scenario IDs. The exact same untouched test windows are used for every policy in each fold.

The imitation-regularized classifier minimizes CE(y,p) + lambda CE(teacher_probability,p),
equivalently CE((y+lambda*teacher)/(1+lambda),p), with an L2 term of 0.001 in the normalized
objective. The teacher is the canonical random forest fitted on that fold's training data only.
lambda=0.25 is fixed in advance, and feature standardization is fitted on training only.
This is supervised distillation, not reinforcement learning or behavior-policy evaluation.

The temporal risk selector fits its own temporal graph classifier and applies the recorded
validation threshold plus a fixed requirement that 1-p <= 0.1. Rejected mitigation proposals
become NONE and are counted as abstentions. This is an uncalibrated probability safety heuristic,
not a conformal bound or a guarantee of maximum realized benign damage. No test labels enter it.

Contextual bandit and conservative offline RL results are WITHDRAWN, not synthesized. Existing
logs lack exploration probabilities and sufficiently supported action-conditioned outcomes.
The old next-row probability/packet-count differences do not identify mitigation effects, and
overlapping trajectory windows cross old split boundaries. A classification reward cannot repair
this. New logged trajectories with actions, propensities, episode boundaries and measured
outcomes are required before an honest bandit/OPE or conservative-RL evaluation.

RATE_LIMIT denotes a mitigation decision only; this pipeline does not measure successful
network mitigation. Every identical prediction result is retained. Pairwise records report
exact prediction equality, probability equality, disagreement counts and maximum probability
differences. Shared labels or strong simulated traffic signals can legitimately yield equal
decisions from different feature sets. Prediction equality is not evidence of identical models.
The deployment artifact is the last chronological fold; earlier folds use earlier canonical
fits, so aggregate agreement is with the corresponding fold baseline, not a retrospectively
applied final model that has trained on earlier test periods.
"""

THRESHOLD = """# Threshold governance

configs/threshold_registry.json distinguishes a diagnostic raw 0.5 probability reference,
validation-selected operating thresholds, disabled runtime safety overrides, policy actions,
and fixed-transfer external diagnostics. Old 0.1316 and 0.4 values are not reused.

For each fitted model, all unique validation probabilities, zero, and nextafter(1,+inf) are
candidates. The latter permits no mitigation even when a probability is exactly one. Select
maximum validation F1 subject to FPR <= 0.05, breaking ties by higher recall, lower FPR and
then higher threshold. It is a validation constraint, not a guarantee on future/test FPR.
Validation partitions must contain both classes; passing a test partition fails. No objective
or hyperparameter is selected by looking at test performance.

Each model directory saves its full validation curve and a threshold_selection.json binding
the value to model/schema hashes, validation data hash/run IDs, objective, constraint, registry
hash and selection timestamp. The root files are copies for the predetermined deployment model.
The runtime loader verifies model and feature-schema hashes. The runtime uses its saved threshold
and unchanged probability, without the old rate/event score scaling. It uses NONE or RATE_LIMIT;
BLOCK is not supported by this revision's action evidence. Canonical /detect-window requests
cannot override thresholds. Legacy partial-window and flow endpoints are separate operating
modes and are not the completed-window evaluation evidence.

The registry's operating.selection_file points at the versioned deployment selection. To use
another reproduced output, copy the registry to a new file, point selection_file at that
output's deployment/threshold_selection.json, then set GRAPHSHIELD_THRESHOLD_REGISTRY to its
path. This selects an already validation-governed model/threshold pair rather than retuning
on test labels. Root canonical configuration describes the default release output.

External datasets receive the fixed deployment model and threshold without any target fitting,
calibration or threshold search. These results are diagnostic feature-compatible transfer;
their rate/exposure and aggregation semantics differ from controller windows. Legacy
external_split and combined_to_external_holdout rows used target validation and are not zero-shot.
No oracle/target-label-optimized result is presented as transfer in the revised tables.
"""


def write_reports(output, config, table_map, elapsed):
    for filename, content in [("statistical_methodology.md", STATISTICS), ("graph_schema.md", GRAPH),
                              ("policy_ablation_methodology.md", POLICY), ("threshold_governance.md", THRESHOLD)]:
        (output / filename).write_text(content, encoding="utf-8")
    old = pd.read_csv(ROOT / "docs/legacy_q1_evaluation_summary_v2.csv")
    old_temporal = old[old["mode"] == "true_timestamp_temporal_split"].iloc[0]
    m, profile = read_json(output / "temporal_aggregate_metrics.json"), read_json(output / "data_profile.json")
    policy = pd.read_csv(output / "policy_comparison.csv")
    ci = pd.read_csv(output / "temporal_confidence_intervals.csv").set_index("metric")
    selection = read_json(output / "threshold_selection.json")
    artifact_map = "# Revised claim to artifact map\n\n" + "\n".join(f"- Table {k}: `{v}` (copy: `tables/table_{k}{Path(v).suffix}`)." for k, v in table_map.items())
    artifact_map += "\n\nTable 2 also needs temporal_aggregate_metrics.json, temporal_confidence_intervals.csv and temporal_fold_definitions.csv. Table 9 needs policy_pairwise_statistics.csv and the feature/configuration manifests. Table 4 must be titled controlled simulation with measured controller-method timings. Tables 6/7 cover local append/mode transitions, not network consensus or rule reversal.\n"
    (output / "CLAIM_TO_ARTIFACT_MAP.md").write_text(artifact_map, encoding="utf-8")
    report = f"""# Reviewer revision execution report

Generated by scripts/run_reviewer_revision.py. Pipeline runtime: {elapsed:.3f} seconds.
Configuration seed {config['seed']}; model seed 42; bootstrap seed {config['bootstrap_seed']}.
This report covers code-generated results only. Manuscript/DOCX files and previous outputs were
hashed and preserved; see preservation_verification.json. No git repository metadata exists.

## Main measured result

{profile['windows']} completed switch-destination windows from {profile['runs']} independently
seeded simulated runs; {profile['test_windows']} test windows across {profile['fold_count']} folds.
Pooled TN/FP/FN/TP: {m['tn']}/{m['fp']}/{m['fn']}/{m['tp']}.
F1 {m['f1']:.6f}, 95% whole-run bootstrap CI
[{ci.loc['f1', 'ci_lower']:.6f}, {ci.loc['f1', 'ci_upper']:.6f}].
Precision {m['precision']:.6f}, recall {m['recall']:.6f}, FPR {m['fpr']:.6f}.

Canonical model: sklearn RandomForestClassifier, 240 trees, min_samples_leaf=2,
class_weight=balanced, random_state=42, n_jobs=1; other sklearn defaults recorded via
environment/library versions. Eight ordered window features, no scaling/calibration, strict
missing-value rejection. The last chronological fold is deployed; its selected threshold is
{selection['selected_value']:.17g}. Other folds/policies have separately traceable selections.

## Implemented changes

- sdn.py: shared saved detector/threshold; completed-window API and audited rollback transition.
- scripts/q1_system_upgrade_v2.py: label-leaking ablation removed and old generator retired.
- reviewer_revision/: strict data/feature construction, policies, statistics, pipeline, verifier and reporting.
- configs/: canonical detector, threshold registry and seeded experiment configuration.
- scripts/run_reviewer_revision.py: one versioned reproduction command; existing directories rejected.
- tests/test_reviewer_revision.py: leakage, temporal boundaries, graph sensitivity, schema, threshold,
  model persistence, runtime parity, rollback and clean-output integration tests.
- README.md and root claim map: revised entrypoint and bounded artifact references.

Independent recomputation passed: verification_report.json. The test execution log and final
source/command review are recorded separately by the executing audit session. No claim that
the pipeline itself runs the entire legacy test suite is implied.

## Old versus new

The old temporal result used {int(old_temporal["n"])} pooled windows and F1 {old_temporal["f1"]:.6f}. The revised aggregate uses
{m['n']} completed switch-destination test windows and F1 {m['f1']:.6f}. This is not a paired
improvement estimate: data size, aggregation and fitted models changed. See old_versus_new.csv.
Old audit comparisons used different traffic scales/seeds and formula latency. Revised
comparisons have {config['stress_trials']} pairs of identical inputs and measured code timings.
Old Table 9 arithmetic transforms and label-based risk selection are invalid policy evidence;
the revised table uses independent fits and saved predictions. Identical results are retained.

## Policy results

"""
    for row in policy.itertuples():
        report += f"- {row.policy}: F1 {row.f1:.6f}; benign damage {row.benign_damage:.6f}; disagreements {row.disagreement_count}.\n"
    report += """
## Remaining limitations and unavailable experiments

- Controlled stochastic simulator evidence does not establish real-world performance or new
  unseen-scenario generalization. Repeated scenario templates, one destination and synthetic
  source pools limit graph diversity. Larger sample size cannot fix those external-validity limits.
- Completed-window API accepts preaggregated telemetry. Legacy /detect scores partial windows;
  its partial-window operating performance is not evaluated by the completed-window tables.
- Bandit and conservative offline RL were not executed: required logged outcomes, action
  probabilities and supported trajectories are unavailable. Imitation is supervised distillation.
- No real network attack, OpenFlow mitigation effectiveness, HTTP load, Go service consensus,
  actual packet recovery, production controller CPU or distributed audit scaling was measured.
- Local audit appends are serial and do not fsync. Complete suffix deletion cannot be detected
  without a trusted external tip. Reopen/append and malformed trailing records are tested;
  power-loss durability and multi-process writers are not.
- Runtime rollback disables an injected shadow test callback; it does not reverse switch rules.
- External prepared rates/aggregation are not semantically identical to controller telemetry;
  fixed transfer is explicitly diagnostic. No target-label threshold tuning is used.
- Confidence intervals condition on simulator and fitted models; shared training dependence,
  few independent runs and multiple comparisons restrict inferential claims.

"""
    report += artifact_map
    (output / "FINAL_REVISION_REPORT.md").write_text(report, encoding="utf-8")
