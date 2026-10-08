# External-data reproduction

Two historical evaluations must be distinguished. `data/external/processed` holds
the older compact diagnostic inputs used by the controlled reviewer pipeline.
The larger, raw-derived evaluation is in
`release_assets/external_raw_diagnostic_evidence_v1.zip`. Do not substitute one
for the other or attribute their results to the live OVS detector.

## Verify existing evidence without downloading raw datasets

Run `scripts/verify_public_release.py` as described in the README. It extracts
into a new directory, checks every archived file, replays external probabilities
using the archived **controlled** model, checks its threshold and input hashes,
and recomputes metrics and scenario-block bootstrap intervals (2,000 draws,
seed 20260928). The OVS detector is a separate frozen model.

## Obtain original sources

Obtain data directly under each publisher's terms. This repository does not grant
rights to their raw datasets or relicense third-party data.

- CIC-DDoS2019: https://www.unb.ca/cic/datasets/ddos-2019.html — timestamped network CSVs.
- IoT-23: https://www.stratosphereips.org/datasets-iot23 — labeled Zeek connection logs.
- TON_IoT: https://research.unsw.edu.au/projects/toniot-datasets — processed network CSVs.

Extract locally with this layout (case-sensitive on Linux):

```text
RAW_ROOT/
  CIC-DDoS2019/CSVs/.../*.csv
  IoT23/.../*.labeled
  TON_IoT_datasets/Processed_datasets/Processed_Network_dataset/Network_dataset_*.csv
```

The original consumed subset has 18 CIC CSVs, 23 IoT-23 logs and 23 TON network
CSVs: 64 files, 81,488,802,851 bytes. Match exact filenames, sizes and SHA-256 in
`external_raw_source_hashes_v1/raw_source_fingerprints.csv` from the evidence ZIP.
These are hashes of consumed files, not a claim to have used every publisher file.
`source_files.csv` and `processing_manifest.json` record the selected files and
row counts for each dataset. The manifests' original machine paths are provenance,
not runtime dependencies; use your own `--input-root`.

## Regenerate from those sources

After public evidence verification, with its output at `results/public_check_v1`:

```bash
.venv/bin/python scripts/reproduce_external.py \
  --input-root /absolute/path/to/RAW_ROOT \
  --deployment results/public_check_v1/extracted/reviewer_revision_v1/deployment \
  --output results/external_reproduction_v2
```

This sequentially processes the three datasets, verifies the resulting windows,
hashes all consumed raw files, applies the frozen controlled detector and its
internal-validation threshold, recomputes evaluation metrics/CIs and builds tables.
It refuses existing output directories. No external labels select a threshold.
Large raw-source processing was not rerun during the public-bundle packaging check;
archived windows and row-level predictions are independently replayed instead.

## Feature and statistical boundaries

All windows are five seconds. Packet and byte totals of flow records are assigned
to their recorded timestamp's window, not reconstructed as individual packet arrival
times. `pkt_sum` sums record packet counts; `pkt_rate=pkt_sum/5`;
`byte_rate=sum(record bytes)/5`. `events` and `flow_count` count flow records;
`flow_rate=flow_count/5`. `unique_src` counts distinct source addresses, and
`src_ip_entropy` uses flow-occurrence weights. Dataset-specific byte fields and
fallbacks are explicit in `process_external_raw_datasets.py` and the generated
feature-semantics table. These are proxies, not identical controller telemetry.

Features are aggregated separately from labels; labels are attached afterward.
DDoS-only/DoS views exclude other-malicious windows after feature construction.
Original parser coercions and historical zero-division conventions remain visible
in the source and processing manifests; this portability revision does not silently
redefine historical metrics. ROC/PR metrics that cannot be computed remain empty.
`benign_damage` in these classification tables means false-positive rate, not
measured service harm. Scenario-block intervals have a finite-scenario limitation.
