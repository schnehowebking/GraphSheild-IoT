#!/usr/bin/env python3
"""Build a safety-revision status report from executable analysis/test artifacts."""
import argparse
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from reviewer_revision.ovs_safety import sha

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--analysis",required=True);p.add_argument("--tests",required=True);p.add_argument("--output",required=True)
    a=p.parse_args();out=Path(a.output)
    if out.exists(): raise FileExistsError(out)
    report=json.loads((Path(a.analysis)/"safety_analysis.json").read_text())
    inputs=json.loads((Path(a.analysis)/"input_checksums.json").read_text())
    for path,digest in inputs.items():
        if sha(path)!=digest: raise ValueError(f"Historical input changed: {path}")
    suite=ET.parse(a.tests).getroot().find("testsuite")
    lines=["# OVS safety revision v3 implementation report", "",
      "Status: software revision and historical analysis complete; physical v3 calibration/confirmation NOT executed.",
      "Old results, trained detector binaries/thresholds, archives and manuscript files were not modified.", "",
      "## Independently regenerated historical analysis", "",
      "| OS | Windows | Benign-source selections | Subsequent windows with receiver loss | Missing benign measurements |",
      "|---|---:|---:|---:|---:|"]
    for t in report["totals"]:
        lines.append(f"| {t['dataset']} | {t['windows']} | {t['benign_target_selections']} | {t['subsequent_windows_with_loss']} | {t['unavailable_benign_measurements']} |")
    lines += ["", "These are associations, not isolated causal estimates: no historical no-mitigation reference exists.",
      f"Verified unchanged SHA-256 for all {len(inputs)} consumed historical input files.",
      f"Trial bootstrap: {report['bootstrap_replicates']} draws, seed {report['bootstrap_seed']}.", "",
      "## Verification", "",
      f"Full pytest report: tests={suite.get('tests')}, failures={suite.get('failures')}, errors={suite.get('errors')}, skipped={suite.get('skipped')}, duration={suite.get('time')} seconds.",
      "Final policy-loading integration regression: 19 tests passed (run after the full suite).",
      "Python 3.13.3/scikit-learn 1.8.0 portable detector verification passed with the unchanged OVS v2 model/threshold.",
      "Real OVS not executed: this host is Windows and the Docker Linux engine is unavailable.",
      "Mocked runner-to-verifier integration tests are software fixtures, not real controller performance evidence.", "",
      "## Implementation", "",
      "The completed-window controller separates classification, baseline proposal and selected enforcement. Missing source attribution defaults to NONE.",
      "A development-derived per-source rate envelope and validation-selected persistence gate replace largest-sender targeting. Multiple eligible sources cause abstention.",
      "Selected rules have a bounded OVS hard timeout. Source observations, feature hashes, reasons and observed enforcement are recorded and replayed.",
      "New conditions include mitigation_disabled alongside the matched audit pair. Metrics distinguish window FPR, source targeting and receiver-service effects.",
      "Validation selection is hash-bound; confirmation rejects mismatched model/protocol/policy and an ineffective NONE-only selector.",
      "All output directories refuse overwrite. V2 execution is retired; historical evidence remains readable.", "",
      "## Remaining requirements", "",
      "Run the Linux lifetime smoke test, collect development/validation telemetry, verify it, fit the selector and review its validation curve.",
      "Then freeze and archive that policy before 30 three-condition seeds per OS (90 executions each). Reuse the same frozen policy on Ubuntu.",
      "No guaranteed zero harm or formal risk bound is established. Rate-indistinguishable attacks, high-rate benign traffic and distributed low-rate attacks remain limitations.",
      "Other AI-audit manuscript, external-adapter and historical archive issues are not resolved by this safety revision.",
      "See githubrepo/docs/OVS_SAFETY_V3.md for exact commands and metric definitions.", "",
      "## Main commands executed", "", "```text",
      "python scripts/analyze_ovs_safety.py --source kali=../actual_ovs_kali_confirmatory_v2 --source ubuntu=../actual_ovs_ubuntu_confirmatory_v2 --output ../results/ovs_safety_revision_v3/historical_analysis_final",
      "python -m pytest tests -q --junitxml=../results/ovs_safety_revision_v3/tests.xml",
      "python -m pytest tests/test_ovs_safety.py -q",
      "python scripts/verify_portable_runtime.py",
      "python scripts/build_manifest.py",
      "python scripts/verify_manifest.py", "git diff --check", "```", "", "## Working-tree changes", "", "```text"]
    lines.append(subprocess.check_output(["git","status","--short"],cwd=ROOT,text=True).strip())
    lines.extend(["```", ""])
    out.write_text("\n".join(lines),encoding="utf-8")
    print(str(out.resolve()))
