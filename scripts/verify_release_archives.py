#!/usr/bin/env python3
"""Verify bundled OVS archives and recompute reviewer metrics from row-level evidence."""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reviewer_revision.verify import verify_results


def verify_embedded_manifest(archive: zipfile.ZipFile, manifest_name: str) -> int:
    prefix = Path(manifest_name).parent.as_posix()
    count = 0
    for line in archive.read(manifest_name).decode("utf-8").splitlines():
        if not line.strip():
            continue
        expected, relative = line.split("  ", 1)
        member = f"{prefix}/{relative}" if prefix != "." else relative
        actual = hashlib.sha256(archive.read(member)).hexdigest()
        if actual != expected:
            raise AssertionError(f"Archive checksum mismatch: {member}")
        count += 1
    return count


def one_member(archive: zipfile.ZipFile, suffix: str) -> str:
    matches = [name for name in archive.namelist() if name.endswith(suffix)]
    if len(matches) != 1:
        raise AssertionError((suffix, matches))
    return matches[0]


def verify_ovs(path: Path) -> dict:
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None:
            raise AssertionError(f"Corrupt ZIP member in {path}")
        checks = verify_embedded_manifest(archive, one_member(archive, "/CHECKSUMS.sha256"))
        report = json.loads(archive.read(one_member(archive, "/verification_report.json")))
    required = {
        "passed": True,
        "paired_trials": 30,
        "executions": 60,
        "windows_verified": 720,
        "same_inputs_within_pairs": True,
        "confirmatory_protocol_verified": True,
        "measurement_type": "actual_single_host_ovs_runtime",
    }
    for key, value in required.items():
        if report.get(key) != value:
            raise AssertionError((path.name, key, report.get(key), value))
    return {"archive": path.name, "checksums": checks, "report": required}


def verify_reviewer(path: Path) -> dict:
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None:
            raise AssertionError(f"Corrupt ZIP member in {path}")
        manifest = one_member(archive, "/PUBLIC_CHECKSUMS.sha256")
        checks = verify_embedded_manifest(archive, manifest)
        with tempfile.TemporaryDirectory(prefix="graphshield-reviewer-") as directory:
            archive.extractall(directory)
            output = Path(directory) / "reviewer_revision_v1"
            report = verify_results(output, require_model_binaries=False)
    if not report.get("passed"):
        raise AssertionError("Reviewer evidence recomputation failed")
    return {"archive": path.name, "checksums": checks, "recomputation": report}


def main() -> None:
    reports = [
        verify_ovs(ROOT / "actual_ovs_kali_confirmatory_v2.zip"),
        verify_ovs(ROOT / "actual_ovs_ubuntu_confirmatory_v2.zip"),
        verify_reviewer(ROOT / "reviewer_revision_v1_evidence.zip"),
    ]
    print(json.dumps({"passed": True, "archives": reports}, indent=2))


if __name__ == "__main__":
    main()
