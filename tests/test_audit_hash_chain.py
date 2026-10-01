from __future__ import annotations

import json
import shutil
import unittest
import uuid
from pathlib import Path

from integration.audit_hash_chain import append_hash_chained_jsonl, verify_hash_chained_jsonl

TEST_DIR = Path(__file__).resolve().parent
ROOT = TEST_DIR.parents[0]


def workspace_tmp(name: str) -> Path:
    path = ROOT / "tests" / "_tmp" / f"{name}_{uuid.uuid4().hex}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def cleanup_workspace_tmp(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)
    scratch_root = ROOT / "tests" / "_tmp"
    try:
        scratch_root.rmdir()
    except OSError:
        pass


class AuditHashChainTests(unittest.TestCase):
    def test_hash_chain_verifies_and_detects_tamper(self) -> None:
        tmp = workspace_tmp("audit_chain")
        try:
            path = tmp / "audit.jsonl"
            append_hash_chained_jsonl(path, {"event": "allow", "idx": 1})
            append_hash_chained_jsonl(path, {"event": "rate_limit", "idx": 2})

            report = verify_hash_chained_jsonl(path)
            self.assertTrue(report["valid_embedded_hash_chain"])
            self.assertEqual(report["records"], 2)

            lines = path.read_text(encoding="utf-8").splitlines()
            second = json.loads(lines[1])
            second["event"] = "block"
            lines[1] = json.dumps(second, sort_keys=True)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            tampered = verify_hash_chained_jsonl(path)
            self.assertFalse(tampered["valid_embedded_hash_chain"])
            self.assertTrue(any(item["reason"] == "record_hash_mismatch" for item in tampered["errors"]))
        finally:
            cleanup_workspace_tmp(tmp)

    def test_legacy_unhashed_records_are_not_called_tamper_evident(self) -> None:
        tmp = workspace_tmp("legacy_audit")
        try:
            path = tmp / "legacy.jsonl"
            path.write_text('{"event":"legacy"}\n', encoding="utf-8")

            report = verify_hash_chained_jsonl(path)
            self.assertFalse(report["valid_embedded_hash_chain"])
            self.assertEqual(report["legacy_unhashed_records"], 1)
        finally:
            cleanup_workspace_tmp(tmp)


if __name__ == "__main__":
    unittest.main()
