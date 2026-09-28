from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List

GENESIS_HASH = "0" * 64
HASH_FIELDS = {"prev_hash", "record_hash", "hash"}


def canonical_json(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def record_payload(record: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in record.items() if key not in HASH_FIELDS}


def compute_record_hash(record: Dict[str, Any], prev_hash: str) -> str:
    material = {"prev_hash": str(prev_hash), "record": record_payload(record)}
    return hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()


def _iter_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                yield json.loads(text)
            except json.JSONDecodeError as exc:
                yield {"_malformed_line": line_no, "_error": str(exc), "_raw": text}


def last_embedded_hash(path: Path) -> str:
    tip = GENESIS_HASH
    for record in _iter_jsonl(path) or []:
        if "_malformed_line" in record:
            break
        embedded = record.get("record_hash") or record.get("hash")
        if isinstance(embedded, str) and len(embedded) == 64:
            tip = embedded
    return tip


def append_hash_chained_jsonl(path: Path, record: Dict[str, Any]) -> Dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    prev_hash = last_embedded_hash(path)
    entry = dict(record)
    entry.setdefault("audit_written_unix", time.time())
    entry["prev_hash"] = prev_hash
    entry["record_hash"] = compute_record_hash(entry, prev_hash)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(canonical_json(entry) + "\n")
    return entry


def verify_hash_chained_jsonl(path: Path) -> Dict[str, Any]:
    records = list(_iter_jsonl(path) or [])
    prev_hash = GENESIS_HASH
    errors: List[Dict[str, Any]] = []
    legacy_records = 0
    embedded_records = 0

    for idx, record in enumerate(records, start=1):
        if "_malformed_line" in record:
            errors.append({"line": idx, "reason": "malformed_json", "detail": record.get("_error")})
            break

        embedded = record.get("record_hash") or record.get("hash")
        if not embedded:
            legacy_records += 1
            continue

        embedded_records += 1
        expected_prev = record.get("prev_hash")
        if expected_prev != prev_hash:
            errors.append(
                {
                    "line": idx,
                    "reason": "prev_hash_mismatch",
                    "expected": prev_hash,
                    "observed": expected_prev,
                }
            )
        expected_hash = compute_record_hash(record, str(expected_prev))
        if embedded != expected_hash:
            errors.append(
                {
                    "line": idx,
                    "reason": "record_hash_mismatch",
                    "expected": expected_hash,
                    "observed": embedded,
                }
            )
        prev_hash = str(embedded)

    return {
        "path": str(path),
        "exists": path.exists(),
        "records": len(records),
        "embedded_hash_records": embedded_records,
        "legacy_unhashed_records": legacy_records,
        "valid_embedded_hash_chain": bool(embedded_records > 0 and not errors and legacy_records == 0),
        "valid_with_legacy_prefix": bool(embedded_records > 0 and not errors),
        "chain_tip": prev_hash,
        "errors": errors,
    }
