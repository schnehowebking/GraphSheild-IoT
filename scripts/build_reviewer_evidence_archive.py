#!/usr/bin/env python3
"""Build a compact, deterministic archive of row-level reviewer evidence."""
from __future__ import annotations

import argparse
import hashlib
import zipfile
from pathlib import Path


def include(relative: Path) -> bool:
    if relative.name == "CHECKSUMS.sha256":
        return False
    if "audit_logs" in relative.parts or "stress_inputs" in relative.parts:
        return False
    if relative.name == "model.joblib" and "models" in relative.parts:
        return False
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="results/reviewer_revision_v1")
    parser.add_argument("--output", default="reviewer_revision_v1_evidence.zip")
    args = parser.parse_args()
    source = Path(args.source).resolve()
    output = Path(args.output).resolve()
    if not source.is_dir():
        raise FileNotFoundError(source)
    files = sorted(p for p in source.rglob("*") if p.is_file() and include(p.relative_to(source)))
    checksums = []
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            relative = path.relative_to(source).as_posix()
            data = path.read_bytes()
            checksums.append(f"{hashlib.sha256(data).hexdigest()}  {relative}")
            info = zipfile.ZipInfo(f"reviewer_revision_v1/{relative}", date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data, compresslevel=9)
        manifest = ("\n".join(checksums) + "\n").encode()
        info = zipfile.ZipInfo("reviewer_revision_v1/PUBLIC_CHECKSUMS.sha256", date_time=(2026, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        archive.writestr(info, manifest, compresslevel=9)
    print(f"Wrote {output} with {len(files)} evidence files")


if __name__ == "__main__":
    main()
