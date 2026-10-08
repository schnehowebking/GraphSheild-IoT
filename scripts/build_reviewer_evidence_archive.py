#!/usr/bin/env python3
"""Build a complete deterministic evidence archive; refuse existing outputs."""
from __future__ import annotations

import argparse
import hashlib
import zipfile
from pathlib import Path


def include(relative: Path) -> bool:
    return not ({"__pycache__", ".pytest_cache"} & set(relative.parts))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="results/reviewer_revision_v1")
    parser.add_argument("--output", default="release_assets/reviewer_revision_v1_complete_v2.zip")
    args = parser.parse_args()
    source = Path(args.source).resolve()
    output = Path(args.output).resolve()
    if not source.is_dir():
        raise FileNotFoundError(source)
    if output.exists():
        raise FileExistsError(output)
    if output.is_relative_to(source):
        raise ValueError("Archive output must be outside source")
    output.parent.mkdir(parents=True, exist_ok=True)
    files = sorted(p for p in source.rglob("*") if p.is_file() and include(p.relative_to(source)))
    checksums = []
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
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
