#!/usr/bin/env python3
"""Verify the GitHub source-bundle checksum manifest."""
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {".csv", ".json", ".md", ".py", ".sh", ".txt", ".yaml", ".yml"}
TEXT_NAMES = {".gitattributes", ".gitignore"}


def sha256(path):
    data = path.read_bytes()
    if path.suffix.lower() in TEXT_SUFFIXES or path.name in TEXT_NAMES:
        data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(data).hexdigest()


def main():
    count = 0
    for line in (ROOT / "MANIFEST.sha256").read_text().splitlines():
        expected, relative = line.split("  ", 1)
        path = (ROOT / relative).resolve()
        if not path.is_relative_to(ROOT) or not path.is_file() or sha256(path) != expected:
            raise AssertionError(f"Manifest mismatch: {relative}")
        count += 1
    print(f"PASS: {count} GitHub bundle files verified")


if __name__ == "__main__":
    main()
