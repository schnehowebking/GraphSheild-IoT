#!/usr/bin/env python3
"""Regenerate the GitHub source-bundle checksum manifest."""
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "MANIFEST.sha256"
EXCLUDED_PARTS = {".git", ".venv", ".pytest_cache", "__pycache__", "results"}
TEXT_SUFFIXES = {".cff", ".csv", ".json", ".md", ".py", ".sh", ".txt", ".yaml", ".yml"}
TEXT_NAMES = {".gitattributes", ".gitignore", "LICENSE"}


def sha256(path):
    data = path.read_bytes()
    if path.suffix.lower() in TEXT_SUFFIXES or path.name in TEXT_NAMES:
        data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(data).hexdigest()


def selected(path):
    relative = path.relative_to(ROOT)
    return path.is_file() and path != OUTPUT and not (set(relative.parts) & EXCLUDED_PARTS)


def main():
    files = sorted(path for path in ROOT.rglob("*") if selected(path))
    OUTPUT.write_text("".join(
        f"{sha256(path)}  {path.relative_to(ROOT).as_posix()}\n" for path in files), encoding="utf-8")
    print(f"Wrote {OUTPUT} with {len(files)} files")


if __name__ == "__main__":
    main()
