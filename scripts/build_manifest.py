#!/usr/bin/env python3
"""Regenerate the GitHub source-bundle checksum manifest."""
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "MANIFEST.sha256"
EXCLUDED_PARTS = {".git", ".venv", ".pytest_cache", "__pycache__", "results"}
TEXT_SUFFIXES = {".sha256", ".cff", ".csv", ".json", ".md", ".py", ".sh", ".txt", ".yaml", ".yml"}
TEXT_NAMES = {".gitattributes", ".gitignore", "LICENSE"}


def sha256(path):
    data = path.read_bytes()
    if path.suffix.lower() in TEXT_SUFFIXES or path.name in TEXT_NAMES:
        data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(data).hexdigest()


def selected(path):
    relative = path.relative_to(ROOT)
    return not (set(relative.parts) & EXCLUDED_PARTS) and path != OUTPUT and path.is_file()


def main():
    files = []
    # Prune excluded trees BEFORE stat/scandir of their children. Linux venv
    # symlinks copied onto Windows may be unreadable, and are never release input.
    for directory, dirs, names in ROOT.walk(top_down=True):
        dirs[:] = [name for name in dirs if name not in EXCLUDED_PARTS]
        files.extend(directory / name for name in names if selected(directory / name))
    files.sort()
    OUTPUT.write_text("".join(
        f"{sha256(path)}  {path.relative_to(ROOT).as_posix()}\n" for path in files), encoding="utf-8")
    print(f"Wrote {OUTPUT} with {len(files)} files")


if __name__ == "__main__":
    main()
