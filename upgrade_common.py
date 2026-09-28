from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict


def repo_root_from(file_path: str, levels_up: int = 1) -> Path:
    root = Path(file_path).resolve()
    if root.is_file():
        root = root.parent
    for _ in range(levels_up):
        root = root.parent
    return root


def ensure_repo_root_on_path(file_path: str, levels_up: int = 1) -> Path:
    root = repo_root_from(file_path, levels_up=levels_up)
    root_str = str(root)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    return root


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))
