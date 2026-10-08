"""Read historical Windows artifact references portably, without escaping roots."""
from pathlib import Path, PurePosixPath


def relative_name(value):
    name = str(value).replace("\\", "/")
    parts = PurePosixPath(name).parts
    if not parts or name.startswith("/") or any(p in {"..", "."} or ":" in p for p in parts):
        raise ValueError(f"Unsafe artifact reference: {value}")
    return "/".join(parts)


def artifact_path(root, value):
    root = Path(root).resolve()
    path = root.joinpath(*relative_name(value).split("/")).resolve()
    if not path.is_relative_to(root):
        raise ValueError(f"Artifact outside root: {value}")
    return path
