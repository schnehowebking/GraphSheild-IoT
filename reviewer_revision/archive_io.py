"""Checked archive extraction and checksum verification shared by public replay."""
import hashlib
import zipfile
from reviewer_revision.artifact_paths import relative_name, artifact_path


def archive_index(archive):
    index = {}
    for info in archive.infolist():
        name = relative_name(info.filename)
        if name in index:
            raise ValueError(f"Duplicate normalized ZIP member: {name}")
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            raise ValueError(f"Symlink ZIP member: {name}")
        index[name] = info
    return index


def extract_checked(archive, directory, skip_members=()):
    """Normalize historical separators, reject traversal, never overwrite files."""
    for name, info in archive_index(archive).items():
        if name in skip_members:
            continue
        path = artifact_path(directory, name)
        if info.is_dir():
            path.mkdir(parents=True, exist_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, path.open('xb') as target:
                import shutil
                shutil.copyfileobj(source, target)


def verify_embedded_manifest(archive: zipfile.ZipFile, manifest_name: str) -> int:
    index = archive_index(archive)
    manifest_name = relative_name(manifest_name)
    prefix = manifest_name.rpartition('/')[0]
    count = 0
    seen = set()
    for line in archive.read(index[manifest_name]).decode("utf-8").splitlines():
        if not line.strip():
            continue
        expected, relative = line.split("  ", 1)
        relative = relative_name(relative)
        member = f"{prefix}/{relative}" if prefix else relative
        if member in seen:
            raise ValueError(f"Duplicate checksum entry: {member}")
        seen.add(member)
        actual = hashlib.sha256(archive.read(index[member])).hexdigest()
        if actual != expected:
            raise AssertionError(f"Archive checksum mismatch: {member}")
        count += 1
    return count
