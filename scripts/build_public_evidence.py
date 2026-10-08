#!/usr/bin/env python3
"""Package existing evidence byte-for-byte with full portable manifests. No metrics edits."""
import argparse
import hashlib
import json
import zipfile
from pathlib import Path


def build(mappings, output):
    if output.exists():
        raise FileExistsError(output)
    files = []
    for prefix, source in mappings:
        if not source.is_dir():
            raise FileNotFoundError(source)
        if output.resolve().is_relative_to(source.resolve()):
            raise ValueError('Output must be outside source')
        files += [(f'{prefix}/{p.relative_to(source).as_posix()}', p)
                  for p in sorted(source.rglob('*')) if p.is_file()]
    if len({name for name, _ in files}) != len(files):
        raise ValueError('Duplicate destination')
    output.parent.mkdir(parents=True, exist_ok=True)
    hashes = []
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name, path in files:
            data = path.read_bytes()
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
            hashes.append(f'{hashlib.sha256(data).hexdigest()}  {name}\n')
        info = zipfile.ZipInfo('PUBLIC_CHECKSUMS.sha256', date_time=(2026, 1, 1, 0, 0, 0))
        archive.writestr(info, ''.join(hashes))
    return {'archive': output.name, 'files': len(files), 'bytes': output.stat().st_size,
            'sha256': hashlib.sha256(output.read_bytes()).hexdigest()}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--workspace', type=Path, required=True,
                   help='Private source workspace containing the existing results; never published automatically')
    p.add_argument('--output', type=Path, default=Path('release_assets'))
    p.add_argument('--bundle', choices=['all','source-calibration'], default='all')
    a = p.parse_args(); w = a.workspace.resolve(); repo = Path(__file__).resolve().parents[1]
    bundles = {
        'ovs_source_calibration_v3_evidence_v1.zip': [
            (f'ovs_safety_{stage}_v3', repo/'results'/f'ovs_safety_{stage}_v3')
            for stage in ['development','validation']],
        'ovs_safety_confirmatory_v3_evidence_v1.zip': [
            (f'actual_ovs_{os}_safety_v3', repo/'results'/f'actual_ovs_{os}_safety_v3')
            for os in ['kali', 'ubuntu']],
        'external_raw_diagnostic_evidence_v1.zip': [
            (f'external_raw_processing_v1/{part}', w/'results/external_raw_processing_v1'/part)
            for part in ['cicddos2019', 'iot23', 'toniot_final']] + [
            (name, w/'results'/name) for name in [
                'external_raw_transfer_v1', 'external_final_tables_v1', 'external_raw_source_hashes_v1']],
    }
    if a.bundle == 'source-calibration':
        bundles = {name: entries for name, entries in bundles.items() if name.startswith('ovs_source_calibration_')}
    reports = [build(mappings, a.output/name) for name, mappings in bundles.items()]
    print(json.dumps(reports, indent=2))


if __name__ == '__main__':
    main()
