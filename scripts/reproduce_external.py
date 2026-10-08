#!/usr/bin/env python3
"""Process locally obtained sources, hash them, apply the frozen model, and build tables."""
import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-root', type=Path, required=True)
    parser.add_argument('--deployment', type=Path, required=True,
                        help='Controlled deployment from extracted complete reviewer evidence, NOT deployment_ovs_v2')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source, deploy, out = (p.resolve() for p in [args.input_root, args.deployment, args.output])
    if not source.is_dir() or not (deploy/'model.joblib').is_file():
        raise FileNotFoundError('Source dataset directory or frozen deployment missing')
    if out.exists():
        raise FileExistsError(out)
    out.mkdir(parents=True)

    def run(script, *options):
        subprocess.run([sys.executable, str(ROOT/'scripts'/script), *map(str, options)], check=True, cwd=ROOT)

    processed = out/'processing'
    for dataset, part in [('cic','cicddos2019'),('iot23','iot23'),('toniot','toniot_final')]:
        run('process_external_raw_datasets.py', '--input-root', source, '--datasets', dataset,
            '--output', processed/part)
        run('verify_external_raw_processing.py', processed/part)
    run('hash_external_raw_sources.py', '--processing-root', processed, '--input-root', source, '--output', out/'source_hashes')
    run('evaluate_external_raw_transfer.py', '--processed-root', processed, '--deployment', deploy, '--output', out/'evaluation')
    run('verify_external_raw_transfer.py', out/'evaluation')
    run('build_external_final_tables.py', '--evaluation', out/'evaluation', '--output', out/'tables')


if __name__ == '__main__':
    main()
