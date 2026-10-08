#!/usr/bin/env python3
"""Replay original calibration and re-fit in a NEW directory; never replace frozen policy."""
import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT/'scripts'))
from fit_ovs_source_selector import fit
from verify_ovs_safety import verify as verify_collection
from reviewer_revision.source_selector import canonical_hash


def normalize_fingerprints(mapping, collection):
    """Keep file identity and byte hashes while allowing a relocated parent root."""
    normalized = {}
    for path, digest in mapping.items():
        parts = path.replace('\\', '/').split('/')
        if parts.count(collection) != 1 or '..' in parts:
            raise ValueError(f'Invalid collection reference: {path}')
        relative = '/'.join(parts[parts.index(collection)+1:])
        if not relative or relative in normalized:
            raise ValueError('Duplicate or empty source reference')
        normalized[relative] = digest
    return normalized


def verify(train, validation, frozen_dir, output, protocol_path=None):
    output = Path(output)
    if output.exists(): raise FileExistsError(output)
    protocol = json.loads(Path(protocol_path or ROOT/'configs/ovs_experiment_protocol_v3.json').read_text())
    frozen_dir = Path(frozen_dir)
    frozen = json.loads((frozen_dir/'source_policy.json').read_text())
    selection = json.loads((frozen_dir/'selection.json').read_text())
    original_inputs = json.loads((frozen_dir/'input_checksums.json').read_text())
    if canonical_hash(frozen) != selection['policy_hash']:
        raise ValueError('Frozen policy hash mismatch')
    for key, field in [('training','training_input_hash'),('validation','validation_input_hash')]:
        if canonical_hash(original_inputs[key]) != frozen[field]:
            raise ValueError('Frozen input-manifest hash mismatch')
    reports = {}
    for stage, directory in [('development',train),('validation',validation)]:
        print(f'Verifying original {stage} observations', flush=True)
        reports[stage] = verify_collection(directory, ROOT/'deployment_ovs_v2',ROOT/'configs/threshold_registry_ovs_v2.json')
        if reports[stage]['stage'] != stage: raise ValueError('Wrong calibration stage')
    output.mkdir(parents=True)
    rebuilt = fit(train, validation, output/'recomputed_selector', protocol)
    new_inputs = json.loads((output/'recomputed_selector/input_checksums.json').read_text())
    compared = {}
    for key, collection in [('training','ovs_safety_development_v3'),('validation','ovs_safety_validation_v3')]:
        a = normalize_fingerprints(original_inputs[key], collection)
        b = normalize_fingerprints(new_inputs[key], collection)
        if a != b: raise ValueError(f'Original {key} file identities/hashes differ from supplied files')
        compared[key] = len(a)
    # New creation time and path-derived manifest hashes must differ after relocation.
    provenance_fields = {'created_at','training_input_hash','validation_input_hash'}
    if {k:v for k,v in rebuilt.items() if k not in provenance_fields} != {k:v for k,v in frozen.items() if k not in provenance_fields}:
        raise ValueError('Recomputed source policy differs from frozen policy')
    def curve(path):
        with path.open(newline='') as handle: return list(csv.DictReader(handle))
    original_curve = curve(frozen_dir/'validation_source_threshold_curve.csv')
    if original_curve != curve(output/'recomputed_selector/validation_source_threshold_curve.csv'):
        raise ValueError('Full candidate threshold curve differs')
    regenerated_selection = json.loads((output/'recomputed_selector/selection.json').read_text())
    if {k:v for k,v in selection.items() if k != 'policy_hash'} != {k:v for k,v in regenerated_selection.items() if k != 'policy_hash'}:
        raise ValueError('Objective or selection outcome differs')
    report = {'passed':True,'collections':reports,'original_input_fingerprints_verified':compared,
              'frozen_policy_hash':selection['policy_hash'],'byte_rate_threshold':frozen['byte_rate_threshold'],
              'consecutive_windows':frozen['consecutive_windows'],'rule_ttl_seconds':frozen['rule_ttl_seconds'],
              'validation_metrics':frozen['validation_metrics'],'candidate_rows_verified':len(original_curve),
              'frozen_policy_unchanged':True,
              'provenance_difference':'Only recomputation timestamp and relocated absolute-path manifest hashes differ; every referenced file identity and byte hash verified.',
              'scope':'Original development/validation selection replay, not a formal safety guarantee'}
    (output/'verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    return report


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--train',type=Path,required=True);p.add_argument('--validation',type=Path,required=True)
    p.add_argument('--frozen',type=Path,default=ROOT/'deployment_source_v3')
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();print(json.dumps(verify(a.train,a.validation,a.frozen,a.output),indent=2))
