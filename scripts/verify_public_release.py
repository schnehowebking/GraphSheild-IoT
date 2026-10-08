#!/usr/bin/env python3
"""Extract fresh public evidence and independently replay its saved results. No root/OVS needed."""
import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path
import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT/'scripts'))
from reviewer_revision.archive_io import archive_index, extract_checked, verify_embedded_manifest
from verify_ovs_safety import verify as verify_ovs
from verify_external_raw_transfer import verify as verify_external
from reviewer_revision.verify import verify_results
from integration.audit_hash_chain import verify_hash_chained_jsonl
from verify_source_policy import verify as verify_source_policy


def unpack(path, target):
    with zipfile.ZipFile(path) as archive:
        index = archive_index(archive)
        manifest = 'PUBLIC_CHECKSUMS.sha256'
        if manifest not in index:
            manifest = 'reviewer_revision_v1/PUBLIC_CHECKSUMS.sha256'
        count = verify_embedded_manifest(archive, manifest)
        listed = set()
        prefix = manifest.rpartition('/')[0]
        from reviewer_revision.artifact_paths import relative_name
        for line in archive.read(index[manifest]).decode().splitlines():
            _, name = line.split('  ', 1)
            listed.add(f'{prefix}/{relative_name(name)}' if prefix else relative_name(name))
        actual = {n for n, info in index.items() if not info.is_dir() and n != manifest}
        if listed != actual:
            raise ValueError('Incomplete public checksum coverage')
        # Outer manifests describe different archives; retain each under its name.
        if manifest == 'PUBLIC_CHECKSUMS.sha256':
            manifests = target/'_archive_manifests'
            manifests.mkdir(parents=True, exist_ok=True)
            with (manifests/f'{path.stem}.sha256').open('xb') as handle:
                handle.write(archive.read(index[manifest]))
            extract_checked(archive, target, skip_members=(manifest,))
        else:
            extract_checked(archive, target)
        return {'archive': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'files_checked': count}


def replay_external(extracted):
    folder = extracted/'external_raw_transfer_v1'
    manifest = json.loads((folder/'evaluation_manifest.json').read_text())
    deployment = extracted/'reviewer_revision_v1/deployment'
    model_path = deployment/'model.joblib'
    if hashlib.sha256(model_path.read_bytes()).hexdigest() != manifest['model_sha256']:
        raise ValueError('External evaluation uses a different model')
    selection = json.loads((deployment/'threshold_selection.json').read_text())
    if selection['selected_value'] != manifest['threshold']:
        raise ValueError('External threshold differs from frozen selection')
    model = joblib.load(model_path)
    saved = pd.read_csv(folder/'external_predictions.csv', float_precision='round_trip')
    records = 0
    for dataset, part, file in [('CIC-DDoS2019','cicddos2019','cicddos2019'),
                                ('IoT-23','iot23','iot23'),('TON_IoT','toniot_final','toniot')]:
        path = extracted/f'external_raw_processing_v1/{part}/windows/{file}_windows.csv'
        if hashlib.sha256(path.read_bytes()).hexdigest() != manifest['input_sha256'][dataset]:
            raise ValueError('External input hash mismatch')
        # Preserve the original evaluator's CSV parsing and tiny entropy clamp.
        frame = pd.read_csv(path)
        features = frame[manifest['feature_order']].apply(pd.to_numeric, errors='raise')
        features['src_ip_entropy'] = features['src_ip_entropy'].clip(lower=0)
        probabilities = model.predict_proba(features)[:, list(model.classes_).index(1)]
        subset = saved[saved.dataset == dataset]
        np.testing.assert_array_equal(probabilities, subset.probability.to_numpy())
        for key in ['scenario_id','window_start_epoch','label','target_label','target_eligible']:
            np.testing.assert_array_equal(frame[key].to_numpy(), subset[key].to_numpy())
        records += len(frame)
    return {'prediction_rows_replayed': records, 'model_hash_and_threshold_verified': True,
            **verify_external(folder)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--assets', type=Path, default=ROOT/'release_assets')
    p.add_argument('--output', type=Path, required=True, help='New directory; refuses overwrite')
    args = p.parse_args(); output = args.output.resolve()
    if output.exists(): raise FileExistsError(output)
    output.mkdir(parents=True); extracted = output/'extracted'
    reports = []
    for name in ['reviewer_revision_v1_complete_v2.zip','ovs_safety_confirmatory_v3_evidence_v1.zip',
                 'external_raw_diagnostic_evidence_v1.zip','ovs_source_calibration_v3_evidence_v1.zip']:
        print(f'Checking and extracting {name}', flush=True)
        reports.append(unpack(args.assets/name, extracted))
    print('Recomputing controlled results', flush=True)
    controlled = verify_results(extracted/'reviewer_revision_v1', require_model_binaries=True)
    logs = extracted/'reviewer_revision_v1/audit_logs'
    valid = invalid = 0
    for path in sorted(logs.glob('*.jsonl')):
        result = verify_hash_chained_jsonl(path)
        expected = path.name not in ['tampered_fixture.jsonl','truncated_fixture.jsonl']
        if result['valid_embedded_hash_chain'] != expected: raise ValueError(f'Audit replay mismatch: {path.name}')
        valid += int(expected); invalid += int(not expected)
    if not valid or invalid != 2: raise ValueError('Audit fixtures missing')
    source_calibration = verify_source_policy(extracted/'ovs_safety_development_v3',
        extracted/'ovs_safety_validation_v3', ROOT/'deployment_source_v3', output/'source_policy_replay')
    ovs = {}
    for os in ['kali','ubuntu']:
        print(f'Replaying {os} OVS observations and service metrics', flush=True)
        source = extracted/f'actual_ovs_{os}_safety_v3'
        cfg = json.loads((source/'run_configuration.json').read_text())
        frozen = json.loads((ROOT/'deployment_source_v3/source_policy.json').read_text())
        if cfg['source_policy'] != frozen: raise ValueError('Frozen source policy mismatch')
        ovs[os] = verify_ovs(source, ROOT/'deployment_ovs_v2', ROOT/'configs/threshold_registry_ovs_v2.json')
    print('Replaying external fixed-transfer predictions and intervals', flush=True)
    external = replay_external(extracted)
    calibration = []
    with zipfile.ZipFile(ROOT/'ovs_calibration_v2.zip') as archive:
        for name in archive.namelist():
            if name.endswith('/CHECKSUMS.sha256'):
                calibration.append({'manifest':name,'checksums':verify_embedded_manifest(archive,name)})
    report = {'passed': True, 'scope':'Included artifact integrity and saved-result replay; not full scientific readiness',
              'archives':reports,'controlled':controlled,'controlled_audit':{'valid_chains':valid,'invalid_fixtures_detected':invalid},
              'ovs':ovs,'external':external,'detector_calibration_checksums':calibration,
              'source_policy_calibration':source_calibration,
              'remaining_limitations':[
              'Raw external datasets require separate publisher downloads; included fingerprints identify consumed files.',
              'No new actual OVS traffic is generated by this offline verifier.']}
    (output/'verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))


if __name__ == '__main__': main()
