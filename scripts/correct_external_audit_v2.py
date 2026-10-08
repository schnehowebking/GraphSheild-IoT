"""Repair affected source/time windows and publish descriptive block sensitivity.

Run from any directory with explicit --raw-root, --evidence and --output.
Old results and the frozen detector are never modified. Only source files with
fragmented windows are re-read; unaffected feature rows are retained with hashes.
Source files are NOT asserted to be independent capture sessions.
"""
from __future__ import annotations
import argparse
import json
import platform
import shutil
import sys
import time
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import sklearn

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import process_external_raw_datasets as raw
from scripts import evaluate_external_raw_transfer as ev


def correct(raw_root: Path, evidence: Path, out: Path) -> None:
    if out.exists():
        raise FileExistsError(out)
    out.mkdir(parents=True)
    started = time.perf_counter()
    fingerprints = pd.read_csv(evidence / 'external_raw_source_hashes_v1/raw_source_fingerprints.csv')
    expected = dict(zip(fingerprints.relative_path, fingerprints.sha256))
    manifest = {'version': 'external_source_time_correction_v2', 'sources_reprocessed': [],
                'retained_inputs': {}, 'aggregation_unit': 'source file and five-second flow-start bin; IoT-23 original scenario and bin',
                'block_interpretation': 'descriptive sensitivity, not population confidence; cross-file/session independence unestablished',
                'python': platform.python_version(), 'sklearn': sklearn.__version__,
                'numpy': np.__version__, 'pandas': pd.__version__}
    mapping = [('CIC-DDoS2019', 'cicddos2019/windows/cicddos2019_windows.csv', raw.process_cic),
               ('IoT-23', 'iot23/windows/iot23_windows.csv', None),
               ('TON_IoT', 'toniot_final/windows/toniot_windows.csv', raw.process_toniot)]
    deployment = evidence / 'reviewer_revision_v1/deployment'
    schema = json.loads((deployment / 'feature_schema.json').read_text())
    features = schema['features']
    if isinstance(features[0], dict): features = [f['name'] for f in features]
    selection = json.loads((deployment / 'threshold_selection.json').read_text())
    model_path = deployment / 'model.joblib'
    assert ev.sha256(model_path) == selection['model_hash']
    model = joblib.load(model_path)
    threshold = selection['selected_value']
    manifest.update(model_sha256=ev.sha256(model_path), threshold=threshold,
                    threshold_selection_sha256=ev.sha256(deployment/'threshold_selection.json'),
                    bootstrap_seed=ev.SEED, bootstrap_replicates=ev.BOOTSTRAPS)
    summaries, intervals, predictions, blocks, changes = [], [], [], [], []
    for dataset, rel, processor in mapping:
        old_path = evidence / 'external_raw_processing_v1' / rel
        old = pd.read_csv(old_path, float_precision='round_trip')
        manifest['retained_inputs'][dataset] = {'path': rel, 'sha256': ev.sha256(old_path)}
        if processor is not None:
            duplicate = old.duplicated(['source_file', 'window_start_epoch'], keep=False)
            affected = sorted(old.loc[duplicate, 'source_file'].unique())
            raw_paths = [raw_root / p for p in affected]
            for p, name in zip(raw_paths, affected):
                print(f'Hashing {name}', flush=True)
                digest = ev.sha256(p)
                assert digest == expected[name], f'Raw source mismatch: {name}'
                manifest['sources_reprocessed'].append({'relative_path': name, 'sha256': digest, 'bytes': p.stat().st_size})
            corrected_path = out / (dataset.replace('-', '_') + '_reprocessed_sources.csv')
            print(f'Processing {dataset}: {len(affected)} affected raw files', flush=True)
            stats = processor(raw_root, corrected_path, None, 200_000, files=raw_paths)
            fresh = pd.read_csv(corrected_path, float_precision='round_trip')
            retained = old.loc[~old.source_file.isin(affected)].copy()
            assert not retained.duplicated(['source_file', 'window_start_epoch']).any()
            retained['scenario_id'] = retained.scenario_id.str.replace(r'__segment_\d+$', '', regex=True)
            retained['segment_id'] = 0
            frame = pd.concat([retained, fresh], ignore_index=True).sort_values(['source_file', 'window_start_epoch']).reset_index(drop=True)
            assert not frame.duplicated(['source_file', 'window_start_epoch']).any()
            assert int(frame.raw_rows.sum()) == int(old.raw_rows.sum())
            assert np.isclose(frame.pkt_sum.sum(), old.pkt_sum.sum(), rtol=1e-12)
            assert np.isclose(frame.byte_rate.sum(), old.byte_rate.sum(), rtol=1e-12)
            changes.append({'dataset': dataset, 'old_rows': len(old), 'new_rows': len(frame),
                            'affected_sources': affected, 'processing': stats, 'raw_row_totals_preserved': True})
            frame['bootstrap_block'] = frame.source_file
        else:
            frame = old.copy()
            frame['bootstrap_block'] = frame.scenario_id
            changes.append({'dataset': dataset, 'old_rows': len(old), 'new_rows': len(frame), 'raw_processing': 'unchanged SQLite scenario/time aggregation'})
        frame.to_csv(out / (dataset.replace('-', '_') + '_windows.csv'), index=False)
        x = frame[features].copy()
        x['src_ip_entropy'] = x.src_ip_entropy.clip(lower=0)
        assert np.isfinite(x.to_numpy(dtype=float)).all()
        probability = model.predict_proba(x)[:, list(model.classes_).index(1)]
        saved = frame[['scenario_id','source_file','window_start_epoch','bootstrap_block','label','target_label','target_eligible']].copy()
        saved.insert(0, 'dataset', dataset)
        saved['probability'] = probability
        saved['prediction'] = (probability >= threshold).astype(int)
        saved['threshold'] = threshold
        predictions.append(saved)
        modes = [('binary','label',np.ones(len(frame),dtype=bool))]
        if dataset != 'CIC-DDoS2019': modes.append(('ddos_only' if dataset=='IoT-23' else 'ddos_dos','target_label',frame.target_eligible.eq(1).to_numpy()))
        for mode, label, eligible in modes:
            working = saved.copy()
            # Legacy numeric routine, explicitly supplied with revised block IDs.
            working['scenario_id'] = working.bootstrap_block
            metric, ci = ev.evaluate(working, label, eligible)
            summaries.append({'dataset':dataset,'label_mode':mode,'threshold':threshold, **metric})
            for v in ci:
                v['method'] = 'descriptive source-file/scenario block resampling; independence unestablished'
                intervals.append({'dataset':dataset,'label_mode':mode,**v})
            for block, group in saved.loc[eligible].groupby('bootstrap_block',sort=True):
                blocks.append({'dataset':dataset,'label_mode':mode,'bootstrap_block':block,
                               'sources':';'.join(sorted(group.source_file.unique())), 'n':len(group),
                               'positive_windows':int(group[label].sum()),'negative_windows':int((group[label]==0).sum())})
    pd.concat(predictions,ignore_index=True).to_csv(out/'external_predictions.csv',index=False)
    pd.DataFrame(summaries).to_csv(out/'external_metrics.csv',index=False)
    pd.DataFrame(intervals).to_csv(out/'external_confidence_intervals.csv',index=False)
    pd.DataFrame(blocks).to_csv(out/'external_block_map.csv',index=False)
    pd.DataFrame(blocks).groupby(['dataset','label_mode']).agg(blocks=('bootstrap_block','size'),positive_blocks=('positive_windows',lambda s:int((s>0).sum())),n=('n','sum')).to_csv(out/'external_block_support.csv')
    table = pd.DataFrame(summaries).merge(pd.DataFrame(intervals).query("metric == 'f1'")[['dataset','label_mode','lower_95','upper_95']],on=['dataset','label_mode'],validate='one_to_one').rename(columns={'lower_95':'f1_ci_lower','upper_95':'f1_ci_upper'})
    table.to_csv(out/'external_table_publication.csv',index=False)
    # Independently recompute point metrics from persisted rows, not in-memory summaries.
    saved_all = pd.read_csv(out/'external_predictions.csv',float_precision='round_trip')
    for r in summaries:
        g = saved_all[saved_all.dataset.eq(r['dataset'])]
        label = 'label'
        if r['label_mode'] != 'binary': g=g[g.target_eligible.eq(1)]; label='target_label'
        tn,fp,fn,tp = ev.confusion(g[label].to_numpy(),g.prediction.to_numpy())
        assert (tn,fp,fn,tp)==tuple(r[k] for k in ['tn','fp','fn','tp'])
        assert np.isclose(2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0,r['f1'])
        assert (g.prediction.to_numpy()==(g.probability.to_numpy()>=threshold)).all()
    manifest.update(corrections=changes,runtime_seconds=time.perf_counter()-started,row_level_recomputation_passed=True,
                    limitations=['No new detector fitting or threshold selection','Source files may share capture sessions; ranges are descriptive only','IoT-23 raw processing was not repeated','Zero-denominator bootstrap ratios retain the disclosed legacy zero convention'])
    raw.json_dump(out/'correction_manifest.json',manifest)
    (out/'CHECKSUMS.sha256').write_text(''.join(f'{ev.sha256(p)}  {p.name}\n' for p in sorted(out.iterdir()) if p.is_file()),encoding='utf-8')
    print(table.to_string(index=False),flush=True)


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    for arg in ['raw-root','evidence','output']: ap.add_argument('--'+arg,required=True,type=Path)
    a=ap.parse_args();correct(a.raw_root.resolve(),a.evidence.resolve(),a.output.resolve())
