"""Replay correction checksums, frozen scores, count metrics and block ranges."""
import argparse,hashlib,json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score,average_precision_score

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def metrics(counts):
    tn,fp,fn,tp=map(int,counts)
    d=lambda a,b:a/b if b else 0.
    return dict(accuracy=d(tn+tp,tn+fp+fn+tp),precision=d(tp,tp+fp),recall=d(tp,tp+fn),f1=d(2*tp,2*tp+fp+fn),fpr=d(fp,fp+tn),fnr=d(fn,fn+tp),benign_damage=d(fp,fp+tn))
def counts(y,p):return np.array([np.sum((y==0)&(p==0)),np.sum((y==0)&(p==1)),np.sum((y==1)&(p==0)),np.sum((y==1)&(p==1))],dtype=np.int64)
def verify(folder,deployment):
    checked=0
    for line in (folder/'CHECKSUMS.sha256').read_text().splitlines():
        digest,name=line.split('  ',1)
        target=(folder/name).resolve();assert target.is_relative_to(folder.resolve())
        assert sha(target)==digest,name;checked+=1
    manifest=json.loads((folder/'correction_manifest.json').read_text())
    assert sha(deployment/'model.joblib')==manifest['model_sha256']
    assert sha(deployment/'threshold_selection.json')==manifest['threshold_selection_sha256']
    threshold=manifest['threshold'];model=joblib.load(deployment/'model.joblib')
    schema=json.loads((deployment/'feature_schema.json').read_text());features=schema['features']
    if isinstance(features[0],dict):features=[f['name'] for f in features]
    predictions=pd.read_csv(folder/'external_predictions.csv',float_precision='round_trip')
    for name,g in predictions.groupby('dataset',sort=False):
        frame=pd.read_csv(folder/(name.replace('-','_')+'_windows.csv'),float_precision='round_trip')
        key=['scenario_id','window_start_epoch'] if name=='IoT-23' else ['source_file','window_start_epoch']
        assert not frame.duplicated(key).any()
        assert len(frame)==len(g)
        x=frame[features].copy();x['src_ip_entropy']=x.src_ip_entropy.clip(lower=0)
        assert np.isfinite(x.to_numpy()).all()
        prob=model.predict_proba(x)[:,list(model.classes_).index(1)]
        assert np.allclose(prob,g.probability,atol=1e-14,rtol=0)
        assert np.array_equal(prob>=threshold,g.prediction.to_numpy(dtype=bool))
    summaries=pd.read_csv(folder/'external_metrics.csv',float_precision='round_trip')
    ranges=pd.read_csv(folder/'external_confidence_intervals.csv',float_precision='round_trip')
    blockmap=pd.read_csv(folder/'external_block_map.csv')
    for _,s in summaries.iterrows():
        g=predictions[predictions.dataset.eq(s.dataset)]
        label='label'
        if s.label_mode!='binary':g=g[g.target_eligible.eq(1)];label='target_label'
        c=counts(g[label].to_numpy(),g.prediction.to_numpy())
        assert tuple(c)==tuple(s[k] for k in ['tn','fp','fn','tp'])
        expected=metrics(c);expected.update(roc_auc=roc_auc_score(g[label],g.probability),pr_auc=average_precision_score(g[label],g.probability))
        for k,v in expected.items():assert np.isclose(v,s[k],atol=1e-14,rtol=0),(s.dataset,k)
        blocks=[]
        bm=blockmap[blockmap.dataset.eq(s.dataset)&blockmap.label_mode.eq(s.label_mode)]
        for block,b in g.groupby('bootstrap_block',sort=True):
            row=bm[bm.bootstrap_block.eq(block)].iloc[0]
            assert row.n==len(b) and row.positive_windows==int(b[label].sum())
            blocks.append(counts(b[label].to_numpy(),b.prediction.to_numpy()))
        a=np.asarray(blocks);rng=np.random.default_rng(manifest['bootstrap_seed'])
        draws=[metrics(a[rng.integers(0,len(a),size=len(a))].sum(axis=0)) for _ in range(manifest['bootstrap_replicates'])]
        for _,r in ranges[ranges.dataset.eq(s.dataset)&ranges.label_mode.eq(s.label_mode)].iterrows():
            lo,hi=np.quantile([d[r.metric] for d in draws],[.025,.975])
            assert np.allclose([lo,hi],[r.lower_95,r.upper_95],atol=1e-14,rtol=0)
            assert int(r.blocks)==len(a)
    print(json.dumps({'passed':True,'checksums':checked,'frozen_model_predictions':len(predictions),'metric_groups':len(summaries),'block_ranges_recomputed':len(ranges),'scope':'saved artifact replay; source-file resampling is descriptive only'},indent=2))
if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--results',required=True,type=Path);ap.add_argument('--deployment',required=True,type=Path)
    a=ap.parse_args();verify(a.results,a.deployment)
