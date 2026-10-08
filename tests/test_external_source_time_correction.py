import pandas as pd
import numpy as np
from scripts.process_external_raw_datasets import SourceWindowWriter, process_monotonic_frame


def test_out_of_order_records_and_chunks_share_complete_window(tmp_path):
    frame=pd.DataFrame({'_ts':[1.,6.,2.,3.], '_packets':[2.,9.,3.,4.], '_bytes':[20.,90.,30.,40.],
                        '_src':['a','c','b','a'], '_binary':[0,0,1,0], '_target':[0,0,1,0],
                        '_other':[0,0,0,0], '_label_text':['benign','benign','ddos','benign']})
    def run(df,name,chunks):
        p=tmp_path/name;w=SourceWindowWriter(p,'test');w.start_source('capture','source.csv','unix_utc')
        stats={'last_ts':None,'out_of_order_resets':0}
        for indices in np.array_split(np.arange(len(df)),chunks):process_monotonic_frame(df.iloc[indices],w,stats)
        w.close();return pd.read_csv(p)
    actual=run(frame,'unordered.csv',2)
    ordered=run(frame.sort_values('_ts').reset_index(drop=True),'ordered.csv',1)
    pd.testing.assert_frame_equal(actual,ordered)
    assert len(actual)==2
    a=actual.iloc[0]
    assert (a.events,a.pkt_sum,a.unique_src)==(3,9.,2)
    assert np.isclose(a.src_ip_entropy,-(2/3)*np.log2(2/3)-(1/3)*np.log2(1/3))
    assert a.label==1


def test_source_boundary_remains_distinct(tmp_path):
    p=tmp_path/'two.csv';w=SourceWindowWriter(p,'test')
    frame=pd.DataFrame({'_ts':[1.], '_packets':[2.], '_bytes':[20.], '_src':['a'],
                        '_binary':[0], '_target':[0], '_other':[0], '_label_text':['benign']})
    for source in ['one','two']:
        w.start_source(source,source+'.csv','unix_utc')
        process_monotonic_frame(frame,w,{'last_ts':None,'out_of_order_resets':0})
    w.close();g=pd.read_csv(p)
    assert list(g.scenario_id)==['one','two'] and len(g)==2
