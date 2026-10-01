import json
from pathlib import Path
from contextlib import contextmanager
import numpy as np
import pytest
from reviewer_revision.source_selector import SourceSelector, canonical_hash
from reviewer_revision.ovs_safety import receiver_metrics
from sdn import CompletedWindowController


def policy(threshold=100, persistence=2):
    return dict(version="test",byte_rate_threshold=threshold,consecutive_windows=persistence,rule_ttl_seconds=15)


def obs(ip="10.0.0.1",rate=200):
    return dict(source_ip=ip,packets=10,bytes=rate*5,duration_seconds=5.0)


class Detector:
    threshold=.5
    selection={"model_hash":"0"*64}
    def decide(self,features):
        return dict(probability=1.0,prediction=1,threshold=.5,action="RATE_LIMIT",model_hash="0"*64,threshold_selection_file="fixture")
    def predict_proba_or_action(self,features): return np.ones(len(features))


def test_missing_selector_never_authorizes_enforcement(tmp_path):
    c=CompletedWindowController(Detector(),tmp_path/"audit.jsonl")
    decision=c.detect_completed_window({"rate":1.0},"0")
    assert decision["prediction"]==1 and decision["baseline_action"]=="RATE_LIMIT"
    assert decision["action"]=="NONE" and decision["target_source"] is None
    saved=json.loads((tmp_path/"audit.jsonl").read_text())
    assert saved["input_feature_hash"]==canonical_hash({"rate":1.0})


def test_unique_persistent_source_and_label_free_identity():
    s=SourceSelector(policy())
    assert s.select([obs()],prediction=1,window_index=0)["action"]=="NONE"
    assert s.select([obs()],prediction=1,window_index=1)["target_source"]=="10.0.0.1"
    # No whitelist for the historical benign IP: identities do not determine risk.
    t=SourceSelector(policy())
    t.select([obs("10.253.0.1")],prediction=1,window_index=0)
    assert t.select([obs("10.253.0.1")],prediction=1,window_index=1)["action"]=="RATE_LIMIT"


def test_large_sender_below_envelope_does_not_trigger():
    s=SourceSelector(policy(threshold=1000,persistence=1))
    assert s.select([obs(rate=900),obs("10.0.0.2",10)],prediction=1,window_index=0)["action"]=="NONE"


def test_ambiguity_negative_prediction_and_missing_history_abstain():
    s=SourceSelector(policy(persistence=1))
    assert s.select([obs(),obs("10.0.0.2",300)],prediction=1,window_index=0)["safety_reason"]=="ambiguous_sources"
    assert s.select([obs()],prediction=0,window_index=1)["action"]=="NONE"
    t=SourceSelector(policy())
    t.select([obs()],prediction=1,window_index=0)
    t.select([],prediction=1,window_index=1)
    assert t.select([obs()],prediction=1,window_index=2)["action"]=="NONE"


@pytest.mark.parametrize("extra",["label","role","y","future_outcome","scheduled_attack_mbps"])
def test_labels_and_future_metadata_rejected(extra):
    with pytest.raises(ValueError,match="telemetry"):
        SourceSelector(policy()).select([{**obs(),extra:1}],prediction=1,window_index=0)


def test_order_nonfinite_duplicates_and_abstention_policy():
    with pytest.raises(ValueError,match="ordered"):
        SourceSelector(policy()).select([obs()],prediction=1,window_index=1)
    with pytest.raises(ValueError,match="Invalid"):
        SourceSelector(policy()).select([obs(rate=float("nan"))],prediction=1,window_index=0)
    with pytest.raises(ValueError,match="Duplicate"):
        SourceSelector(policy()).select([obs(),obs()],prediction=1,window_index=0)
    assert SourceSelector(policy(None)).select([obs()],prediction=1,window_index=0)["action"]=="NONE"


def test_reference_condition_suppresses_action_but_keeps_proposal(tmp_path):
    c=CompletedWindowController(Detector(),tmp_path/"a.jsonl",source_selector=SourceSelector(policy(persistence=1)))
    d=c.detect_completed_window({"rate":1.0},"0",source_observations=[obs()],window_index=0,enforcement_enabled=False)
    assert d["action"]=="NONE" and d["proposed_action"]=="RATE_LIMIT"


def test_receiver_not_sender_and_missing_not_zero(tmp_path):
    f=tmp_path/"i.json"
    f.write_text(json.dumps({"end":{"sum_sent":{"bits_per_second":9000000},
        "sum_received":{"bits_per_second":1000000,"lost_percent":80}}}))
    assert receiver_metrics(f)["receiver_mbps"]==1
    f.write_text('{}')
    assert receiver_metrics(f)["receiver_mbps"] is None


def test_flow_rule_has_bounded_lifetime(monkeypatch):
    import scripts.run_ovs_controller_trials as runner
    calls=[]
    class R: stdout="meter=1"
    monkeypatch.setattr(runner,"command",lambda args,**kw: calls.append(args) or R())
    lab=runner.OvsLab("fixture",1000)
    monkeypatch.setattr(lab,"dump_flows",lambda:"cookie=0x475402")
    lab.set_rate_limit("10.0.0.2",15)
    assert any("hard_timeout=15" in arg for call in calls for arg in call)
    with pytest.raises(ValueError): lab.set_rate_limit("10.0.0.2",0)


def test_old_runner_is_retired(monkeypatch):
    import scripts.run_ovs_controller_trials as runner
    monkeypatch.setattr("sys.argv",["runner","--output","unused"])
    with pytest.raises(RuntimeError,match="retired"): runner.main()


def test_fit_rejects_confirmatory_input_before_loading_rows(tmp_path):
    from scripts.fit_ovs_source_selector import load_collection
    protocol={"version":"test"}
    (tmp_path/"run_configuration.json").write_text(json.dumps(dict(stage="confirmatory_kali",protocol_hash=canonical_hash(protocol))))
    with pytest.raises(ValueError,match="test data forbidden"):
        load_collection(tmp_path,"development",protocol)


def test_mocked_collection_replay_and_tamper_detection(tmp_path,monkeypatch):
    # This is a software fixture, never reported as actual OVS evidence.
    import scripts.run_ovs_safety as entry
    import run_ovs_controller_trials as runner
    import scripts.verify_ovs_safety as verifier
    from reviewer_revision.ovs_safety import sha
    protocol=json.loads((Path(__file__).resolve().parents[1]/"configs/ovs_experiment_protocol_v3.json").read_text())
    protocol["confirmatory_kali"]["runs"]=1
    for k in ["benign_windows","attack_windows","recovery_windows"]: protocol["traffic"][k]=1
    p=tmp_path/"protocol.json"; p.write_text(json.dumps(protocol))
    selected=policy(threshold=100,persistence=1)
    selected.update(protocol_hash=canonical_hash(protocol),detector_model_hash="0"*64,status="validation_selected",validation_attack_targets=1)
    sp=tmp_path/"policy.json"; sp.write_text(json.dumps(selected))
    (tmp_path/"selection.json").write_text(json.dumps(dict(policy_hash=canonical_hash(selected))))
    class Lab:
        hosts={"benign":"10.253.0.1","attacker_1":"10.253.0.11","server":"10.253.0.3"}
        attackers=["attacker_1"]
        bridge="fixture"
        def __init__(self): self.servers=[]; self.target=None
        def dump_flows(self):
            return f"cookie=0x475402,hard_timeout=15,nw_src={self.target},actions=meter:1,NORMAL" if self.target else "NORMAL"
        def set_rate_limit(self,ip,ttl): self.target=ip
        def clear_meter(self): self.target=None
    @contextmanager
    def lab(*args): yield Lab()
    class Capture:
        def __init__(self,args,**kw): Path(args[args.index("-w")+1]).write_bytes(b"fixture"*10)
        def poll(self): return None
        def terminate(self): pass
        def wait(self,**kw): pass
    def collect(lab,item,seconds,poll,folder):
        observations=[obs("10.253.0.1",10)]
        if item["attack_mbps"]: observations.append(obs("10.253.0.11",500))
        (folder/"source_observations.json").write_text(json.dumps(observations))
        receiver={"end":{"sum_received":{"bits_per_second":1e6,"lost_percent":0}}}
        (folder/"iperf_benign.json").write_text(json.dumps(receiver))
        if item["attack_mbps"]: (folder/"iperf_attack_01.json").write_text(json.dumps(receiver))
        return {f:1.0 for f in runner.FEATURES},"10.253.0.11",1.0
    class Response: stdout=""
    for module in [entry,runner,verifier]: monkeypatch.setattr(module,"RuntimeDetector",lambda **kw:Detector())
    monkeypatch.setattr(entry,"preflight",lambda:None)
    monkeypatch.setattr(entry,"version",lambda args:"fixture")
    monkeypatch.setattr(entry.platform,"freedesktop_os_release",lambda:{"ID":"kali"},raising=False)
    monkeypatch.setattr(runner,"ovs_lab",lab)
    monkeypatch.setattr(runner,"collect_window",collect)
    monkeypatch.setattr(runner.subprocess,"Popen",Capture)
    monkeypatch.setattr(runner,"command",lambda *a,**kw:Response())
    out=tmp_path/"output"
    monkeypatch.setattr("sys.argv",["runner","--stage","confirmatory_kali","--protocol",str(p),"--source-policy",str(sp),"--output",str(out)])
    entry.main()
    assert verifier.verify(out,"fixture","fixture")["windows_verified"]==9
    f=next(out.glob("seed_*/window_results.csv")); f.write_text(f.read_text().replace("unique_persistent_rate_exceedance","forged_reason"))
    # Even a recomputed outer manifest must not hide semantic record tampering.
    (out/"CHECKSUMS.sha256").write_text("".join(f"{sha(x)}  {x.relative_to(out).as_posix()}\n" for x in sorted(out.rglob("*")) if x.is_file() and x!=out/"CHECKSUMS.sha256"))
    with pytest.raises(ValueError,match="Reason mismatch"):
        verifier.verify(out,"fixture","fixture")


def test_validation_selection_and_input_integrity(tmp_path):
    import csv
    from scripts.fit_ovs_source_selector import fit
    from reviewer_revision.ovs_safety import sha
    protocol=json.loads((Path(__file__).resolve().parents[1]/"configs/ovs_experiment_protocol_v3.json").read_text())
    protocol["development"]["runs"]=1; protocol["validation"]["runs"]=1
    for key in ["benign_windows","attack_windows","recovery_windows"]: protocol["traffic"][key]=1
    for stage in ["development","validation"]:
        directory=tmp_path/stage; directory.mkdir()
        (directory/"run_configuration.json").write_text(json.dumps(dict(stage=stage,protocol_hash=canonical_hash(protocol),detector_model_hash="0"*64)))
        seed=protocol[stage]["seed_start"]; folder=directory/f"seed_{seed:08d}_mitigation_disabled"; folder.mkdir()
        (folder/"source_truth.json").write_text(json.dumps({"10.0.0.1":0,"10.0.0.2":1}))
        with (folder/"window_results.csv").open("w",newline="") as f:
            w=csv.DictWriter(f,fieldnames=["window_index","action","prediction"]);w.writeheader()
            for index in range(3):
                w.writerow(dict(window_index=index,action="NONE",prediction=1))
                window=folder/f"window_{index:03d}";window.mkdir()
                observed=[obs("10.0.0.1",50)] + ([obs("10.0.0.2",500)] if index==1 else [])
                (window/"source_observations.json").write_text(json.dumps(observed))
        (directory/"CHECKSUMS.sha256").write_text("".join(f"{sha(x)}  {x.relative_to(directory).as_posix()}\n" for x in sorted(directory.rglob("*")) if x.is_file()))
        (directory/"verification_v3.json").write_text(json.dumps(dict(passed=True,stage=stage)))
    selected=fit(tmp_path/"development",tmp_path/"validation",tmp_path/"fitted",protocol)
    assert selected["validation_attack_targets"]==1
    assert selected["validation_metrics"]["benign_targets"]==0
    assert selected["byte_rate_threshold"]==100 # deterministic conservative tie break
    assert selected["consecutive_windows"]==1
    f=next((tmp_path/"validation").rglob("source_observations.json"));f.write_text('[]')
    with pytest.raises(ValueError,match="changed after verification"):
        fit(tmp_path/"development",tmp_path/"validation",tmp_path/"bad",protocol)


def test_new_protocol_has_disjoint_seeds_and_explicit_reference():
    protocol=json.loads((Path(__file__).resolve().parents[1]/"configs/ovs_experiment_protocol_v3.json").read_text())
    seen=set(range(51000,53030))|set(range(63000,63030))
    for name in ["development","validation","confirmatory_kali","confirmatory_ubuntu"]:
        d=protocol[name]; seeds=set(range(d["seed_start"],d["seed_start"]+d["runs"]))
        assert not seen & seeds;seen|=seeds
    assert protocol["confirmatory_conditions"]==["mitigation_disabled","audit_disabled","audit_enabled"]


def test_sha256_text_manifest_survives_line_endings(tmp_path):
    from scripts.verify_manifest import sha256
    f=tmp_path/"CHECKSUMS.sha256"
    f.write_bytes(b"abc  file\r\n"); crlf=sha256(f)
    f.write_bytes(b"abc  file\n"); assert sha256(f)==crlf
