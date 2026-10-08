import pytest
from scripts.verify_source_policy import normalize_fingerprints


def test_relocation_keeps_identity_and_digest():
    name='ovs_safety_development_v3'
    old={f'/mnt/project/results/{name}/seed_00071000_mitigation_disabled/window_results.csv':'abc'}
    new={rf'F:\project\results\{name}\seed_00071000_mitigation_disabled\window_results.csv':'abc'}
    assert normalize_fingerprints(old,name)==normalize_fingerprints(new,name)
    assert normalize_fingerprints(old,name)!=normalize_fingerprints({next(iter(new)):'tampered'},name)


@pytest.mark.parametrize('path',[
    '/results/confirmatory_kali/window_results.csv',
    '/results/ovs_safety_development_v3/../window_results.csv',
    '/ovs_safety_development_v3/ovs_safety_development_v3/file',
])
def test_reject_wrong_collection_or_ambiguous_path(path):
    with pytest.raises(ValueError):
        normalize_fingerprints({path:'abc'},'ovs_safety_development_v3')


def test_reject_duplicate_relocated_identity():
    with pytest.raises(ValueError):
        normalize_fingerprints({'/a/ovs_safety_development_v3/file':'a',
                                '/b/ovs_safety_development_v3/file':'a'},'ovs_safety_development_v3')


def test_empty_summary_newline_portability_does_not_hide_rows(tmp_path):
    from scripts.verify_ovs_safety import verify_empty_summary
    a,b=tmp_path/'a.csv',tmp_path/'b.csv'
    a.write_bytes(b'\n');b.write_bytes(b'\r\n')
    verify_empty_summary(a,b)
    a.write_bytes(b'0\n')
    with pytest.raises(ValueError):verify_empty_summary(a,b)
    a.write_bytes(b'')
    with pytest.raises(ValueError):verify_empty_summary(a,b)
