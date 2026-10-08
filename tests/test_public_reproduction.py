import hashlib
import io
import zipfile
from pathlib import Path, PurePosixPath
import pytest
from reviewer_revision.artifact_paths import relative_name, artifact_path
from reviewer_revision.archive_io import archive_index, extract_checked, verify_embedded_manifest
from scripts.build_public_evidence import build
from scripts.verify_public_release import unpack


def test_windows_saved_reference_has_posix_components(tmp_path):
    name = r'models\fold_0\ML_window\threshold_selection.json'
    assert PurePosixPath(relative_name(name)).parts == ('models','fold_0','ML_window','threshold_selection.json')
    assert artifact_path(tmp_path,name) == tmp_path/'models/fold_0/ML_window/threshold_selection.json'


@pytest.mark.parametrize('name',['../private','/absolute',r'C:\private',r'folder\..\private',r'\\server\share'])
def test_reject_escaping_artifact_references(name,tmp_path):
    with pytest.raises(ValueError): artifact_path(tmp_path,name)


def test_archive_normalizes_checksum_and_member_separators(tmp_path):
    memory=io.BytesIO(); payload=b'recorded evidence\n'
    with zipfile.ZipFile(memory,'w') as z:
        z.writestr(r'evidence\models\fold_0\x.txt',payload)
        z.writestr('evidence/PUBLIC_CHECKSUMS.sha256',hashlib.sha256(payload).hexdigest()+r'  models\fold_0\x.txt'+'\n')
    with zipfile.ZipFile(memory) as z:
        assert verify_embedded_manifest(z,'evidence/PUBLIC_CHECKSUMS.sha256') == 1
        extract_checked(z,tmp_path)
        assert (tmp_path/'evidence/models/fold_0/x.txt').read_bytes() == payload


def test_duplicate_normalized_archive_members_rejected():
    memory=io.BytesIO()
    with zipfile.ZipFile(memory,'w') as z:
        z.writestr('a/b','one'); z.writestr(r'a\b','two')
    with zipfile.ZipFile(memory) as z:
        with pytest.raises(ValueError): archive_index(z)


def test_packaging_preserves_bytes_and_refuses_overwrite(tmp_path):
    source=tmp_path/'source'; source.mkdir(); (source/'x.json').write_bytes(b'{"record": 1}\r\n')
    out=tmp_path/'evidence.zip'; build([('source',source)],out)
    with zipfile.ZipFile(out) as z:
        assert verify_embedded_manifest(z,'PUBLIC_CHECKSUMS.sha256') == 1
        assert z.read('source/x.json') == (source/'x.json').read_bytes()
    with pytest.raises(FileExistsError): build([('source',source)],out)


def test_checksum_detects_changed_payload():
    memory=io.BytesIO()
    with zipfile.ZipFile(memory,'w') as z:
        z.writestr('a',b'changed');z.writestr('PUBLIC_CHECKSUMS.sha256',hashlib.sha256(b'original').hexdigest()+'  a\n')
    with zipfile.ZipFile(memory) as z:
        with pytest.raises(AssertionError): verify_embedded_manifest(z,'PUBLIC_CHECKSUMS.sha256')


def test_multiple_outer_manifests_do_not_collide(tmp_path):
    for name in ['first','second']:
        source=tmp_path/name; source.mkdir(); (source/'data.txt').write_text(name)
        archive=tmp_path/f'{name}.zip'; build([(name,source)],archive)
        unpack(archive,tmp_path/'extracted')
        assert (tmp_path/'extracted'/name/'data.txt').read_text() == name
    assert len(list((tmp_path/'extracted/_archive_manifests').glob('*.sha256'))) == 2
