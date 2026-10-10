import hashlib
import json
import stat
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegis.atomic_storage import StorageIntegrityError
from aegis.assessment_package import AssessmentExporter, AssessmentPackageReader, PackageLimits
from aegis.cli import app
from aegis.custody import CustodyManager
from test_evidence_store import setup, attach
from test_custody import snapshot

TIME = datetime(2026, 10, 10, tzinfo=timezone.utc)


@pytest.mark.parametrize('profile', ['share', 'forensic'])
@pytest.mark.parametrize('objects', [False, True])
def test_profiles_and_determinism(setup, tmp_path, profile, objects):
    campaign, _, _ = setup
    record = attach(setup)
    CustodyManager(campaign).initialize(actor='PRIVATE_OPERATOR', reason='PRIVATE_REASON')
    exporter = AssessmentExporter(campaign)
    first, second = tmp_path / 'one.zip', tmp_path / 'two.zip'
    before = snapshot(campaign)
    if profile == 'share' and objects:
        with pytest.raises(ValueError):
            exporter.export(first, profile=profile, include_objects=True, generated_at=TIME)
        assert not first.exists()
        return
    exporter.export(first, profile=profile, include_objects=objects, generated_at=TIME)
    exporter.export(second, profile=profile, include_objects=objects, generated_at=TIME)
    assert first.read_bytes() == second.read_bytes()
    reader = AssessmentPackageReader()
    answer = reader.verify(first)
    assert answer['package_integrity'] == 'verified'
    assert answer['custody']['status'] == ('checkpoint_only' if profile == 'share' else 'chain_verified')
    assert answer['evidence'][0]['content_status'] == ('content_verified' if objects else 'content_not_included')
    assert answer['evidence'][0]['metadata_status'] == ('projection_only' if profile == 'share' else 'verified')
    assert snapshot(campaign) == before
    assert reader.verify(first, expected_sha256=hashlib.sha256(first.read_bytes()).hexdigest()) == answer
    with pytest.raises(StorageIntegrityError):
        reader.verify(first, expected_sha256='f' * 64)
    if profile == 'share':
        raw = first.read_bytes()
        for secret in [b'PRIVATE_OPERATOR', b'PRIVATE_REASON', b'capture.bin', b'example.test', b'Description']:
            assert secret not in raw


def test_legacy_empty_package_and_no_initialization(setup, tmp_path):
    campaign, _, _ = setup
    before = snapshot(campaign)
    path = tmp_path / 'legacy.zip'
    AssessmentExporter(campaign).export(path)
    assert AssessmentPackageReader().verify(path)['custody']['status'] == 'not_initialized'
    assert snapshot(campaign) == before
    assert not campaign.evidence_dir.exists()


@pytest.mark.parametrize('target', ['existing', 'internal', 'symlink'])
def test_invalid_destination_does_not_publish(setup, tmp_path, target):
    campaign, _, _ = setup
    path = tmp_path / 'output.zip'
    if target == 'existing':
        path.write_bytes(b'keep')
    elif target == 'internal':
        path = campaign.path / 'output.zip'
    else:
        import os
        if os.name == 'posix':
            path.symlink_to(tmp_path / 'missing')
        else:
            path.write_bytes(b'keep')
    before = snapshot(campaign)
    with pytest.raises((ValueError, OSError)):
        AssessmentExporter(campaign).export(path)
    assert snapshot(campaign) == before
    if target == 'existing':
        assert path.read_bytes() == b'keep'


def rewrite(path, mutation):
    with zipfile.ZipFile(path) as archive:
        files = [(i, archive.read(i)) for i in archive.infolist()]
    files = mutation(files)
    with zipfile.ZipFile(path, 'w') as archive:
        for info, raw in files:
            archive.writestr(info, raw)


@pytest.mark.parametrize('attack', ['traversal', 'absolute', 'duplicate', 'case', 'symlink',
    'compression', 'hash', 'missing', 'extra', 'manifest', 'overflow', 'share-secret', 'limit'])
def test_malicious_packages_are_rejected(setup, tmp_path, attack):
    campaign, _, _ = setup
    attach(setup)
    path = tmp_path / 'bad.zip'
    AssessmentExporter(campaign).export(path)
    def damage(files):
        info, raw = files[-1]
        if attack in ('traversal','absolute','case','extra','symlink'):
            name = {'traversal':'../bad','absolute':'/bad','case':info.filename.upper(),
                    'extra':'unexpected.json','symlink':'evil.json'}[attack]
            extra = zipfile.ZipInfo(name)
            if attack == 'symlink':
                extra.external_attr = (stat.S_IFLNK | 0o777) << 16
            return files + [(extra, raw)]
        if attack == 'duplicate':
            return files + [(info, raw)]
        if attack == 'missing':
            return files[:-1]
        if attack == 'hash':
            return files[:-1] + [(info, b'changed')]
        if attack == 'compression':
            info.compress_type = zipfile.ZIP_DEFLATED
            return files
        # Modify and rehash the projection, ensuring semantic checks are required.
        if attack in ('overflow','share-secret'):
            value = json.loads(raw)
            value['secret'] = 'PRIVATE_MARKER' if attack == 'share-secret' else float('inf')
            raw = json.dumps(value).replace('Infinity', '1e10000').encode()
            manifest = json.loads(files[0][1])
            member = next(m for m in manifest['members'] if m['path'] == info.filename)
            member.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            return [(files[0][0], json.dumps(manifest).encode())] + files[1:-1] + [(info, raw)]
        if attack == 'manifest':
            return [(files[0][0], b'{')] + files[1:]
        return files
    rewrite(path, damage)
    limits = PackageLimits(max_total_content_bytes=1) if attack == 'limit' else PackageLimits()
    before = {p.name for p in tmp_path.iterdir()}
    with pytest.raises(StorageIntegrityError) as caught:
        AssessmentPackageReader(limits=limits).verify(path)
    assert 'PRIVATE_MARKER' not in str(caught.value)
    assert {p.name for p in tmp_path.iterdir()} == before


def test_failed_publication_has_no_final_package(setup, tmp_path, monkeypatch):
    import os
    campaign, _, _ = setup
    path = tmp_path / 'output.zip'
    monkeypatch.setattr(os, 'link', lambda *args: (_ for _ in ()).throw(OSError('PRIVATE_MARKER')))
    with pytest.raises(OSError):
        AssessmentExporter(campaign).export(path)
    assert not path.exists()


def test_cli_profiles_and_independent_verification(setup, tmp_path, monkeypatch):
    campaign, _, _ = setup
    monkeypatch.chdir(campaign.path)
    path = tmp_path / 'export.zip'
    answer = CliRunner().invoke(app, ['assessment','export','--output',str(path),'--profile','forensic'])
    assert answer.exit_code == 0 and 'plain' in answer.stderr.lower()
    monkeypatch.chdir(tmp_path)
    answer = CliRunner().invoke(app, ['assessment','package','verify',str(path),'--json'])
    assert answer.exit_code == 0
    assert json.loads(answer.stdout)['package_integrity'] == 'verified'
    assert answer.stderr == ''


@pytest.mark.parametrize('category', ['manifest', 'members', 'metadata', 'object', 'physical'])
def test_category_limits_use_local_policy(setup,tmp_path,category):
    campaign, _, _=setup
    attach(setup)
    path=tmp_path/'limits.zip'
    AssessmentExporter(campaign).export(path,profile='forensic',include_objects=True)
    field={'manifest':'max_manifest_bytes','members':'max_members','metadata':'max_metadata_bytes',
           'object':'max_object_bytes','physical':'max_archive_bytes'}[category]
    with pytest.raises(StorageIntegrityError):
        AssessmentPackageReader(limits=PackageLimits(**{field:1})).verify(path)


def test_export_rejects_pending_custody_and_preserves_sources(setup,tmp_path,monkeypatch):
    import aegis.custody as custody
    campaign, _, _=setup
    CustodyManager(campaign).initialize(actor='operator',reason='activate')
    original=custody.publish
    def fail(path,raw):
        if path.parent.name=='completions':
            raise OSError('injected')
        return original(path,raw)
    monkeypatch.setattr(custody,'publish',fail)
    with pytest.raises(OSError):
        attach(setup)
    monkeypatch.setattr(custody,'publish',original)
    before=snapshot(campaign)
    path=tmp_path/'pending.zip'
    with pytest.raises(StorageIntegrityError):
        AssessmentExporter(campaign).export(path)
    assert not path.exists() and snapshot(campaign)==before


def test_export_enumeration_error_never_means_empty(setup,tmp_path,monkeypatch):
    import os
    campaign, _, _=setup
    original=os.scandir
    def denied(path):
        if not isinstance(path,int) and Path(path)==campaign.findings_dir:
            raise PermissionError('PRIVATE_MARKER')
        return original(path)
    monkeypatch.setattr(os,'scandir',denied)
    path=tmp_path/'denied.zip'
    with pytest.raises(StorageIntegrityError):
        AssessmentExporter(campaign).export(path)
    assert not path.exists()


def test_empty_assessment_and_external_reference(setup,tmp_path):
    from aegis.evidence_manager import EvidenceManager
    campaign, finding, _=setup
    record=EvidenceManager(campaign).attach_reference(finding.finding_id,'https://example.test/private',actor='secret',reason='secret')
    path=tmp_path/'reference.zip'
    AssessmentExporter(campaign).export(path)
    assert AssessmentPackageReader().verify(path)['evidence'][0]['content_status']=='reference_only'
    assert b'example.test' not in path.read_bytes()


@pytest.mark.parametrize('command', [['assessment','export'],['assessment','custody','init'],
    ['assessment','custody','recover'],['assessment','custody','verify'],
    ['assessment','package','inspect'],['assessment','package','verify'],
    ['findings','evidence','custody-history']])
def test_new_command_help(command):
    assert CliRunner().invoke(app,command+['--help']).exit_code==0


def test_invalid_package_cli_is_sanitized(tmp_path):
    path=tmp_path/'private.zip'; path.write_bytes(b'PRIVATE_MARKER')
    result=CliRunner().invoke(app,['assessment','package','verify',str(path),'--json'])
    assert result.exit_code==1 and result.stderr and result.stdout==''
    assert 'PRIVATE_MARKER' not in result.output and 'Traceback' not in result.output


def test_cli_symlink_loop_runtime_error_is_controlled(monkeypatch):
    import aegis.custody_cli as commands
    def failure():
        raise RuntimeError('Symlink loop from PRIVATE_MARKER')
    monkeypatch.setattr(commands,'campaign',failure)
    result=CliRunner().invoke(app,['assessment','custody','verify'])
    assert result.exit_code==1 and result.stderr and result.stdout==''
    assert 'PRIVATE_MARKER' not in result.output and 'Traceback' not in result.output


def test_cli_unrelated_runtime_error_is_not_hidden(monkeypatch):
    import aegis.custody_cli as commands
    def failure():
        raise RuntimeError('internal defect')
    monkeypatch.setattr(commands,'campaign',failure)
    result=CliRunner().invoke(app,['assessment','custody','verify'])
    assert isinstance(result.exception,RuntimeError)


def test_export_rejects_linked_journal_before_parsing(setup,tmp_path,monkeypatch):
    from aegis import triage_journal
    campaign, _, _=setup
    directory=campaign.findings_dir/'.triage-journal'
    external=tmp_path/'external-journal'; external.mkdir()
    try:
        directory.symlink_to(external,target_is_directory=True)
    except OSError:
        from types import SimpleNamespace
        directory.mkdir()
        original=Path.lstat
        def linked(path,*args,**kwargs):
            if path==directory:
                return SimpleNamespace(st_mode=stat.S_IFDIR,st_file_attributes=0x400)
            return original(path,*args,**kwargs)
        monkeypatch.setattr(Path,'lstat',linked)
    calls=[]
    monkeypatch.setattr(triage_journal,'inspect_completed',lambda path: calls.append(path) or [])
    with pytest.raises((StorageIntegrityError,ValueError)):
        AssessmentExporter(campaign).export(tmp_path/'linked-journal.zip')
    assert not calls and not (tmp_path/'linked-journal.zip').exists()
