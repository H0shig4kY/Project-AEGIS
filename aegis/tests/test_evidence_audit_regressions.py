import errno
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from aegis.atomic_storage import StorageIntegrityError, directory_lock
from aegis.cli import app
from aegis.evidence_manager import EvidenceManager
from aegis.evidence_models import ObservationOrigin
from aegis.evidence_store import EvidenceReader, association_key
from aegis.findings_report import build_report
from test_evidence_observations import result
from test_evidence_store import setup


def invoke(campaign, arguments, monkeypatch):
    monkeypatch.chdir(campaign.path)
    return CliRunner().invoke(app, arguments)


@pytest.mark.parametrize('field,value', [
    ('observation_index', 999), ('plugin', 'contradictory'),
    ('observation_id', 'f' * 64), ('result_id', 'f' * 64),
    ('result_sha256', 'f' * 64), ('result_filename', 'other.json'),
    ('plugin_version', 'other'), ('source_timestamp', 'other')])
def test_snapshot_origin_must_match_record(setup, field, value):
    campaign, finding, _ = setup
    path = result(campaign)
    record = EvidenceManager(campaign).attach_observation(finding.finding_id, path.name, 0,
        actor='audit', reason='regression')
    root = campaign.evidence_dir / 'managed-v1'
    blob = root / 'objects' / (record.content_sha256 + '.blob')
    original = blob.read_bytes()
    record_path = root / 'records' / (record.evidence_id + '.json')
    payload = json.loads(record_path.read_text())
    payload['origin'][field] = value
    payload['deduplication_key'] = association_key(record.finding_id, record.kind,
        ObservationOrigin.model_validate(payload['origin']), record.content_sha256)
    record_path.write_text(json.dumps(payload))
    with pytest.raises(StorageIntegrityError):
        EvidenceReader(campaign).verify(record.evidence_id)
    with pytest.raises(StorageIntegrityError):
        build_report(campaign, schema_version=2)
    assert blob.read_bytes() == original
    assert hashlib.sha256(original).hexdigest() == record.content_sha256
    assert build_report(campaign)['schema_version'] == 1


@pytest.mark.parametrize('component', ['results', 'data', 'file', 'integrity', 'missing', 'invalid'])
def test_observation_paths_rejected_before_locks(setup, monkeypatch, component):
    import stat
    campaign, finding, _ = setup
    path = result(campaign)
    target = {'results': path.parent, 'data': campaign.data_dir,
              'file': path, 'integrity': campaign.data_dir / 'integrity',
              'missing': path.parent, 'invalid': path.parent}[component]
    original = Path.lstat
    def lstat(current, *args, **kwargs):
        if current == target:
            if component == 'missing':
                raise FileNotFoundError('missing')
            mode = stat.S_IFREG if component == 'invalid' else stat.S_IFLNK
            return SimpleNamespace(st_mode=mode, st_file_attributes=0)
        return original(current, *args, **kwargs)
    monkeypatch.setattr(Path, 'lstat', lstat)
    import aegis.evidence_manager as manager
    def lock(*args, **kwargs):
        pytest.fail('lock acquired before unsafe path validation')
    monkeypatch.setattr(manager, 'directory_lock', lock)
    with pytest.raises((ValueError, OSError)):
        EvidenceManager(campaign).attach_observation(finding.finding_id, path.name, 0,
            actor='audit', reason='test')
    assert not campaign.evidence_dir.exists()


@pytest.mark.parametrize('source', ['url', 'observation', 'metadata', 'record', 'report'])
def test_validation_errors_never_echo_secrets(setup, monkeypatch, source):
    campaign, finding, capture = setup
    secret = 'UNTRUSTED_SECRET_627'
    prefix = ['findings', 'evidence']
    if source == 'url':
        args = prefix + ['add-reference', finding.finding_id, '--source',
                        'https://u:' + secret + '@example.test']
    elif source == 'observation':
        path = result(campaign)
        raw = json.loads(path.read_text()); raw['observations'][0]['type'] = {'private': secret}
        path.write_text(json.dumps(raw))
        args = prefix + ['add-observation', finding.finding_id, '--result', path.name, '--index', '0']
    elif source == 'metadata':
        path = result(campaign)
        raw = json.loads(path.read_text()); raw['version'] = {'private': secret}
        path.write_text(json.dumps(raw))
        args = prefix + ['add-observation', finding.finding_id, '--result', path.name, '--index', '0']
    else:
        record = EvidenceManager(campaign).attach_file(finding.finding_id, capture,
            actor='audit', reason='test')
        path = campaign.evidence_dir / 'managed-v1' / 'records' / (record.evidence_id + '.json')
        raw = json.loads(path.read_text()); raw['actor'] = {'private': secret}
        path.write_text(json.dumps(raw))
        args = prefix + ['show', record.evidence_id] if source == 'record' else ['findings', 'report', '--schema-version', '2']
    if source in ('url', 'observation', 'metadata'):
        args += ['--actor', 'audit', '--reason', 'test']
    answer = invoke(campaign, args, monkeypatch)
    assert answer.exit_code == 1 and answer.stdout == '' and answer.stderr
    assert secret not in answer.output
    assert 'input_value' not in answer.stderr and 'Traceback' not in answer.stderr


@pytest.mark.parametrize('failure', ['runtime-loop', 'eloop'])
def test_lock_resolution_cycles_are_controlled(setup, monkeypatch, failure):
    campaign, finding, capture = setup
    original = Path.resolve
    def resolve(path, *args, **kwargs):
        if path == campaign.findings_dir:
            if failure == 'runtime-loop':
                raise RuntimeError('Symlink loop from SECRET_PATH')
            raise OSError(errno.ELOOP, 'SECRET_PATH')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'resolve', resolve)
    answer = invoke(campaign, ['findings', 'evidence', 'add-file', finding.finding_id,
        str(capture), '--actor', 'audit', '--reason', 'test'], monkeypatch)
    assert answer.exit_code == 1 and answer.stderr
    assert 'symlink' in answer.stderr.lower()
    assert 'SECRET_PATH' not in answer.output and 'Traceback' not in answer.output
    assert not campaign.evidence_dir.exists()


def test_unrelated_runtime_error_is_not_masked(setup, monkeypatch):
    campaign, _, _ = setup
    def resolve(*args, **kwargs):
        raise RuntimeError('unrelated programming defect')
    monkeypatch.setattr(Path, 'resolve', resolve)
    with pytest.raises(RuntimeError, match='unrelated programming defect'):
        with directory_lock(campaign.findings_dir):
            pass
