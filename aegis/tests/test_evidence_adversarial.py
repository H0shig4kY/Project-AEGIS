import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from aegis.atomic_storage import StorageIntegrityError
from aegis.evidence_manager import EvidenceManager
from aegis.evidence_models import EvidenceRecord, EvidenceLimits
from aegis.evidence_store import EvidenceReader
from aegis.findings_report import build_report
from aegis.result_store import ResultStore
from aegis.results import Observation, PluginResult
from test_evidence_models import payload
from test_evidence_store import setup, attach, domain_snapshot


def test_timestamp_overflow_is_a_validation_error():
    data = payload(); data['registered_at'] = datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=23)))
    with pytest.raises(ValidationError):
        EvidenceRecord(**data)


def test_oversized_record_is_rejected_before_any_publication(setup):
    campaign, _, _ = setup
    path = ResultStore(campaign.data_dir / 'results').save(PluginResult(plugin='dns',
        version='v' * 70000, observations=[Observation(type='dns', target='example.test')]))
    with pytest.raises(ValueError, match='metadata.*limit'):
        EvidenceManager(campaign).attach_observation('a' * 64, path.name, 0, actor='operator', reason='review')
    assert not campaign.evidence_dir.exists()


def test_retry_after_record_failure_reuses_orphan_without_losing_provenance(setup, monkeypatch):
    campaign, _, source = setup
    manager = EvidenceManager(campaign, limits=EvidenceLimits(max_object_bytes=source.stat().st_size,
        max_assessment_bytes=source.stat().st_size))
    original = os.link
    def fail(src, dst, *args, **kwargs):
        if str(dst).endswith('.json'):
            raise OSError('record publication interruption')
        return original(src, dst, *args, **kwargs)
    with monkeypatch.context() as scoped:
        scoped.setattr(os, 'link', fail)
        with pytest.raises(OSError):
            manager.attach_file('a' * 64, source, actor='operator', reason='review')
    root = campaign.evidence_dir / 'managed-v1'
    abandoned = list((root / 'staging').iterdir())
    record = manager.attach_file('a' * 64, source, actor='operator', reason='review')
    assert all(p.exists() for p in abandoned)
    assert EvidenceReader(campaign).get(record.evidence_id).reason == 'review'
    assert len(list((root / 'objects').glob('*.blob'))) == 1


def test_failure_after_record_link_is_idempotently_discoverable(setup, monkeypatch):
    campaign, _, _ = setup
    import aegis.evidence_store as store
    original = store.sync_directory
    def fail(path):
        if path.name == 'records':
            raise OSError('publication sync failed after link')
        return original(path)
    with monkeypatch.context() as scoped:
        scoped.setattr(store, 'sync_directory', fail)
        with pytest.raises(OSError):
            attach(setup)
    first = EvidenceReader(campaign).list_for_finding('a' * 64)[0]
    assert attach(setup).evidence_id == first.evidence_id
    assert len(EvidenceReader(campaign).list_for_finding('a' * 64)) == 1


def test_orphan_and_staging_bytes_cannot_bypass_quota(setup):
    campaign, _, source = setup
    from aegis.evidence_store import EvidenceStore
    store = EvidenceStore(campaign); store.initialize()
    (store.staging / 'object-abandoned.tmp').write_bytes(b'x' * source.stat().st_size)
    limits = EvidenceLimits(max_object_bytes=source.stat().st_size, max_assessment_bytes=source.stat().st_size)
    with pytest.raises(ValueError, match='limit'):
        attach(setup, limits=limits)
    assert not list(store.records_dir.iterdir())


def test_changed_opaque_legacy_evidence_is_not_promoted(setup):
    campaign, finding, _ = setup
    path = campaign.findings_dir / f'{finding.finding_id}.json'
    data = json.loads(path.read_text()); data['evidence'] = {'legacy': True}
    path.write_text(json.dumps(data))
    before = domain_snapshot(campaign)
    result = build_report(campaign, schema_version=2)
    assert result['findings'][0]['evidence'] == []
    assert result['findings'][0]['source_extensions']['evidence'] == {'legacy': True}
    assert domain_snapshot(campaign) == before


def test_record_referencing_removed_finding_prevents_schema_two(setup):
    campaign, finding, _ = setup; attach(setup)
    (campaign.findings_dir / f'{finding.finding_id}.json').unlink()
    with pytest.raises(StorageIntegrityError, match='missing finding'):
        build_report(campaign, schema_version=2)


def test_configured_limits_are_applied_without_truncation(setup):
    campaign, _, source = setup
    campaign.config_file.write_text('name: Test\nevidence:\n  max_object_bytes: 2\n  max_assessment_bytes: 4\n')
    original = source.read_bytes()
    with pytest.raises(ValueError, match='limit'):
        attach(setup)
    assert source.read_bytes() == original and not campaign.evidence_dir.exists()


def test_local_capture_does_not_follow_a_linked_parent(setup, monkeypatch):
    import stat
    from types import SimpleNamespace
    campaign, _, source = setup
    original = Path.lstat
    def lstat(path, *args, **kwargs):
        if path == source.parent:
            return SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'lstat', lstat)
    with pytest.raises(ValueError, match='symlink'):
        attach(setup)
    assert not campaign.evidence_dir.exists()


def test_silent_short_staging_write_never_publishes_a_record(setup, monkeypatch):
    campaign, _, _ = setup
    original = os.fdopen
    class ShortStream:
        def __init__(self, *args, **kwargs):
            self.stream = original(*args, **kwargs)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.stream.close()
        def write(self, data):
            return self.stream.write(data[:2])
        def flush(self):
            self.stream.flush()
        def fileno(self):
            return self.stream.fileno()
    monkeypatch.setattr(os, 'fdopen', ShortStream)
    with pytest.raises(OSError, match='Incomplete'):
        attach(setup)
    assert EvidenceReader(campaign).list_for_finding('a' * 64) == []


def test_queries_and_reporting_preserve_every_persisted_byte_and_mtime(setup):
    campaign, _, _ = setup; record = attach(setup)
    before = {str(p): (p.read_bytes(), p.stat().st_mtime_ns)
              for p in campaign.path.rglob('*') if p.is_file()}
    reader = EvidenceReader(campaign)
    reader.get(record.evidence_id); reader.verify(record.evidence_id); reader.list_for_finding('a' * 64)
    build_report(campaign, schema_version=2)
    after = {str(p): (p.read_bytes(), p.stat().st_mtime_ns)
             for p in campaign.path.rglob('*') if p.is_file()}
    assert after == before


def test_windows_reparse_attribute_is_rejected_on_regular_file(setup, monkeypatch):
    import stat
    from types import SimpleNamespace
    campaign, _, source = setup
    original = Path.lstat
    def lstat(path, *args, **kwargs):
        if path == source:
            return SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x400)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'lstat', lstat)
    with pytest.raises(ValueError, match='regular file'):
        attach(setup)
    assert not campaign.evidence_dir.exists()


def test_cooperative_config_writer_cannot_change_limits_during_capture(setup, monkeypatch):
    import threading
    from aegis.atomic_storage import atomic_write_text
    campaign, _, _ = setup
    finished = threading.Event()
    started = threading.Event()
    errors = []
    def write():
        started.set()
        try:
            atomic_write_text(campaign.config_file,
                'name: Test\nevidence:\n  max_object_bytes: 1\n  max_assessment_bytes: 1\n')
        except Exception as error:
            errors.append(error)
        finally:
            finished.set()
    original = os.read
    threads = []
    def read(descriptor, size):
        if not threads:
            thread = threading.Thread(target=write); threads.append(thread); thread.start()
            assert started.wait(2)
            assert not finished.wait(0.05), 'configuration writer bypassed evidence operation lock'
        return original(descriptor, size)
    monkeypatch.setattr(os, 'read', read)
    try:
        record = attach(setup)
    finally:
        for thread in threads:
            thread.join(10)
            assert not thread.is_alive()
    assert not errors
    assert EvidenceReader(campaign).get(record.evidence_id)
