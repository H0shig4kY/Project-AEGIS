import json
import multiprocessing
import os
import stat
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis.atomic_storage import StorageIntegrityError
from aegis.context import CampaignContext
from aegis.evidence_manager import EvidenceManager
from aegis.evidence_store import EvidenceReader, read_regular
from test_evidence_store import setup, attach


def worker(root, source, ready, output):
    ready.wait(10)
    try:
        record = EvidenceManager(CampaignContext(Path(root))).attach_file('a' * 64, Path(source),
            actor='operator', reason='review')
        output.put(('ok', record.evidence_id))
    except Exception as error:
        output.put(('error', f'{type(error).__name__}: {error}'))


@pytest.mark.parametrize('mode', ['threads', 'processes'])
@pytest.mark.parametrize('scenario', ['duplicate', 'quota'])
def test_concurrent_publication_and_quota(setup, tmp_path, mode, scenario):
    campaign, _, source = setup
    size = source.stat().st_size
    campaign.config_file.write_text(f'name: Test\nevidence:\n  max_object_bytes: {size}\n  max_assessment_bytes: {size}\n')
    other = source
    if scenario == 'quota':
        other = tmp_path / 'other.bin'; other.write_bytes(b'x' * size)
    if mode == 'processes':
        context = multiprocessing.get_context('spawn')
        ready, output = context.Event(), context.Queue()
        make = context.Process
    else:
        import queue
        ready, output = threading.Event(), queue.Queue()
        make = threading.Thread
    workers = [make(target=worker, args=(str(campaign.path), str(path), ready, output))
               for path in (source, other)]
    for process in workers:
        process.start()
    ready.set()
    outcomes = [output.get(timeout=30) for _ in workers]
    for process in workers:
        process.join(timeout=30)
        assert not process.is_alive()
    if scenario == 'duplicate':
        successful = [value for status, value in outcomes if status == 'ok']
        assert successful, outcomes
        for status, value in outcomes:
            if status == 'error':
                # Read-only finding validation conservatively rejects busy SQLite sidecars.
                assert 'Busy or unsettled storage lock metadata' in value, outcomes
        repeated = EvidenceManager(campaign).attach_file('a' * 64, source, actor='operator', reason='review')
        assert set(successful) == {repeated.evidence_id}
    else:
        assert sorted(status for status, _ in outcomes) == ['error', 'ok'], outcomes
        existing = EvidenceReader(campaign).list_for_finding('a' * 64)[0]
        blocked = other if existing.origin.source_name == source.name else source
        with pytest.raises(ValueError, match='limit'):
            EvidenceManager(campaign).attach_file('a' * 64, blocked, actor='operator', reason='review')
    assert len(EvidenceReader(campaign).list_for_finding('a' * 64)) == 1
    assert sum(p.stat().st_size for p in (campaign.evidence_dir / 'managed-v1' / 'objects').glob('*.blob')) <= size


@pytest.mark.parametrize('mode', [stat.S_IFLNK, stat.S_IFIFO, stat.S_IFCHR])
def test_local_links_and_special_files_are_rejected(setup, monkeypatch, mode):
    campaign, _, source = setup
    original = Path.lstat
    def lstat(path, *args, **kwargs):
        if path == source:
            return SimpleNamespace(st_mode=mode, st_file_attributes=0)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'lstat', lstat)
    with pytest.raises(ValueError, match='regular file'):
        attach(setup)
    assert not campaign.evidence_dir.exists()


def test_source_change_during_capture_is_detected(setup, monkeypatch):
    _, _, source = setup
    original = os.read
    changed = False
    def read(descriptor, size):
        nonlocal changed
        data = original(descriptor, size)
        if not changed:
            source.write_bytes(b'changed length during capture')
            changed = True
        return data
    monkeypatch.setattr(os, 'read', read)
    with pytest.raises(StorageIntegrityError, match='changed'):
        read_regular(source, 100)


@pytest.mark.parametrize('directory', ['objects', 'records', 'staging'])
def test_incomplete_existing_storage_is_not_reinitialized(setup, directory):
    campaign, _, _ = setup
    record = attach(setup)
    root = campaign.evidence_dir / 'managed-v1'
    path = root / directory
    for item in path.iterdir():
        item.unlink()
    path.rmdir()
    with pytest.raises(StorageIntegrityError, match='incomplete'):
        EvidenceReader(campaign).list_for_finding('a' * 64)
    with pytest.raises(StorageIntegrityError, match='incomplete'):
        attach(setup)
    assert not path.exists()


def test_unidentifiable_physical_objects_fail_quota_accounting(setup, monkeypatch):
    campaign, _, _ = setup; attach(setup)
    from aegis.evidence_store import EvidenceStore
    original = Path.lstat
    def lstat(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if path.suffix == '.blob':
            return SimpleNamespace(st_mode=info.st_mode, st_size=info.st_size, st_dev=info.st_dev,
                st_ino=0, st_file_attributes=0)
        return info
    monkeypatch.setattr(Path, 'lstat', lstat)
    with pytest.raises(StorageIntegrityError, match='identity'):
        EvidenceStore(campaign).physical_bytes()
