import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from aegis.atomic_storage import atomic_write_text, directory_lock, StorageIntegrityError
from aegis.finding_store import FindingStore
from aegis.finding_triage import FindingTriageManager, InvalidTriageTransition
from aegis.finding_triage_history_store import FindingTriageHistoryStore
from aegis.finding_lifecycle import FindingLifecycleManager
from aegis.models import AssetType, FindingRecord, FindingTriageState, FindingState


@pytest.fixture
def stores(tmp_path):
    store = FindingStore(tmp_path / 'findings')
    history = FindingTriageHistoryStore(tmp_path / 'triage')
    record = FindingRecord(finding_id='a' * 64, rule_id='TEST', severity='medium',
        title='test', description='test', asset_type=AssetType.SERVICE, asset_value='test:80')
    store.save(record)
    return store, history, record, FindingTriageManager(store, history)


def test_failed_replace_preserves_old_json(tmp_path, monkeypatch):
    path = tmp_path / 'record.json'
    path.write_text('{"old": true}')
    def fail(*args):
        raise OSError('replace failure')
    monkeypatch.setattr(os, 'replace', fail)
    with pytest.raises(OSError, match='replace failure'):
        atomic_write_text(path, '{"new": true}')
    assert json.loads(path.read_text()) == {'old': True}
    assert list(tmp_path.glob('*.tmp'))


def test_failed_file_sync_preserves_old_json(tmp_path, monkeypatch):
    path = tmp_path / 'record.json'
    path.write_text('{"old": true}')
    def fail(*args):
        raise OSError('sync failure')
    monkeypatch.setattr(os, 'fsync', fail)
    with pytest.raises(OSError, match='sync failure'):
        atomic_write_text(path, '{"new": true}')
    assert json.loads(path.read_text()) == {'old': True}


@pytest.mark.parametrize('method', ['get', 'find'])
def test_corrupt_finding_explicit_and_preserved(stores, method):
    store, _, record, _ = stores
    path = store.path / f'{record.finding_id}.json'
    path.write_text('{')
    with pytest.raises(StorageIntegrityError, match=path.name):
        getattr(store, method)(*([record.finding_id] if method == 'get' else []))
    with pytest.raises(StorageIntegrityError):
        store.save(record)
    assert path.read_text() == '{'


def test_invalid_schema_preserved(stores):
    store, _, record, _ = stores
    path = store.path / f'{record.finding_id}.json'
    path.write_text('[]')
    with pytest.raises(StorageIntegrityError):
        store.get(record.finding_id)
    assert path.read_text() == '[]'


def test_abandoned_temps_ignored(stores):
    store, history, record, _ = stores
    for directory in (store.path, history.directory):
        (directory / 'abandoned.json.tmp').write_text('{')
    assert store.find() == [record] and history.find() == []
    assert (store.path / 'abandoned.json.tmp').exists()


class Crash(BaseException):
    pass


@pytest.mark.parametrize('point', ['before_state', 'after_state', 'after_event', 'before_receipt'])
def test_crash_recovered_on_reopen(stores, monkeypatch, point):
    store, history, record, manager = stores
    from aegis import triage_journal
    original_save = store.save
    original_history_save = history.save
    original_receipt = triage_journal.finish
    def state_save(value):
        if point == 'before_state':
            raise Crash()
        result = original_save(value)
        if point == 'after_state':
            raise Crash()
        return result
    def event_save(value):
        result = original_history_save(value)
        if point == 'after_event':
            raise Crash()
        return result
    def finish(*args, **kwargs):
        if point == 'before_receipt':
            raise Crash()
        return original_receipt(*args, **kwargs)
    monkeypatch.setattr(store, 'save', state_save)
    monkeypatch.setattr(history, 'save', event_save)
    monkeypatch.setattr(triage_journal, 'finish', finish)
    with pytest.raises(Crash):
        manager.suppress(record.finding_id, actor='operator', reason='review')
    monkeypatch.undo()
    reopened = FindingStore(store.path)
    assert reopened.get(record.finding_id).triage_state == FindingTriageState.SUPPRESSED
    events = FindingTriageHistoryStore(history.directory).find()
    assert len(events) == 1 and events[0].reason == 'review'
    assert reopened.get(record.finding_id).triage_state == FindingTriageState.SUPPRESSED
    assert len(history.find()) == 1


def test_missing_completed_event_restored(stores):
    store, history, record, manager = stores
    manager.acknowledge(record.finding_id, actor='operator', reason='review')
    event = history.find()[0]
    path = history.directory / f'{event.event_id}.json'
    before = path.read_bytes()
    path.unlink()
    FindingStore(store.path).get(record.finding_id)
    assert path.read_bytes() == before and history.find() == [event]


def test_conflicting_event_not_overwritten(stores):
    store, history, record, manager = stores
    manager.suppress(record.finding_id, actor='operator', reason='review')
    event = history.find()[0]
    path = history.directory / f'{event.event_id}.json'
    payload = json.loads(path.read_text()); payload['reason'] = 'modified'
    path.write_text(json.dumps(payload))
    before = path.read_bytes()
    with pytest.raises(StorageIntegrityError):
        FindingStore(store.path).get(record.finding_id)
    assert path.read_bytes() == before


def test_done_state_divergence_reported_without_overwrite(stores):
    store, _, record, manager = stores
    manager.suppress(record.finding_id, actor='operator', reason='review')
    path = store.path / f'{record.finding_id}.json'
    payload = json.loads(path.read_text()); payload['triage_state'] = 'open'
    path.write_text(json.dumps(payload))
    before = path.read_bytes()
    with pytest.raises(StorageIntegrityError):
        store.get(record.finding_id)
    assert path.read_bytes() == before


def test_corrupt_journal_retained(stores):
    store, _, record, manager = stores
    manager.acknowledge(record.finding_id, actor='operator', reason='review')
    path = next((store.path / '.triage-journal').glob('*.txn'))
    path.write_text('{')
    with pytest.raises(StorageIntegrityError):
        store.get(record.finding_id)
    assert path.read_text() == '{'


def test_ordinary_audit_failure_aborts_without_event(stores, monkeypatch):
    store, history, record, manager = stores
    def fail(event):
        raise OSError('audit unavailable')
    monkeypatch.setattr(history, 'save', fail)
    with pytest.raises(OSError):
        manager.suppress(record.finding_id, actor='operator', reason='review')
    monkeypatch.undo()
    assert FindingStore(store.path).get(record.finding_id) == record
    assert history.find() == []


def test_threads_only_one_transition_wins(stores):
    store, history, record, _ = stores
    def change(index):
        manager = FindingTriageManager(FindingStore(store.path), FindingTriageHistoryStore(history.directory))
        try:
            manager.acknowledge(record.finding_id, actor=str(index), reason='review')
            return True
        except InvalidTriageTransition:
            return False
    with ThreadPoolExecutor(max_workers=8) as executor:
        assert sum(executor.map(change, range(8))) == 1
    assert len(history.find()) == 1


def test_lifecycle_and_triage_threads_preserve_both(stores):
    store, history, record, manager = stores
    def lifecycle():
        FindingLifecycleManager(FindingStore(store.path)).process([])
    with ThreadPoolExecutor(max_workers=2) as executor:
        tasks = [executor.submit(lifecycle), executor.submit(manager.suppress,
            record.finding_id, actor='operator', reason='review')]
        for task in tasks:
            task.result(timeout=20)
    loaded = store.get(record.finding_id)
    assert loaded.state == FindingState.CANDIDATE_MISSING
    assert loaded.triage_state == FindingTriageState.SUPPRESSED


PROCESS_CHANGE = '''
import sys
from pathlib import Path
from aegis.finding_store import FindingStore
from aegis.finding_triage_history_store import FindingTriageHistoryStore
from aegis.finding_triage import FindingTriageManager, InvalidTriageTransition
manager=FindingTriageManager(FindingStore(Path(sys.argv[1])), FindingTriageHistoryStore(Path(sys.argv[2])))
try:
 manager.acknowledge('a'*64, actor='process', reason='review')
except InvalidTriageTransition:
 sys.exit(3)
'''


def test_processes_only_one_transition_wins(stores):
    store, history, _, _ = stores
    processes = [subprocess.Popen([sys.executable, '-c', PROCESS_CHANGE,
        str(store.path), str(history.directory)], stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(4)]
    codes = []
    for process in processes:
        out, err = process.communicate(timeout=30)
        assert process.returncode in (0, 3), err.decode()
        codes.append(process.returncode)
    assert codes.count(0) == 1 and len(history.find()) == 1


def test_process_crash_releases_lock(tmp_path):
    code = 'from pathlib import Path; from aegis.atomic_storage import directory_lock; import os,sys\nwith directory_lock(Path(sys.argv[1])): os._exit(17)'
    result = subprocess.run([sys.executable, '-c', code, str(tmp_path)], timeout=30)
    assert result.returncode == 17
    with directory_lock(tmp_path, timeout=1):
        pass


def test_lock_timeout_is_explicit(tmp_path):
    code = 'from pathlib import Path; from aegis.atomic_storage import directory_lock; import sys\nwith directory_lock(Path(sys.argv[1]), timeout=0.05): pass'
    with directory_lock(tmp_path):
        result = subprocess.run([sys.executable, '-c', code, str(tmp_path)], capture_output=True, timeout=30)
    assert result.returncode != 0 and b'lock' in result.stderr.lower()


def test_legacy_json_without_journal(stores):
    store, history, record, manager = stores
    path = store.path / f'{record.finding_id}.json'
    payload = json.loads(path.read_text()); payload.pop('triage_state')
    path.write_text(json.dumps(payload))
    assert store.get(record.finding_id).triage_state == FindingTriageState.OPEN
    manager.acknowledge(record.finding_id, actor='operator', reason='legacy')
    assert len(history.find()) == 1
