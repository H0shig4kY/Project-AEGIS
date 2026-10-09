import json
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone

import pytest

from aegis.finding_store import FindingStore
from aegis.finding_history_store import FindingHistoryStore
from aegis.finding_lifecycle import FindingLifecycleManager
from aegis.finding_triage import FindingTriageManager, InvalidTriageTransition
from aegis.finding_triage_history_store import FindingTriageHistoryStore
from aegis.models import AssetType, FindingRecord, FindingState, FindingTriageState, FindingTriageEventType

S = FindingTriageState
VALID = [('acknowledge', S.OPEN, S.ACKNOWLEDGED), ('suppress', S.OPEN, S.SUPPRESSED),
         ('suppress', S.ACKNOWLEDGED, S.SUPPRESSED), ('unsuppress', S.SUPPRESSED, S.OPEN)]


@pytest.fixture
def setup(tmp_path):
    store = FindingStore(tmp_path / 'findings')
    history = FindingTriageHistoryStore(tmp_path / 'triage_history')
    record = FindingRecord(finding_id='a' * 64, rule_id='TEST', severity='medium',
        title='Test', description='Test finding', asset_type=AssetType.SERVICE,
        asset_value='example.com:80', seen_count=4, missing_count=0,
        first_seen=datetime(2026, 1, 1, tzinfo=timezone.utc))
    store.save(record)
    return store, history, record, FindingTriageManager(store, history)


@pytest.mark.parametrize('operation,previous,next_state', VALID)
@pytest.mark.parametrize('technical_state', list(FindingState))
def test_valid_transitions_and_event_integrity(setup, operation, previous, next_state, technical_state):
    store, history, record, manager = setup
    record.triage_state = previous; record.state = technical_state
    record.active = technical_state != FindingState.RESOLVED
    store.save(record)
    before = asdict(record)
    start = datetime.now(timezone.utc)
    result = getattr(manager, operation)(record.finding_id, actor=' carlos ', reason=' Reviewed evidence ')
    loaded = FindingStore(store.path).get(record.finding_id)
    assert result == loaded and loaded.triage_state == next_state
    after = asdict(loaded)
    before.pop('triage_state'); after.pop('triage_state')
    assert before == after
    events = FindingTriageHistoryStore(history.directory).find_by_finding_id(record.finding_id)
    assert len(events) == 1
    event = events[0]
    assert event.finding_id == record.finding_id
    assert event.event_type == FindingTriageEventType(operation)
    assert event.from_state == previous and event.to_state == next_state
    assert event.actor == 'carlos' and event.reason == 'Reviewed evidence'
    assert start <= event.detected_at <= datetime.now(timezone.utc)
    assert event.detected_at.utcoffset() == timedelta(0)
    assert history.get(event.event_id) == event
    payload = json.loads((history.directory / f'{event.event_id}.json').read_text())
    assert payload['actor'] == event.actor and payload['reason'] == event.reason
    assert payload['from_state'] == previous.value and payload['to_state'] == next_state.value


@pytest.mark.parametrize('operation,state', [(op, state)
    for op in ('acknowledge', 'suppress', 'unsuppress') for state in S
    if not any(v[0] == op and v[1] == state for v in VALID)])
def test_invalid_transitions_have_no_side_effects(setup, operation, state):
    store, history, record, manager = setup
    record.triage_state = state; store.save(record)
    before = (store.path / f'{record.finding_id}.json').read_bytes()
    with pytest.raises(InvalidTriageTransition, match=operation):
        getattr(manager, operation)(record.finding_id, actor='carlos', reason='review')
    assert (store.path / f'{record.finding_id}.json').read_bytes() == before
    assert history.find() == []


@pytest.mark.parametrize('operation', ['acknowledge', 'suppress', 'unsuppress'])
@pytest.mark.parametrize('field,value', [('actor', ''), ('actor', ' \t\n'), ('actor', None),
    ('actor', 7), ('reason', ''), ('reason', ' \t\n'), ('reason', None), ('reason', 7),
    ('finding_id', ''), ('finding_id', '../escape'), ('finding_id', None)])
def test_invalid_parameters(setup, operation, field, value):
    store, history, record, manager = setup
    args = dict(finding_id=record.finding_id, actor='carlos', reason='review'); args[field] = value
    with pytest.raises(ValueError, match=field):
        getattr(manager, operation)(**args)
    assert store.get(record.finding_id) == record and history.find() == []


@pytest.mark.parametrize('operation', ['acknowledge', 'suppress', 'unsuppress'])
def test_missing_finding(setup, operation):
    _, history, _, manager = setup
    with pytest.raises(LookupError, match='Finding not found'):
        getattr(manager, operation)('b' * 64, actor='carlos', reason='review')
    assert history.find() == []


@pytest.mark.parametrize('operation,previous,next_state', VALID)
def test_repeated_operation_rejected_without_extra_event(setup, operation, previous, next_state):
    store, history, record, manager = setup
    record.triage_state = previous; store.save(record)
    getattr(manager, operation)(record.finding_id, actor='carlos', reason='review')
    with pytest.raises(InvalidTriageTransition):
        getattr(manager, operation)(record.finding_id, actor='carlos', reason='review')
    assert store.get(record.finding_id).triage_state == next_state
    assert len(history.find()) == 1


def test_legacy_finding(setup):
    store, history, record, manager = setup
    path = store.path / f'{record.finding_id}.json'
    payload = json.loads(path.read_text()); payload.pop('triage_state')
    path.write_text(json.dumps(payload))
    manager.acknowledge(record.finding_id, actor='carlos', reason='legacy review')
    assert store.get(record.finding_id).triage_state == S.ACKNOWLEDGED
    assert history.find()[0].from_state == S.OPEN


def test_history_order_filter_and_no_overwrite(setup):
    _, history, record, manager = setup
    manager.suppress(record.finding_id, actor='carlos', reason='review')
    event = history.find()[0]
    earlier = replace(event, event_id='0' * 32, detected_at=event.detected_at - timedelta(hours=1))
    other = replace(event, event_id='1' * 32, finding_id='b' * 64)
    history.save(other); history.save(earlier)
    reopened = FindingTriageHistoryStore(history.directory)
    assert reopened.find_by_finding_id(record.finding_id) == [earlier, event]
    assert reopened.get('2' * 32) is None
    with pytest.raises(FileExistsError):
        history.save(replace(event, reason='overwrite'))
    assert history.get(event.event_id) == event


def test_technical_lifecycle_preserves_triage_and_history(setup, tmp_path):
    store, history, record, manager = setup
    technical = FindingHistoryStore(tmp_path / 'technical_history')
    manager.suppress(record.finding_id, actor='carlos', reason='review')
    assert technical.find() == []
    lifecycle = FindingLifecycleManager(store, technical)
    lifecycle.process([]); lifecycle.process([])
    assert store.get(record.finding_id).state == FindingState.RESOLVED
    assert store.get(record.finding_id).triage_state == S.SUPPRESSED
    before = {p.name: p.read_bytes() for p in technical.directory.glob('*.json')}
    assert len(before) == 2
    manager.unsuppress(record.finding_id, actor='carlos', reason='recheck')
    assert store.get(record.finding_id).state == FindingState.RESOLVED
    assert {p.name: p.read_bytes() for p in technical.directory.glob('*.json')} == before
    assert len(history.find()) == 2


def test_cycles_keep_distinct_events_with_same_timestamp(setup, monkeypatch):
    _, history, record, manager = setup
    import aegis.finding_triage as module
    class Clock:
        @staticmethod
        def now(tz):
            return datetime(2026, 1, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(module, 'datetime', Clock)
    for _ in range(2):
        manager.suppress(record.finding_id, actor='carlos', reason='review')
        manager.unsuppress(record.finding_id, actor='carlos', reason='review')
    events = history.find()
    assert len(events) == len({e.event_id for e in events}) == 4


def test_audit_failure_rolls_back_state(setup, monkeypatch):
    store, history, record, manager = setup
    def fail(event):
        raise OSError('audit unavailable')
    monkeypatch.setattr(history, 'save', fail)
    with pytest.raises(OSError, match='audit unavailable'):
        manager.acknowledge(record.finding_id, actor='carlos', reason='review')
    assert store.get(record.finding_id) == record and history.find() == []


def test_state_failure_does_not_emit_event(setup, monkeypatch):
    store, history, record, manager = setup
    def fail(record):
        raise OSError('state unavailable')
    monkeypatch.setattr(store, 'save', fail)
    with pytest.raises(OSError, match='state unavailable'):
        manager.acknowledge(record.finding_id, actor='carlos', reason='review')
    assert store.get(record.finding_id) == record and history.find() == []


def test_reject_shared_state_and_audit_directory(setup):
    store, _, _, _ = setup
    with pytest.raises(ValueError, match='directories'):
        FindingTriageManager(store, FindingTriageHistoryStore(store.path))


@pytest.mark.parametrize('event_id', ['../escape', '', None])
def test_history_rejects_unsafe_event_id(setup, event_id):
    _, history, _, _ = setup
    with pytest.raises(ValueError, match='event_id'):
        history.get(event_id)


def test_history_normalizes_timezone_and_rejects_naive_timestamp(setup):
    _, history, record, manager = setup
    manager.suppress(record.finding_id, actor='carlos', reason='review')
    event = history.find()[0]
    offset = timezone(timedelta(hours=2))
    changed = replace(event, event_id='3' * 32, detected_at=event.detected_at.astimezone(offset))
    history.save(changed)
    assert history.get(changed.event_id).detected_at.utcoffset() == timedelta(0)
    assert history.get(changed.event_id).detected_at == event.detected_at
    with pytest.raises(ValueError, match='timezone-aware'):
        history.save(replace(event, event_id='4' * 32, detected_at=datetime(2026, 1, 1)))
    assert history.get('4' * 32) is None


def test_corrupt_audit_is_reported_not_silently_skipped(setup):
    _, history, record, manager = setup
    manager.suppress(record.finding_id, actor='carlos', reason='review')
    event = history.find()[0]
    (history.directory / f'{event.event_id}.json').write_text('{')
    with pytest.raises(json.JSONDecodeError):
        history.find()
