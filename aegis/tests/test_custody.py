import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from aegis.atomic_storage import StorageIntegrityError
from aegis.custody import CustodyManager, CustodyReader
from aegis.evidence_manager import EvidenceManager
from aegis.evidence_store import EvidenceReader, EvidenceStore
from aegis.finding_store import FindingStore
from aegis.findings_report import build_report
from test_evidence_store import setup, attach, domain_snapshot


def snapshot(campaign):
    return {str(p.relative_to(campaign.path)): (p.read_bytes(), p.stat().st_mtime_ns)
            for p in campaign.path.rglob('*') if p.is_file()}


def test_absent_custody_is_read_only(setup):
    campaign, _, _ = setup
    before = snapshot(campaign)
    assert CustodyReader(campaign).verify()['status'] == 'not_initialized'
    assert CustodyReader(campaign).list_events() == []
    assert snapshot(campaign) == before


def test_baseline_is_explicit_and_not_retroactive(setup):
    campaign, _, _ = setup
    record = attach(setup)
    before = domain_snapshot(campaign)
    manager = CustodyManager(campaign)
    checkpoint = manager.initialize(actor='operator', reason='activate')
    assert checkpoint['sequence'] == 1
    assert manager.initialize(actor='operator', reason='activate') == checkpoint
    events = CustodyReader(campaign).list_events()
    assert [e['event_type'] for e in events] == ['custody_initialized']
    assert CustodyReader(campaign).verify()['status'] == 'chain_verified'
    assert CustodyReader(campaign).inventory()[record.evidence_id]
    assert domain_snapshot(campaign) == before


def test_new_associations_and_idempotency(setup):
    campaign, finding, source = setup
    CustodyManager(campaign).initialize(actor='operator', reason='activate')
    before = domain_snapshot(campaign)
    record = attach(setup)
    assert attach(setup) == record
    events = CustodyReader(campaign).list_events(record.evidence_id)
    assert len(events) == 1 and events[0]['finding_id'] == finding.finding_id
    assert events[0]['actor_declared'] == 'operator'
    assert CustodyReader(campaign).verify()['checkpoint']['sequence'] == 2
    assert domain_snapshot(campaign) == before
    with pytest.raises(StorageIntegrityError):
        EvidenceStore(campaign).publish_record(record)


@pytest.mark.parametrize('phase', ['intent', 'association', 'event', 'completion'])
def test_interruption_requires_explicit_idempotent_recovery(setup, monkeypatch, phase):
    import aegis.custody as custody
    campaign, _, _ = setup
    manager = CustodyManager(campaign)
    manager.initialize(actor='operator', reason='activate')
    original = custody.publish
    def fail(path, content):
        name = path.parent.name
        selected = {'intent': 'intents', 'association': 'records', 'event': 'events', 'completion': 'completions'}[phase]
        if name == selected:
            raise OSError('controlled failure')
        return original(path, content)
    monkeypatch.setattr(custody, 'publish', fail)
    with pytest.raises(OSError):
        attach(setup)
    monkeypatch.setattr(custody, 'publish', original)
    if phase == 'intent':
        assert EvidenceReader(campaign).list_for_finding('a' * 64) == []
    else:
        before = snapshot(campaign)
        for read in [lambda: CustodyReader(campaign).verify(),
                     lambda: EvidenceReader(campaign).all_verified(),
                     lambda: build_report(campaign, schema_version=2)]:
            with pytest.raises(StorageIntegrityError):
                read()
        assert snapshot(campaign) == before
        manager.recover(actor='recovery', reason='interruption')
        after = snapshot(campaign)
        manager.recover(actor='recovery', reason='interruption')
        assert snapshot(campaign) == after
        assert len(EvidenceReader(campaign).all_verified()) == 1
        assert len(CustodyReader(campaign).list_events()) == 2


@pytest.mark.parametrize('damage', ['alter', 'remove', 'sequence', 'association', 'extra'])
def test_custody_corruption_is_not_repaired(setup, damage):
    campaign, _, _ = setup
    CustodyManager(campaign).initialize(actor='operator', reason='activate')
    record = attach(setup)
    root = campaign.evidence_dir / 'custody-v1'
    event = sorted((root / 'events').glob('*.json'))[-1]
    if damage == 'remove':
        event.unlink()
    elif damage in ('alter', 'sequence'):
        value = json.loads(event.read_bytes())
        value['actor_declared' if damage == 'alter' else 'sequence'] = 'changed' if damage == 'alter' else 99
        event.write_text(json.dumps(value))
    elif damage == 'association':
        path = campaign.evidence_dir / 'managed-v1' / 'records' / (record.evidence_id + '.json')
        value = json.loads(path.read_bytes()); value['actor'] = 'changed'
        path.write_text(json.dumps(value))
    else:
        (root / 'events' / 'unexpected.json').write_text('{}')
    before = snapshot(campaign)
    with pytest.raises(StorageIntegrityError):
        CustodyReader(campaign).verify()
    with pytest.raises(StorageIntegrityError):
        CustodyManager(campaign).recover(actor='operator', reason='no repair')
    assert snapshot(campaign) == before


def test_external_checkpoint_and_clock_anomaly(setup, monkeypatch):
    import aegis.custody as custody
    campaign, _, _ = setup
    manager = CustodyManager(campaign)
    checkpoint = manager.initialize(actor='operator', reason='activate')
    assert CustodyReader(campaign).verify(expected_checkpoint=checkpoint)['external_checkpoint_match'] is True
    monkeypatch.setattr(custody, 'utc_now', lambda: '2000-01-01T00:00:00Z')
    attach(setup)
    assert CustodyReader(campaign).verify()['temporal_anomalies'] == [2]
    with pytest.raises(StorageIntegrityError):
        CustodyReader(campaign).verify(expected_checkpoint=checkpoint)


def test_threads_serialize_chain_and_associations(setup):
    campaign, finding, source = setup
    for letter in 'bcde':
        FindingStore(campaign.findings_dir).save(replace(finding, finding_id=letter * 64))
    CustodyManager(campaign).initialize(actor='operator', reason='activate')
    def attach_retry(letter):
        import time
        for _ in range(100):
            try:
                return EvidenceManager(campaign).attach_file(letter * 64, source, actor='operator', reason='review')
            except StorageIntegrityError as error:
                if 'Busy or unsettled' not in str(error):
                    raise
                time.sleep(.01)
        pytest.fail('cooperative writer did not finish')
    with ThreadPoolExecutor(5) as pool:
        records = list(pool.map(attach_retry, 'abcde'))
    assert len({r.evidence_id for r in records}) == 5
    assert CustodyReader(campaign).verify()['checkpoint']['sequence'] == 6


def test_initialization_failure_is_recoverable(setup, monkeypatch):
    import aegis.custody as custody
    campaign, _, _ = setup
    original = custody.publish
    def fail_event(path, raw):
        if path.parent.name == 'events':
            raise OSError('injected')
        return original(path, raw)
    monkeypatch.setattr(custody, 'publish', fail_event)
    with pytest.raises(OSError):
        CustodyManager(campaign).initialize(actor='operator', reason='activate')
    monkeypatch.setattr(custody, 'publish', original)
    with pytest.raises(StorageIntegrityError):
        CustodyReader(campaign).verify()
    assert CustodyManager(campaign).recover(actor='operator', reason='recover')['status'] == 'chain_verified'
