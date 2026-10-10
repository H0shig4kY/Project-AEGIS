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


def process_attach(root, source, letter, output):
    from pathlib import Path
    from aegis.context import CampaignContext
    import time
    for _ in range(100):
        try:
            record = EvidenceManager(CampaignContext(Path(root))).attach_file(letter * 64,
                Path(source), actor='operator', reason='review')
            output.put(('ok', record.evidence_id)); return
        except StorageIntegrityError as error:
            if 'Busy or unsettled' not in str(error):
                output.put(('error', type(error).__name__)); return
            time.sleep(.02)
    output.put(('error','timeout'))


def test_processes_have_no_lost_events(setup):
    import multiprocessing
    campaign, finding, source = setup
    FindingStore(campaign.findings_dir).save(replace(finding, finding_id='b' * 64))
    CustodyManager(campaign).initialize(actor='operator', reason='activate')
    context = multiprocessing.get_context('spawn')
    output = context.Queue()
    processes = [context.Process(target=process_attach,args=(str(campaign.path),str(source),letter,output)) for letter in 'ab']
    for process in processes:
        process.start()
    results = [output.get(timeout=30) for _ in processes]
    for process in processes:
        process.join(timeout=30)
        assert not process.is_alive() and process.exitcode == 0
    assert all(status=='ok' for status,_ in results), results
    assert CustodyReader(campaign).verify()['checkpoint']['sequence'] == 3


def test_read_only_and_completed_receipt_survive_reopen(setup):
    campaign, _, _ = setup
    CustodyManager(campaign).initialize(actor='operator',reason='activate')
    attach(setup)
    before=snapshot(campaign)
    CustodyReader(campaign).verify()
    CustodyReader(campaign).list_events()
    build_report(campaign)
    build_report(campaign,schema_version=2)
    assert snapshot(campaign)==before


def test_direct_commit_cannot_bypass_writer_locks(setup):
    campaign, _, _ = setup
    record=attach(setup)
    CustodyManager(campaign).initialize(actor='operator',reason='activate')
    before=snapshot(campaign)
    with pytest.raises(StorageIntegrityError):
        CustodyManager(campaign).commit_record(record)
    assert snapshot(campaign)==before


def test_pending_recovery_rechecks_finding_existence(setup, monkeypatch):
    import aegis.custody as custody
    campaign, finding, _ = setup
    manager=CustodyManager(campaign)
    manager.initialize(actor='operator',reason='activate')
    original=custody.publish
    def fail_record(path,raw):
        if path.parent.name=='records':
            raise OSError('injected')
        return original(path,raw)
    monkeypatch.setattr(custody,'publish',fail_record)
    with pytest.raises(OSError):
        attach(setup)
    monkeypatch.setattr(custody,'publish',original)
    (campaign.findings_dir/(finding.finding_id+'.json')).unlink()
    with pytest.raises((StorageIntegrityError,LookupError)):
        manager.recover(actor='operator',reason='recover')
    assert not list((campaign.evidence_dir/'managed-v1'/'records').glob('*.json'))


def test_tail_truncation_requires_external_checkpoint(setup):
    campaign, _, _ = setup
    CustodyManager(campaign).initialize(actor='operator',reason='activate')
    record=attach(setup)
    trusted=CustodyReader(campaign).verify()['checkpoint']
    event=CustodyReader(campaign).list_events()[-1]
    root=campaign.evidence_dir/'custody-v1'
    (root/'events'/('%020d-%s.json'%(event['sequence'],event['event_id']))).unlink()
    for directory in ('intents','completions'):
        (root/directory/(event['operation_id']+'.json')).unlink()
    (campaign.evidence_dir/'managed-v1'/'records'/(record.evidence_id+'.json')).unlink()
    assert CustodyReader(campaign).verify()['status']=='chain_verified'
    with pytest.raises(StorageIntegrityError):
        CustodyReader(campaign).verify(expected_checkpoint=trusted)


def test_lock_graph_has_no_inversions(setup, tmp_path, monkeypatch):
    from contextlib import contextmanager
    from pathlib import Path
    import aegis.atomic_storage as atomic
    import aegis.custody as custody
    import aegis.evidence_manager as manager
    import aegis.evidence_store as store
    import aegis.findings_report as report
    import aegis.assessment_package as package
    from test_evidence_observations import result
    campaign, finding, _=setup
    selected=result(campaign)
    ranks={campaign.findings_dir:0,campaign.finding_history_dir:1,
        campaign.finding_triage_history_dir:1,campaign.data_dir/'integrity':1,
        campaign.data_dir/'results':1,campaign.path:2,
        campaign.evidence_dir/'managed-v1':3,campaign.evidence_dir/'custody-v1':4}
    original=atomic.directory_lock
    held={}
    @contextmanager
    def ordered(path,*args,**kwargs):
        path=Path(path).resolve()
        rank=ranks.get(path)
        if rank is not None and path not in held:
            assert all(rank>=ranks[p] for p in held if p in ranks), (path,held)
        with original(path,*args,**kwargs) as nested:
            held[path]=held.get(path,0)+1
            try:
                yield nested
            finally:
                held[path]-=1
                if not held[path]:
                    del held[path]
    for module in (atomic,custody,manager,store,report,package):
        monkeypatch.setattr(module,'directory_lock',ordered)
    CustodyManager(campaign).initialize(actor='operator',reason='activate')
    EvidenceManager(campaign).attach_observation(finding.finding_id,selected.name,0,actor='operator',reason='review')
    CustodyManager(campaign).recover(actor='operator',reason='no-op')
    package.AssessmentExporter(campaign).export(tmp_path/'graph.zip',profile='forensic',include_objects=True)
    assert not held


@pytest.mark.parametrize('phase',['genesis','baseline','completion'])
def test_initialization_interruptions_preserve_pending_state(setup, monkeypatch, phase):
    import aegis.custody as custody
    campaign, _, _=setup
    original=custody.publish
    def fail(path,raw):
        if path.name==phase+'.json' or (phase=='completion' and path.parent.name=='completions'):
            raise OSError('injected')
        return original(path,raw)
    monkeypatch.setattr(custody,'publish',fail)
    with pytest.raises(OSError):
        CustodyManager(campaign).initialize(actor='operator',reason='activate')
    monkeypatch.setattr(custody,'publish',original)
    with pytest.raises(StorageIntegrityError):
        CustodyReader(campaign).verify()
    assert CustodyManager(campaign).recover(actor='operator',reason='recover')['status']=='chain_verified'


def test_direct_record_publication_checks_activation_under_writer_locks(setup,monkeypatch):
    import os
    import aegis.atomic_storage as atomic
    import aegis.custody as custody
    campaign, _, _=setup
    record=attach(setup)
    original=custody.CustodyReader.exists
    def guarded(reader):
        required=[campaign.findings_dir,campaign.path,campaign.evidence_dir/'managed-v1']
        assert all(os.path.normcase(str(p.resolve())) in getattr(atomic._local,'locks',{}) for p in required)
        return original(reader)
    monkeypatch.setattr(custody.CustodyReader,'exists',guarded)
    # An existing immutable record conflicts, but activation must be checked safely first.
    with pytest.raises(FileExistsError):
        EvidenceStore(campaign).publish_record(record)


@pytest.mark.parametrize('area',['root','events','intents','completions','staging'])
def test_custody_rejects_linked_or_special_entries(setup,monkeypatch,area):
    import stat
    from pathlib import Path
    from types import SimpleNamespace
    campaign, _, _=setup
    CustodyManager(campaign).initialize(actor='operator',reason='activate')
    root=campaign.evidence_dir/'custody-v1'
    target=root/'unexpected' if area=='root' else root/area/'.publication-abandoned.tmp'
    target.write_bytes(b'preserve')
    original=Path.lstat
    def linked(path,*args,**kwargs):
        if path==target:
            return SimpleNamespace(st_mode=stat.S_IFLNK,st_file_attributes=0x400)
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'lstat',linked)
    with pytest.raises(StorageIntegrityError):
        CustodyReader(campaign).verify()


def test_initialization_before_intent_can_be_retried_explicitly(setup,monkeypatch):
    import aegis.custody as custody
    campaign, _, _=setup
    original=custody.publish
    def fail(path,raw):
        if path.parent.name=='intents':
            raise OSError('injected before intent')
        return original(path,raw)
    monkeypatch.setattr(custody,'publish',fail)
    with pytest.raises(OSError):
        CustodyManager(campaign).initialize(actor='operator',reason='activate')
    monkeypatch.setattr(custody,'publish',original)
    with pytest.raises(StorageIntegrityError):
        CustodyReader(campaign).verify()
    assert CustodyManager(campaign).initialize(actor='operator',reason='retry')['sequence']==1
