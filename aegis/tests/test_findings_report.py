import json
import os
import subprocess
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegis.atomic_storage import StorageIntegrityError, directory_lock
from aegis.context import CampaignContext
from aegis.finding_history_store import FindingHistoryStore
from aegis.finding_store import FindingStore
from aegis.finding_triage import FindingTriageManager
from aegis.finding_triage_history_store import FindingTriageHistoryStore
from aegis.models import (AssetType, FindingEvent, FindingEventType, FindingRecord,
                          FindingState, FindingTriageState)
from aegis.cli import app
from aegis.findings_report import build_report, render_json, render_markdown, write_report

NOW = datetime(2026, 10, 9, 20, 0, tzinfo=timezone.utc)
runner = CliRunner()


def snapshot(root):
    return {p.relative_to(root): (p.read_bytes(), p.stat().st_mtime_ns)
            for p in root.rglob('*') if p.is_file()}


@pytest.fixture
def campaign(tmp_path, monkeypatch):
    root = tmp_path / 'campaign'
    root.mkdir()
    (root / 'aegis.yaml').write_text('name: Test assessment\n', encoding='utf-8')
    monkeypatch.chdir(root)
    return CampaignContext(root)


def finding(campaign, identifier='a', **fields):
    record = FindingRecord(finding_id=identifier * 64, rule_id='RULE', severity='medium',
        title='Exposure', description='Existing technical description',
        asset_type=AssetType.SERVICE, asset_value='example.test:443', **fields)
    FindingStore(campaign.findings_dir).save(record)
    return record


def manager(campaign):
    return FindingTriageManager(FindingStore(campaign.findings_dir),
                               FindingTriageHistoryStore(campaign.finding_triage_history_dir))


def report(campaign):
    return build_report(campaign, generated_at=NOW)


def cli(*options):
    return runner.invoke(app, ['findings', 'report', *options])


def test_empty_assessment_has_stable_schema_and_creates_nothing(campaign):
    before = snapshot(campaign.path)
    result = report(campaign)
    assert set(result) == {'schema_version', 'assessment', 'generated_at', 'summary', 'findings'}
    assert result['schema_version'] == 1
    assert result['assessment'] == {'name': 'Test assessment'}
    assert result['generated_at'] == NOW.isoformat()
    assert result['summary'] == {'total': 0, 'by_state': {s.value: 0 for s in FindingState},
                                'by_triage_state': {s.value: 0 for s in FindingTriageState}}
    assert result['findings'] == []
    assert snapshot(campaign.path) == before
    assert not campaign.data_dir.exists()


@pytest.mark.parametrize('state', list(FindingState))
@pytest.mark.parametrize('triage_state', list(FindingTriageState))
def test_states_and_original_fields(campaign, state, triage_state):
    record = finding(campaign, state=state, triage_state=triage_state)
    before = snapshot(campaign.path)
    result = report(campaign)
    item = result['findings'][0]
    assert set(item) == {'record', 'source_fields', 'source_extensions', 'technical_history', 'triage_history'}
    assert item['record'] == FindingStore._serialize(record)
    assert item['source_fields'] == sorted(item['record'])
    assert item['technical_history'] == item['triage_history'] == []
    assert item['source_extensions'] == {}
    assert result['summary']['by_state'][state.value] == 1
    assert result['summary']['by_triage_state'][triage_state.value] == 1
    assert snapshot(campaign.path) == before


def test_legacy_absence_is_distinct_from_null_and_opaque_evidence_is_preserved(campaign):
    record = finding(campaign)
    path = campaign.findings_dir / f'{record.finding_id}.json'
    payload = json.loads(path.read_text())
    for field in ('triage_state', 'plugin', 'first_seen'):
        payload.pop(field)
    payload['affected_service'] = None
    payload['evidence'] = {'source': 'legacy operator data', 'text': '<script>evidence</script>'}
    path.write_text(json.dumps(payload))
    before = snapshot(campaign.path)
    item = report(campaign)['findings'][0]
    assert item['record']['triage_state'] == 'open'
    assert 'triage_state' not in item['source_fields']
    assert 'plugin' not in item['source_fields'] and 'affected_service' in item['source_fields']
    assert item['record']['affected_service'] is None
    assert item['source_extensions'] == {'evidence': payload['evidence']}
    assert 'cvss' not in item['record'] and 'recommendations' not in item['record']
    assert snapshot(campaign.path) == before


def test_findings_and_event_order_with_offset_ties_and_both_histories(campaign):
    b = finding(campaign, 'b', state=FindingState.RESOLVED, active=False)
    a = finding(campaign)
    history = FindingHistoryStore(campaign.finding_history_dir)
    later = FindingEvent('f' * 64, a.finding_id, FindingEventType.STATE_CHANGED,
                         FindingState.ACTIVE, FindingState.RESOLVED, NOW + timedelta(hours=1))
    tied = replace(later, event_id='0' * 64,
                   detected_at=NOW.astimezone(timezone(timedelta(hours=2))))
    earlier = replace(later, event_id='1' * 64, detected_at=NOW)
    for event in (later, earlier, tied):
        history.save(event)
    m = manager(campaign)
    m.acknowledge(a.finding_id, actor='João', reason='reviewed')
    m.suppress(a.finding_id, actor='João', reason='accepted')
    before = snapshot(campaign.path)
    result = report(campaign)
    assert [f['record']['finding_id'] for f in result['findings']] == [a.finding_id, b.finding_id]
    item = result['findings'][0]
    assert [e['event_id'] for e in item['technical_history']] == ['0' * 64, '1' * 64, 'f' * 64]
    assert [e['event_type'] for e in item['triage_history']] == ['acknowledge', 'suppress']
    assert item['triage_history'][0]['actor'] == 'João'
    assert item['triage_history'][1]['reason'] == 'accepted'
    assert render_json(result) == render_json(report(campaign))
    assert snapshot(campaign.path) == before


@pytest.mark.parametrize('config,expected', [('{}', {}), ('name: null', {'name': None})])
def test_absent_assessment_name_is_not_invented(campaign, config, expected):
    campaign.config_file.write_text(config)
    assert report(campaign)['assessment'] == expected


def test_legacy_naive_technical_timestamp_is_preserved(campaign):
    record = finding(campaign)
    event = FindingEvent('e' * 64, record.finding_id, FindingEventType.CREATED, None,
                         FindingState.ACTIVE, NOW.replace(tzinfo=None))
    FindingHistoryStore(campaign.finding_history_dir).save(event)
    assert report(campaign)['findings'][0]['technical_history'][0]['detected_at'] == '2026-10-09T20:00:00'


@pytest.mark.parametrize('target', ['finding', 'technical', 'triage', 'journal', 'config'])
def test_corrupt_sources_fail_without_repairs_or_partial_stdout(campaign, target):
    record = finding(campaign)
    manager(campaign).suppress(record.finding_id, actor='operator', reason='review')
    paths = {'finding': campaign.findings_dir / f'{record.finding_id}.json',
             'technical': campaign.finding_history_dir / ('e' * 64 + '.json'),
             'triage': next(campaign.finding_triage_history_dir.glob('*.json')),
             'journal': next((campaign.findings_dir / '.triage-journal').glob('*.txn')),
             'config': campaign.config_file}
    paths[target].parent.mkdir(parents=True, exist_ok=True)
    paths[target].write_text('{' if target != 'config' else '[')
    before = snapshot(campaign.path)
    with pytest.raises(StorageIntegrityError):
        report(campaign)
    result = cli('--format', 'json')
    assert result.exit_code == 1 and result.stdout == ''
    assert result.stderr and 'Traceback' not in result.output
    assert snapshot(campaign.path) == before


@pytest.mark.parametrize('fault', ['pending', 'abort', 'missing_event', 'changed_event',
                                 'divergent_state', 'contradictory_receipt', 'duplicate_sequence'])
def test_journal_integrity_requires_explicit_recovery(campaign, fault):
    record = finding(campaign)
    m = manager(campaign)
    m.suppress(record.finding_id, actor='operator', reason='review')
    receipt_path = next((campaign.findings_dir / '.triage-journal').glob('*.txn'))
    receipt = json.loads(receipt_path.read_text())
    event_path = next(campaign.finding_triage_history_dir.glob('*.json'))
    if fault in ('pending', 'abort'):
        receipt['status'] = fault
        receipt_path.write_text(json.dumps(receipt))
    elif fault == 'missing_event':
        event_path.unlink()
    elif fault == 'changed_event':
        event = json.loads(event_path.read_text()); event['reason'] = 'tampered'
        event_path.write_text(json.dumps(event))
    elif fault == 'divergent_state':
        path = campaign.findings_dir / f'{record.finding_id}.json'
        payload = json.loads(path.read_text()); payload['triage_state'] = 'open'
        path.write_text(json.dumps(payload))
    else:
        duplicate = json.loads(json.dumps(receipt))
        duplicate['event']['event_id'] = '0' * 32
        if fault == 'contradictory_receipt':
            duplicate['sequence'] = 2
        (receipt_path.parent / ('0' * 32 + '.txn')).write_text(json.dumps(duplicate))
    before = snapshot(campaign.path)
    with pytest.raises(StorageIntegrityError):
        report(campaign)
    assert snapshot(campaign.path) == before


def test_aborted_receipt_without_event_is_valid_readonly(campaign, monkeypatch):
    record = finding(campaign)
    m = manager(campaign)
    def fail(*args):
        raise OSError('injected event failure')
    monkeypatch.setattr(m.history_store, 'save', fail)
    with pytest.raises(OSError):
        m.suppress(record.finding_id, actor='operator', reason='review')
    before = snapshot(campaign.path)
    item = report(campaign)['findings'][0]
    assert item['record']['triage_state'] == 'open' and item['triage_history'] == []
    assert snapshot(campaign.path) == before


def test_legacy_store_without_lock_files_is_read_without_creating_them(campaign):
    record = finding(campaign)
    for path in campaign.path.rglob('.aegis-lock.sqlite'):
        path.unlink()
    before = snapshot(campaign.path)
    assert report(campaign)['findings'][0]['record']['finding_id'] == record.finding_id
    assert snapshot(campaign.path) == before


def test_temporary_files_ignored_without_deletion(campaign):
    finding(campaign)
    (campaign.findings_dir / '.abandoned.json.tmp').write_text('{')
    before = snapshot(campaign.path)
    assert report(campaign)['summary']['total'] == 1
    assert snapshot(campaign.path) == before


def test_writer_lock_appearing_in_legacy_read_is_detected(campaign):
    with pytest.raises(StorageIntegrityError):
        with directory_lock(campaign.findings_dir, create=False):
            with directory_lock(campaign.findings_dir):
                pass


def test_markdown_escapes_untrusted_record_extensions_and_actor(campaign):
    payload = '<script>alert(1)</script>\n# Injected\n[click](javascript:alert(1)) | `code` **bold** &'
    record = finding(campaign)
    path = campaign.findings_dir / f'{record.finding_id}.json'
    data = json.loads(path.read_text()); data['title'] = payload
    data['evidence'] = {'untrusted': payload}
    path.write_text(json.dumps(data))
    manager(campaign).acknowledge(record.finding_id, actor=payload, reason=payload)
    rendered = render_markdown(report(campaign))
    assert rendered.startswith('# AEGIS findings report\n')
    for unsafe in ('<script>', '\n# Injected', '[click](', '| `code`', '**bold**'):
        assert unsafe not in rendered
    assert '&#' in rendered and 'alert' in rendered
    assert 'Technical history' in rendered and 'Triage history' in rendered
    assert 'source_extensions' in rendered


@pytest.mark.parametrize('format', ['json', 'markdown'])
def test_cli_stdout_and_file(campaign, tmp_path, format):
    finding(campaign)
    before = snapshot(campaign.path)
    result = cli('--format', format)
    assert result.exit_code == 0, result.output
    if format == 'json':
        assert json.loads(result.stdout)['schema_version'] == 1
    else:
        assert result.stdout.startswith('# AEGIS findings report')
    destination = tmp_path / ('report.' + ('json' if format == 'json' else 'md'))
    output = cli('--format', format, '--output', str(destination))
    assert output.exit_code == 0 and output.stdout == ''
    assert destination.exists()
    if format == 'json':
        assert json.loads(destination.read_text())['summary']['total'] == 1
    assert snapshot(campaign.path) == before


def test_output_exists_never_overwritten(campaign, tmp_path):
    path = tmp_path / 'existing.json'; path.write_text('original')
    result = cli('--format', 'json', '--output', str(path))
    assert result.exit_code == 1 and result.stdout == '' and result.stderr
    assert path.read_text() == 'original'
    assert not list(tmp_path.glob('.existing.json.*.tmp'))


@pytest.mark.parametrize('phase', ['fsync', 'link'])
def test_export_write_failure_leaves_no_partial_file(campaign, tmp_path, monkeypatch, phase):
    destination = tmp_path / 'report.json'
    def fail(*args):
        raise OSError('injected publication failure')
    monkeypatch.setattr(os, phase, fail)
    before = snapshot(campaign.path)
    with pytest.raises(OSError):
        write_report(destination, render_json(report(campaign)), campaign=campaign)
    assert not destination.exists() and not list(tmp_path.glob('.report.json.*.tmp'))
    assert snapshot(campaign.path) == before


def test_concurrent_destination_creation_is_preserved(campaign, tmp_path, monkeypatch):
    destination = tmp_path / 'report.md'
    original = os.link
    def race(source, target):
        Path(target).write_text('other writer')
        original(source, target)
    monkeypatch.setattr(os, 'link', race)
    with pytest.raises(FileExistsError):
        write_report(destination, 'complete report\n', campaign=campaign)
    assert destination.read_text() == 'other writer'
    assert not list(tmp_path.glob('.report.md.*.tmp'))


@pytest.mark.parametrize('relative', ['aegis.yaml', 'scope.yaml', 'data/report.json',
                                    'data/findings/report.json', 'evidence/report.md'])
def test_output_cannot_modify_assessment_inputs(campaign, relative):
    finding(campaign)
    before = snapshot(campaign.path)
    result = cli('--output', str(campaign.path / relative))
    assert result.exit_code == 1 and result.stdout == ''
    assert snapshot(campaign.path) == before


def test_missing_output_parent_is_not_created(campaign, tmp_path):
    result = cli('--output', str(tmp_path / 'missing' / 'report.json'))
    assert result.exit_code == 1 and result.stdout == ''
    assert not (tmp_path / 'missing').exists()


def test_help_invalid_format_and_no_campaign(campaign, tmp_path, monkeypatch):
    help_result = cli('--help')
    assert help_result.exit_code == 0 and '--format' in help_result.output and '--output' in help_result.output
    assert cli('--format', 'html').exit_code == 2
    monkeypatch.chdir(tmp_path)
    result = cli('--format', 'json')
    assert result.exit_code == 1 and result.stdout == '' and 'campaign' in result.stderr


def test_real_cli_from_nested_directory(campaign):
    record = finding(campaign)
    child = campaign.path / 'nested'; child.mkdir()
    before = snapshot(campaign.path)
    result = subprocess.run([sys.executable, '-m', 'aegis.cli', 'findings', 'report', '--format', 'json'],
                            cwd=child, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ''
    assert json.loads(result.stdout)['findings'][0]['record']['finding_id'] == record.finding_id
    assert snapshot(campaign.path) == before


def test_report_avoids_normal_recovery_and_assessment_construction(campaign, monkeypatch):
    finding(campaign)
    def forbidden(*args, **kwargs):
        raise AssertionError('report attempted a mutating read path')
    monkeypatch.setattr(FindingStore, 'transaction', forbidden)
    monkeypatch.setattr('aegis.cli.AssessmentContext', forbidden)
    monkeypatch.setattr('aegis.cli.create_plugin_manager', forbidden)
    assert cli().exit_code == 0


@pytest.mark.parametrize('target', ['finding_id', 'event_id', 'orphan', 'triage_transition'])
def test_invalid_source_identity_or_transition_is_explicit(campaign, target):
    record = finding(campaign)
    manager(campaign).suppress(record.finding_id, actor='operator', reason='review')
    path = (campaign.findings_dir / f'{record.finding_id}.json' if target == 'finding_id'
            else next(campaign.finding_triage_history_dir.glob('*.json')))
    payload = json.loads(path.read_text())
    if target == 'finding_id':
        payload['finding_id'] = 'b' * 64
    elif target == 'event_id':
        payload['event_id'] = '0' * 32
    elif target == 'orphan':
        payload['finding_id'] = 'b' * 64
    else:
        payload['to_state'] = 'acknowledged'
    path.write_text(json.dumps(payload))
    before = snapshot(campaign.path)
    with pytest.raises(StorageIntegrityError):
        report(campaign)
    assert snapshot(campaign.path) == before


def test_integrity_error_prevents_destination_creation(campaign, tmp_path):
    record = finding(campaign)
    (campaign.findings_dir / f'{record.finding_id}.json').write_text('{')
    destination = tmp_path / 'failed.json'
    result = cli('--output', str(destination))
    assert result.exit_code == 1 and result.stdout == ''
    assert not destination.exists() and not list(tmp_path.glob('.failed.json.*.tmp'))


def test_nonfinite_opaque_data_is_rejected_before_any_output(campaign):
    record = finding(campaign)
    path = campaign.findings_dir / f'{record.finding_id}.json'
    payload = json.loads(path.read_text()); payload['unmodeled'] = float('nan')
    path.write_text(json.dumps(payload))
    before = snapshot(campaign.path)
    with pytest.raises(StorageIntegrityError):
        report(campaign)
    for format in ('json', 'markdown'):
        result = cli('--format', format)
        assert result.exit_code == 1 and result.stdout == ''
    assert snapshot(campaign.path) == before


def test_export_stream_write_failure_cleans_up(campaign, tmp_path, monkeypatch):
    import aegis.findings_report as reporting
    destination = tmp_path / 'report.json'
    original = os.fdopen
    class BrokenStream:
        def __init__(self, *args, **kwargs):
            self.stream = original(*args, **kwargs)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.stream.close()
        def write(self, content):
            self.stream.write(content[:10])
            raise OSError('injected partial write')
    monkeypatch.setattr(reporting.os, 'fdopen', BrokenStream)
    with pytest.raises(OSError):
        write_report(destination, render_json(report(campaign)), campaign=campaign)
    assert not destination.exists() and not list(tmp_path.glob('.report.json.*.tmp'))


@pytest.mark.parametrize('suffix', ['', '-journal', '-wal', '-shm'])
def test_output_cannot_create_lock_database(campaign, suffix):
    before = snapshot(campaign.path)
    result = cli('--output', str(campaign.path / ('.aegis-lock.sqlite' + suffix)))
    assert result.exit_code == 1 and result.stdout == ''
    assert snapshot(campaign.path) == before


def test_existing_read_lock_blocks_an_independent_writer(campaign):
    finding(campaign)
    before = snapshot(campaign.path)
    code = '''
import sys
from pathlib import Path
from aegis.atomic_storage import directory_lock, StorageIntegrityError
try:
    with directory_lock(Path(sys.argv[1]), timeout=0.05):
        raise AssertionError('writer bypassed report lock')
except StorageIntegrityError:
    print('blocked')
'''
    with directory_lock(campaign.findings_dir, create=False):
        process = subprocess.run([sys.executable, '-c', code, str(campaign.findings_dir)],
                                 capture_output=True, text=True, timeout=30)
        assert process.returncode == 0, process.stderr
        assert process.stdout.strip() == 'blocked'
    assert snapshot(campaign.path) == before


def test_report_snapshot_blocks_triage_writer_until_read_finishes(campaign, monkeypatch):
    import threading
    from aegis import triage_journal
    record = finding(campaign)
    m = manager(campaign)
    started = threading.Event()
    finished = threading.Event()
    errors = []
    def writer():
        started.set()
        try:
            m.suppress(record.finding_id, actor='operator', reason='concurrent review')
        except BaseException as error:
            errors.append(error)
        finally:
            finished.set()
    original = triage_journal.inspect_completed
    threads = []
    def inspect(path):
        thread = threading.Thread(target=writer)
        threads.append(thread)
        thread.start()
        assert started.wait(timeout=2)
        assert not finished.wait(timeout=0.05)
        return original(path)
    monkeypatch.setattr(triage_journal, 'inspect_completed', inspect)
    try:
        item = report(campaign)['findings'][0]
        assert item['record']['triage_state'] == 'open' and item['triage_history'] == []
    finally:
        for thread in threads:
            thread.join(timeout=5)
            assert not thread.is_alive()
    assert errors == []
    assert FindingStore(campaign.findings_dir).get(record.finding_id).triage_state == FindingTriageState.SUPPRESSED


def test_receipt_referencing_alternate_history_is_included(campaign):
    record = finding(campaign)
    alternate = campaign.data_dir / 'alternate_history'
    m = FindingTriageManager(FindingStore(campaign.findings_dir), FindingTriageHistoryStore(alternate))
    m.acknowledge(record.finding_id, actor='operator', reason='legacy location')
    before = snapshot(campaign.path)
    item = report(campaign)['findings'][0]
    assert item['triage_history'][0]['reason'] == 'legacy location'
    assert snapshot(campaign.path) == before


def test_export_cannot_write_into_a_referenced_external_history(campaign, tmp_path):
    record = finding(campaign)
    external = tmp_path / 'external_history'
    m = FindingTriageManager(FindingStore(campaign.findings_dir), FindingTriageHistoryStore(external))
    m.acknowledge(record.finding_id, actor='operator', reason='external legacy location')
    before = snapshot(tmp_path)
    result = cli('--output', str(external / 'report.json'))
    assert result.exit_code == 1 and result.stdout == ''
    assert snapshot(tmp_path) == before


def test_json_is_unicode_without_decorations_and_invalid_format_has_no_stdout(campaign):
    record = finding(campaign)
    path = campaign.findings_dir / f'{record.finding_id}.json'
    payload = json.loads(path.read_text()); payload['title'] = 'Exposição — João'
    path.write_text(json.dumps(payload))
    result = cli('--format', 'json')
    assert result.exit_code == 0 and result.stderr == ''
    assert json.loads(result.stdout)['findings'][0]['record']['title'] == payload['title']
    invalid = cli('--format', 'html')
    assert invalid.exit_code == 2 and invalid.stdout == '' and invalid.stderr


def test_markdown_empty_assessment_and_no_evidence_are_explicit(campaign):
    assert 'Total: 0' in render_markdown(report(campaign))
    finding(campaign)
    item = report(campaign)['findings'][0]
    assert 'evidence' not in item['record'] and item['source_extensions'] == {}
    assert 'No recorded events.' in render_markdown(report(campaign))


def test_corrupt_existing_lock_is_preserved_with_clean_error(campaign):
    finding(campaign)
    (campaign.findings_dir / '.aegis-lock.sqlite').write_bytes(b'corrupt lock database')
    before = snapshot(campaign.path)
    result = cli()
    assert result.exit_code == 1 and result.stdout == '' and result.stderr
    assert 'Traceback' not in result.output
    assert snapshot(campaign.path) == before


@pytest.mark.parametrize('suffix', ['-journal', '-wal', '-shm'])
def test_abandoned_lock_sidecars_are_not_cleaned_by_reporting(campaign, suffix):
    finding(campaign)
    sidecar = campaign.findings_dir / ('.aegis-lock.sqlite' + suffix)
    sidecar.write_bytes(b'potentially recoverable operational metadata')
    before = snapshot(campaign.path)
    result = cli()
    assert result.exit_code == 1 and result.stdout == ''
    assert snapshot(campaign.path) == before


def test_reserved_lock_filename_is_case_insensitive(campaign):
    before = snapshot(campaign.path)
    result = cli('--output', str(campaign.path / '.AEGIS-LOCK.SQLITE'))
    assert result.exit_code == 1 and result.stdout == ''
    assert snapshot(campaign.path) == before


def test_failed_stream_open_closes_descriptor_and_removes_temp(campaign, tmp_path, monkeypatch):
    import aegis.findings_report as reporting
    descriptors = []
    original = reporting.tempfile.mkstemp
    def allocate(*args, **kwargs):
        descriptor, path = original(*args, **kwargs)
        descriptors.append(descriptor)
        return descriptor, path
    def fail(*args, **kwargs):
        raise OSError('injected stream-open failure')
    monkeypatch.setattr(reporting.tempfile, 'mkstemp', allocate)
    monkeypatch.setattr(reporting.os, 'fdopen', fail)
    destination = tmp_path / 'report.json'
    with pytest.raises(OSError):
        write_report(destination, render_json(report(campaign)), campaign=campaign)
    assert descriptors
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
    assert not destination.exists() and not list(tmp_path.glob('.report.json.*.tmp'))
