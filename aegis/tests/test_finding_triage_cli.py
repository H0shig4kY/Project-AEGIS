import json
import subprocess
import sys
from dataclasses import asdict, replace
from datetime import timedelta

import pytest
from typer.testing import CliRunner

from aegis.assessment import AssessmentContext
from aegis.cli import app
from aegis.context import CampaignContext
from aegis.finding_triage_history_store import FindingTriageHistoryStore
from aegis.models import AssetType, FindingRecord, FindingState, FindingTriageState

runner = CliRunner()
S = FindingTriageState
OPS = ['acknowledge', 'suppress', 'unsuppress']
VALID = [('acknowledge', S.OPEN, S.ACKNOWLEDGED), ('suppress', S.OPEN, S.SUPPRESSED),
         ('suppress', S.ACKNOWLEDGED, S.SUPPRESSED), ('unsuppress', S.SUPPRESSED, S.OPEN)]


@pytest.fixture
def campaign(tmp_path, monkeypatch):
    root = tmp_path / 'campaign'
    root.mkdir()
    (root / 'aegis.yaml').write_text('name: test\n')
    context = AssessmentContext(CampaignContext(root))
    record = FindingRecord(finding_id='a' * 64, rule_id='TEST', severity='medium',
        title='Test', description='test', asset_type=AssetType.SERVICE, asset_value='example.com:80',
        state=FindingState.RESOLVED, active=False, seen_count=4)
    context.findings.save(record)
    monkeypatch.chdir(root)
    return context, record


def invoke(operation, finding_id, *extra):
    args = ['findings', operation, finding_id]
    if operation in OPS:
        args += ['--actor', 'carlos', '--reason', 'Evidence reviewed']
    return runner.invoke(app, [*args, *extra])


@pytest.mark.parametrize('operation', [*OPS, 'triage-history'])
def test_command_help_without_campaign(tmp_path, monkeypatch, operation):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ['findings', operation, '--help'])
    assert result.exit_code == 0
    assert '--json' in result.output and 'FINDING_ID' in result.output
    if operation in OPS:
        assert '--actor' in result.output and '--reason' in result.output


@pytest.mark.parametrize('operation,previous,next_state', VALID)
@pytest.mark.parametrize('json_output', [False, True])
def test_valid_transition_persistence_and_json_schema(campaign, operation, previous, next_state, json_output):
    context, record = campaign
    record.triage_state = previous
    context.findings.save(record)
    before = asdict(record)
    result = invoke(operation, record.finding_id, *(['--json'] if json_output else []))
    assert result.exit_code == 0, result.output
    loaded = AssessmentContext(context.campaign).findings.get(record.finding_id)
    assert loaded.triage_state == next_state
    after = asdict(loaded)
    before.pop('triage_state'); after.pop('triage_state')
    assert after == before
    if json_output:
        assert json.loads(result.stdout) == {'id': record.finding_id, 'state': 'resolved',
            'triage_state': next_state.value, 'active': False}
    else:
        assert next_state.value in result.output
    history = invoke('triage-history', record.finding_id, '--json')
    assert history.exit_code == 0
    payload = json.loads(history.stdout)
    assert set(payload) == {'finding', 'timeline'}
    assert payload['finding']['triage_state'] == next_state.value
    event = payload['timeline'][0]
    assert set(event) == {'event_id', 'finding_id', 'event_type', 'from_state', 'to_state',
                         'detected_at', 'actor', 'reason'}
    assert event['actor'] == 'carlos' and event['reason'] == 'Evidence reviewed'
    assert event['from_state'] == previous.value and event['to_state'] == next_state.value
    assert event['detected_at'].endswith('+00:00')


@pytest.mark.parametrize('operation,state', [(op, state) for op in OPS for state in S
    if not any(v[0] == op and v[1] == state for v in VALID)])
def test_invalid_transitions_no_events(campaign, operation, state):
    context, record = campaign
    record.triage_state = state
    context.findings.save(record)
    result = invoke(operation, record.finding_id, '--json')
    assert result.exit_code == 1 and result.stdout == ''
    assert 'Cannot' in result.stderr and 'Traceback' not in result.output
    assert context.findings.get(record.finding_id) == record
    history = invoke('triage-history', record.finding_id, '--json')
    assert json.loads(history.stdout)['timeline'] == []


@pytest.mark.parametrize('operation', [*OPS, 'triage-history'])
@pytest.mark.parametrize('finding_id,message', [('b' * 64, 'not found'), ('../escape', 'finding_id'),
                                               ('a' * 12, 'finding_id'), ('', 'finding_id')])
def test_invalid_or_missing_id(campaign, operation, finding_id, message):
    result = invoke(operation, finding_id, '--json')
    assert result.exit_code == 1 and result.stdout == ''
    assert message in result.stderr and 'Traceback' not in result.output


@pytest.mark.parametrize('operation', OPS)
@pytest.mark.parametrize('field', ['actor', 'reason'])
@pytest.mark.parametrize('value', ['', '   '])
def test_empty_actor_reason(campaign, operation, field, value):
    _, record = campaign
    args = ['findings', operation, record.finding_id, '--actor', 'carlos', '--reason', 'review', '--json']
    args[args.index('--' + field) + 1] = value
    result = runner.invoke(app, args)
    assert result.exit_code == 1 and result.stdout == ''
    assert field in result.stderr and 'Traceback' not in result.output


@pytest.mark.parametrize('operation', OPS)
def test_required_options(campaign, operation):
    _, record = campaign
    result = runner.invoke(app, ['findings', operation, record.finding_id])
    assert result.exit_code == 2 and 'Traceback' not in result.output


def test_empty_history_and_text(campaign):
    _, record = campaign
    result = invoke('triage-history', record.finding_id, '--json')
    assert result.exit_code == 0 and json.loads(result.stdout)['timeline'] == []
    assert 'No triage history found.' in invoke('triage-history', record.finding_id).output


def test_multiple_invocations_order_and_no_duplicates(campaign):
    context, record = campaign
    for op in OPS:
        assert invoke(op, record.finding_id, '--json').exit_code == 0
    rejected = invoke('unsuppress', record.finding_id, '--json')
    assert rejected.exit_code == 1
    payload = json.loads(invoke('triage-history', record.finding_id, '--json').stdout)
    assert [e['event_type'] for e in payload['timeline']] == OPS
    assert len(payload['timeline']) == 3
    history = FindingTriageHistoryStore(context.data_dir / 'finding_triage_history')
    event = history.find()[0]
    earlier = replace(event, event_id='0' * 32, detected_at=event.detected_at - timedelta(hours=1))
    history.save(earlier)
    payload = json.loads(invoke('triage-history', record.finding_id, '--json').stdout)
    assert payload['timeline'][0]['event_id'] == earlier.event_id
    text = invoke('triage-history', record.finding_id).output
    assert 'carlos' in text and 'Evidence reviewed' in text
    assert earlier.detected_at.isoformat() in text


@pytest.mark.parametrize('operation', [*OPS, 'triage-history'])
def test_no_campaign(tmp_path, monkeypatch, operation):
    monkeypatch.chdir(tmp_path)
    result = invoke(operation, 'a' * 64, '--json')
    assert result.exit_code == 1 and result.stdout == ''
    assert 'campaign' in result.stderr and 'Traceback' not in result.output


def test_subprocess_entrypoint_and_nested_campaign(campaign):
    context, record = campaign
    child = context.root / 'nested'
    child.mkdir()
    for op in OPS:
        result = subprocess.run([sys.executable, '-m', 'aegis.cli', 'findings', op,
            record.finding_id, '--actor', 'carlos', '--reason', 'real CLI', '--json'],
            cwd=child, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)['state'] == 'resolved'
    result = subprocess.run([sys.executable, '-m', 'aegis.cli', 'findings', 'triage-history',
        record.finding_id, '--json'], cwd=child, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0
    assert len(json.loads(result.stdout)['timeline']) == 3


def test_corrupt_audit_clean_error(campaign):
    context, record = campaign
    assert invoke('suppress', record.finding_id).exit_code == 0
    path = next((context.data_dir / 'finding_triage_history').glob('*.json'))
    path.write_text('{')
    result = invoke('triage-history', record.finding_id, '--json')
    assert result.exit_code == 1 and result.stdout == ''
    assert 'Traceback' not in result.output and result.stderr
