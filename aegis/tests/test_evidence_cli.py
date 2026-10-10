import json
import os
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from aegis.cli import app
from aegis.evidence_store import EvidenceReader
from aegis.findings_report import build_report
from test_evidence_store import setup, domain_snapshot

runner = CliRunner()


def invoke(campaign, *args):
    previous = os.getcwd()
    try:
        os.chdir(campaign.path)
        return runner.invoke(app, ['findings', 'evidence', *args])
    finally:
        os.chdir(previous)


@pytest.mark.parametrize('command', ['add-file', 'add-observation', 'add-reference', 'list', 'show', 'verify'])
def test_command_help(setup, command):
    result = invoke(setup[0], command, '--help')
    assert result.exit_code == 0


def test_real_cli_persistence_json_and_readonly(setup):
    campaign, finding, source = setup
    before = domain_snapshot(campaign)
    added = invoke(campaign, 'add-file', finding.finding_id, str(source), '--actor', 'operator', '--reason', 'review', '--json')
    assert added.exit_code == 0, added.output
    record = json.loads(added.stdout)
    assert added.stderr == '' and record['kind'] == 'local_file'
    for command, identifier in [('list', finding.finding_id), ('show', record['evidence_id']), ('verify', record['evidence_id'])]:
        result = invoke(campaign, command, identifier, '--json')
        assert result.exit_code == 0 and result.stderr == ''
        json.loads(result.stdout)
    assert domain_snapshot(campaign) == before


@pytest.mark.parametrize('identifier', ['../bad', 'f' * 64])
def test_cli_errors_are_clear_and_do_not_initialize(setup, identifier):
    campaign, _, source = setup
    result = invoke(campaign, 'add-file', identifier, str(source), '--actor', 'operator', '--reason', 'review', '--json')
    assert result.exit_code != 0 and result.stdout == '' and result.stderr
    assert 'Traceback' not in result.output and not campaign.evidence_dir.exists()


def test_empty_read_does_not_initialize(setup):
    campaign, finding, _ = setup
    result = invoke(campaign, 'list', finding.finding_id, '--json')
    assert result.exit_code == 0 and json.loads(result.stdout) == []
    assert not campaign.evidence_dir.exists()


@pytest.mark.parametrize('format', ['json', 'markdown'])
def test_schema_two_exports_verified_metadata_without_blob(setup, format):
    campaign, finding, source = setup
    source.write_bytes(b'PRIVATE CONTENT NEVER EXPORT')
    from aegis.evidence_manager import EvidenceManager
    record = EvidenceManager(campaign).attach_file(finding.finding_id, source, actor='operator', reason='<script>review</script>')
    before = domain_snapshot(campaign)
    old = build_report(campaign)
    assert old['schema_version'] == 1 and 'evidence' not in old['findings'][0]
    previous = os.getcwd()
    try:
        os.chdir(campaign.path)
        result = runner.invoke(app, ['findings', 'report', '--schema-version', '2', '--format', format])
    finally:
        os.chdir(previous)
    assert result.exit_code == 0, result.output
    assert 'PRIVATE CONTENT NEVER EXPORT' not in result.stdout and str(source) not in result.stdout
    if format == 'json':
        report = json.loads(result.stdout)
        assert report['schema_version'] == 2
        evidence = report['findings'][0]['evidence'][0]
        assert evidence['verification']['status'] == 'verified'
        assert evidence['metadata']['evidence_id'] == record.evidence_id
        assert 'source_name' not in evidence['metadata']['origin']
    else:
        assert 'Evidence' in result.stdout and '<script>' not in result.stdout
    assert domain_snapshot(campaign) == before


def test_schema_two_corruption_fails_but_schema_one_is_unchanged(setup):
    campaign, finding, source = setup
    from aegis.evidence_manager import EvidenceManager
    record = EvidenceManager(campaign).attach_file(finding.finding_id, source, actor='operator', reason='review')
    (campaign.evidence_dir / 'managed-v1' / 'objects' / (record.content_sha256 + '.blob')).unlink()
    assert build_report(campaign)['schema_version'] == 1
    with pytest.raises(ValueError):
        build_report(campaign, schema_version=2)


def test_cli_external_reference_and_unknown_evidence(setup):
    campaign, finding, _ = setup
    result = invoke(campaign, 'add-reference', finding.finding_id, '--source', 'https://example.test/report',
        '--actor', 'operator', '--reason', 'review', '--json')
    assert result.exit_code == 0, result.output
    record = json.loads(result.stdout)
    verification = invoke(campaign, 'verify', record['evidence_id'], '--json')
    assert json.loads(verification.stdout)['status'] == 'reference_only'
    missing = invoke(campaign, 'show', 'f' * 32, '--json')
    assert missing.exit_code == 1 and missing.stdout == '' and missing.stderr


def test_subprocess_cli_and_schema_two_persist_across_processes(setup):
    campaign, finding, source = setup
    process = subprocess.run([sys.executable, '-m', 'aegis.cli', 'findings', 'evidence',
        'add-file', finding.finding_id, str(source), '--actor', 'operator', '--reason', 'review', '--json'],
        cwd=campaign.path, capture_output=True, text=True, timeout=30)
    assert process.returncode == 0, process.stderr
    identifier = json.loads(process.stdout)['evidence_id']
    verify = subprocess.run([sys.executable, '-m', 'aegis.cli', 'findings', 'evidence',
        'verify', identifier, '--json'], cwd=campaign.path, capture_output=True, text=True, timeout=30)
    assert verify.returncode == 0 and json.loads(verify.stdout)['status'] == 'verified'


@pytest.mark.parametrize('format', ['json', 'markdown'])
def test_schema_two_corruption_prevents_output_file(setup, tmp_path, format):
    campaign, finding, source = setup
    from aegis.evidence_manager import EvidenceManager
    record = EvidenceManager(campaign).attach_file(finding.finding_id, source, actor='operator', reason='review')
    (campaign.evidence_dir / 'managed-v1' / 'objects' / (record.content_sha256 + '.blob')).write_bytes(b'corrupt')
    destination = tmp_path / 'report.txt'
    previous = os.getcwd()
    try:
        os.chdir(campaign.path)
        result = runner.invoke(app, ['findings', 'report', '--schema-version', '2', '--format', format,
                                     '--output', str(destination)])
    finally:
        os.chdir(previous)
    assert result.exit_code == 1 and result.stdout == '' and result.stderr
    assert not destination.exists()
