import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from aegis.atomic_storage import StorageIntegrityError
from aegis.context import CampaignContext
from aegis.evidence_manager import EvidenceManager
from aegis.evidence_models import EvidenceLimits
from aegis.evidence_store import EvidenceReader
from aegis.finding_store import FindingStore
from aegis.models import AssetType, FindingRecord, FindingTriageState


@pytest.fixture
def setup(tmp_path):
    root = tmp_path / 'assessment'; root.mkdir()
    (root / 'aegis.yaml').write_text('name: Evidence test\n')
    campaign = CampaignContext(root)
    record = FindingRecord('a' * 64, 'RULE', 'medium', 'Title', 'Description',
                           AssetType.SERVICE, 'example.test:443')
    FindingStore(campaign.findings_dir).save(record)
    source = tmp_path / 'capture.bin'; source.write_bytes(b'\x00real evidence\xff')
    return campaign, record, source


def attach(setup, **kwargs):
    campaign, finding, source = setup
    return EvidenceManager(campaign, **kwargs).attach_file(finding.finding_id, source,
                                                        actor='operator', reason='review')


def domain_snapshot(campaign):
    return {str(p.relative_to(campaign.data_dir)): (p.read_bytes(), p.stat().st_mtime_ns)
            for p in campaign.data_dir.rglob('*') if p.is_file()}


def test_capture_and_reopen_preserve_domain(setup):
    campaign, finding, source = setup
    before = domain_snapshot(campaign)
    record = attach(setup)
    assert record.content_sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert EvidenceReader(campaign).get(record.evidence_id) == record
    assert EvidenceReader(campaign).verify(record.evidence_id)['status'] == 'verified'
    assert domain_snapshot(campaign) == before
    assert FindingStore(campaign.findings_dir).get(finding.finding_id).triage_state == FindingTriageState.OPEN


def test_readers_do_not_initialize_storage(setup):
    campaign, finding, _ = setup
    before = domain_snapshot(campaign)
    assert EvidenceReader(campaign).list_for_finding(finding.finding_id) == []
    assert not campaign.evidence_dir.exists()
    assert domain_snapshot(campaign) == before


def test_association_and_content_deduplication(setup):
    campaign, finding, source = setup
    first = attach(setup)
    assert attach(setup).evidence_id == first.evidence_id
    other = replace(finding, finding_id='b' * 64)
    FindingStore(campaign.findings_dir).save(other)
    second = EvidenceManager(campaign).attach_file(other.finding_id, source, actor='other', reason='review')
    assert first.evidence_id != second.evidence_id
    assert len(list((campaign.evidence_dir / 'managed-v1' / 'objects').glob('*.blob'))) == 1
    with pytest.raises(ValueError, match='conflict'):
        EvidenceManager(campaign).attach_file(finding.finding_id, source, actor='changed', reason='review')


@pytest.mark.parametrize('failure', ['missing', 'corrupt', 'metadata'])
def test_corrupt_or_missing_evidence_fails_without_repair(setup, failure):
    campaign, _, _ = setup
    record = attach(setup)
    root = campaign.evidence_dir / 'managed-v1'
    blob = root / 'objects' / (record.content_sha256 + '.blob')
    if failure == 'missing':
        blob.unlink()
    elif failure == 'corrupt':
        blob.write_bytes(b'corrupt')
    else:
        (root / 'records' / (record.evidence_id + '.json')).write_text('{')
    before = {str(p): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    with pytest.raises(StorageIntegrityError):
        EvidenceReader(campaign).get(record.evidence_id)
    assert {str(p): p.read_bytes() for p in root.rglob('*') if p.is_file()} == before


@pytest.mark.parametrize('limit', ['object', 'assessment'])
def test_limits_fail_without_record(setup, limit):
    campaign, _, source = setup
    size = len(source.read_bytes())
    limits = EvidenceLimits(max_object_bytes=size-1, max_assessment_bytes=size) if limit == 'object' else EvidenceLimits(max_object_bytes=size, max_assessment_bytes=size)
    manager = EvidenceManager(campaign, limits=limits)
    if limit == 'assessment':
        manager.attach_file('a' * 64, source, actor='operator', reason='review')
        source.write_bytes(b'x' * size)
    with pytest.raises(ValueError, match='limit'):
        manager.attach_file('a' * 64, source, actor='operator', reason='review')
    expected = 0 if limit == 'object' else 1
    assert len(EvidenceReader(campaign).list_for_finding('a' * 64)) == expected


@pytest.mark.parametrize('phase', ['object', 'record', 'fsync'])
def test_publication_failure_preserves_orphans_and_temporaries(setup, monkeypatch, phase):
    campaign, _, _ = setup
    original = os.link
    def link(src, dst, *args, **kwargs):
        if (phase == 'object' and str(dst).endswith('.blob')) or (phase == 'record' and str(dst).endswith('.json')):
            raise OSError('injected publication failure')
        return original(src, dst, *args, **kwargs)
    if phase == 'fsync':
        monkeypatch.setattr(os, 'fsync', lambda *args: (_ for _ in ()).throw(OSError('injected fsync failure')))
    else:
        monkeypatch.setattr(os, 'link', link)
    with pytest.raises(OSError):
        attach(setup)
    assert EvidenceReader(campaign).list_for_finding('a' * 64) == []
    root = campaign.evidence_dir / 'managed-v1'
    assert list((root / 'staging').iterdir())
    if phase == 'record':
        assert list((root / 'objects').glob('*.blob'))


@pytest.mark.parametrize('field,value', [('finding_id', '../bad'), ('finding_id', 'f' * 64),
    ('actor', ''), ('reason', ' ')])
def test_bad_association_does_not_publish(setup, field, value):
    campaign, _, source = setup
    values = dict(finding_id='a' * 64, actor='operator', reason='review'); values[field] = value
    with pytest.raises((ValueError, LookupError)):
        EvidenceManager(campaign).attach_file(path=source, **values)
    assert not campaign.evidence_dir.exists()


def test_private_permissions_for_managed_storage(setup):
    if os.name != 'posix':
        return  # Windows access control is external; no POSIX permission claim.
    record = attach(setup)
    root = setup[0].evidence_dir / 'managed-v1'
    for path in root.rglob('*'):
        if path.name.startswith('.aegis-lock.sqlite'):
            continue
        assert path.stat().st_mode & 0o077 == 0


def test_storage_enumeration_permission_error_is_not_empty(setup, monkeypatch):
    campaign, _, _ = setup; attach(setup)
    original = os.scandir
    def scan(path):
        if Path(path).name == 'records':
            raise PermissionError('denied records enumeration')
        return original(path)
    monkeypatch.setattr(os, 'scandir', scan)
    with pytest.raises(StorageIntegrityError):
        EvidenceReader(campaign).list_for_finding('a' * 64)


def test_external_reference_is_not_verified_content(setup):
    campaign, _, _ = setup
    record = EvidenceManager(campaign).attach_reference('a' * 64, 'https://example.test/report', actor='operator', reason='review')
    assert EvidenceReader(campaign).verify(record.evidence_id)['status'] == 'reference_only'
    assert not list((campaign.evidence_dir / 'managed-v1' / 'objects').glob('*.blob'))
