import json
from datetime import datetime, timezone

import pytest

from aegis.atomic_storage import StorageIntegrityError
from aegis.evidence_manager import EvidenceManager
from aegis.evidence_store import EvidenceReader
from aegis.integrity import sha256_file
from aegis.integrity_store import IntegrityStore
from aegis.models import IntegrityBaselineType
from aegis.result_store import ResultStore
from aegis.results import Observation, PluginResult
from test_evidence_store import setup, domain_snapshot


def result(campaign):
    value = PluginResult(plugin='dns', version='1', observations=[
        Observation(type='dns', target='example.test', data={'secret': '<script>data</script>'})])
    return ResultStore(campaign.data_dir / 'results').save(value)


@pytest.mark.parametrize('baseline', ['original', 'retrospective', 'unknown'])
def test_observation_snapshot_preserves_sources_and_baseline(setup, baseline):
    campaign, _, _ = setup
    path = result(campaign)
    if baseline != 'unknown':
        IntegrityStore(campaign.data_dir / 'integrity').upsert(path.name, sha256_file(path),
            IntegrityBaselineType(baseline), datetime.now(timezone.utc))
    before = domain_snapshot(campaign)
    manager = EvidenceManager(campaign)
    record = manager.attach_observation('a' * 64, path.name, 0, actor='operator', reason='review')
    assert record.kind == 'stored_observation' and record.source_integrity == baseline
    assert record.origin.result_sha256 == sha256_file(path)
    assert manager.attach_observation('a' * 64, path.name, 0, actor='operator', reason='review') == record
    assert domain_snapshot(campaign) == before
    path.unlink()
    assert EvidenceReader(campaign).verify(record.evidence_id)['status'] == 'verified'


def test_tampered_result_cannot_be_snapshotted(setup):
    campaign, _, _ = setup; path = result(campaign)
    IntegrityStore(campaign.data_dir / 'integrity').upsert(path.name, sha256_file(path),
        IntegrityBaselineType.ORIGINAL, datetime.now(timezone.utc))
    data = json.loads(path.read_text()); data['observations'][0]['data'] = {'changed': True}
    path.write_text(json.dumps(data))
    with pytest.raises(StorageIntegrityError):
        EvidenceManager(campaign).attach_observation('a' * 64, path.name, 0, actor='operator', reason='review')
    assert not campaign.evidence_dir.exists()


@pytest.mark.parametrize('filename,index', [('../result.json', 0), ('result.json', -1), ('result.json', True)])
def test_invalid_selection(setup, filename, index):
    campaign, _, _ = setup
    with pytest.raises(ValueError):
        EvidenceManager(campaign).attach_observation('a' * 64, filename, index, actor='operator', reason='review')
    assert not campaign.evidence_dir.exists()


def test_equal_observations_in_distinct_occurrences_are_not_collapsed(setup):
    campaign, _, _ = setup
    observation = Observation(type='dns', target='example.test', data={'value': 1})
    path = ResultStore(campaign.data_dir / 'results').save(PluginResult(plugin='dns', version='1',
        observations=[observation, observation]))
    manager = EvidenceManager(campaign)
    first = manager.attach_observation('a' * 64, path.name, 0, actor='operator', reason='review')
    second = manager.attach_observation('a' * 64, path.name, 1, actor='operator', reason='review')
    assert first.origin.observation_id == second.origin.observation_id
    assert first.evidence_id != second.evidence_id
