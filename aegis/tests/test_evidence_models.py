from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from aegis.evidence_models import EvidenceLimits, EvidenceRecord, ExternalOrigin, LocalOrigin


def payload():
    return dict(evidence_id='a' * 32, finding_id='b' * 64, kind='local_file',
                origin=LocalOrigin(kind='local_file', source_name='capture.bin'),
                registered_at=datetime.now(timezone.utc), actor='operator', reason='review',
                content_sha256='c' * 64, content_size=3, representation='raw-v1',
                source_integrity='unknown', deduplication_key='d' * 64)


def test_record_is_immutable_and_roundtrips():
    record = EvidenceRecord(**payload())
    assert EvidenceRecord.model_validate_json(record.model_dump_json()) == record
    with pytest.raises(ValidationError):
        record.actor = 'changed'


@pytest.mark.parametrize('field,value', [('finding_id', '../file'), ('evidence_id', 'x'),
    ('actor', ' '), ('reason', ''), ('content_size', -1), ('content_size', True),
    ('registered_at', datetime(2026, 1, 1)), ('content_sha256', 'z' * 64),
    ('schema_version', True), ('source_integrity', 'original')])
def test_invalid_record_fields(field, value):
    data = payload(); data[field] = value
    with pytest.raises(ValidationError):
        EvidenceRecord(**data)


@pytest.mark.parametrize('locator', ['https://user:password@example.test/a',
    'https://example.test/?token=secret', 'file:///etc/passwd', 'https://example.test/#secret',
    'https://example.test/\nsecret'])
def test_external_origin_rejects_sensitive_or_unsafe_locators(locator):
    with pytest.raises(ValidationError):
        ExternalOrigin(kind='external_reference', locator=locator)


def test_external_origin_is_declarative():
    data = payload()
    data.update(kind='external_reference', origin=ExternalOrigin(kind='external_reference',
        locator='https://example.test/public'), content_sha256=None, content_size=None,
        representation='reference-v1')
    assert EvidenceRecord(**data).content_sha256 is None
    data['content_sha256'] = 'c' * 64
    with pytest.raises(ValidationError):
        EvidenceRecord(**data)


@pytest.mark.parametrize('name', ['/tmp/a', '..', r'C:\secret', 'dir/a'])
def test_origin_names_are_not_paths(name):
    with pytest.raises(ValidationError):
        LocalOrigin(kind='local_file', source_name=name)


def test_limits_are_strict_and_configurable():
    assert EvidenceLimits().max_object_bytes == 50 * 1024**2
    assert EvidenceLimits().max_assessment_bytes == 1024**3
    with pytest.raises(ValidationError):
        EvidenceLimits(max_object_bytes=20, max_assessment_bytes=10)
    with pytest.raises(ValidationError):
        EvidenceLimits(max_object_bytes=True)
