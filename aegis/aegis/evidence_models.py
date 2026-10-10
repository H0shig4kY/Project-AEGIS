"""Versioned evidence metadata. Hashes check bytes, not origin authentication."""

import re
from datetime import datetime, timezone
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Digest = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$', strict=True)]
Identifier = Annotated[str, Field(pattern=r'^[0-9a-f]{32}$', strict=True)]


class ImmutableModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid')


class EvidenceLimits(ImmutableModel):
    max_object_bytes: int = Field(default=50 * 1024**2, gt=0, strict=True)
    max_assessment_bytes: int = Field(default=1024**3, gt=0, strict=True)

    @model_validator(mode='after')
    def ordered(self):
        if self.max_object_bytes > self.max_assessment_bytes:
            raise ValueError('Object limit must not exceed assessment limit')
        return self


def source_name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,255}', value) or '..' in value:
        raise ValueError('Source name must be a plain filename, not a path')
    return value


class LocalOrigin(ImmutableModel):
    kind: Literal['local_file']
    source_name: str
    _name = field_validator('source_name')(source_name)


class ObservationOrigin(ImmutableModel):
    kind: Literal['stored_observation']
    result_filename: str
    result_sha256: Digest
    result_id: Digest
    observation_id: Digest
    observation_index: int = Field(ge=0, strict=True)
    plugin: str
    plugin_version: str
    source_timestamp: str
    _name = field_validator('result_filename')(source_name)


class ExternalOrigin(ImmutableModel):
    kind: Literal['external_reference']
    locator: str = Field(max_length=2048)

    @field_validator('locator')
    @classmethod
    def public_locator(cls, value):
        if any(ord(c) < 33 for c in value) or '\\' in value:
            raise ValueError('Reference must not contain whitespace or control characters')
        parsed = urlsplit(value)
        if (parsed.scheme not in {'https', 'http'} or not parsed.hostname or
                parsed.username is not None or parsed.password is not None or
                parsed.query or parsed.fragment):
            raise ValueError('Use an HTTP(S) reference without credentials, query or fragment')
        return value


Origin = Annotated[LocalOrigin | ObservationOrigin | ExternalOrigin, Field(discriminator='kind')]


class EvidenceRecord(ImmutableModel):
    schema_version: Literal[1] = 1
    evidence_id: Identifier
    finding_id: Digest
    kind: Literal['local_file', 'stored_observation', 'external_reference']
    origin: Origin
    registered_at: datetime
    observed_at: datetime | None = None
    actor: str = Field(max_length=4096)
    reason: str = Field(max_length=4096)
    content_sha256: Digest | None = None
    content_size: int | None = Field(default=None, ge=0, strict=True)
    representation: Literal['raw-v1', 'observation-json-v1', 'reference-v1']
    source_integrity: Literal['original', 'retrospective', 'unknown']
    deduplication_key: Digest

    @field_validator('actor', 'reason')
    @classmethod
    def nonempty(cls, value):
        if not value.strip():
            raise ValueError('Actor and reason must be non-empty')
        return value.strip()

    @field_validator('registered_at', 'observed_at')
    @classmethod
    def utc(cls, value):
        if value is None:
            return value
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError('Evidence timestamps must be timezone-aware')
        return value.astimezone(timezone.utc)

    @model_validator(mode='after')
    def coherent(self):
        if self.kind != self.origin.kind:
            raise ValueError('Evidence kind and origin must agree')
        expected = {'local_file': 'raw-v1', 'stored_observation': 'observation-json-v1',
                    'external_reference': 'reference-v1'}[self.kind]
        if self.representation != expected:
            raise ValueError('Unexpected evidence representation')
        if self.kind == 'external_reference':
            if self.content_sha256 is not None or self.content_size is not None:
                raise ValueError('External reference has no captured content')
        elif self.content_sha256 is None or self.content_size is None:
            raise ValueError('Captured evidence requires digest and size')
        return self
