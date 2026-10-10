"""Explicit evidence associations, without modifying findings or triage."""

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import yaml

from aegis.atomic_storage import StorageIntegrityError, directory_lock
from aegis.evidence_models import EvidenceLimits, EvidenceRecord, ExternalOrigin, LocalOrigin
from aegis.evidence_store import EvidenceStore, association_key, read_regular
from aegis.finding_snapshot import require_finding


class EvidenceManager:
    def __init__(self, campaign, *, limits=None):
        self.campaign = campaign
        self.store = EvidenceStore(campaign)
        self.limits = limits

    def _limits(self):
        if self.limits is not None:
            return EvidenceLimits.model_validate(self.limits)
        try:
            data = yaml.safe_load(self.campaign.config_file.read_text(encoding='utf-8'))
            return EvidenceLimits.model_validate(data.get('evidence', {}))
        except (ValueError, TypeError, AttributeError, yaml.YAMLError, RecursionError) as error:
            raise StorageIntegrityError(f'Invalid evidence configuration: {error}') from error

    @staticmethod
    def _text(value, field):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f'{field} must be non-empty')
        return value.strip()

    def _attach(self, finding_id, origin, capture, actor, reason, observed_at, representation,
                source_integrity='unknown'):
        self.store._identifier(finding_id, 64)
        actor = self._text(actor, 'actor'); reason = self._text(reason, 'reason')
        with directory_lock(self.campaign.findings_dir, create=False):
            require_finding(self.campaign, finding_id)
            limits = self._limits()
            content = capture(limits) if capture else None
            digest = hashlib.sha256(content).hexdigest() if content is not None else None
            record = EvidenceRecord(evidence_id=uuid4().hex, finding_id=finding_id,
                kind=origin.kind, origin=origin, registered_at=datetime.now(timezone.utc),
                observed_at=observed_at, actor=actor, reason=reason,
                content_sha256=digest, content_size=len(content) if content is not None else None,
                representation=representation, source_integrity=source_integrity,
                deduplication_key=association_key(finding_id, origin.kind, origin, digest))
            self.store.initialize()
            with directory_lock(self.store.root):
                self.store._layout()
                records = self.store._records()
                for existing in records:
                    self.store._verify(existing)
                    if existing.deduplication_key == record.deduplication_key:
                        if (existing.actor, existing.reason, existing.observed_at) != (actor, reason, record.observed_at):
                            raise ValueError('Evidence association metadata conflict')
                        return existing
                used = self.store.physical_bytes()
                if used > limits.max_assessment_bytes:
                    raise ValueError('Assessment evidence storage limit exceeded')
                if content is not None:
                    path = self.store.objects / (digest + '.blob')
                    additional = 0 if path.exists() else len(content)
                    if used + additional > limits.max_assessment_bytes:
                        raise ValueError('Assessment evidence storage limit exceeded')
                    self.store.publish_object(digest, content)
                self.store.publish_record(record)
                return record

    def attach_file(self, finding_id, path, *, actor, reason, observed_at=None):
        path = Path(path)
        origin = LocalOrigin(kind='local_file', source_name=path.name)
        return self._attach(finding_id, origin,
            lambda limits: read_regular(path, limits.max_object_bytes)[0], actor, reason,
            observed_at, 'raw-v1')

    def attach_reference(self, finding_id, locator, *, actor, reason, observed_at=None):
        origin = ExternalOrigin(kind='external_reference', locator=locator)
        return self._attach(finding_id, origin, None, actor, reason, observed_at, 'reference-v1')
