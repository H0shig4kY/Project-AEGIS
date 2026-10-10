"""Explicit evidence associations, without modifying findings or triage."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import yaml

from aegis.atomic_storage import StorageIntegrityError, directory_lock
from aegis.evidence_models import (EvidenceLimits, EvidenceRecord, ExternalOrigin, LocalOrigin,
                                   ObservationOrigin, source_name)
from aegis.evidence_store import (EvidenceStore, _linklike, association_key, canonical,
                                  read_regular, validate_storage_path)
from aegis.validation_errors import validation_summary
from aegis.finding_snapshot import require_finding
from aegis.models import ResultIntegrityManifest
from aegis.provenance import build_observation_id, build_result_id
from aegis.results import PluginResult


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
            raise StorageIntegrityError(f'Invalid evidence configuration: {validation_summary(error)}') from error

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
            with directory_lock(self.campaign.path):
                limits = self._limits()
                content = capture(limits) if capture else None
                if content is not None and len(content) > limits.max_object_bytes:
                    raise ValueError('Evidence object size limit exceeded')
                digest = hashlib.sha256(content).hexdigest() if content is not None else None
                record = EvidenceRecord(evidence_id=uuid4().hex, finding_id=finding_id,
                    kind=origin.kind, origin=origin, registered_at=datetime.now(timezone.utc),
                    observed_at=observed_at, actor=actor, reason=reason,
                    content_sha256=digest, content_size=len(content) if content is not None else None,
                    representation=representation, source_integrity=source_integrity,
                    deduplication_key=association_key(finding_id, origin.kind, origin, digest))
                if len(canonical(record.model_dump(mode='json'))) > 65536:
                    raise ValueError('Evidence metadata size limit exceeded')
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
        def capture(limits):
            for parent in path.absolute().parents:
                if _linklike(parent.lstat()):
                    raise ValueError('Local source path must not contain symlinks or reparse points')
            return read_regular(path, limits.max_object_bytes)[0]
        return self._attach(finding_id, origin,
            capture, actor, reason,
            observed_at, 'raw-v1')

    def attach_reference(self, finding_id, locator, *, actor, reason, observed_at=None):
        origin = ExternalOrigin(kind='external_reference', locator=locator)
        return self._attach(finding_id, origin, None, actor, reason, observed_at, 'reference-v1')

    def attach_observation(self, finding_id, result_filename, observation_index, *, actor, reason):
        source_name(result_filename)
        if not result_filename.endswith('.json') or type(observation_index) is not int or observation_index < 0:
            raise ValueError('Select a JSON result and a non-negative observation index')
        results = self.campaign.data_dir / 'results'
        integrity = self.campaign.data_dir / 'integrity'
        self.store._identifier(finding_id, 64)
        validate_storage_path(results / result_filename, self.campaign.path, regular=True)
        validate_storage_path(integrity / 'results-manifest.json', self.campaign.path,
                              regular=True, optional=True)
        with directory_lock(self.campaign.findings_dir, create=False):
            require_finding(self.campaign, finding_id)
            # Existing results/manifest are read without constructing mutable stores.
            with directory_lock(integrity, create=False), directory_lock(results, create=False):
                try:
                    validate_storage_path(results / result_filename, self.campaign.path, regular=True)
                    validate_storage_path(integrity / 'results-manifest.json', self.campaign.path,
                                          regular=True, optional=True)
                    raw, digest, _ = read_regular(results / result_filename, self._limits().max_object_bytes)
                    payload = json.loads(raw)
                    result = PluginResult.model_validate(payload)
                    if observation_index >= len(result.observations):
                        raise ValueError('Observation index is outside the stored result')
                    baseline = 'unknown'
                    manifest_path = integrity / 'results-manifest.json'
                    try:
                        manifest_raw, _, _ = read_regular(manifest_path, 16 * 1024**2)
                    except FileNotFoundError:
                        manifest_raw = None
                    if manifest_raw is not None:
                        manifest = ResultIntegrityManifest.model_validate_json(manifest_raw)
                        matches = [r for r in manifest.results if r.filename == result_filename]
                        if len(matches) > 1:
                            raise ValueError('Conflicting result integrity records')
                        if matches:
                            if matches[0].sha256 != digest:
                                raise ValueError('Stored result differs from its integrity baseline')
                            baseline = matches[0].baseline_type.value
                    observation = result.observations[observation_index]
                    origin = ObservationOrigin(kind='stored_observation', result_filename=result_filename,
                        result_sha256=digest, result_id=build_result_id(result),
                        observation_id=build_observation_id(result.plugin, observation),
                        observation_index=observation_index, plugin=result.plugin,
                        plugin_version=result.version, source_timestamp=payload['timestamp'])
                    content = canonical({'schema_version': 1,
                        'origin': origin.model_dump(mode='json'),
                        'observation': payload['observations'][observation_index]})
                    observed_at = result.timestamp if result.timestamp.tzinfo is not None else None
                except (OSError, ValueError, KeyError, TypeError, RecursionError, OverflowError) as error:
                    raise StorageIntegrityError(f'Cannot capture stored observation: {validation_summary(error)}') from error
                # Reentrant finding lock; source locks stay held until the commit marker.
                return self._attach(finding_id, origin, lambda limits: content, actor, reason,
                                    observed_at, 'observation-json-v1', baseline)
