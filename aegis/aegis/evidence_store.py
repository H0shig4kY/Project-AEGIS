"""Immutable evidence publication. Records are commit markers; reads never repair."""

import hashlib
import json
import os
import re
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path

from aegis.atomic_storage import StorageIntegrityError, directory_lock, sync_directory
from aegis.evidence_models import EvidenceRecord, ObservationOrigin
from aegis.provenance import build_observation_id
from aegis.results import Observation
from aegis.validation_errors import validation_summary


def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _unique_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate observation snapshot member')
        result[key] = value
    return result


def _invalid_constant(_value):
    raise ValueError('Nonfinite observation snapshot value')


def association_key(finding_id, kind, origin, content_sha256):
    return hashlib.sha256(b'AEGIS-evidence-association-v1\0' + canonical({
        'finding_id': finding_id, 'kind': kind, 'origin': origin.model_dump(mode='json'),
        'content_sha256': content_sha256})).hexdigest()


def _linklike(info):
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, 'st_file_attributes', 0) & 0x400)


def _identity(info):
    return info.st_dev, info.st_ino


def validate_storage_path(path, root, *, regular=False, optional=False):
    """Check lexical assessment components before resolution; no hostile-race claim."""
    path, root = Path(path), Path(root)
    components = [root]
    for part in path.relative_to(root).parts:
        components.append(components[-1] / part)
    for current in components:
        try:
            info = current.lstat()
        except FileNotFoundError:
            if optional:
                return
            raise ValueError('Observation source path does not exist') from None
        if _linklike(info):
            raise ValueError('Observation storage path contains a symlink or reparse point')
        expected = stat.S_ISREG if regular and current == path else stat.S_ISDIR
        if not expected(info.st_mode):
            raise ValueError('Invalid observation storage path type')


def read_regular(path, limit, *, content=True):
    """Read one stable regular file; reject links/reparse points and observable races."""
    path = Path(path)
    before = path.lstat()
    if _linklike(before) or not stat.S_ISREG(before.st_mode):
        raise ValueError(f'Expected a regular file without symlinks: {path.name}')
    if before.st_size > limit:
        raise ValueError('Evidence object size limit exceeded')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _identity(opened) != _identity(before):
            raise StorageIntegrityError(f'Source changed while opening: {path.name}')
        digest = hashlib.sha256()
        data = bytearray() if content else None
        size = 0
        while chunk := os.read(descriptor, min(65536, limit - size + 1)):
            size += len(chunk)
            if size > limit:
                raise ValueError('Evidence object size limit exceeded')
            digest.update(chunk)
            if content:
                data.extend(chunk)
        after = os.fstat(descriptor)
        current = path.lstat()
        if (_identity(current) != _identity(opened) or _linklike(current) or
                (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) !=
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns) or size != after.st_size):
            raise StorageIntegrityError(f'Source changed during capture: {path.name}')
        return bytes(data) if content else None, digest.hexdigest(), size
    finally:
        os.close(descriptor)


def _scan(directory):
    try:
        try:
            scan = os.scandir(directory)
        except FileNotFoundError:
            try:
                directory.lstat()
            except FileNotFoundError:
                return []
            raise
        with scan:
            return sorted(directory / entry.name for entry in scan)
    except OSError as error:
        raise StorageIntegrityError(f'Cannot enumerate evidence storage: {error}') from error


class EvidenceReader:
    def __init__(self, campaign):
        self.campaign = campaign
        self.root = campaign.evidence_dir / 'managed-v1'
        self.objects = self.root / 'objects'
        self.records_dir = self.root / 'records'
        self.staging = self.root / 'staging'

    def _layout(self):
        try:
            self.root.lstat()
            initialized = True
        except FileNotFoundError:
            initialized = False
        for path in (self.campaign.evidence_dir, self.root, self.objects, self.records_dir, self.staging):
            try:
                info = path.lstat()
            except FileNotFoundError:
                if initialized and path in (self.objects, self.records_dir, self.staging):
                    raise StorageIntegrityError(f'Evidence storage is incomplete: {path.name}')
                continue
            if _linklike(info) or not stat.S_ISDIR(info.st_mode):
                raise StorageIntegrityError(f'Invalid evidence storage directory: {path.name}')
            if path != self.campaign.evidence_dir and os.name == 'posix' and info.st_mode & 0o077:
                raise StorageIntegrityError(f'Evidence storage requires private permissions: {path.name}')

    @contextmanager
    def locked(self):
        self._layout()
        with directory_lock(self.root, create=False):
            self._layout()
            yield

    @staticmethod
    def _identifier(value, length):
        if not isinstance(value, str) or not re.fullmatch(f'[0-9a-f]{{{length}}}', value):
            raise ValueError('Invalid complete lowercase evidence/finding identifier')

    def _record(self, path):
        try:
            self._identifier(path.stem, 32)
            raw, _, _ = read_regular(path, 65536)
            record = EvidenceRecord.model_validate_json(raw)
            if record.evidence_id != path.stem or record.deduplication_key != association_key(
                    record.finding_id, record.kind, record.origin, record.content_sha256):
                raise ValueError('Record identity or association key mismatch')
            return record
        except (OSError, ValueError, RecursionError, OverflowError) as error:
            raise StorageIntegrityError(f'Invalid evidence record: {validation_summary(error)}') from error

    def _verify(self, record):
        if record.content_sha256 is None:
            return {'evidence_id': record.evidence_id, 'status': 'reference_only'}
        try:
            snapshot_bytes, digest, size = read_regular(self.objects / (record.content_sha256 + '.blob'),
                record.content_size, content=record.representation == 'observation-json-v1')
            if digest != record.content_sha256 or size != record.content_size:
                raise ValueError('Evidence content digest or size mismatch')
            if record.representation == 'observation-json-v1':
                snapshot = json.loads(snapshot_bytes, object_pairs_hook=_unique_members,
                                      parse_constant=_invalid_constant)
                if (not isinstance(snapshot, dict) or
                        set(snapshot) != {'schema_version', 'origin', 'observation'} or
                        type(snapshot['schema_version']) is not int or snapshot['schema_version'] != 1):
                    raise ValueError('Invalid observation snapshot structure')
                origin = ObservationOrigin.model_validate(snapshot['origin'])
                observation = Observation.model_validate(snapshot['observation'])
                if origin != record.origin or build_observation_id(origin.plugin, observation) != origin.observation_id:
                    raise ValueError('Observation snapshot provenance contradicts association')
        except (OSError, ValueError, TypeError, RecursionError, OverflowError) as error:
            raise StorageIntegrityError(f'Invalid evidence object for {record.evidence_id}: {validation_summary(error)}') from error
        return {'evidence_id': record.evidence_id, 'status': 'verified',
                'content_sha256': digest, 'content_size': size}

    def _records(self):
        records = []
        keys = set()
        for path in _scan(self.records_dir):
            if path.suffix != '.json':
                raise StorageIntegrityError(f'Unexpected evidence record path: {path.name}')
            record = self._record(path)
            if record.deduplication_key in keys:
                raise StorageIntegrityError('Duplicate evidence association')
            keys.add(record.deduplication_key)
            records.append(record)
        return sorted(records, key=lambda r: (r.registered_at, r.evidence_id))

    def all_verified(self):
        with self.locked():
            return [(record, self._verify(record)) for record in self._records()]

    def get(self, evidence_id):
        self._identifier(evidence_id, 32)
        with self.locked():
            records = self._records()
            for record in records:
                if record.evidence_id == evidence_id:
                    self._verify(record)
                    return record
        raise LookupError(f'Evidence not found: {evidence_id}')

    def list_for_finding(self, finding_id):
        self._identifier(finding_id, 64)
        return [record for record, _ in self.all_verified() if record.finding_id == finding_id]

    def verify(self, evidence_id):
        record = self.get(evidence_id)
        with self.locked():
            return self._verify(record)


class EvidenceStore(EvidenceReader):
    def initialize(self):
        self._layout()
        for path in (self.campaign.evidence_dir, self.root, self.objects, self.records_dir, self.staging):
            path.mkdir(mode=0o700, exist_ok=True)
        self._layout()

    def physical_bytes(self):
        """Count all physical content, including orphans and abandoned staging."""
        total = 0
        seen = set()
        for directory in (self.objects, self.staging):
            for path in _scan(directory):
                info = path.lstat()
                if _linklike(info) or not stat.S_ISREG(info.st_mode):
                    raise StorageIntegrityError(f'Invalid content storage entry: {path.name}')
                if info.st_ino == 0:
                    raise StorageIntegrityError('Cannot establish physical object identity for quota accounting')
                if directory == self.staging and path.name.startswith('metadata-'):
                    continue  # Quota concerns physical content, not JSON metadata.
                if directory == self.objects:
                    if not re.fullmatch(r'[0-9a-f]{64}\.blob', path.name):
                        raise StorageIntegrityError(f'Invalid object name: {path.name}')
                    _, digest, _ = read_regular(path, info.st_size, content=False)
                    if digest != path.stem:
                        raise StorageIntegrityError(f'Corrupt stored object: {path.name}')
                identity = _identity(info)
                if identity not in seen:
                    total += info.st_size
                    seen.add(identity)
        return total

    def _publish(self, destination, content):
        self._layout()
        prefix = 'object-' if destination.suffix == '.blob' else 'metadata-'
        descriptor, temporary = tempfile.mkstemp(prefix=prefix, suffix='.tmp', dir=self.staging)
        try:
            stream = os.fdopen(descriptor, 'wb')
        except BaseException:
            os.close(descriptor)
            raise
        # Failed staging files are deliberately preserved for inspection.
        with stream:
            if stream.write(content) != len(content):
                raise OSError('Incomplete evidence staging write')
            stream.flush()
            os.fsync(stream.fileno())
        self._layout()
        os.link(temporary, destination)
        sync_directory(destination.parent)
        os.unlink(temporary)
        sync_directory(self.staging)

    def publish_object(self, digest, content):
        destination = self.objects / (digest + '.blob')
        try:
            destination.lstat()
        except FileNotFoundError:
            self._publish(destination, content)
        _, existing, size = read_regular(destination, len(content), content=False)
        if existing != digest or size != len(content):
            raise StorageIntegrityError('Existing evidence object conflicts with captured content')

    def publish_record(self, record):
        self._publish(self.records_dir / (record.evidence_id + '.json'),
                      canonical(record.model_dump(mode='json')))
