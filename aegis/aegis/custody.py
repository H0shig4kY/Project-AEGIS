"""Explicit cooperative custody, not identity authentication or trusted time.

Lock order: findings -> assessment -> managed evidence -> custody. Readers of
custody only acquire the last two and never acquire an earlier lock afterwards.
"""
import hashlib
import json
import os
import re
import stat
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from aegis.atomic_storage import StorageIntegrityError, directory_lock, sync_directory, _local
from aegis.evidence_models import EvidenceRecord
from aegis.evidence_store import (EvidenceReader, EvidenceStore, canonical, read_regular,
                                  validate_storage_path, association_key, _unique_members, _invalid_constant, _finite_float)

MIB = 1024 ** 2
MAX_METADATA = 256 * MIB


def fail():
    raise StorageIntegrityError('Custody integrity failure; inspect storage or recover explicitly')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def strict_json(raw):
    try:
        return json.loads(raw, object_pairs_hook=_unique_members,
                          parse_constant=_invalid_constant, parse_float=_finite_float)
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise StorageIntegrityError('Invalid strict JSON data') from None


def read(path, limit):
    try:
        return read_regular(path, limit)[0]
    except (OSError, ValueError, RecursionError):
        raise StorageIntegrityError('Cannot read custody or export source') from None


def scan(path):
    try:
        with os.scandir(path) as entries:
            return sorted(path / entry.name for entry in entries)
    except OSError:
        raise StorageIntegrityError('Cannot enumerate custody or export source') from None


def publish(path, raw):
    """Exclusive full-file publication; retain unsuccessful temporary files."""
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    else:
        if read(path, len(raw)) != raw:
            fail()
        return
    fd, temporary = tempfile.mkstemp(prefix='.publication-', suffix='.tmp', dir=path.parent)
    with os.fdopen(fd, 'wb') as stream:
        if stream.write(raw) != len(raw):
            raise OSError('Incomplete custody publication')
        stream.flush()
        os.fsync(stream.fileno())
    os.link(temporary, path)
    sync_directory(path.parent)
    os.unlink(temporary)
    sync_directory(path.parent)


def bounded(raw, limit):
    if len(raw) > limit:
        raise StorageIntegrityError('Custody metadata limit exceeded')
    return raw


def identifier(value, length=32):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{%d}' % length, value):
        fail()


def event_hash(event):
    return digest(b'AEGIS-custody-event-v1\0' + canonical({k: v for k, v in event.items() if k != 'event_sha256'}))


def event_for(chain_id, sequence, previous, operation, actor, reason, record=None):
    event = dict(schema_version=1, chain_id=chain_id, sequence=sequence,
        event_id=uuid4().hex, operation_id=operation,
        event_type='evidence_attached' if record else 'custody_initialized',
        recorded_at=utc_now(), actor_declared=actor, reason=reason,
        evidence_id=record.evidence_id if record else None,
        finding_id=record.finding_id if record else None,
        association_sha256=digest(canonical(record.model_dump(mode='json'))) if record else None,
        content_sha256=record.content_sha256 if record else None,
        content_size=record.content_size if record else None,
        previous_event_sha256=previous)
    event['event_sha256'] = event_hash(event)
    bounded(canonical(event), 65536)
    return event


def validate_event(event, sequence, chain, previous):
    keys = {'schema_version','chain_id','sequence','event_id','operation_id','event_type',
            'recorded_at','actor_declared','reason','evidence_id','finding_id','association_sha256',
            'content_sha256','content_size','previous_event_sha256','event_sha256'}
    if not isinstance(event, dict) or set(event) != keys:
        fail()
    for key in ('event_id', 'operation_id', 'chain_id'):
        identifier(event[key])
    if (type(event['schema_version']) is not int or event['schema_version'] != 1 or
            type(event['sequence']) is not int or event['sequence'] != sequence or
            event['chain_id'] != chain or event['previous_event_sha256'] != previous or
            event['event_sha256'] != event_hash(event)):
        fail()
    for key in ('actor_declared', 'reason'):
        if not isinstance(event[key], str) or not event[key].strip() or len(event[key]) > 4096:
            fail()
    try:
        timestamp = datetime.fromisoformat(event['recorded_at'])
        if timestamp.utcoffset() is None or timestamp.utcoffset().total_seconds() != 0:
            fail()
    except (ValueError, TypeError, OverflowError):
        fail()
    expected = 'custody_initialized' if sequence == 1 else 'evidence_attached'
    if event['event_type'] != expected:
        fail()
    if sequence == 1:
        if any(event[k] is not None for k in ('evidence_id','finding_id','association_sha256','content_sha256','content_size')):
            fail()
    else:
        identifier(event['evidence_id']); identifier(event['finding_id'], 64)
        identifier(event['association_sha256'], 64)
        if event['content_sha256'] is not None:
            identifier(event['content_sha256'], 64)
            if type(event['content_size']) is not int or event['content_size'] < 0:
                fail()
        elif event['content_size'] is not None:
            fail()


class CustodyReader:
    def __init__(self, campaign):
        self.campaign = campaign
        self.root = campaign.evidence_dir / 'custody-v1'

    def exists(self):
        try:
            self.root.lstat()
        except FileNotFoundError:
            return False
        validate_storage_path(self.root, self.campaign.path)
        if os.name == 'posix' and self.root.stat().st_mode & 0o077:
            fail()
        return True

    @contextmanager
    def locked(self):
        # Only acquire evidence -> custody here; never an earlier lock.
        reader = EvidenceReader(self.campaign)
        reader._layout()
        with directory_lock(reader.root, create=False):
            if self.exists():
                for name in ('events','intents','completions','staging'):
                    validate_storage_path(self.root / name, self.campaign.path)
                with directory_lock(self.root, create=False):
                    yield
            else:
                yield

    def _state(self, *, pending=False):
        if not self.exists():
            return None
        directories = {'events', 'intents', 'completions', 'staging'}
        for path in scan(self.root):
            if path.name in directories:
                validate_storage_path(path, self.campaign.path)
                if os.name == 'posix' and path.stat().st_mode & 0o077:
                    fail()
            else:
                temporary = path.name.startswith('.publication-') and path.suffix == '.tmp'
                lock_metadata = {'.aegis-lock.sqlite' + suffix for suffix in ('', '-journal', '-wal', '-shm')}
                if path.name not in {'genesis.json', 'baseline.json'} | lock_metadata and not temporary:
                    fail()
                validate_storage_path(path, self.campaign.path, regular=True)
        for directory in directories:
            for path in scan(self.root / directory):
                validate_storage_path(path, self.campaign.path, regular=True)
        intents = []
        processed = 0
        for path in scan(self.root / 'intents'):
            if path.name.startswith('.publication-') and path.suffix == '.tmp':
                continue
            if not re.fullmatch('[0-9a-f]{32}\\.json', path.name):
                fail()
            raw = read(path, 16 * MIB + 256 * 1024)
            processed += len(raw)
            if processed > MAX_METADATA:
                fail()
            value = strict_json(raw)
            if not isinstance(value, dict) or set(value) != {'schema_version','operation_id','event','record','genesis','baseline'}:
                fail()
            if type(value['schema_version']) is not int or value['schema_version'] != 1 or value['operation_id'] != path.stem:
                fail()
            intents.append((value, raw))
        if not intents:
            fail()
        intents.sort(key=lambda item: item[0]['event']['sequence'])
        first = intents[0][0]
        genesis, baseline = first['genesis'], first['baseline']
        if (not isinstance(genesis, dict) or set(genesis) != {'schema_version','chain_id','baseline_sha256'} or
                type(genesis['schema_version']) is not int or genesis['schema_version'] != 1 or
                not isinstance(baseline, dict) or genesis['baseline_sha256'] != digest(canonical(baseline))):
            fail()
        identifier(genesis['chain_id'])
        for evidence, sha in baseline.items():
            identifier(evidence); identifier(sha, 64)
        expected = dict(baseline)
        previous = None
        events, incomplete, anomalies = [], [], []
        event_names, completion_names = set(), set()
        for sequence, (intent, raw) in enumerate(intents, 1):
            event = intent['event']
            validate_event(event, sequence, genesis['chain_id'], previous)
            if intent['operation_id'] != event['operation_id']:
                fail()
            if sequence == 1:
                if intent['record'] is not None:
                    fail()
            else:
                if intent['genesis'] is not None or intent['baseline'] is not None:
                    fail()
                try:
                    record = EvidenceRecord.model_validate(intent['record'])
                except ValueError:
                    fail()
                if record.deduplication_key != association_key(record.finding_id, record.kind, record.origin, record.content_sha256):
                    fail()
                if (event['evidence_id'] != record.evidence_id or event['finding_id'] != record.finding_id or
                        event['content_sha256'] != record.content_sha256 or event['content_size'] != record.content_size or
                        event['actor_declared'] != record.actor or event['reason'] != record.reason or
                        event['association_sha256'] != digest(canonical(intent['record'])) or record.evidence_id in expected):
                    fail()
                expected[record.evidence_id] = event['association_sha256']
            name = '%020d-%s.json' % (sequence, event['event_id'])
            event_path = self.root / 'events' / name
            completion = self.root / 'completions' / (intent['operation_id'] + '.json')
            receipt = canonical(dict(schema_version=1, operation_id=intent['operation_id'],
                                     intent_sha256=digest(raw), event_sha256=event['event_sha256']))
            try:
                actual_receipt = read_regular(completion, 128 * 1024)[0]
            except FileNotFoundError:
                actual_receipt = None
            if actual_receipt is None:
                incomplete.append(intent)
                if not pending or sequence != len(intents):
                    fail()
            elif actual_receipt != receipt:
                fail()
            else:
                completion_names.add(completion.name)
            try:
                actual_event = read_regular(event_path, 65536)[0]
            except FileNotFoundError:
                actual_event = None
            if actual_event is not None:
                if actual_event != canonical(event):
                    fail()
                event_names.add(name)
            elif actual_receipt is not None:
                fail()
            events.append(event)
            if sequence > 1 and datetime.fromisoformat(event['recorded_at']) < datetime.fromisoformat(events[-2]['recorded_at']):
                anomalies.append(sequence)
            previous = event['event_sha256']
        for directory, names in [('events', event_names), ('completions', completion_names)]:
            actual = {p.name for p in scan(self.root / directory)
                      if not (p.name.startswith('.publication-') and p.suffix == '.tmp')}
            if actual != names:
                fail()
        for name, payload in [('genesis.json', genesis), ('baseline.json', baseline)]:
            try:
                raw = read_regular(self.root / name, 16 * MIB)[0]
            except FileNotFoundError:
                if pending and incomplete and len(intents) == 1:
                    continue
                fail()
            if raw != canonical(payload):
                fail()
        evidence = EvidenceReader(self.campaign)
        actual = {}
        for record in evidence._records():
            evidence._verify(record)
            raw = read(evidence.records_dir / (record.evidence_id + '.json'), 65536)
            actual[record.evidence_id] = digest(raw)
        missing = set(expected) - set(actual)
        allowed = {i['event']['evidence_id'] for i in incomplete if i['record'] is not None}
        if set(actual) - set(expected) or missing - allowed or any(actual[k] != expected[k] for k in actual):
            fail()
        return dict(genesis=genesis, baseline=baseline, events=events, incomplete=incomplete,
                    inventory=expected, temporal_anomalies=anomalies)

    def verify(self, expected_checkpoint=None):
        try:
            with self.locked():
                state = self._state()
                if state is None:
                    if expected_checkpoint is not None:
                        fail()
                    return dict(status='not_initialized', checkpoint=None, external_checkpoint_match=None,
                                temporal_anomalies=[])
                last = state['events'][-1]
                checkpoint = dict(chain_id=state['genesis']['chain_id'], sequence=last['sequence'],
                    head_event_sha256=last['event_sha256'], genesis_sha256=digest(canonical(state['genesis'])))
                if expected_checkpoint is not None and checkpoint != expected_checkpoint:
                    fail()
                return dict(status='chain_verified', checkpoint=checkpoint,
                    external_checkpoint_match=True if expected_checkpoint is not None else None,
                    temporal_anomalies=state['temporal_anomalies'])
        except (OSError, ValueError, KeyError, TypeError, RecursionError, OverflowError):
            raise StorageIntegrityError('Custody verification failed; no data was repaired') from None

    def list_events(self, evidence_id=None):
        if evidence_id is not None:
            identifier(evidence_id)
        with self.locked():
            state = self._state()
            return [e for e in state['events'] if evidence_id is None or e['evidence_id'] == evidence_id] if state else []

    def inventory(self):
        with self.locked():
            state = self._state()
            return state['inventory'] if state else {}


class CustodyManager(CustodyReader):
    @staticmethod
    def _text(value):
        if not isinstance(value, str) or not value.strip() or len(value) > 4096:
            raise ValueError('Custody actor and reason must be nonempty bounded text')
        return value.strip()

    @contextmanager
    def writing(self):
        evidence = EvidenceStore(self.campaign)
        with directory_lock(self.campaign.findings_dir, create=False), directory_lock(self.campaign.path):
            evidence.initialize()
            with directory_lock(evidence.root):
                yield evidence

    def _finish(self, intent, raw):
        event = intent['event']
        if intent['genesis'] is not None:
            publish(self.root / 'baseline.json', bounded(canonical(intent['baseline']), 16 * MIB))
            publish(self.root / 'genesis.json', bounded(canonical(intent['genesis']), 16 * MIB))
        if intent['record'] is not None:
            record = EvidenceRecord.model_validate(intent['record'])
            EvidenceReader(self.campaign)._verify(record)
            publish(self.campaign.evidence_dir / 'managed-v1' / 'records' / (record.evidence_id + '.json'),
                    bounded(canonical(intent['record']), 65536))
        name = '%020d-%s.json' % (event['sequence'], event['event_id'])
        publish(self.root / 'events' / name, bounded(canonical(event), 65536))
        publish(self.root / 'completions' / (intent['operation_id'] + '.json'),
                canonical(dict(schema_version=1, operation_id=intent['operation_id'],
                    intent_sha256=digest(raw), event_sha256=event['event_sha256'])))

    def _commit(self, intent):
        raw = bounded(canonical(intent), 16 * MIB + 256 * 1024)
        total = sum(p.stat().st_size for directory in ('intents','events','completions')
                    for p in scan(self.root / directory))
        if total + len(raw) + len(canonical(intent['event'])) + 1024 > MAX_METADATA:
            raise StorageIntegrityError('Custody metadata limit exceeded')
        publish(self.root / 'intents' / (intent['operation_id'] + '.json'), raw)
        self._finish(intent, raw)

    def initialize(self, *, actor, reason):
        with directory_lock(self.campaign.findings_dir, create=False):
            return self._initialize(actor=actor, reason=reason)

    def _initialize(self, *, actor, reason):
        actor, reason = self._text(actor), self._text(reason)
        # Validate using the established history-before-assessment lock order.
        from aegis.findings_report import build_report
        report = build_report(self.campaign)
        with self.writing() as evidence:
            if self.exists() and not self._blank_initialization():
                return self.verify()['checkpoint']
            # Validate legacy finding/history/journal relationships before activation.
            records = evidence._records()
            baseline = {}
            for record in records:
                if record.finding_id not in {item['record']['finding_id'] for item in report['findings']}:
                    fail()
                evidence._verify(record)
                baseline[record.evidence_id] = digest(read(evidence.records_dir / (record.evidence_id + '.json'), 65536))
            self.root.mkdir(mode=0o700, exist_ok=True)
            for name in ('events','intents','completions','staging'):
                (self.root / name).mkdir(mode=0o700, exist_ok=True)
            with directory_lock(self.root):
                chain, operation = uuid4().hex, uuid4().hex
                genesis = dict(schema_version=1, chain_id=chain, baseline_sha256=digest(canonical(baseline)))
                event = event_for(chain, 1, None, operation, actor, reason)
                self._commit(dict(schema_version=1, operation_id=operation, event=event,
                                  record=None, genesis=genesis, baseline=baseline))
                return self.verify()['checkpoint']

    def _blank_initialization(self):
        """Explicit init may retry before any intent was published; preserve temps."""
        for path in scan(self.root):
            if path.name in {'events', 'intents', 'completions', 'staging'}:
                validate_storage_path(path, self.campaign.path)
                for child in scan(path):
                    validate_storage_path(child, self.campaign.path, regular=True)
                    if child.suffix == '.json':
                        return False
                    if not (child.name.startswith('.publication-') and child.suffix == '.tmp'):
                        fail()
            else:
                validate_storage_path(path, self.campaign.path, regular=True)
                if path.name in {'genesis.json', 'baseline.json'}:
                    return False
                if not (path.name.startswith('.aegis-lock.sqlite') or
                        (path.name.startswith('.publication-') and path.suffix == '.tmp')):
                    fail()
        return True

    def commit_record(self, record):
        # Caller holds finding/assessment/evidence locks; new associations only.
        held = getattr(_local, 'locks', {}) if getattr(_local, 'pid', None) == os.getpid() else {}
        required = (self.campaign.findings_dir, self.campaign.path,
                    self.campaign.evidence_dir / 'managed-v1')
        if any(os.path.normcase(str(path.resolve())) not in held for path in required):
            raise StorageIntegrityError('Custody publication requires the evidence writer lock scope')
        with directory_lock(self.root, create=False):
            state = self._state()
            if state is None:
                fail()
            if record.evidence_id in state['inventory']:
                fail()
            last = state['events'][-1]
            operation = uuid4().hex
            event = event_for(state['genesis']['chain_id'], last['sequence'] + 1,
                              last['event_sha256'], operation, record.actor, record.reason, record)
            self._commit(dict(schema_version=1, operation_id=operation, event=event,
                              record=record.model_dump(mode='json'), genesis=None, baseline=None))

    def recover(self, *, actor, reason):
        self._text(actor); self._text(reason)
        # No creation or implicit recovery on an absent chain.
        if not self.exists():
            raise LookupError('Custody is not initialized')
        with directory_lock(self.campaign.findings_dir, create=False):
            with self.locked():
                preliminary = self._state(pending=True)
            from aegis.finding_snapshot import require_finding
            for intent in preliminary['incomplete']:
                if intent['record'] is not None:
                    require_finding(self.campaign, intent['record']['finding_id'])
            return self._recover_locked()

    def _recover_locked(self):
        with self.writing(), directory_lock(self.root):
            state = self._state(pending=True)
            from aegis.evidence_manager import EvidenceManager
            limits = EvidenceManager(self.campaign)._limits()
            store = EvidenceStore(self.campaign)
            if state['incomplete'] and store.physical_bytes() > limits.max_assessment_bytes:
                raise StorageIntegrityError('Recovery exceeds current assessment content limit')
            for intent in state['incomplete']:
                if intent['record'] is not None and intent['record']['content_size'] is not None and intent['record']['content_size'] > limits.max_object_bytes:
                    raise StorageIntegrityError('Recovery exceeds current object limit')
                raw = read(self.root / 'intents' / (intent['operation_id'] + '.json'), 16 * MIB + 256 * 1024)
                self._finish(intent, raw)
            return self.verify()
