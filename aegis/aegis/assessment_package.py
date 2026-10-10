"""Portable bounded packages. Verification never extracts, imports or fetches URLs."""
import hashlib
import json
import os
import re
import stat
import struct
import tempfile
import zipfile
from contextlib import ExitStack
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from pathlib import Path

from aegis.atomic_storage import StorageIntegrityError, directory_lock, sync_directory
from aegis.custody import (CustodyReader, canonical, digest, read, scan, strict_json,
                          validate_event, identifier, validate_baseline)
from aegis.evidence_models import EvidenceRecord, ObservationOrigin
from aegis.evidence_store import EvidenceReader, association_key, read_regular, validate_storage_path
from aegis.finding_store import FindingStore
from aegis.finding_history_store import FindingHistoryStore
from aegis.findings_report import build_report
from aegis.models import FindingState, FindingTriageState
from aegis.provenance import build_observation_id
from aegis.results import Observation
from aegis import triage_journal

MIB = 1024 ** 2
HEX = '[0-9a-f]{64}'
UUID = '[0-9a-f]{32}'
CATEGORIES = {
    'finding_projection': (r'projections/findings/' + HEX + r'\.json', 16*MIB),
    'evidence_projection': (r'projections/evidence/' + UUID + r'\.json', 65536),
    'finding': (r'findings/' + HEX + r'\.json', 16*MIB),
    'technical_history': (r'histories/technical/' + UUID + r'\.json', 16*MIB),
    'triage_history': (r'histories/triage/' + UUID + r'\.json', 16*MIB),
    'triage_receipt': (r'triage/receipts/' + UUID + r'\.json', 16*MIB),
    'evidence_record': (r'evidence/records/' + UUID + r'\.json', 65536),
    'evidence_object': (r'evidence/objects/' + HEX + r'\.blob', 50*MIB),
    'custody_genesis': (r'custody/genesis\.json', 16*MIB),
    'custody_baseline': (r'custody/baseline\.json', 16*MIB),
    'custody_event': (r'custody/events/[0-9]{20}-' + UUID + r'\.json', 65536),
    'custody_completion': (r'custody/completions/' + UUID + r'\.json', 128*1024),
}
SHARE = {'finding_projection','evidence_projection'}
EVIDENCE_FIELDS = {'projection_schema_version','evidence_id','finding_id','kind','representation',
                  'content_sha256','content_size','source_integrity','association_sha256','verification'}


@dataclass(frozen=True)
class PackageLimits:
    max_total_content_bytes: int = 2*1024**3
    max_members: int = 100000
    max_manifest_bytes: int = 16*MIB
    max_metadata_bytes: int = 256*MIB
    max_archive_bytes: int = 2*1024**3 + 256*MIB
    max_object_bytes: int = 50*MIB

    def __post_init__(self):
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or value <= 0:
                raise ValueError('Package limits must be positive integers')


def failure():
    raise StorageIntegrityError('Package verification failed: invalid structure, integrity or limits')


def bounded_json(raw, limit):
    if len(raw) > limit:
        failure()
    return strict_json(raw)


def checkpoint_for(genesis, event):
    return dict(chain_id=genesis['chain_id'], sequence=event['sequence'],
                head_event_sha256=event['event_sha256'], genesis_sha256=digest(canonical(genesis)))


def safe_package_source(path):
    path = Path(path).absolute()
    if '..' in path.parts:
        raise ValueError('Invalid package path')
    validate_storage_path(path, Path(path.anchor), regular=True)
    return path


def preflight(stream, limits):
    """Bound central-directory entry count before ZipFile allocates its inventory."""
    size = os.fstat(stream.fileno()).st_size
    if size > limits.max_archive_bytes or size < 22:
        failure()
    stream.seek(size - min(size, 65557))
    tail = stream.read(min(size, 65557))
    index = tail.rfind(b'PK\x05\x06')
    if index < 0 or index + 22 != len(tail):  # no archive comment or trailing data
        failure()
    eocd = struct.unpack('<4sHHHHLLH', tail[index:index+22])
    if eocd[1] or eocd[2] or eocd[7]:
        failure()
    absolute = size - len(tail) + index
    count, directory_size, offset = eocd[4], eocd[5], eocd[6]
    central_end = absolute
    locator = None
    if absolute >= 20:
        stream.seek(absolute - 20)
        candidate = stream.read(20)
        if candidate.startswith(b'PK\x06\x07'):
            locator = struct.unpack('<4sLQL', candidate)
    if locator is not None:
        if locator[1] or locator[3] != 1 or locator[2] + 56 != absolute - 20:
            failure()
        stream.seek(locator[2])
        record = struct.unpack('<4sQHHLLQQQQ', stream.read(56))
        if record[0] != b'PK\x06\x06' or record[1] != 44 or record[4] or record[5] or record[6] != record[7]:
            failure()
        for declared, actual, marker in ((eocd[3],record[6],65535),
                (count,record[7],65535),(directory_size,record[8],0xffffffff),
                (offset,record[9],0xffffffff)):
            if declared != marker and declared != actual:
                failure()
        count, directory_size, offset = record[7], record[8], record[9]
        central_end = locator[2]
    elif directory_size == 0xffffffff or offset == 0xffffffff or eocd[3] != count:
        # Exactly 65,535 entries can be a legitimate non-ZIP64 archive.
        # A missing locator is safe only when the actual bounded count matches.
        failure()
    if count > limits.max_members or directory_size > limits.max_members*512 or offset + directory_size != central_end:
        failure()
    # ZipFile ignores the advertised entry count when allocating ZipInfo objects.
    # Walk fixed-size central headers first, with O(1) additional memory and a
    # bounded number of reads. No inventory objects exist at this stage.
    stream.seek(offset)
    actual = 0
    while stream.tell() < central_end:
        if central_end - stream.tell() < 46:
            failure()
        header = struct.unpack('<4s6H3L5H2L', stream.read(46))
        actual += 1
        variable = header[10] + header[11] + header[12]
        if (header[0] != b'PK\x01\x02' or actual > limits.max_members or
                header[10] > 128 or variable > 466 or header[13] or
                stream.tell() + variable > central_end):
            failure()
        stream.seek(variable, 1)
    if actual != count:
        failure()
    stream.seek(0)


class AssessmentPackageReader:
    def __init__(self, *, limits=None):
        self.limits = limits or PackageLimits()

    def inspect(self, path):
        # Inspection validates the complete package; never suggests corrupt data is valid.
        return self._read(path)[0]

    def verify(self, path, *, expected_sha256=None, expected_checkpoint=None):
        try:
            manifest, documents, object_hashes, archive_sha256 = self._read(path)
            result = self._semantics(manifest, documents, object_hashes)
            if expected_sha256 is not None:
                identifier(expected_sha256, 64)
                if archive_sha256 != expected_sha256:
                    failure()
            if expected_checkpoint is not None:
                if result['custody']['checkpoint'] != expected_checkpoint:
                    failure()
                result['custody']['external_checkpoint_match'] = True
            return result
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError,
                OverflowError, struct.error, zipfile.BadZipFile, NotImplementedError):
            failure()

    def _read(self, path):
        try:
            path = safe_package_source(path)
            before = path.lstat()
            flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
            with os.fdopen(os.open(path, flags), 'rb') as stream:
                opened = os.fstat(stream.fileno())
                if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    failure()
                preflight(stream, self.limits)
                with zipfile.ZipFile(stream) as archive:
                    infos = archive.infolist()
                    if len(infos) > self.limits.max_members or not infos or min(i.header_offset for i in infos) != 0:
                        failure()
                    names, total, metadata = set(), 0, 0
                    for info in infos:
                        name = info.filename
                        mode = stat.S_IFMT(info.external_attr >> 16)
                        if (not name.isascii() or len(name) > 128 or name.casefold() in names or
                                '\\' in name or ':' in name or any(ord(c) < 32 for c in name) or
                                name.startswith('/') or '..' in name.split('/') or info.is_dir() or
                                info.compress_type != zipfile.ZIP_STORED or info.flag_bits & ~0x808 or
                                mode not in (0, stat.S_IFREG) or info.compress_size != info.file_size):
                            failure()
                        names.add(name.casefold())
                        total += info.file_size
                    if total > self.limits.max_total_content_bytes or 'manifest.json' not in names:
                        failure()
                    manifest_info = archive.getinfo('manifest.json')
                    manifest = bounded_json(self._bytes(archive, manifest_info, self.limits.max_manifest_bytes),
                                            self.limits.max_manifest_bytes)
                    self._manifest(manifest)
                    inventory = {m['path']:m for m in manifest['members']}
                    if len(inventory) != len(manifest['members']) or set(inventory) | {'manifest.json'} != {i.filename for i in infos}:
                        failure()
                    documents, object_hashes = {}, {}
                    metadata = manifest_info.file_size
                    for info in infos:
                        if info.filename == 'manifest.json':
                            continue
                        member = inventory[info.filename]
                        category = member['category']
                        pattern, limit = CATEGORIES[category]
                        if not re.fullmatch(pattern, info.filename) or info.file_size != member['size']:
                            failure()
                        if category == 'evidence_object':
                            limit = self.limits.max_object_bytes
                        else:
                            metadata += info.file_size
                            if metadata > self.limits.max_metadata_bytes:
                                failure()
                        if category == 'evidence_object':
                            h, length = hashlib.sha256(), 0
                            with archive.open(info) as content:
                                while chunk := content.read(65536):
                                    length += len(chunk)
                                    if length > limit:
                                        failure()
                                    h.update(chunk)
                            if length != info.file_size or h.hexdigest() != member['sha256'] or h.hexdigest() != Path(info.filename).stem:
                                failure()
                            object_hashes[Path(info.filename).stem] = length
                            # Snapshots need semantic validation; bounded to one object at a time.
                        else:
                            raw = self._bytes(archive, info, limit)
                            if digest(raw) != member['sha256']:
                                failure()
                            strict_json(raw)
                            documents[info.filename] = raw
                    self._validate_snapshots(archive, documents, object_hashes)
                stream.seek(0)
                archive_digest = hashlib.sha256()
                while chunk := stream.read(65536):
                    archive_digest.update(chunk)
                after, current = os.fstat(stream.fileno()), path.lstat()
                if ((opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) !=
                        (after.st_size, after.st_mtime_ns, after.st_ctime_ns) or
                        (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)):
                    failure()
                self._semantics(manifest, documents, object_hashes)
                return manifest, documents, object_hashes, archive_digest.hexdigest()
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError,
                OverflowError, struct.error, zipfile.BadZipFile, NotImplementedError):
            failure()

    @staticmethod
    def _bytes(archive, info, limit):
        if info.file_size > limit:
            failure()
        chunks, length = [], 0
        with archive.open(info) as content:
            while chunk := content.read(min(65536, limit-length+1)):
                length += len(chunk)
                if length > limit:
                    failure()
                chunks.append(chunk)
        if length != info.file_size:
            failure()
        return b''.join(chunks)

    @staticmethod
    def _manifest(m):
        keys = {'package_schema_version','package_type','profile','generated_at','assessment',
                'coverage','custody','summary','limits','members'}
        if not isinstance(m, dict) or set(m) != keys or type(m['package_schema_version']) is not int or m['package_schema_version'] != 1:
            failure()
        if m['package_type'] != 'aegis-assessment-export' or m['profile'] not in ('share','forensic'):
            failure()
        timestamp = datetime.fromisoformat(m['generated_at'])
        if timestamp.utcoffset() is None or timestamp.utcoffset().total_seconds() != 0:
            failure()
        if set(m['assessment']) != {'chain_id'} or set(m['custody']) != {'status','checkpoint'}:
            failure()
        if set(m['limits']) != {'max_total_content_bytes','max_members','max_manifest_bytes'} or any(type(v) is not int or v <= 0 for v in m['limits'].values()):
            failure()
        if not isinstance(m['members'], list):
            failure()
        allowed = SHARE if m['profile'] == 'share' else set(CATEGORIES)-SHARE
        previous = ''
        for member in m['members']:
            if set(member) != {'path','category','size','sha256'} or member['category'] not in allowed or type(member['size']) is not int or member['size'] < 0:
                failure()
            identifier(member['sha256'], 64)
            if not isinstance(member['path'], str) or member['path'] <= previous:
                failure()
            previous = member['path']
        custody = m['custody']
        if custody['status'] not in ('not_initialized','checkpoint_only','chain_verified'):
            failure()
        cp = custody['checkpoint']
        if custody['status'] == 'not_initialized':
            if cp is not None or m['assessment']['chain_id'] is not None:
                failure()
        else:
            if not isinstance(cp, dict) or set(cp) != {'chain_id','sequence','head_event_sha256','genesis_sha256'}:
                failure()
            identifier(cp['chain_id']); identifier(cp['head_event_sha256'],64); identifier(cp['genesis_sha256'],64)
            if type(cp['sequence']) is not int or cp['sequence'] < 1 or m['assessment']['chain_id'] != cp['chain_id']:
                failure()
            if custody['status'] != ('checkpoint_only' if m['profile'] == 'share' else 'chain_verified'):
                failure()
        coverage = dict(findings='projection' if m['profile']=='share' else 'original',
            technical_history='omitted' if m['profile']=='share' else 'original',
            triage_history='omitted' if m['profile']=='share' else 'original',
            triage_receipts='omitted' if m['profile']=='share' else 'portable_projection',
            evidence_records='projection' if m['profile']=='share' else 'original',
            evidence_objects=m['coverage'].get('evidence_objects'),
            custody={'not_initialized':'absent','checkpoint_only':'checkpoint_only','chain_verified':'full'}[custody['status']])
        if m['coverage'] != coverage or coverage['evidence_objects'] not in ('included','omitted') or (m['profile']=='share' and coverage['evidence_objects']!='omitted'):
            failure()

    def _validate_snapshots(self, archive, documents, objects):
        for path, raw in documents.items():
            if not path.startswith('evidence/records/'):
                continue
            record = EvidenceRecord.model_validate(strict_json(raw))
            if record.representation != 'observation-json-v1' or record.content_sha256 not in objects:
                continue
            content = self._bytes(archive, archive.getinfo('evidence/objects/'+record.content_sha256+'.blob'), self.limits.max_object_bytes)
            snapshot = strict_json(content)
            if set(snapshot) != {'schema_version','origin','observation'} or type(snapshot['schema_version']) is not int or snapshot['schema_version']!=1:
                failure()
            origin = ObservationOrigin.model_validate(snapshot['origin'])
            observation = Observation.model_validate(snapshot['observation'])
            if origin != record.origin or build_observation_id(origin.plugin, observation) != origin.observation_id:
                failure()

    def _semantics(self, manifest, documents, objects):
        findings, records, evidence, technical, triage, receipts = {}, {}, [], {}, {}, []
        for path, raw in documents.items():
            data = strict_json(raw)
            stem = Path(path).stem
            if path.startswith('projections/findings/'):
                if set(data) != {'finding_id','state','triage_state'} or data['finding_id'] != stem:
                    failure()
                FindingState(data['state']); FindingTriageState(data['triage_state'])
                findings[stem] = data
            elif path.startswith('findings/'):
                finding = FindingStore._deserialize(data)
                if finding.finding_id != stem:
                    failure()
                findings[stem] = FindingStore._serialize(finding)
            elif path.startswith('projections/evidence/'):
                if set(data) != EVIDENCE_FIELDS or type(data['projection_schema_version']) is not int or data['projection_schema_version'] != 1 or data['evidence_id'] != stem:
                    failure()
                identifier(data['evidence_id']); identifier(data['finding_id'],64); identifier(data['association_sha256'],64)
                if data['kind'] not in ('local_file','stored_observation','external_reference') or data['source_integrity'] not in ('original','retrospective','unknown'):
                    failure()
                reference = data['kind']=='external_reference'
                expected = {'local_file':'raw-v1','stored_observation':'observation-json-v1','external_reference':'reference-v1'}[data['kind']]
                if data['representation']!=expected or (data['kind']!='stored_observation' and data['source_integrity']!='unknown'):
                    failure()
                if reference:
                    if data['content_sha256'] is not None or data['content_size'] is not None:
                        failure()
                else:
                    identifier(data['content_sha256'],64)
                    if type(data['content_size']) is not int or data['content_size']<0:
                        failure()
                status = 'reference_only' if reference else 'content_not_included'
                if data['verification'] != {'metadata_status':'projection_only','content_status':status}:
                    failure()
                records[stem] = data
                evidence.append(dict(evidence_id=stem, metadata_status='projection_only',content_status=status))
            elif path.startswith('evidence/records/'):
                record = EvidenceRecord.model_validate(data)
                if record.evidence_id != stem or record.deduplication_key != association_key(record.finding_id,record.kind,record.origin,record.content_sha256):
                    failure()
                records[stem] = data
                included = record.content_sha256 in objects
                if included and objects[record.content_sha256] != record.content_size:
                    failure()
                evidence.append(dict(evidence_id=stem,metadata_status='verified',
                    content_status='reference_only' if record.content_sha256 is None else 'content_verified' if included else 'content_not_included'))
            elif path.startswith('histories/'):
                if data['event_id'] != stem:
                    failure()
                identifier(stem)
                if path.startswith('histories/triage/'):
                    triage_journal._decode_event(data)
                    triage[stem] = data
                else:
                    FindingHistoryStore._deserialize(data)
                    technical[stem] = data
            elif path.startswith('triage/receipts/'):
                if set(data) != {'version','sequence','status','event','history_ref'} or data['version']!=1 or type(data['sequence']) is not int or data['sequence']<1 or data['status'] not in ('done','aborted') or data['history_ref'] != 'triage_history' or data['event']['event_id']!=stem:
                    failure()
                triage_journal._decode_event(data['event']); receipts.append(data)
        if any(r['finding_id'] not in findings for r in records.values()) or any(e['finding_id'] not in findings for e in list(technical.values())+list(triage.values())):
            failure()
        keys = [r.get('deduplication_key') for r in records.values() if 'deduplication_key' in r]
        if len(set(keys)) != len(keys):
            failure()
        referenced = {r['content_sha256'] for r in records.values() if r['content_sha256'] is not None}
        if set(objects) != (referenced if manifest['coverage']['evidence_objects']=='included' else set()):
            failure()
        previous, sequences, latest = {}, set(), {}
        for receipt in sorted(receipts,key=lambda r:r['sequence']):
            event = receipt['event']; fid=event['finding_id']
            if receipt['sequence'] in sequences or fid not in findings:
                failure()
            sequences.add(receipt['sequence'])
            if fid in previous and event['from_state'] != previous[fid]:
                failure()
            if receipt['status']=='done' and triage.get(event['event_id'])!=event:
                failure()
            if receipt['status']=='aborted' and event['event_id'] in triage:
                failure()
            previous[fid] = event['from_state'] if receipt['status']=='aborted' else event['to_state']
            latest[fid] = previous[fid]
        if any(findings[fid]['triage_state']!=state for fid,state in latest.items()):
            failure()
        summary = dict(findings_total=len(findings),
            by_state={s.value:sum(f['state']==s.value for f in findings.values()) for s in FindingState},
            by_triage_state={s.value:sum(f['triage_state']==s.value for f in findings.values()) for s in FindingTriageState},
            evidence_associations=len(records),captured_evidence=sum(r['content_sha256'] is not None for r in records.values()),
            external_references=sum(r['content_sha256'] is None for r in records.values()))
        if manifest['summary'] != summary or any(type(v) is not int for k,v in manifest['summary'].items() if not isinstance(v,dict)):
            failure()
        if any(type(v) is not int for counts in (manifest['summary']['by_state'], manifest['summary']['by_triage_state']) for v in counts.values()):
            failure()
        custody = dict(manifest['custody'],external_checkpoint_match=None,temporal_anomalies=[])
        custody_files = {p:r for p,r in documents.items() if p.startswith('custody/')}
        if custody['status']=='chain_verified':
            custody['temporal_anomalies'] = self._chain(custody_files, records, documents, custody['checkpoint'])
        elif custody_files:
            failure()
        return dict(package_integrity='verified',custody=custody,evidence=sorted(evidence,key=lambda e:e['evidence_id']))

    @staticmethod
    def _chain(files, records, documents, checkpoint):
        genesis = strict_json(files['custody/genesis.json']); baseline = strict_json(files['custody/baseline.json'])
        if set(genesis) != {'schema_version','chain_id','baseline_sha256'} or type(genesis['schema_version']) is not int or genesis['schema_version']!=1 or genesis['baseline_sha256']!=digest(canonical(baseline)):
            failure()
        identifier(genesis['chain_id'])
        validate_baseline(baseline)
        expected = dict(baseline)
        previous, anomalies, previous_time = None, [], None
        event_paths = sorted(p for p in files if p.startswith('custody/events/'))
        used = {'custody/genesis.json','custody/baseline.json'}
        operations = set()
        for sequence,path in enumerate(event_paths,1):
            event = strict_json(files[path]); validate_event(event,sequence,genesis['chain_id'],previous)
            if path!='custody/events/%020d-%s.json'%(sequence,event['event_id']) or event['operation_id'] in operations:
                failure()
            operations.add(event['operation_id'])
            record = None
            if sequence>1:
                eid=event['evidence_id']; record=records[eid]
                if eid in expected or event['finding_id']!=record['finding_id'] or event['content_sha256']!=record['content_sha256'] or event['content_size']!=record['content_size'] or event['actor_declared']!=record['actor'] or event['reason']!=record['reason']:
                    failure()
                expected[eid]=event['association_sha256']
            intent = dict(schema_version=1,operation_id=event['operation_id'],event=event,record=record,
                          genesis=genesis if sequence==1 else None,baseline=baseline if sequence==1 else None)
            receipt_path='custody/completions/'+event['operation_id']+'.json'
            receipt=canonical(dict(schema_version=1,operation_id=event['operation_id'],
                                  intent_sha256=digest(canonical(intent)),event_sha256=event['event_sha256']))
            if files[receipt_path]!=receipt:
                failure()
            used.update((path,receipt_path))
            timestamp=datetime.fromisoformat(event['recorded_at'])
            if previous_time is not None and timestamp<previous_time:
                anomalies.append(sequence)
            previous_time=timestamp; previous=event['event_sha256']
        if not event_paths or set(files)!=used or set(expected)!=set(records):
            failure()
        for eid,sha in expected.items():
            if digest(documents['evidence/records/'+eid+'.json'])!=sha:
                failure()
        if checkpoint_for(genesis,event)!=checkpoint:
            failure()
        return anomalies


class AssessmentExporter:
    def __init__(self,campaign,*,limits=None):
        self.campaign=campaign
        self.limits=limits or PackageLimits()

    def export(self,destination,*,profile='share',include_objects=False,generated_at=None):
        if profile not in ('share','forensic') or type(include_objects) is not bool or (profile=='share' and include_objects):
            raise ValueError('Select share without objects or explicitly select forensic')
        destination=Path(destination).absolute()
        if '..' in destination.parts:
            raise ValueError('Invalid export destination')
        validate_storage_path(destination.parent,Path(destination.anchor))
        if destination.is_relative_to(self.campaign.path):
            raise ValueError('Export destination must be outside the assessment')
        try:
            destination.lstat()
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError('Export destination already exists')
        generated_at=generated_at or datetime.now(timezone.utc)
        if generated_at.utcoffset() is None:
            raise ValueError('Generation timestamp must be timezone-aware')
        with tempfile.TemporaryDirectory(prefix='.aegis-export-',dir=destination.parent) as temporary:
            package=Path(temporary)/'package.zip'
            with ExitStack() as stack:
                stack.enter_context(directory_lock(self.campaign.findings_dir,create=False))
                journal=self.campaign.findings_dir/'.triage-journal'
                validate_storage_path(journal,self.campaign.path,optional=True)
                journal_bytes=0
                try:
                    journal.lstat()
                except FileNotFoundError:
                    pass
                else:
                    for path in scan(journal):
                        validate_storage_path(path,self.campaign.path,regular=True)
                        if path.suffix=='.txn':
                            journal_bytes+=len(read(path,16*MIB))
                            if journal_bytes>self.limits.max_metadata_bytes:
                                raise StorageIntegrityError('Export metadata limit exceeded')
                receipts=triage_journal.inspect_completed(self.campaign.findings_dir)
                histories={self.campaign.finding_history_dir,self.campaign.finding_triage_history_dir}
                histories.update(Path(os.path.normpath(self.campaign.findings_dir/r['history_directory'])) for _,r in receipts)
                for directory in sorted(histories,key=str):
                    validate_storage_path(directory,self.campaign.path,optional=True)
                    stack.enter_context(directory_lock(directory,create=False))
                stack.enter_context(directory_lock(self.campaign.path,create=False))
                evidence=EvidenceReader(self.campaign)
                stack.enter_context(evidence.locked())
                custody=CustodyReader(self.campaign)
                stack.enter_context(custody.locked())
                documents={}
                source_bytes=journal_bytes
                # Bound source metadata before the legacy report projection parses it.
                source_directories={self.campaign.findings_dir,*histories,evidence.records_dir}
                if custody.exists():
                    source_directories.update(custody.root/name for name in ('events','intents','completions'))
                for directory in source_directories:
                    try:
                        directory.lstat()
                    except FileNotFoundError:
                        continue
                    validate_storage_path(directory,self.campaign.path)
                    for path in scan(directory):
                        if directory==self.campaign.findings_dir and path==journal:
                            # This exact directory was validated and bounded above.
                            validate_storage_path(path,self.campaign.path)
                            continue
                        validate_storage_path(path,self.campaign.path,regular=True)
                        if path.name in {'.aegis-lock.sqlite'+suffix for suffix in ('','-journal','-wal','-shm')} or path.suffix in ('.tmp','.txn'):
                            continue
                        if path.suffix!='.json':
                            raise StorageIntegrityError('Unexpected export source entry')
                        source_bytes+=len(read(path,16*MIB+256*1024))
                        if source_bytes>self.limits.max_metadata_bytes:
                            raise StorageIntegrityError('Export metadata limit exceeded')
                read(self.campaign.config_file,16*MIB)
                for record in evidence._records():
                    if record.content_sha256 is not None and record.content_size>self.limits.max_object_bytes:
                        raise StorageIntegrityError('Export object limit exceeded')
                report=build_report(self.campaign,schema_version=2)
                custody_result=custody.verify()
                verified=evidence.all_verified()
                def add(path,category,raw):
                    if path in documents:
                        if documents[path]!=(category,raw):
                            raise StorageIntegrityError('Conflicting export documents')
                        return
                    if len(raw)>CATEGORIES[category][1]:
                        raise StorageIntegrityError('Export document limit exceeded')
                    documents[path]=(category,raw)
                if profile=='share':
                    for finding in report['findings']:
                        record=finding['record']
                        add('projections/findings/'+record['finding_id']+'.json','finding_projection',
                            canonical({k:record[k] for k in ('finding_id','state','triage_state')}))
                    for record,_ in verified:
                        raw=read(evidence.records_dir/(record.evidence_id+'.json'),65536)
                        payload={k:getattr(record,k) for k in ('evidence_id','finding_id','kind','representation','content_sha256','content_size','source_integrity')}
                        payload.update(projection_schema_version=1,association_sha256=digest(raw),
                            verification=dict(metadata_status='projection_only',content_status='reference_only' if record.content_sha256 is None else 'content_not_included'))
                        add('projections/evidence/'+record.evidence_id+'.json','evidence_projection',canonical(payload))
                else:
                    for finding in report['findings']:
                        fid=finding['record']['finding_id']
                        add('findings/'+fid+'.json','finding',read(self.campaign.findings_dir/(fid+'.json'),16*MIB))
                    for directory in sorted(histories,key=str):
                        try:
                            directory.lstat()
                        except FileNotFoundError:
                            continue
                        operational=directory!=self.campaign.finding_history_dir
                        category='triage_history' if operational else 'technical_history'
                        for path in scan(directory):
                            if path.suffix=='.json':
                                add('histories/'+('triage' if operational else 'technical')+'/'+path.name,category,read(path,16*MIB))
                    for _,receipt in receipts:
                        payload={k:receipt[k] for k in ('version','sequence','status','event')}
                        payload['history_ref']='triage_history'
                        add('triage/receipts/'+receipt['event']['event_id']+'.json','triage_receipt',canonical(payload))
                    for record,_ in verified:
                        add('evidence/records/'+record.evidence_id+'.json','evidence_record',read(evidence.records_dir/(record.evidence_id+'.json'),65536))
                    if custody.exists():
                        add('custody/genesis.json','custody_genesis',read(custody.root/'genesis.json',16*MIB))
                        add('custody/baseline.json','custody_baseline',read(custody.root/'baseline.json',16*MIB))
                        for directory,category,limit in [('events','custody_event',65536),('completions','custody_completion',128*1024)]:
                            for path in scan(custody.root/directory):
                                if path.suffix=='.json':
                                    add('custody/'+directory+'/'+path.name,category,read(path,limit))
                status=custody_result['status']
                if status=='chain_verified' and profile=='share':
                    status='checkpoint_only'
                manifest=dict(package_schema_version=1,package_type='aegis-assessment-export',profile=profile,
                    generated_at=generated_at.astimezone(timezone.utc).isoformat().replace('+00:00','Z'),
                    assessment=dict(chain_id=custody_result['checkpoint']['chain_id'] if custody_result['checkpoint'] else None),
                    coverage=dict(findings='projection' if profile=='share' else 'original',
                        technical_history='omitted' if profile=='share' else 'original',
                        triage_history='omitted' if profile=='share' else 'original',
                        triage_receipts='omitted' if profile=='share' else 'portable_projection',
                        evidence_records='projection' if profile=='share' else 'original',
                        evidence_objects='included' if include_objects else 'omitted',
                        custody={'not_initialized':'absent','checkpoint_only':'checkpoint_only','chain_verified':'full'}[status]),
                    custody=dict(status=status,checkpoint=custody_result['checkpoint']),
                    summary=dict(findings_total=report['summary']['total'],by_state=report['summary']['by_state'],
                        by_triage_state=report['summary']['by_triage_state'],evidence_associations=len(verified),
                        captured_evidence=sum(r.content_sha256 is not None for r,_ in verified),
                        external_references=sum(r.content_sha256 is None for r,_ in verified)),
                    limits={k:getattr(self.limits,k) for k in ('max_total_content_bytes','max_members','max_manifest_bytes')},members=[])
                objects={r.content_sha256:r.content_size for r,_ in verified if r.content_sha256 is not None} if include_objects else {}
                manifest['members']=[dict(path=p,category=c,size=len(raw),sha256=digest(raw)) for p,(c,raw) in documents.items()]
                manifest['members'] += [dict(path='evidence/objects/'+sha+'.blob',category='evidence_object',size=size,sha256=sha) for sha,size in objects.items()]
                manifest['members'].sort(key=lambda m:m['path'])
                encoded=canonical(manifest)
                total=len(encoded)+sum(m['size'] for m in manifest['members'])
                metadata=len(encoded)+sum(len(raw) for _,raw in documents.values())
                if total>self.limits.max_total_content_bytes or metadata>self.limits.max_metadata_bytes or len(encoded)>self.limits.max_manifest_bytes or len(manifest['members'])+1>self.limits.max_members:
                    raise StorageIntegrityError('Export package limit exceeded')
                def info(name):
                    value=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0))
                    value.compress_type=zipfile.ZIP_STORED; value.create_system=3
                    value.external_attr=(stat.S_IFREG|0o600)<<16
                    return value
                with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_STORED,allowZip64=True) as archive:
                    archive.writestr(info('manifest.json'),encoded)
                    for member in manifest['members']:
                        path=member['path']
                        if member['category']=='evidence_object':
                            raw=read(evidence.objects/(Path(path).stem+'.blob'),self.limits.max_object_bytes)
                            if len(raw)!=member['size'] or digest(raw)!=member['sha256']:
                                raise StorageIntegrityError('Evidence changed during export')
                        else:
                            raw=documents[path][1]
                        archive.writestr(info(path),raw)
            os.chmod(package,0o600)
            result=AssessmentPackageReader(limits=self.limits).verify(package)
            with package.open('r+b') as stream:
                os.fsync(stream.fileno())
            os.link(package,destination)
            sync_directory(destination.parent)
            return result
