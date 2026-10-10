"""Regression counterexamples from the independent PR #8 audit."""
import json
import struct
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from unittest.mock import patch

import pytest
from typer.testing import CliRunner
from test_evidence_store import setup, attach
from test_custody import snapshot
from aegis.atomic_storage import directory_lock, StorageIntegrityError
from aegis.assessment_package import AssessmentExporter, AssessmentPackageReader, PackageLimits
from aegis.custody import CustodyManager, CustodyReader, canonical, digest
from aegis.evidence_models import ExternalOrigin, EvidenceRecord, LocalOrigin
from aegis.evidence_store import association_key
from aegis.finding_store import FindingStore
from aegis.finding_triage import FindingTriageManager
from aegis.finding_triage_history_store import FindingTriageHistoryStore
from aegis.finding_history_store import FindingHistoryStore
from aegis.models import FindingEvent, FindingEventType, FindingState
from aegis.cli import app


@pytest.mark.parametrize('profile',['share','forensic'])
def test_r1_real_triage_export(setup,tmp_path,profile):
    campaign,finding,_=setup
    FindingTriageManager(FindingStore(campaign.findings_dir),FindingTriageHistoryStore(campaign.finding_triage_history_dir)).acknowledge(finding.finding_id,actor='PRIVATE_MARKER',reason='review')
    before=snapshot(campaign)
    path=tmp_path/'triage.zip'
    AssessmentExporter(campaign).export(path,profile=profile)
    assert AssessmentPackageReader().verify(path)['package_integrity']=='verified'
    assert snapshot(campaign)==before


@pytest.mark.parametrize('invalid',['missing','duplicate','quota','record','key','object','assessment'])
def test_r2_direct_commit_validates_before_intent(setup,invalid):
    campaign,finding,_=setup
    record=attach(setup)
    CustodyManager(campaign).initialize(actor='operator',reason='activate')
    updates={'evidence_id':uuid4().hex}
    if invalid=='missing':
        origin=ExternalOrigin(kind='external_reference',locator='https://example.test/')
        record=EvidenceRecord(evidence_id=uuid4().hex,finding_id='b'*64,kind=origin.kind,origin=origin,registered_at=datetime.now(timezone.utc),actor='operator',reason='direct',representation='reference-v1',source_integrity='unknown',deduplication_key=association_key('b'*64,origin.kind,origin,None))
    else:
        if invalid!='duplicate':
            origin=LocalOrigin(kind='local_file',source_name='other.bin')
            updates.update(origin=origin,deduplication_key=association_key(finding.finding_id,origin.kind,origin,record.content_sha256))
        if invalid=='quota':
            campaign.config_file.write_text('name: Test\nevidence:\n  max_object_bytes: 1\n  max_assessment_bytes: 1024\n')
        elif invalid=='assessment':
            campaign.config_file.write_text('name: Test\nevidence:\n  max_object_bytes: 1\n  max_assessment_bytes: 1\n')
        elif invalid=='record': updates['actor']=''
        elif invalid=='key': updates['deduplication_key']='f'*64
        elif invalid=='object':
            updates.update(content_sha256='f'*64,deduplication_key=association_key(finding.finding_id,origin.kind,origin,'f'*64))
        record=record.model_copy(update=updates)
    with directory_lock(campaign.findings_dir,create=False),directory_lock(campaign.path),directory_lock(campaign.evidence_dir/'managed-v1'):
        before=snapshot(campaign)
        with pytest.raises((ValueError,LookupError)):
            CustodyManager(campaign).commit_record(record)
        assert snapshot(campaign)==before


def lie_counts(path):
    with path.open('r+b') as stream:
        stream.seek(-22,2);position=stream.tell();raw=bytearray(stream.read())
        original=struct.unpack_from('<H',raw,10)[0]
        struct.pack_into('<HH',raw,8,1,1);stream.seek(position);stream.write(raw)
        if original==65535:
            stream.seek(position-20);locator=struct.unpack('<4sLQL',stream.read(20))
            stream.seek(locator[2]+24);stream.write(struct.pack('<QQ',1,1))


@pytest.mark.parametrize('count,limit',[(10000,2000),(100001,100000)])
def test_r3_count_rejected_before_zipinfo(tmp_path,count,limit):
    path=tmp_path/'counts.zip'
    with zipfile.ZipFile(path,'w') as archive:
        for n in range(count): archive.writestr('x%06d'%n,b'')
    lie_counts(path)
    with patch('aegis.assessment_package.zipfile.ZipFile',side_effect=AssertionError('inventory materialized')) as constructor:
        with pytest.raises(StorageIntegrityError):
            AssessmentPackageReader(limits=PackageLimits(max_members=limit)).verify(path)
        constructor.assert_not_called()


def test_r3_false_count_valid_package(setup,tmp_path):
    attach(setup);path=tmp_path/'valid.zip';AssessmentExporter(setup[0]).export(path)
    lie_counts(path)
    with pytest.raises(StorageIntegrityError):AssessmentPackageReader().verify(path)


def rewrite(path,mutate):
    with zipfile.ZipFile(path) as archive: files={i.filename:(i,archive.read(i)) for i in archive.infolist()}
    manifest=json.loads(files['manifest.json'][1]);mutate(files,manifest)
    for member in manifest['members']:
        raw=files[member['path']][1];member.update(size=len(raw),sha256=digest(raw))
    files['manifest.json']=(files['manifest.json'][0],canonical(manifest))
    with zipfile.ZipFile(path,'w') as archive:
        for info,raw in files.values():archive.writestr(info,raw)


@pytest.mark.parametrize('baseline',[[],[['a'*32,'f'*64]],{'bad':'bad'},None])
def test_r4_invalid_baseline_rehashed(setup,tmp_path,baseline):
    campaign,_,_=setup;CustodyManager(campaign).initialize(actor='operator',reason='activate')
    path=tmp_path/'baseline.zip';AssessmentExporter(campaign).export(path,profile='forensic')
    def mutate(files,manifest):
        genesis=json.loads(files['custody/genesis.json'][1]);genesis['baseline_sha256']=digest(canonical(baseline))
        files['custody/baseline.json']=(files['custody/baseline.json'][0],canonical(baseline))
        files['custody/genesis.json']=(files['custody/genesis.json'][0],canonical(genesis))
        event=json.loads(next(raw for p,(_,raw) in files.items() if p.startswith('custody/events/')))
        name='custody/completions/'+event['operation_id']+'.json';receipt=json.loads(files[name][1])
        receipt['intent_sha256']=digest(canonical(dict(schema_version=1,operation_id=event['operation_id'],event=event,record=None,genesis=genesis,baseline=baseline)))
        files[name]=(files[name][0],canonical(receipt));manifest['custody']['checkpoint']['genesis_sha256']=digest(canonical(genesis))
    rewrite(path,mutate)
    with pytest.raises(StorageIntegrityError):AssessmentPackageReader().verify(path)


@pytest.mark.parametrize('field,value',[('asset_type','IMPOSSIBLE'),('event_type','IMPOSSIBLE'),('to_state','IMPOSSIBLE'),('from_state','IMPOSSIBLE'),('detected_at','invalid'),('detected_at',None)])
def test_r5_history_domain_rehashed(setup,tmp_path,field,value):
    campaign,finding,_=setup
    event=FindingEvent(uuid4().hex,finding.finding_id,FindingEventType.CREATED,None,FindingState.ACTIVE,datetime.now(timezone.utc))
    FindingHistoryStore(campaign.finding_history_dir).save(event)
    path=tmp_path/'history.zip';AssessmentExporter(campaign).export(path,profile='forensic')
    def mutate(files,manifest):
        name='histories/technical/'+event.event_id+'.json';data=json.loads(files[name][1]);data[field]=value
        files[name]=(files[name][0],canonical(data))
    rewrite(path,mutate)
    with pytest.raises(StorageIntegrityError):AssessmentPackageReader().verify(path)


def test_r6_profile_error_is_sanitized(tmp_path):
    result=CliRunner().invoke(app,['assessment','export','--output',str(tmp_path/'no.zip'),'--profile','PRIVATE_MARKER'])
    assert result.exit_code and result.stdout==''
    assert 'PRIVATE_MARKER' not in result.stderr and 'share' in result.stderr and 'forensic' in result.stderr
    assert not (tmp_path/'no.zip').exists()


@pytest.mark.parametrize('count',[65535,65536])
def test_r3_legitimate_count_boundary_and_zip64(tmp_path,count):
    from aegis.assessment_package import preflight
    path=tmp_path/'boundary.zip'
    with zipfile.ZipFile(path,'w') as archive:
        for n in range(count): archive.writestr('x%06d'%n,b'')
    with path.open('rb') as stream: preflight(stream,PackageLimits(max_members=count))


def test_r3_valid_package_at_member_limit(setup,tmp_path):
    attach(setup);path=tmp_path/'limit.zip';AssessmentExporter(setup[0]).export(path)
    assert AssessmentPackageReader(limits=PackageLimits(max_members=3)).verify(path)['package_integrity']=='verified'


@pytest.mark.parametrize('damage',['signature','truncated','length','count-mismatch','zip64-mismatch'])
def test_r3_malformed_directory_precedes_inventory(tmp_path,damage):
    path=tmp_path/'broken.zip'
    with zipfile.ZipFile(path,'w') as archive: archive.writestr('x',b'')
    raw=bytearray(path.read_bytes());central=raw.find(b'PK\x01\x02');eocd=raw.find(b'PK\x05\x06')
    if damage=='signature':raw[central:central+4]=b'BAD!'
    elif damage=='truncated':del raw[central+10:central+20]
    elif damage=='length':struct.pack_into('<H',raw,central+28,65535)
    elif damage=='count-mismatch':struct.pack_into('<H',raw,eocd+8,2)
    else:
        # A real ZIP64 EOCD/locator, contradicting the ordinary EOCD count.
        size,offset=struct.unpack_from('<LL',raw,eocd+12)
        z64=struct.pack('<4sQHHLLQQQQ',b'PK\x06\x06',44,45,45,0,0,2,2,size,offset)
        locator=struct.pack('<4sLQL',b'PK\x06\x07',0,eocd,1)
        raw[eocd:eocd]=z64+locator
    path.write_bytes(raw)
    with patch('aegis.assessment_package.zipfile.ZipFile',side_effect=AssertionError('inventory materialized')) as constructor:
        with pytest.raises(StorageIntegrityError):AssessmentPackageReader().verify(path)
        constructor.assert_not_called()


@pytest.mark.parametrize('optional',[{}, {'asset_type':None,'plugin':None,'rule_id':None,'asset_value':None}])
@pytest.mark.parametrize('timestamp',['2020-01-01T00:00:00','2020-01-01T00:00:00+00:00'])
def test_r5_legacy_optional_fields_remain_valid(setup,tmp_path,optional,timestamp):
    campaign,finding,_=setup;event_id=uuid4().hex
    directory=campaign.finding_history_dir;directory.mkdir(parents=True)
    data=dict(event_id=event_id,finding_id=finding.finding_id,event_type='created',to_state='active',detected_at=timestamp,**optional)
    (directory/(event_id+'.json')).write_text(json.dumps(data))
    path=tmp_path/'legacy.zip';AssessmentExporter(campaign).export(path,profile='forensic')
    assert AssessmentPackageReader().verify(path)['package_integrity']=='verified'


@pytest.mark.parametrize('kind',['unknown-directory','reparse-journal'])
def test_r1_unexpected_sources_still_rejected(setup,tmp_path,monkeypatch,kind):
    from types import SimpleNamespace
    import stat
    campaign,_,_=setup
    directory=campaign.findings_dir/('unknown' if kind=='unknown-directory' else '.triage-journal');directory.mkdir()
    if kind=='reparse-journal':
        original=Path.lstat
        def linked(path,*args,**kwargs):
            if path==directory:return SimpleNamespace(st_mode=stat.S_IFDIR,st_file_attributes=0x400)
            return original(path,*args,**kwargs)
        monkeypatch.setattr(Path,'lstat',linked)
    output=tmp_path/'bad.zip'
    with pytest.raises(ValueError):AssessmentExporter(campaign).export(output)
    assert not output.exists()


@pytest.mark.parametrize('name',['.aegis-lock.sqlite-unexpected','ignored.tmp'])
def test_r1_skip_names_do_not_hide_unknown_directories(setup,tmp_path,name):
    campaign,_,_=setup;(campaign.findings_dir/name).mkdir()
    with pytest.raises(ValueError):AssessmentExporter(campaign).export(tmp_path/'no.zip')
    assert not (tmp_path/'no.zip').exists()


def test_r1_ignored_temporary_reparse_is_rejected(setup,tmp_path,monkeypatch):
    from types import SimpleNamespace
    import stat
    campaign,_,_=setup;target=campaign.findings_dir/'ignored.tmp';target.write_bytes(b'preserve')
    original=Path.lstat
    def linked(path,*args,**kwargs):
        if path==target:return SimpleNamespace(st_mode=stat.S_IFREG,st_file_attributes=0x400)
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'lstat',linked)
    with pytest.raises(ValueError):AssessmentExporter(campaign).export(tmp_path/'no.zip')
    assert not (tmp_path/'no.zip').exists()
