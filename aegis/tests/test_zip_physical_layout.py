"""Independent physical-envelope counterexamples from the second PR #8 audit."""
import json
import struct
import zipfile
from unittest.mock import patch

import pytest
from typer.testing import CliRunner
from aegis.assessment_package import AssessmentExporter, AssessmentPackageReader, PackageLimits, preflight
from aegis.atomic_storage import StorageIntegrityError
from aegis.cli import app
from test_evidence_store import setup


def sections(raw):
    end=len(raw)-22
    eocd=list(struct.unpack_from('<4sHHHHLLH',raw,end))
    central=eocd[6];pos=central;entries=[]
    while pos<central+eocd[5]:
        h=struct.unpack_from('<4s6H3L5H2L',raw,pos)
        entries.append((pos,h));pos+=46+h[10]+h[11]+h[12]
    return end,eocd,entries


def check_rejected(path):
    with patch('aegis.assessment_package.zipfile.ZipFile',side_effect=AssertionError('inventory reached')) as constructor:
        with pytest.raises(StorageIntegrityError):AssessmentPackageReader().verify(path)
        constructor.assert_not_called()


@pytest.mark.parametrize('profile',['share','forensic'])
def test_hidden_local_member_is_rejected(setup,tmp_path,profile):
    path=tmp_path/'hidden.zip';AssessmentExporter(setup[0]).export(path,profile=profile)
    with zipfile.ZipFile(path) as z:visible=sum(i.file_size for i in z.infolist())
    with zipfile.ZipFile(path,'a') as z:z.writestr('SECRET_HIDDEN.bin',b'PRIVATE_MARKER_NOT_IN_MANIFEST')
    raw=bytearray(path.read_bytes());end,e,entries=sections(raw);position,h=entries[-1];length=46+h[10]+h[11]+h[12]
    del raw[position:position+length];e[3]-=1;e[4]-=1;e[5]-=length;raw[-22:]=struct.pack('<4sHHHHLLH',*e);path.write_bytes(raw)
    with pytest.raises(StorageIntegrityError):AssessmentPackageReader(limits=PackageLimits(max_total_content_bytes=visible+1)).verify(path)
    check_rejected(path)


@pytest.mark.parametrize('profile',['share','forensic'])
@pytest.mark.parametrize('channel',['comment','unknown-extra'])
def test_opaque_member_metadata_is_rejected(setup,tmp_path,profile,channel):
    path=tmp_path/'metadata.zip';AssessmentExporter(setup[0]).export(path,profile=profile)
    with zipfile.ZipFile(path) as z:values={i.filename:z.read(i) for i in z.infolist()}
    with zipfile.ZipFile(path,'w') as z:
        for name,value in values.items():
            info=zipfile.ZipInfo(name)
            if channel=='comment':info.comment=b'PRIVATE_MARKER_COMMENT'
            else:
                secret=b'PRIVATE_MARKER_UNKNOWN';info.extra=struct.pack('<HH',0xCAFE,len(secret))+secret
            z.writestr(info,value)
    check_rejected(path)
    result=CliRunner().invoke(app,['assessment','package','verify',str(path)])
    assert result.exit_code and 'PRIVATE_MARKER' not in result.stdout+result.stderr


@pytest.mark.parametrize('damage',['gap','overlap','offset','local-size','local-name','local-crc','local-flags','payload-trailer','truncated-local','descriptor','central-extra','local-extra','global-comment','redundant-zip64','malformed-zip64'])
def test_physical_layout_and_metadata_rejected(setup,tmp_path,damage):
    path=tmp_path/'bad.zip';AssessmentExporter(setup[0]).export(path)
    raw=bytearray(path.read_bytes());end,e,entries=sections(raw);position,h=entries[0];local=h[16]
    if damage in ('gap','payload-trailer'):
        insertion=entries[1][1][16] if damage=='gap' else e[6]
        raw[insertion:insertion]=b'ORPHAN';end+=6;e[6]+=6
        if damage=='gap':
            for p,entry in entries[1:]:struct.pack_into('<L',raw,p+6+42,entry[16]+6)
    elif damage=='overlap':struct.pack_into('<L',raw,entries[1][0]+42,local)
    elif damage=='offset':struct.pack_into('<L',raw,position+42,local+1)
    elif damage=='local-size':struct.pack_into('<L',raw,local+22,h[9]+1)
    elif damage=='local-name':raw[local+30]^=1
    elif damage=='local-crc':struct.pack_into('<L',raw,local+14,h[7]^1)
    elif damage=='local-flags':struct.pack_into('<H',raw,local+6,h[3]^0x800)
    elif damage=='truncated-local':raw[local:local+4]=b'BAD!'
    elif damage=='descriptor':
        # Valid-looking flags still represent an unsupported streaming layout.
        struct.pack_into('<H',raw,position+8,h[3]|8);struct.pack_into('<H',raw,local+6,h[3]|8)
    elif damage in ('central-extra','redundant-zip64','malformed-zip64'):
        extra=b'\xfe\xca\x00\x00' if damage=='central-extra' else b'\x01\x00\x08\x00'+struct.pack('<Q',h[9]) if damage=='redundant-zip64' else b'\x01\x00\xff\xff'
        insertion=position+46+h[10];raw[insertion:insertion]=extra;struct.pack_into('<H',raw,position+30,len(extra));e[5]+=len(extra);end+=len(extra)
    elif damage=='local-extra':
        insertion=local+30+len(b'manifest.json');extra=b'\xfe\xca\x00\x00';raw[insertion:insertion]=extra;struct.pack_into('<H',raw,local+28,len(extra));end+=len(extra);e[6]+=len(extra)
        for p,entry in entries[1:]:struct.pack_into('<L',raw,p+len(extra)+42,entry[16]+len(extra))
    elif damage=='global-comment':
        e[7]=len(b'PRIVATE_MARKER_GLOBAL');raw.extend(b'PRIVATE_MARKER_GLOBAL')
    raw[end:end+22]=struct.pack('<4sHHHHLLH',*e);path.write_bytes(raw);check_rejected(path)


@pytest.mark.parametrize('profile',['share','forensic'])
def test_canonical_packages_still_accepted(setup,tmp_path,profile):
    path=tmp_path/'valid.zip';AssessmentExporter(setup[0]).export(path,profile=profile)
    assert AssessmentPackageReader().verify(path)['package_integrity']=='verified'


def test_legitimate_zip64_count_preflight(tmp_path):
    path=tmp_path/'zip64.zip'
    with zipfile.ZipFile(path,'w') as z:
        for i in range(65536):z.writestr(str(i),b'')
    with path.open('rb') as stream:preflight(stream,PackageLimits())


@pytest.mark.parametrize('values',[(0xffffffff,1),(1,0xffffffff),(0xffffffff,0xffffffff),(1,1,0xffffffff),(0xffffffff,0xffffffff,0xffffffff)])
def test_necessary_zip64_values(values):
    from aegis.assessment_package import zip64_values
    decoded=tuple(zipfile.ZIP64_LIMIT+10+i if v==0xffffffff else v for i,v in enumerate(values))
    payload=b''.join(struct.pack('<Q',v) for sentinel,v in zip(values,decoded) if sentinel==0xffffffff)
    assert zip64_values(struct.pack('<HH',1,len(payload))+payload,values)==decoded


@pytest.mark.parametrize('extra,values',[(b'',(0xffffffff,1)),(b'\x01\x00\x08\x00'+struct.pack('<Q',1),(0xffffffff,1)),(b'\x01\x00\x00\x00',(1,1)),(b'\x01\x00\x08\x00'+struct.pack('<Q',0xffffffff)+b'\xfe\xca\x00\x00',(0xffffffff,1))])
def test_inconsistent_zip64_values(extra,values):
    from aegis.assessment_package import zip64_values
    with pytest.raises(StorageIntegrityError):zip64_values(extra,values)


@pytest.mark.parametrize('damage',['none','truncated','wrong-crc'])
def test_streaming_data_descriptors_explicitly_unsupported(setup,tmp_path,damage):
    import io
    path=tmp_path/'streaming.zip';AssessmentExporter(setup[0]).export(path)
    with zipfile.ZipFile(path) as z:values={i.filename:z.read(i) for i in z.infolist()}
    class Unseekable(io.BytesIO):
        def seek(self,*args):raise OSError('nonseekable stream')
    stream=Unseekable()
    with zipfile.ZipFile(stream,'w') as z:
        for name,value in values.items():z.writestr(name,value)
    raw=bytearray(stream.getvalue());descriptor=raw.find(b'PK\x07\x08');assert descriptor>=0
    if damage=='truncated':raw[descriptor:descriptor+4]=b'BAD!'
    elif damage=='wrong-crc':struct.pack_into('<L',raw,descriptor+4,0)
    path.write_bytes(raw);check_rejected(path)


def test_redundant_local_zip64_is_rejected(setup,tmp_path):
    path=tmp_path/'forced.zip';AssessmentExporter(setup[0]).export(path)
    with zipfile.ZipFile(path) as z:values={i.filename:z.read(i) for i in z.infolist()}
    with zipfile.ZipFile(path,'w') as z:
        for name,value in values.items():
            with z.open(name,'w',force_zip64=True) as member:member.write(value)
    check_rejected(path)
