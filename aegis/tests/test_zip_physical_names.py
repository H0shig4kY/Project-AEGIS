"""Physical-name regressions: mutate bytes without ZipInfo sanitization."""
import struct
import zipfile
from unittest.mock import patch

import pytest
from typer.testing import CliRunner
from aegis.assessment_package import AssessmentExporter, AssessmentPackageReader, PackageLimits, preflight
from aegis.atomic_storage import StorageIntegrityError
from aegis.cli import app
from test_evidence_store import setup


def rename_physical(path, target, replacement, *, local_only=False):
    raw = path.read_bytes()
    end = list(struct.unpack('<4sHHHHLLH', raw[-22:]))
    cursor = end[6]
    entries = []
    while cursor < end[6] + end[5]:
        header = list(struct.unpack_from('<4s6H3L5H2L', raw, cursor))
        length = 46 + sum(header[10:13])
        entries.append((header, raw[cursor+46:cursor+length]))
        cursor += length
    locals_, central, offset = [], [], 0
    for index, (header, tail) in enumerate(entries):
        stop = entries[index+1][0][16] if index+1 < len(entries) else end[6]
        block = raw[header[16]:stop]
        local = list(struct.unpack_from('<4s5H3L2H', block))
        name = tail[:header[10]]
        if name == target:
            block = struct.pack('<4s5H3L2H', *(local[:9]+[len(replacement), local[10]])) + replacement + block[30+local[9]:]
            if not local_only:
                tail = replacement + tail[header[10]:]
                header[10] = len(replacement)
        header[16] = offset
        locals_.append(block)
        offset += len(block)
        central.append(struct.pack('<4s6H3L5H2L', *header)+tail)
    end[6], end[5] = offset, sum(map(len, central))
    path.write_bytes(b''.join(locals_+central)+struct.pack('<4sHHHHLLH', *end))


def reject_before_zipinfo(path):
    with patch('aegis.assessment_package.zipfile.ZipFile', side_effect=AssertionError('ZipInfo reached')) as constructor:
        with pytest.raises(StorageIntegrityError):
            AssessmentPackageReader().verify(path)
        constructor.assert_not_called()
    result = CliRunner().invoke(app, ['assessment', 'package', 'verify', str(path)])
    assert result.exit_code != 0
    assert 'PRIVATE_MARKER' not in result.stdout + result.stderr


@pytest.mark.parametrize('profile', ['share', 'forensic'])
@pytest.mark.parametrize('target_kind', ['manifest', 'projection'])
@pytest.mark.parametrize('position', ['suffix', 'middle'])
def test_nul_physical_name_rejected(setup, tmp_path, profile, target_kind, position):
    path = tmp_path/'nul.zip'
    AssessmentExporter(setup[0]).export(path, profile=profile)
    with zipfile.ZipFile(path) as archive:
        target = b'manifest.json' if target_kind == 'manifest' else archive.infolist()[1].filename.encode('ascii')
    replacement = target+b'\x00PRIVATE_MARKER_FILENAME' if position == 'suffix' else target[:-5]+b'\x00PRIVATE_MARKER_FILENAME'+target[-5:]
    rename_physical(path, target, replacement)
    # This assertion is the original independent counterexample: canonical
    # documents and inventory remain untouched, but raw names are forbidden.
    with pytest.raises(StorageIntegrityError):
        AssessmentPackageReader().verify(path)
    reject_before_zipinfo(path)


@pytest.mark.parametrize('profile', ['share', 'forensic'])
def test_windows_separator_normalization_rejected(setup, tmp_path, profile):
    path = tmp_path/'windows.zip'
    AssessmentExporter(setup[0]).export(path, profile=profile)
    with zipfile.ZipFile(path) as archive:
        target = archive.infolist()[1].filename.encode('ascii')
    rename_physical(path, target, target.replace(b'/', b'\\'))
    with patch('zipfile.os.sep', '\\'):
        with pytest.raises(StorageIntegrityError):
            AssessmentPackageReader().verify(path)
    reject_before_zipinfo(path)


@pytest.mark.parametrize('name', [
    b'manifest.json\\PRIVATE_MARKER', b'x\\manifest.json',
    b'manifest.json\x01PRIVATE_MARKER', b'manifest.json\x7f', b'manifest.json\xff',
    b'./manifest.json', b'../manifest.json', b'x/./manifest.json',
    b'x/../manifest.json', b'x//manifest.json', b'/manifest.json',
    b'//server/manifest.json', b'C:/manifest.json', b'manifest.json:stream',
    b'CON', b'con.json', b'COM1.json', b'LPT9', b'manifest.json.',
    b'manifest.json ', b'mani?fest.json', b'mani|fest.json',
    b'x'*129, b'unknown.json', b'projections/findings/not-an-id.json',
])
def test_forbidden_names_rejected_before_inventory(setup, tmp_path, name):
    path = tmp_path/'bad-name.zip'
    AssessmentExporter(setup[0]).export(path)
    rename_physical(path, b'manifest.json', name)
    reject_before_zipinfo(path)


def test_local_central_name_mismatch(setup, tmp_path):
    path = tmp_path/'mismatch.zip'
    AssessmentExporter(setup[0]).export(path)
    rename_physical(path, b'manifest.json', b'Manifest.json', local_only=True)
    reject_before_zipinfo(path)


def test_zipinfo_original_name_defense(setup, tmp_path):
    path = tmp_path/'original.zip'
    AssessmentExporter(setup[0]).export(path)
    original = zipfile.ZipFile
    class ChangedInventory(original):
        def infolist(self):
            infos = super().infolist()
            infos[0].orig_filename += '\x00PRIVATE_MARKER_FILENAME'
            return infos
    with patch('aegis.assessment_package.zipfile.ZipFile', ChangedInventory):
        with pytest.raises(StorageIntegrityError):
            AssessmentPackageReader().verify(path)


@pytest.mark.parametrize('profile,objects', [('share', False), ('forensic', False), ('forensic', True)])
def test_canonical_names_remain_valid(setup, tmp_path, profile, objects):
    path = tmp_path/'canonical.zip'
    AssessmentExporter(setup[0]).export(path, profile=profile, include_objects=objects)
    assert AssessmentPackageReader().verify(path)['package_integrity'] == 'verified'


def test_canonical_zip64_names_preflight(tmp_path):
    path = tmp_path/'zip64.zip'
    with zipfile.ZipFile(path, 'w') as archive:
        for index in range(65536):
            archive.writestr(f'evidence/records/{index:032x}.json', b'')
    with path.open('rb') as stream:
        preflight(stream, PackageLimits(), aegis_paths=True)
