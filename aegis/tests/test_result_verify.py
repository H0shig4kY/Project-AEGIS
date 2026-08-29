from aegis.integrity import verify_result_file
from aegis.models import (
    Asset,
    AssetProvenance,
    AssetType,
    IntegrityBaselineType,
)
from aegis.integrity import sha256_file




def test_verify_result_file_ok(
    tmp_path,
):
    path = tmp_path / "result.json"

    path.write_text(
        "AEGIS",
        encoding="utf-8",
    )

    from aegis.integrity import sha256_file

    expected = sha256_file(path)

    asset = Asset(
        value="example.com",
        type=AssetType.DOMAIN,
        source="dns",
        provenance=[
            AssetProvenance(
                plugin="dns",
                observation_type="dns_resolution",
                target="example.com",
                observation_id="obs-1",
                result_id="result-1",
                result_file="result.json",
                result_sha256=expected,
            )
        ],
    )

    status, stored, current = verify_result_file(
        path,
        [asset],
    )

    assert status == "OK"
    assert stored == expected
    assert current == expected


def test_verify_result_file_unknown(
    tmp_path,
):
    path = tmp_path / "legacy.json"

    path.write_text(
        "legacy",
        encoding="utf-8",
    )

    status, stored, current = verify_result_file(
        path,
        [],
    )

    assert status == "UNKNOWN"
    assert stored is None
    assert len(current) == 64


def test_verify_result_file_failed(
    tmp_path,
):
    path = tmp_path / "result.json"

    path.write_text(
        "current",
        encoding="utf-8",
    )

    asset = Asset(
        value="example.com",
        type=AssetType.DOMAIN,
        source="dns",
        provenance=[
            AssetProvenance(
                plugin="dns",
                observation_type="dns_resolution",
                target="example.com",
                observation_id="obs-1",
                result_id="result-1",
                result_file="result.json",
                result_sha256="a" * 64,
            )
        ],
    )

    status, stored, current = verify_result_file(
        path,
        [asset],
    )

    assert status == "FAILED"
    assert stored == "a" * 64
    assert current != stored

def test_verify_result_file_baselined(
    tmp_path,
):
    path = tmp_path / "legacy.json"

    path.write_text(
        "legacy",
        encoding="utf-8",
    )

    expected = sha256_file(path)

    asset = Asset(
        value="example.com",
        type=AssetType.DOMAIN,
        source="dns",
        provenance=[
            AssetProvenance(
                plugin="dns",
                observation_type="dns_resolution",
                target="example.com",
                observation_id=None,
                result_id=None,
                result_file="legacy.json",
                result_sha256=expected,
                integrity_baseline=(
                    IntegrityBaselineType.RETROSPECTIVE
                ),
            )
        ],
    )

    status, stored, current = (
        verify_result_file(
            path,
            [asset],
        )
    )

    assert status == "BASELINED"
    assert stored == expected
    assert current == expected

def test_verify_result_file_original_is_ok(
    tmp_path,
):
    path = tmp_path / "result.json"

    path.write_text(
        "original",
        encoding="utf-8",
    )

    expected = sha256_file(path)

    asset = Asset(
        value="example.com",
        type=AssetType.DOMAIN,
        source="dns",
        provenance=[
            AssetProvenance(
                plugin="dns",
                observation_type="dns_resolution",
                target="example.com",
                observation_id="obs-1",
                result_id="result-1",
                result_file="result.json",
                result_sha256=expected,
                integrity_baseline=(
                    IntegrityBaselineType.ORIGINAL
                ),
            )
        ],
    )

    status, _, _ = verify_result_file(
        path,
        [asset],
    )

    assert status == "OK"