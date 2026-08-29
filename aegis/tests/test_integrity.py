from aegis.integrity import (
    sha256_file,
    verify_sha256,
)


def test_sha256_file_is_stable(tmp_path):
    path = tmp_path / "result.json"

    path.write_text(
        '{"status":"ok"}',
        encoding="utf-8",
    )

    first = sha256_file(path)
    second = sha256_file(path)

    assert first == second
    assert len(first) == 64


def test_sha256_changes_when_file_changes(
    tmp_path,
):
    path = tmp_path / "result.json"

    path.write_text(
        '{"status":"ok"}',
        encoding="utf-8",
    )

    first = sha256_file(path)

    path.write_text(
        '{"status":"changed"}',
        encoding="utf-8",
    )

    second = sha256_file(path)

    assert first != second


def test_result_hash_detects_tampering(
    tmp_path,
):
    result = tmp_path / "result.json"

    result.write_text(
        '{"status":"success"}',
        encoding="utf-8",
    )

    original = sha256_file(result)

    result.write_text(
        '{"status":"tampered"}',
        encoding="utf-8",
    )

    modified = sha256_file(result)

    assert original != modified


def test_verify_sha256(tmp_path):
    path = tmp_path / "result.json"

    path.write_text(
        "AEGIS",
        encoding="utf-8",
    )

    expected = sha256_file(path)

    assert verify_sha256(
        path,
        expected,
    ) is True


def test_verify_sha256_detects_change(
    tmp_path,
):
    path = tmp_path / "result.json"

    path.write_text(
        "AEGIS",
        encoding="utf-8",
    )

    expected = sha256_file(path)

    path.write_text(
        "ALTERED",
        encoding="utf-8",
    )

    assert verify_sha256(
        path,
        expected,
    ) is False