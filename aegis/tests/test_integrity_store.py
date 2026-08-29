from datetime import datetime, timezone

from aegis.integrity_store import IntegrityStore
from aegis.models import IntegrityBaselineType


def test_integrity_store_upsert(tmp_path):
    store = IntegrityStore(
        tmp_path / "integrity"
    )

    created_at = datetime(
        2026,
        8,
        24,
        tzinfo=timezone.utc,
    )

    store.upsert(
        filename="result.json",
        sha256="a" * 64,
        baseline_type=(
            IntegrityBaselineType.ORIGINAL
        ),
        created_at=created_at,
    )

    record = store.get(
        "result.json"
    )

    assert record is not None
    assert record.sha256 == "a" * 64
    assert (
        record.baseline_type
        == IntegrityBaselineType.ORIGINAL
    )


def test_integrity_store_updates_existing(
    tmp_path,
):
    store = IntegrityStore(
        tmp_path / "integrity"
    )

    created_at = datetime.now(
        timezone.utc
    )

    store.upsert(
        filename="result.json",
        sha256="a" * 64,
        baseline_type=(
            IntegrityBaselineType.RETROSPECTIVE
        ),
        created_at=created_at,
    )

    store.upsert(
        filename="result.json",
        sha256="b" * 64,
        baseline_type=(
            IntegrityBaselineType.ORIGINAL
        ),
        created_at=created_at,
    )

    record = store.get(
        "result.json"
    )

    assert record is not None
    assert record.sha256 == "b" * 64
    assert (
        record.baseline_type
        == IntegrityBaselineType.ORIGINAL
    )

def test_integrity_store_manifest_summary_data(
    tmp_path,
):
    store = IntegrityStore(
        tmp_path / "integrity"
    )

    now = datetime.now(
        timezone.utc
    )

    store.upsert(
        filename="original.json",
        sha256="a" * 64,
        baseline_type=(
            IntegrityBaselineType.ORIGINAL
        ),
        created_at=now,
    )

    store.upsert(
        filename="legacy.json",
        sha256="b" * 64,
        baseline_type=(
            IntegrityBaselineType.RETROSPECTIVE
        ),
        created_at=now,
    )

    manifest = store.load()

    assert len(manifest.results) == 2

    original = [
        record
        for record in manifest.results
        if record.baseline_type
        == IntegrityBaselineType.ORIGINAL
    ]

    retrospective = [
        record
        for record in manifest.results
        if record.baseline_type
        == IntegrityBaselineType.RETROSPECTIVE
    ]

    assert len(original) == 1
    assert len(retrospective) == 1

def test_integrity_store_mark_verified(
    tmp_path,
):
    store = IntegrityStore(
        tmp_path / "integrity"
    )

    now = datetime.now(
        timezone.utc
    )

    store.upsert(
        filename="result.json",
        sha256="a" * 64,
        baseline_type=(
            IntegrityBaselineType.ORIGINAL
        ),
        created_at=now,
    )

    store.mark_verified(
        "result.json"
    )

    record = store.get(
        "result.json"
    )

    assert record is not None
    assert record.verified_at is not None