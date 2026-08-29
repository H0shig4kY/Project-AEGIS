from datetime import (
    datetime,
    timedelta,
    timezone,
)

from aegis.change_state import (
    count_missing_since_confirmation,
    should_mark_inactive,
)
from aegis.change_store import ChangeStore
from aegis.models import (
    AssetType,
    ChangeRecord,
    ChangeType,
)


def make_missing(
    current_result: str,
    detected_at: datetime,
) -> ChangeRecord:
    return ChangeRecord(
        change_type=(
            ChangeType.CANDIDATE_MISSING
        ),
        asset_type=AssetType.SERVICE,
        asset_value="example.com:80",
        plugin="service",
        target="example.com",
        current_result=current_result,
        detected_at=detected_at,
    )


def test_one_missing_is_not_inactive(
    tmp_path,
):
    store = ChangeStore(
        tmp_path / "changes"
    )

    confirmed_at = datetime(
        2026,
        8,
        27,
        10,
        0,
        tzinfo=timezone.utc,
    )

    store.save(
        make_missing(
            "service-1.json",
            confirmed_at
            + timedelta(minutes=5),
        )
    )

    count = (
        count_missing_since_confirmation(
            store,
            AssetType.SERVICE,
            "example.com:80",
            confirmed_at,
        )
    )

    assert count == 1

    assert (
        should_mark_inactive(
            store,
            AssetType.SERVICE,
            "example.com:80",
            confirmed_at,
        )
        is False
    )


def test_two_missing_candidates_mark_inactive(
    tmp_path,
):
    store = ChangeStore(
        tmp_path / "changes"
    )

    confirmed_at = datetime(
        2026,
        8,
        27,
        10,
        0,
        tzinfo=timezone.utc,
    )

    store.save(
        make_missing(
            "service-1.json",
            confirmed_at
            + timedelta(minutes=5),
        )
    )

    store.save(
        make_missing(
            "service-2.json",
            confirmed_at
            + timedelta(minutes=10),
        )
    )

    assert (
        should_mark_inactive(
            store,
            AssetType.SERVICE,
            "example.com:80",
            confirmed_at,
        )
        is True
    )


def test_new_confirmation_resets_missing_count(
    tmp_path,
):
    store = ChangeStore(
        tmp_path / "changes"
    )

    start = datetime(
        2026,
        8,
        27,
        10,
        0,
        tzinfo=timezone.utc,
    )

    store.save(
        make_missing(
            "service-1.json",
            start
            + timedelta(minutes=5),
        )
    )

    store.save(
        make_missing(
            "service-2.json",
            start
            + timedelta(minutes=10),
        )
    )

    # Serviço reapareceu depois dos dois
    # missing anteriores.
    new_confirmation = (
        start
        + timedelta(minutes=15)
    )

    store.save(
        make_missing(
            "service-3.json",
            start
            + timedelta(minutes=20),
        )
    )

    count = (
        count_missing_since_confirmation(
            store,
            AssetType.SERVICE,
            "example.com:80",
            new_confirmation,
        )
    )

    assert count == 1

    assert (
        should_mark_inactive(
            store,
            AssetType.SERVICE,
            "example.com:80",
            new_confirmation,
        )
        is False
    )