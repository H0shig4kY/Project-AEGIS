from datetime import (
    datetime,
    timedelta,
    timezone,
)

from aegis.change_state import (
    count_relation_missing_since_confirmation,
    should_mark_relation_inactive,
)
from aegis.change_store import ChangeStore
from aegis.models import (
    AssetRelationType,
    AssetType,
    ChangeRecord,
    ChangeType,
)


def make_missing(
    detected_at: datetime,
    current_result: str,
) -> ChangeRecord:
    return ChangeRecord(
        change_type=(
            ChangeType.CANDIDATE_MISSING
        ),
        relation_type=(
            AssetRelationType.RESOLVES_TO
        ),
        source_type=AssetType.DOMAIN,
        source_value="example.com",
        target_type=AssetType.IP,
        target_value="192.0.2.10",
        plugin="dns",
        target="example.com",
        detected_at=detected_at,
        current_result=current_result,
    )


def test_one_missing_does_not_inactivate_relation(
    tmp_path,
):
    store = ChangeStore(
        tmp_path / "changes"
    )

    confirmed_at = datetime(
        2026,
        8,
        28,
        10,
        0,
        tzinfo=timezone.utc,
    )

    store.save(
        make_missing(
            confirmed_at
            + timedelta(minutes=5),
            "dns-2.json",
        )
    )

    count = (
        count_relation_missing_since_confirmation(
            store,
            AssetRelationType.RESOLVES_TO,
            AssetType.DOMAIN,
            "example.com",
            AssetType.IP,
            "192.0.2.10",
            confirmed_at,
        )
    )

    assert count == 1

    assert (
        should_mark_relation_inactive(
            store,
            AssetRelationType.RESOLVES_TO,
            AssetType.DOMAIN,
            "example.com",
            AssetType.IP,
            "192.0.2.10",
            confirmed_at,
        )
        is False
    )


def test_two_missing_inactivate_relation(
    tmp_path,
):
    store = ChangeStore(
        tmp_path / "changes"
    )

    confirmed_at = datetime(
        2026,
        8,
        28,
        10,
        0,
        tzinfo=timezone.utc,
    )

    store.save(
        make_missing(
            confirmed_at
            + timedelta(minutes=5),
            "dns-2.json",
        )
    )

    store.save(
        make_missing(
            confirmed_at
            + timedelta(minutes=10),
            "dns-3.json",
        )
    )

    assert (
        should_mark_relation_inactive(
            store,
            AssetRelationType.RESOLVES_TO,
            AssetType.DOMAIN,
            "example.com",
            AssetType.IP,
            "192.0.2.10",
            confirmed_at,
        )
        is True
    )


def test_new_confirmation_resets_relation_missing_count(
    tmp_path,
):
    store = ChangeStore(
        tmp_path / "changes"
    )

    start = datetime(
        2026,
        8,
        28,
        10,
        0,
        tzinfo=timezone.utc,
    )

    store.save(
        make_missing(
            start
            + timedelta(minutes=5),
            "dns-2.json",
        )
    )

    store.save(
        make_missing(
            start
            + timedelta(minutes=10),
            "dns-3.json",
        )
    )

    new_confirmation = (
        start
        + timedelta(minutes=15)
    )

    store.save(
        make_missing(
            start
            + timedelta(minutes=20),
            "dns-4.json",
        )
    )

    count = (
        count_relation_missing_since_confirmation(
            store,
            AssetRelationType.RESOLVES_TO,
            AssetType.DOMAIN,
            "example.com",
            AssetType.IP,
            "192.0.2.10",
            new_confirmation,
        )
    )

    assert count == 1

    assert (
        should_mark_relation_inactive(
            store,
            AssetRelationType.RESOLVES_TO,
            AssetType.DOMAIN,
            "example.com",
            AssetType.IP,
            "192.0.2.10",
            new_confirmation,
        )
        is False
    )