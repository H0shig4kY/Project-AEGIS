from datetime import (
    datetime,
    timedelta,
    timezone,
)

from aegis.asset_store import AssetStore
from aegis.change_store import ChangeStore
from aegis.asset_lifecycle import (
    AssetLifecycleManager,
)
from aegis.models import (
    Asset,
    AssetType,
    ChangeRecord,
    ChangeType,
)


def make_asset(
    confirmed_at: datetime,
) -> Asset:
    return Asset(
        value="example.com:80",
        type=AssetType.SERVICE,
        source="service",
        first_seen=confirmed_at,
        last_seen=confirmed_at,
        last_confirmed=confirmed_at,
        seen_count=1,
        active=True,
    )


def make_missing(
    detected_at: datetime,
    result_file: str,
) -> ChangeRecord:
    return ChangeRecord(
        change_type=(
            ChangeType.CANDIDATE_MISSING
        ),
        asset_type=AssetType.SERVICE,
        asset_value="example.com:80",
        plugin="service",
        target="example.com",
        detected_at=detected_at,
        current_result=result_file,
    )


def test_asset_lifecycle_first_missing_keeps_active(
    tmp_path,
):
    asset_store = AssetStore(
        tmp_path / "assets"
    )

    change_store = ChangeStore(
        tmp_path / "changes"
    )

    start = datetime(
        2026,
        8,
        29,
        10,
        0,
        tzinfo=timezone.utc,
    )

    asset_store.save(
        make_asset(start)
    )

    manager = AssetLifecycleManager(
        asset_store,
        change_store,
    )

    change = make_missing(
        start + timedelta(minutes=5),
        "service-2.json",
    )

    change_store.save(
        change
    )

    inactive = manager.process_missing(
        change
    )

    assert inactive is None

    asset = asset_store.find(
        asset_type=AssetType.SERVICE,
    )[0]

    assert asset.active is True


def test_asset_lifecycle_second_missing_marks_inactive(
    tmp_path,
):
    asset_store = AssetStore(
        tmp_path / "assets"
    )

    change_store = ChangeStore(
        tmp_path / "changes"
    )

    start = datetime(
        2026,
        8,
        29,
        10,
        0,
        tzinfo=timezone.utc,
    )

    asset_store.save(
        make_asset(start)
    )

    manager = AssetLifecycleManager(
        asset_store,
        change_store,
    )

    first = make_missing(
        start + timedelta(minutes=5),
        "service-2.json",
    )

    change_store.save(
        first
    )

    assert (
        manager.process_missing(first)
        is None
    )

    second = make_missing(
        start + timedelta(minutes=10),
        "service-3.json",
    )

    change_store.save(
        second
    )

    inactive = manager.process_missing(
        second
    )

    assert inactive is not None

    assert (
        inactive.change_type
        == ChangeType.INACTIVE
    )

    assert (
        inactive.asset_type
        == AssetType.SERVICE
    )

    assert (
        inactive.asset_value
        == "example.com:80"
    )

    asset = asset_store.find(
        asset_type=AssetType.SERVICE,
    )[0]

    assert asset.active is False


def test_asset_lifecycle_builds_reactivated_change(
    tmp_path,
):
    asset_store = AssetStore(
        tmp_path / "assets"
    )

    change_store = ChangeStore(
        tmp_path / "changes"
    )

    start = datetime(
        2026,
        8,
        29,
        10,
        0,
        tzinfo=timezone.utc,
    )

    asset_store.save(
        make_asset(start)
    )

    asset = asset_store.find(
        asset_type=AssetType.SERVICE,
    )[0]

    manager = AssetLifecycleManager(
        asset_store,
        change_store,
    )

    change = manager.build_reactivated(
        asset=asset,
        plugin="service",
        target="example.com",
        detected_at=(
            start + timedelta(minutes=20)
        ),
        previous_result="service-3.json",
        current_result="service-4.json",
    )

    assert (
        change.change_type
        == ChangeType.REACTIVATED
    )

    assert (
        change.asset_type
        == AssetType.SERVICE
    )

    assert (
        change.asset_value
        == "example.com:80"
    )

    assert (
        change.plugin
        == "service"
    )

    assert (
        change.target
        == "example.com"
    )