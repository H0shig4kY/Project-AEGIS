from datetime import (
    datetime,
    timezone,
)

from aegis.asset_store import AssetStore
from aegis.models import (
    Asset,
    AssetType,
)


def test_new_asset_lifecycle(tmp_path):
    store = AssetStore(tmp_path)

    observed_at = datetime(
        2026,
        8,
        24,
        10,
        0,
        tzinfo=timezone.utc,
    )

    asset = Asset(
        value="example.com:443",
        type=AssetType.SERVICE,
        source="service",
        first_seen=observed_at,
        last_seen=observed_at,
        seen_count=1,
    )

    path = store.save(asset)
    stored = store.load(path)

    assert stored.first_seen == observed_at
    assert stored.last_seen == observed_at
    assert stored.seen_count == 1


def test_existing_asset_updates_lifecycle(
    tmp_path,
):
    store = AssetStore(tmp_path)

    first = datetime(
        2026,
        8,
        24,
        10,
        0,
        tzinfo=timezone.utc,
    )

    second = datetime(
        2026,
        8,
        24,
        11,
        0,
        tzinfo=timezone.utc,
    )

    store.save(
        Asset(
            value="example.com:443",
            type=AssetType.SERVICE,
            source="service",
            first_seen=first,
            last_seen=first,
            seen_count=1,
        )
    )

    path = store.save(
        Asset(
            value="example.com:443",
            type=AssetType.SERVICE,
            source="service",
            first_seen=second,
            last_seen=second,
            seen_count=1,
        )
    )

    stored = store.load(path)

    assert stored.first_seen == first
    assert stored.last_seen == second
    assert stored.seen_count == 2

def test_lifecycle_preserves_earliest_first_seen(
    tmp_path,
):
    store = AssetStore(tmp_path)

    newer = datetime(
        2026,
        8,
        24,
        12,
        0,
        tzinfo=timezone.utc,
    )

    older = datetime(
        2026,
        8,
        24,
        9,
        0,
        tzinfo=timezone.utc,
    )

    store.save(
        Asset(
            value="example.com:443",
            type=AssetType.SERVICE,
            source="service",
            first_seen=newer,
            last_seen=newer,
            seen_count=1,
        )
    )

    path = store.save(
        Asset(
            value="example.com:443",
            type=AssetType.SERVICE,
            source="service",
            first_seen=older,
            last_seen=older,
            seen_count=1,
        )
    )

    stored = store.load(path)

    assert stored.first_seen == older
    assert stored.last_seen == newer
    assert stored.seen_count == 2