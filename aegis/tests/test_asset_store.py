from pathlib import Path
from datetime import datetime, timezone

from aegis.asset_store import AssetStore
from aegis.models import (
    Asset,
    AssetProvenance,
    AssetType,
    IntegrityBaselineType,
)

def create_asset() -> Asset:
    return Asset(
        value="example.com",
        type=AssetType.DOMAIN,
        source="dns",
    )

def test_save_asset(tmp_path: Path):
    store = AssetStore(
        tmp_path / "assets"
    )

    asset = create_asset()

    path = store.save(asset)

    assert path.exists()
    assert path.suffix == ".json"
    assert path.parent == tmp_path / "assets"

def test_list_assets(tmp_path: Path):
    store = AssetStore(
        tmp_path / "assets"
    )

    store.save(create_asset())

    store.save(
        Asset(
            value="192.0.2.10",
            type=AssetType.IP,
            source="dns",
        )
    )

    assets = store.list()

    assert len(assets) == 2

def test_load_asset(tmp_path: Path):
    store = AssetStore(
        tmp_path / "assets"
    )

    original = create_asset()

    path = store.save(original)

    loaded = store.load(path)

    assert loaded.value == "example.com"
    assert loaded.type == AssetType.DOMAIN
    assert loaded.source == "dns"

def test_same_asset_uses_same_path(tmp_path: Path):
    store = AssetStore(
        tmp_path / "assets"
    )

    first = store.save(create_asset())
    second = store.save(create_asset())

    assert first == second
    assert len(store.list()) == 1

def test_find_by_type(tmp_path):
    store = AssetStore(
        tmp_path / "assets"
    )

    store.save(
        Asset(
            value="example.com",
            type=AssetType.DOMAIN,
            source="dns",
        )
    )

    store.save(
        Asset(
            value="192.0.2.10",
            type=AssetType.IP,
            source="dns",
        )
    )

    assets = store.find(
        asset_type=AssetType.IP
    )

    assert len(assets) == 1
    assert assets[0].value == "192.0.2.10"

def test_find_by_source(tmp_path):
    store = AssetStore(
        tmp_path / "assets"
    )

    store.save(
        Asset(
            value="example.com",
            type=AssetType.DOMAIN,
            source="dns",
        )
    )

    store.save(
        Asset(
            value="https://example.com",
            type=AssetType.URL,
            source="http",
        )
    )

    assets = store.find(
        source="dns"
    )

    assert len(assets) == 1
    assert assets[0].value == "example.com"

def test_provenance_is_deduplicated_by_ids(
    tmp_path,
):
    store = AssetStore(
        tmp_path / "assets"
    )

    provenance = AssetProvenance(
        plugin="service",
        plugin_version="0.1.0",
        observation_type="service_open",
        target="example.com",
        observation_id="obs-1",
        result_id="result-1",
    )

    first = Asset(
        value="example.com:443",
        type=AssetType.SERVICE,
        source="service",
        provenance=[
            provenance,
        ],
    )

    second = Asset(
        value="example.com:443",
        type=AssetType.SERVICE,
        source="service",
        provenance=[
            provenance,
        ],
    )

    store.save(first)
    path = store.save(second)

    stored = store.load(path)

    assert len(stored.provenance) == 1

def test_existing_provenance_can_be_enriched(
    tmp_path,
):
    store = AssetStore(
        tmp_path / "assets"
    )

    first = Asset(
        value="example.com:443",
        type=AssetType.SERVICE,
        source="service",
        provenance=[
            AssetProvenance(
                plugin="service",
                plugin_version="0.1.0",
                observation_type="service_open",
                target="example.com",
                observation_id="obs-1",
                result_id="result-1",
                result_file="service-test.json",
            )
        ],
    )

    store.save(first)

    second = Asset(
        value="example.com:443",
        type=AssetType.SERVICE,
        source="service",
        provenance=[
            AssetProvenance(
                plugin="service",
                plugin_version="0.1.0",
                observation_type="service_open",
                target="example.com",
                observation_id="obs-1",
                result_id="result-1",
                result_file="service-test.json",
                result_sha256="a" * 64,
                integrity_baseline=(
                    IntegrityBaselineType.RETROSPECTIVE
                ),
            )
        ],
    )

    path = store.save(second)
    stored = store.load(path)

    assert len(stored.provenance) == 1

    provenance = stored.provenance[0]

    assert provenance.result_sha256 == "a" * 64
    assert (
        provenance.integrity_baseline
        == IntegrityBaselineType.RETROSPECTIVE
    )

def test_legacy_provenance_is_deduplicated(
    tmp_path,
):
    store = AssetStore(
        tmp_path / "assets"
    )

    observed_at = datetime(
        2026,
        8,
        24,
        tzinfo=timezone.utc,
    )

    provenance = AssetProvenance(
        plugin="service",
        plugin_version="0.1.0",
        observation_type="service_open",
        target="example.com",
        observed_at=observed_at,
        observation_id="legacy",
        result_file="legacy-result.json",
    )

    asset = Asset(
        value="example.com:443",
        type=AssetType.SERVICE,
        source="service",
        provenance=[
            provenance,
            provenance.model_copy(),
        ],
    )

    store.save(asset)

    path = (
        store.directory
        / "service-example.com_443.json"
    )

    loaded = store.load(path)

    assert len(loaded.provenance) == 1
    assert loaded.seen_count == 1
    assert loaded.first_seen == observed_at
    assert loaded.last_seen == observed_at

def test_asset_store_marks_asset_active_and_confirmed(
    tmp_path,
):
    store = AssetStore(
        tmp_path / "assets"
    )

    observed_at = datetime(
        2026,
        8,
        25,
        15,
        0,
        tzinfo=timezone.utc,
    )

    asset = Asset(
        value="example.com",
        type=AssetType.DOMAIN,
        source="dns",
        provenance=[
            AssetProvenance(
                plugin="dns",
                plugin_version="0.1.0",
                observation_type="dns_resolution",
                target="example.com",
                observed_at=observed_at,
                observation_id="obs-1",
                result_id="result-1",
            )
        ],
    )

    path = store.save(asset)
    stored = store.load(path)

    assert stored.active is True
    assert stored.last_confirmed == observed_at

def test_asset_store_reactivates_asset(
    tmp_path,
):
    store = AssetStore(
        tmp_path / "assets"
    )

    first_seen = datetime(
        2026,
        8,
        25,
        14,
        0,
        tzinfo=timezone.utc,
    )

    asset = Asset(
        value="example.com",
        type=AssetType.DOMAIN,
        source="dns",
        active=False,
        provenance=[
            AssetProvenance(
                plugin="dns",
                plugin_version="0.1.0",
                observation_type="dns_resolution",
                target="example.com",
                observed_at=first_seen,
                observation_id="obs-old",
                result_id="result-old",
            )
        ],
    )

    path = store.save(asset)

    stored = store.load(path)

    # Forçar estado inativo histórico.
    stored.active = False

    path.write_text(
        stored.model_dump_json(indent=2),
        encoding="utf-8",
    )

    rediscovered_at = datetime(
        2026,
        8,
        25,
        15,
        0,
        tzinfo=timezone.utc,
    )

    rediscovered = Asset(
        value="example.com",
        type=AssetType.DOMAIN,
        source="dns",
        provenance=[
            AssetProvenance(
                plugin="dns",
                plugin_version="0.1.0",
                observation_type="dns_resolution",
                target="example.com",
                observed_at=rediscovered_at,
                observation_id="obs-new",
                result_id="result-new",
            )
        ],
    )

    path = store.save(rediscovered)
    stored = store.load(path)

    assert stored.active is True
    assert (
        stored.last_confirmed
        == rediscovered_at
    )
    assert stored.seen_count == 2

def test_asset_store_can_mark_asset_inactive(
    tmp_path,
):
    store = AssetStore(
        tmp_path / "assets"
    )

    asset = Asset(
        value="example.com:80",
        type=AssetType.SERVICE,
        source="service",
    )

    store.save(asset)

    updated = store.set_active(
        AssetType.SERVICE,
        "example.com:80",
        False,
    )

    assert updated is not None
    assert updated.active is False

    loaded = store.load(
        store.list()[0]
    )

    assert loaded.active is False

def test_asset_store_can_reactivate_with_set_active(
    tmp_path,
):
    store = AssetStore(
        tmp_path / "assets"
    )

    asset = Asset(
        value="example.com:80",
        type=AssetType.SERVICE,
        source="service",
    )

    store.save(asset)

    store.set_active(
        AssetType.SERVICE,
        "example.com:80",
        False,
    )

    updated = store.set_active(
        AssetType.SERVICE,
        "example.com:80",
        True,
    )

    assert updated is not None
    assert updated.active is True