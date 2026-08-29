from aegis.asset_store import AssetStore
from aegis.models import (
    Asset,
    AssetProvenance,
    AssetType,
)


def test_asset_provenance_can_store_result_hash(
    tmp_path,
):
    store = AssetStore(
        tmp_path / "assets"
    )

    asset = Asset(
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
            )
        ],
    )

    path = store.save(asset)
    stored = store.load(path)

    assert (
        stored.provenance[0].result_sha256
        == "a" * 64
    )