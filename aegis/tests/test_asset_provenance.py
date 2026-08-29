from datetime import datetime, timezone

from aegis.models import (
    Asset,
    AssetProvenance,
    AssetType,
)


def test_asset_provenance():
    provenance = AssetProvenance(
        plugin="service",
        plugin_version="0.1.0",
        observation_type="service_open",
        target="example.com",
        observed_at=datetime(
            2026,
            8,
            22,
            tzinfo=timezone.utc,
        ),
        result_file="service-test.json",
        observation_id="obs-test-1",
        result_id="result-test-1",
    )

    assert provenance.plugin == "service"
    assert provenance.plugin_version == "0.1.0"
    assert provenance.observation_type == "service_open"
    assert provenance.target == "example.com"
    assert provenance.result_file == "service-test.json"
    assert provenance.observation_id == "obs-test-1"
    assert provenance.result_id == "result-test-1"


def test_asset_provenance_defaults_to_empty():
    asset = Asset(
        value="example.com",
        type=AssetType.DOMAIN,
        source="dns",
    )

    assert asset.provenance == []


def test_asset_can_store_provenance():
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
                observation_id="obs-test-1",
                result_id="result-test-1",
            )
        ],
    )

    assert len(asset.provenance) == 1
    assert asset.provenance[0].plugin == "service"
    assert (
        asset.provenance[0].observation_id
        == "obs-test-1"
    )