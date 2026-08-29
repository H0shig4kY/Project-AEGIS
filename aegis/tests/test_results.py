from datetime import datetime

from aegis.results import Observation, PluginResult, ProcessingResult, RejectedAsset
from aegis.models import Asset, AssetType

def test_observation():
    observation = Observation(
        target="example.com",
        type="dns_resolution",
        data={
            "addresses": [
                "192.0.2.10",
            ]
        },
    )

    assert observation.target == "example.com"
    assert observation.type == "dns_resolution"
    assert observation.data["addresses"] == [
        "192.0.2.10"
    ]

def test_plugin_result():
    result = PluginResult(
        plugin="dns",
        version="0.1.0",
        observations=[
            Observation(
                target="example.com",
                type="dns_resolution",
                data={
                    "addresses": [
                        "192.0.2.10",
                    ]
                },
            )
        ],
    )

    assert result.plugin == "dns"
    assert result.version == "0.1.0"
    assert result.status == "success"
    assert len(result.observations) == 1
    assert isinstance(result.timestamp, datetime)

def test_empty_plugin_result():
    result = PluginResult(
        plugin="dns",
        version="0.1.0",
    )

    assert result.observations == []

def test_processing_result_counts():
    accepted_asset = Asset(
        value="example.com",
        type=AssetType.DOMAIN,
        source="dns",
    )

    rejected_asset = Asset(
        value="192.0.2.10",
        type=AssetType.IP,
        source="dns",
    )

    result = ProcessingResult(
        accepted=[
            accepted_asset,
        ],
        rejected=[
            RejectedAsset(
                asset=rejected_asset,
                reason="outside_scope",
            )
        ],
    )

    assert result.discovered_count == 2
    assert result.accepted_count == 1
    assert result.rejected_count == 1

    assert result.rejected[0].asset.value == "192.0.2.10"
    assert result.rejected[0].reason == "outside_scope"