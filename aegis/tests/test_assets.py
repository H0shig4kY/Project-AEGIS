import pytest
from pydantic import ValidationError

from aegis.models import Asset, AssetType

def test_domain_asset():
    asset = Asset(
        value="example.com",
        type=AssetType.DOMAIN,
        source="dns",
    )

    assert asset.value == "example.com"
    assert asset.type == AssetType.DOMAIN
    assert asset.source == "dns"

def test_ip_asset():
    asset = Asset(
        value="192.0.2.10",
        type=AssetType.IP,
        source="dns",
    )

    assert asset.value == "192.0.2.10"
    assert asset.type == AssetType.IP
    assert asset.source == "dns"

def test_url_asset():
    asset = Asset(
        value="https://example.com",
        type=AssetType.URL,
        source="http",
    )

    assert asset.type == AssetType.URL

def test_service_asset():
    asset = Asset(
        value="example.com:443",
        type=AssetType.SERVICE,
        source="service-discovery",
    )

    assert asset.type == AssetType.SERVICE

def test_asset_requires_source():
    with pytest.raises(ValidationError):
        Asset(
            value="example.com",
            type=AssetType.DOMAIN,
        )

def test_asset_metadata_defaults_to_empty():
    asset = Asset(
        value="example.com",
        type=AssetType.DOMAIN,
        source="dns",
    )

    assert asset.metadata == {}

def test_service_asset_can_store_metadata():
    asset = Asset(
        value="example.com:443",
        type=AssetType.SERVICE,
        source="service",
        metadata={
            "service_name": "https",
            "tls": True,
            "banner": None,
        },
    )

    assert asset.metadata["service_name"] == "https"
    assert asset.metadata["tls"] is True