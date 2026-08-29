from aegis.asset_extractor import (
    assets_from_observation,
)
from aegis.results import Observation
from aegis.models import AssetType

def test_dns_observation_creates_domain_and_ips():
    observation = Observation(
        target="example.com",
        type="dns_resolution",
        data={
            "addresses": [
                "192.0.2.10",
                "192.0.2.11",
            ]
        },
    )

    assets = assets_from_observation(
        observation
    )

    assert len(assets) == 3

    assert assets[0].value == "example.com"
    assert assets[0].type.value == "domain"
    assert assets[0].source == "dns"

    assert assets[1].value == "192.0.2.10"
    assert assets[1].type.value == "ip"

    assert assets[2].value == "192.0.2.11"
    assert assets[2].type.value == "ip"

def test_dns_observation_without_addresses():
    observation = Observation(
        target="example.com",
        type="dns_resolution",
        data={
            "addresses": []
        },
    )

    assets = assets_from_observation(
        observation
    )

    assert len(assets) == 1
    assert assets[0].value == "example.com"

def test_unknown_observation_creates_no_assets():
    observation = Observation(
        target="example.com",
        type="unknown",
        data={},
    )

    assets = assets_from_observation(
        observation
    )

    assert assets == []

def test_http_observation_creates_url_asset():
    observation = Observation(
        target="example.com",
        type="http_probe",
        data={
            "url": "https://example.com/",
            "status_code": 200,
        },
    )

    assets = assets_from_observation(
        observation
    )

    assert len(assets) == 1
    assert assets[0].value == "https://example.com/"
    assert assets[0].type == AssetType.URL
    assert assets[0].source == "http"

def test_service_observation_creates_service_asset():
    observation = Observation(
        target="example.com",
        type="service_open",
        data={
            "host": "example.com",
            "port": 443,
            "transport": "tcp",
            "service_name": "https",
            "tls": True,
            "banner": "test-banner",
        },
    )

    assets = assets_from_observation(
        observation
    )

    assert len(assets) == 1

    asset = assets[0]

    assert asset.value == "example.com:443"
    assert asset.type == AssetType.SERVICE
    assert asset.source == "service"

    assert asset.metadata["host"] == "example.com"
    assert asset.metadata["port"] == 443
    assert asset.metadata["transport"] == "tcp"
    assert asset.metadata["service_name"] == "https"
    assert asset.metadata["tls"] is True
    assert asset.metadata["banner"] == "test-banner"

def test_tls_handshake_creates_service_and_certificate_assets():
    observation = Observation(
        target="example.com",
        type="tls_handshake",
        data={
            "host": "example.com",
            "port": 443,
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "subject": (
                (("commonName", "example.com"),),
            ),
            "issuer": (
                (("commonName", "Example CA"),),
            ),
            "valid_from": (
                "Jan 1 00:00:00 2026 GMT"
            ),
            "valid_to": (
                "Jan 1 00:00:00 2027 GMT"
            ),
            "sans": [
                "example.com",
                "*.example.com",
            ],
            "certificate_sha256": "a" * 64,
        },
    )

    assets = assets_from_observation(
        observation
    )

    assert len(assets) == 2

    service = assets[0]

    assert service.type == AssetType.SERVICE
    assert service.value == "example.com:443"
    assert service.source == "tls"

    assert service.metadata["tls"] is True
    assert (
        service.metadata["tls_version"]
        == "TLSv1.3"
    )

    certificate = assets[1]

    assert (
        certificate.type
        == AssetType.CERTIFICATE
    )

    assert certificate.value == "a" * 64
    assert certificate.source == "tls"

    assert (
        certificate.metadata["sha256"]
        == "a" * 64
    )

    assert (
        certificate.metadata["presented_by"]
        == "example.com:443"
    )

    assert certificate.metadata["sans"] == [
        "example.com",
        "*.example.com",
    ]