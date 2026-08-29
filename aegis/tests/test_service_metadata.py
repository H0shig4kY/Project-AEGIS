import pytest
from pydantic import ValidationError

from aegis.models import (
    FingerprintConfidence,
    FingerprintSource,
    ServiceMetadata,
)


def test_service_metadata():
    metadata = ServiceMetadata(
        host="example.com",
        port=443,
        transport="tcp",
        service_name="https",
        tls=True,
        banner=None,
    )

    assert metadata.host == "example.com"
    assert metadata.port == 443
    assert metadata.transport == "tcp"
    assert metadata.service_name == "https"
    assert metadata.tls is True
    assert metadata.banner is None


def test_service_metadata_defaults():
    metadata = ServiceMetadata(
        host="example.com",
        port=8080,
    )

    assert metadata.transport == "tcp"
    assert metadata.service_name == "unknown"
    assert metadata.tls is False
    assert metadata.banner is None


def test_service_metadata_requires_host():
    with pytest.raises(ValidationError):
        ServiceMetadata(
            port=443,
        )


def test_service_metadata_requires_port():
    with pytest.raises(ValidationError):
        ServiceMetadata(
            host="example.com",
        )


def test_service_metadata_rejects_invalid_port():
    with pytest.raises(ValidationError):
        ServiceMetadata(
            host="example.com",
            port=70000,
        )


def test_service_metadata_rejects_invalid_transport():
    with pytest.raises(ValidationError):
        ServiceMetadata(
            host="example.com",
            port=443,
            transport="banana",
        )

def test_service_metadata_product_and_version():
    metadata = ServiceMetadata(
        host="example.com",
        port=22,
        transport="tcp",
        service_name="ssh",
        tls=False,
        banner="SSH-2.0-OpenSSH_9.6",
        product="OpenSSH",
        version="9.6",
    )

    assert metadata.product == "OpenSSH"
    assert metadata.version == "9.6"

def test_service_metadata_fingerprint_defaults():
    metadata = ServiceMetadata(
        host="example.com",
        port=443,
    )

    assert (
        metadata.confidence
        == FingerprintConfidence.MEDIUM
    )
    assert (
        metadata.fingerprint_source
        == FingerprintSource.PORT
    )

def test_service_metadata_banner_fingerprint():
    metadata = ServiceMetadata(
        host="example.com",
        port=22,
        service_name="ssh",
        banner="SSH-2.0-OpenSSH_9.6",
        product="OpenSSH",
        version="9.6",
        confidence=FingerprintConfidence.HIGH,
        fingerprint_source=FingerprintSource.BANNER,
    )

    assert (
        metadata.confidence
        == FingerprintConfidence.HIGH
    )
    assert (
        metadata.fingerprint_source
        == FingerprintSource.BANNER
    )