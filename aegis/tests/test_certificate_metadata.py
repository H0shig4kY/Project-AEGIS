import pytest
from pydantic import ValidationError

from aegis.models import CertificateMetadata


def test_certificate_metadata():
    metadata = CertificateMetadata(
        host="example.com",
        port=443,
        subject=None,
        issuer=None,
        valid_from="start",
        valid_to="end",
        sans=[
            "example.com",
            "*.example.com",
        ],
        sha256="a" * 64,
        presented_by="example.com:443",
    )

    assert metadata.host == "example.com"
    assert metadata.port == 443
    assert metadata.sha256 == "a" * 64
    assert (
        metadata.presented_by
        == "example.com:443"
    )


def test_certificate_metadata_sans_default():
    metadata = CertificateMetadata(
        host="example.com",
        sha256="a" * 64,
        presented_by="example.com:443",
    )

    assert metadata.sans == []

def test_certificate_metadata_rejects_invalid_sha256():
    with pytest.raises(ValidationError):
        CertificateMetadata(
            host="example.com",
            sha256="invalid",
            presented_by="example.com:443",
        )