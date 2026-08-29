from aegis.models import (
    Asset,
    AssetType,
)
from aegis.results import RejectionReason
from aegis.scope import ScopeEngine


def test_certificate_allowed_for_in_scope_domain():
    scope = ScopeEngine()
    scope.add("example.com")

    asset = Asset(
        value="a" * 64,
        type=AssetType.CERTIFICATE,
        source="tls",
        metadata={
            "host": "example.com",
        },
    )

    decision = scope.evaluate(asset)

    assert decision.allowed is True
    assert decision.reason is None


def test_certificate_rejected_for_out_of_scope_domain():
    scope = ScopeEngine()
    scope.add("example.com")

    asset = Asset(
        value="a" * 64,
        type=AssetType.CERTIFICATE,
        source="tls",
        metadata={
            "host": "evil.com",
        },
    )

    decision = scope.evaluate(asset)

    assert decision.allowed is False
    assert (
        decision.reason
        == RejectionReason.OUTSIDE_SCOPE
    )


def test_certificate_allowed_for_in_scope_ip():
    scope = ScopeEngine()
    scope.add("192.168.1.0/24")

    asset = Asset(
        value="a" * 64,
        type=AssetType.CERTIFICATE,
        source="tls",
        metadata={
            "host": "192.168.1.50",
        },
    )

    assert scope.evaluate(asset).allowed is True


def test_certificate_without_host_is_unsupported():
    scope = ScopeEngine()
    scope.add("example.com")

    asset = Asset(
        value="a" * 64,
        type=AssetType.CERTIFICATE,
        source="tls",
        metadata={},
    )

    decision = scope.evaluate(asset)

    assert decision.allowed is False
    assert (
        decision.reason
        == RejectionReason.UNSUPPORTED_TYPE
    )