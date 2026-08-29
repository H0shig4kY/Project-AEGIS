from aegis.models import Asset, AssetType
from aegis.results import RejectionReason
from aegis.scope import ScopeEngine

def test_service_allowed_for_exact_domain():
    scope = ScopeEngine()
    scope.add("example.com")

    asset = Asset(
        value="example.com:443",
        type=AssetType.SERVICE,
        source="service-discovery",
    )

    decision = scope.evaluate(asset)

    assert decision.allowed is True
    assert decision.reason is None

def test_service_allowed_for_wildcard_subdomain():
    scope = ScopeEngine()
    scope.add("*.example.com")

    asset = Asset(
        value="api.example.com:443",
        type=AssetType.SERVICE,
        source="service-discovery",
    )

    decision = scope.evaluate(asset)

    assert decision.allowed is True
    assert decision.reason is None

def test_service_allowed_for_exact_ip():
    scope = ScopeEngine()
    scope.add("192.168.1.10")

    asset = Asset(
        value="192.168.1.10:22",
        type=AssetType.SERVICE,
        source="service-discovery",
    )

    decision = scope.evaluate(asset)

    assert decision.allowed is True
    assert decision.reason is None

def test_service_allowed_for_ip_inside_cidr():
    scope = ScopeEngine()
    scope.add("192.168.1.0/24")

    asset = Asset(
        value="192.168.1.50:80",
        type=AssetType.SERVICE,
        source="service-discovery",
    )

    decision = scope.evaluate(asset)

    assert decision.allowed is True
    assert decision.reason is None

def test_service_outside_scope_is_rejected():
    scope = ScopeEngine()
    scope.add("example.com")

    asset = Asset(
        value="evil.com:443",
        type=AssetType.SERVICE,
        source="service-discovery",
    )

    decision = scope.evaluate(asset)

    assert decision.allowed is False
    assert decision.reason == RejectionReason.OUTSIDE_SCOPE

def test_invalid_service_is_rejected():
    scope = ScopeEngine()
    scope.add("example.com")

    asset = Asset(
        value="banana",
        type=AssetType.SERVICE,
        source="service-discovery",
    )

    decision = scope.evaluate(asset)

    assert decision.allowed is False
    assert decision.reason == RejectionReason.UNSUPPORTED_TYPE