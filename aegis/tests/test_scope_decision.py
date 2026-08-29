from aegis.models import Asset, AssetType
from aegis.results import RejectionReason
from aegis.scope import ScopeEngine

def test_domain_inside_scope_is_allowed():
    scope = ScopeEngine()
    scope.add("example.com")

    asset = Asset(
        value="example.com",
        type=AssetType.DOMAIN,
        source="dns",
    )

    decision = scope.evaluate(asset)

    assert decision.allowed is True
    assert decision.reason is None

def test_domain_outside_scope_is_rejected():
    scope = ScopeEngine()
    scope.add("example.com")

    asset = Asset(
        value="evil.com",
        type=AssetType.DOMAIN,
        source="dns",
    )

    decision = scope.evaluate(asset)

    assert decision.allowed is False
    assert decision.reason == RejectionReason.OUTSIDE_SCOPE

def test_ip_outside_cidr_is_rejected():
    scope = ScopeEngine()
    scope.add("192.168.1.0/24")

    asset = Asset(
        value="192.168.2.10",
        type=AssetType.IP,
        source="dns",
    )

    decision = scope.evaluate(asset)

    assert decision.allowed is False
    assert decision.reason == RejectionReason.OUTSIDE_SCOPE

def test_url_inside_scope_is_allowed():
    scope = ScopeEngine()
    scope.add("example.com")

    asset = Asset(
        value="https://example.com",
        type=AssetType.URL,
        source="http",
    )

    decision = scope.evaluate(asset)

    assert decision.allowed is True
    assert decision.reason is None

def test_service_inside_scope_is_allowed():
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