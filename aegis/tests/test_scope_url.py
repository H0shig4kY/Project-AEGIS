from aegis.models import Asset, AssetType
from aegis.results import RejectionReason
from aegis.scope import ScopeEngine

def test_https_url_allowed_for_exact_domain():
    scope = ScopeEngine()
    scope.add("example.com")

    asset = Asset(
        value="https://example.com/",
        type=AssetType.URL,
        source="http",
    )

    decision = scope.evaluate(asset)

    assert decision.allowed is True
    assert decision.reason is None

def test_http_url_allowed_for_exact_domain():
    scope = ScopeEngine()
    scope.add("example.com")

    asset = Asset(
        value="http://example.com/test",
        type=AssetType.URL,
        source="http",
    )

    decision = scope.evaluate(asset)

    assert decision.allowed is True
    assert decision.reason is None

def test_subdomain_url_allowed_by_wildcard():
    scope = ScopeEngine()
    scope.add("*.example.com")

    asset = Asset(
        value="https://api.example.com/",
        type=AssetType.URL,
        source="http",
    )

    decision = scope.evaluate(asset)

    assert decision.allowed is True
    assert decision.reason is None

def test_url_outside_scope_is_rejected():
    scope = ScopeEngine()
    scope.add("example.com")

    asset = Asset(
        value="https://evil.com/",
        type=AssetType.URL,
        source="http",
    )

    decision = scope.evaluate(asset)

    assert decision.allowed is False
    assert decision.reason == RejectionReason.OUTSIDE_SCOPE

def test_unsupported_url_scheme_is_rejected():
    scope = ScopeEngine()
    scope.add("example.com")

    asset = Asset(
        value="ftp://example.com/",
        type=AssetType.URL,
        source="http",
    )

    decision = scope.evaluate(asset)

    assert decision.allowed is False
    assert decision.reason == RejectionReason.UNSUPPORTED_TYPE

def test_invalid_url_is_rejected():
    scope = ScopeEngine()
    scope.add("example.com")

    asset = Asset(
        value="not-a-url",
        type=AssetType.URL,
        source="http",
    )

    decision = scope.evaluate(asset)

    assert decision.allowed is False
    assert decision.reason == RejectionReason.UNSUPPORTED_TYPE