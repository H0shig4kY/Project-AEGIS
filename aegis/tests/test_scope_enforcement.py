from aegis.models import Asset, AssetType
from aegis.scope import ScopeEngine


def test_in_scope_domain_is_accepted():
    scope = ScopeEngine()
    scope.add("example.com")

    asset = Asset(
        value="example.com",
        type=AssetType.DOMAIN,
        source="dns",
    )

    assert scope.is_in_scope(asset) is True


def test_out_of_scope_domain_is_rejected():
    scope = ScopeEngine()
    scope.add("example.com")

    asset = Asset(
        value="evil.com",
        type=AssetType.DOMAIN,
        source="dns",
    )

    assert scope.is_in_scope(asset) is False


def test_wildcard_subdomain_is_accepted():
    scope = ScopeEngine()
    scope.add("*.example.com")

    asset = Asset(
        value="api.example.com",
        type=AssetType.DOMAIN,
        source="dns",
    )

    assert scope.is_in_scope(asset) is True


def test_ip_inside_cidr_is_accepted():
    scope = ScopeEngine()
    scope.add("192.168.1.0/24")

    asset = Asset(
        value="192.168.1.50",
        type=AssetType.IP,
        source="dns",
    )

    assert scope.is_in_scope(asset) is True


def test_ip_outside_cidr_is_rejected():
    scope = ScopeEngine()
    scope.add("192.168.1.0/24")

    asset = Asset(
        value="192.168.2.50",
        type=AssetType.IP,
        source="dns",
    )

    assert scope.is_in_scope(asset) is False


def test_unsupported_asset_type_is_rejected():
    scope = ScopeEngine()
    scope.add("example.com")

    asset = Asset(
        value="https://example.com",
        type=AssetType.URL,
        source="dns",
    )

    assert scope.is_in_scope(asset) is False