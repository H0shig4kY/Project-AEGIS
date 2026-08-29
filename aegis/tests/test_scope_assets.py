from aegis.models import Asset, AssetType
from aegis.scope import ScopeEngine


def test_domain_asset_is_in_scope():
    scope = ScopeEngine()
    scope.add("example.com")

    asset = Asset(
        value="example.com",
        type=AssetType.DOMAIN,
        source="dns",
    )

    assert scope.is_in_scope(asset) is True


def test_domain_asset_outside_scope():
    scope = ScopeEngine()
    scope.add("example.com")

    asset = Asset(
        value="evil.com",
        type=AssetType.DOMAIN,
        source="dns",
    )

    assert scope.is_in_scope(asset) is False


def test_wildcard_matches_subdomain():
    scope = ScopeEngine()
    scope.add("*.example.com")

    asset = Asset(
        value="www.example.com",
        type=AssetType.DOMAIN,
        source="dns",
    )

    assert scope.is_in_scope(asset) is True


def test_wildcard_matches_nested_subdomain():
    scope = ScopeEngine()
    scope.add("*.example.com")

    asset = Asset(
        value="api.dev.example.com",
        type=AssetType.DOMAIN,
        source="dns",
    )

    assert scope.is_in_scope(asset) is True


def test_wildcard_does_not_match_root_domain():
    scope = ScopeEngine()
    scope.add("*.example.com")

    asset = Asset(
        value="example.com",
        type=AssetType.DOMAIN,
        source="dns",
    )

    assert scope.is_in_scope(asset) is False


def test_ip_is_in_scope():
    scope = ScopeEngine()
    scope.add("192.168.1.10")

    asset = Asset(
        value="192.168.1.10",
        type=AssetType.IP,
        source="dns",
    )

    assert scope.is_in_scope(asset) is True


def test_ip_outside_scope():
    scope = ScopeEngine()
    scope.add("192.168.1.10")

    asset = Asset(
        value="192.168.1.20",
        type=AssetType.IP,
        source="dns",
    )

    assert scope.is_in_scope(asset) is False


def test_ip_inside_cidr_is_in_scope():
    scope = ScopeEngine()
    scope.add("192.168.1.0/24")

    asset = Asset(
        value="192.168.1.50",
        type=AssetType.IP,
        source="dns",
    )

    assert scope.is_in_scope(asset) is True


def test_ip_outside_cidr_is_not_in_scope():
    scope = ScopeEngine()
    scope.add("192.168.1.0/24")

    asset = Asset(
        value="192.168.2.50",
        type=AssetType.IP,
        source="dns",
    )

    assert scope.is_in_scope(asset) is False


def test_unsupported_asset_type_is_not_in_scope():
    scope = ScopeEngine()
    scope.add("example.com")

    asset = Asset(
        value="https://example.com",
        type=AssetType.URL,
        source="dns",
    )

    assert scope.is_in_scope(asset) is False