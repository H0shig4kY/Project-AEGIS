import pytest

from aegis.models import TargetType
from aegis.scope import ScopeEngine

@pytest.mark.parametrize(
    "value, expected_type",
    [
        ("example.com", TargetType.DOMAIN),
        ("sub.example.com", TargetType.DOMAIN),
        ("192.168.1.10", TargetType.IP),
        ("2001:db8::1", TargetType.IP),
        ("192.168.1.0/24", TargetType.CIDR),
        ("2001:db8::/32", TargetType.CIDR),
    ],
)
def test_valid_targets(value, expected_type):
    scope = ScopeEngine()

    target = scope.add(value)

    assert target.type == expected_type

def test_wildcard_domain():
    scope = ScopeEngine()

    target = scope.add("*.example.com")

    assert target.type == TargetType.WILDCARD

@pytest.mark.parametrize(
    "value",
    [
        "",
        "banana",
        "example",
        "http://example.com",
        "https://example.com",
        "192.168.1.999",
        "192.168.1.1/999",
    ],
)
def test_invalid_targets(value):
    scope = ScopeEngine()

    with pytest.raises(ValueError):
        scope.add(value)