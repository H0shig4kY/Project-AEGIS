from aegis.models import Target, TargetType
from aegis.scope import ScopeEngine

def test_add_target():
    scope = ScopeEngine()

    target = Target(
        value="example.com",
        type=TargetType.DOMAIN,
    )

    scope.add(target.value)

    assert scope.contains("example.com")

def test_unknown_target_is_not_in_scope():
    scope = ScopeEngine()

    scope.add("example.com")

    assert not scope.contains("other.example.com")

def test_domain_is_detected():
    scope = ScopeEngine()

    target = scope.add("example.com")

    assert target.type == TargetType.DOMAIN

def test_ip_is_detected():
    scope = ScopeEngine()

    target = scope.add("192.168.1.10")

    assert target.type == TargetType.IP

def test_cidr_is_detected():
    scope = ScopeEngine()

    target = scope.add("192.168.1.0/24")

    assert target.type == TargetType.CIDR