from pathlib import Path

from aegis.models import TargetType
from aegis.storage import ScopeStorage

def test_save_and_load_scope(tmp_path: Path):
    scope_file = tmp_path / "scope.yaml"

    storage = ScopeStorage(scope_file)

    targets = [
        storage_target("example.com", TargetType.DOMAIN),
        storage_target("192.168.1.10", TargetType.IP),
        storage_target("192.168.1.0/24", TargetType.CIDR),
    ]

    storage.save(targets)

    loaded = storage.load()

    assert len(loaded) == 3

    assert loaded[0].value == "example.com"
    assert loaded[0].type == TargetType.DOMAIN

    assert loaded[1].value == "192.168.1.10"
    assert loaded[1].type == TargetType.IP

    assert loaded[2].value == "192.168.1.0/24"
    assert loaded[2].type == TargetType.CIDR

def storage_target(value: str, target_type: TargetType):
    from aegis.models import Target

    return Target(
        value=value,
        type=target_type,
    )

def test_wildcard_persistence(tmp_path: Path):
    from aegis.models import Target

    scope_file = tmp_path / "scope.yaml"

    storage = ScopeStorage(scope_file)

    targets = [
        Target(
            value="*.example.com",
            type=TargetType.WILDCARD,
        )
    ]

    storage.save(targets)

    loaded = storage.load()

    assert len(loaded) == 1
    assert loaded[0].value == "*.example.com"
    assert loaded[0].type == TargetType.WILDCARD