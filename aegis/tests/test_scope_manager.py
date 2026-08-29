from pathlib import Path

from aegis.models import TargetType
from aegis.scope_manager import ScopeManager

def test_manager_add_and_list(tmp_path: Path):
    scope_file = tmp_path / "scope.yaml"

    manager = ScopeManager(scope_file)

    target = manager.add("example.com")

    assert target.type == TargetType.DOMAIN

    targets = manager.list()

    assert len(targets) == 1
    assert targets[0].value == "example.com"

def test_manager_persists_targets(tmp_path: Path):
    scope_file = tmp_path / "scope.yaml"

    manager = ScopeManager(scope_file)

    manager.add("example.com")
    manager.add("192.168.1.10")

    new_manager = ScopeManager(scope_file)

    targets = new_manager.list()

    assert len(targets) == 2
    assert targets[0].value == "example.com"
    assert targets[1].value == "192.168.1.10"

def test_manager_remove(tmp_path: Path):
    scope_file = tmp_path / "scope.yaml"

    manager = ScopeManager(scope_file)

    manager.add("example.com")
    manager.add("192.168.1.10")

    removed = manager.remove("example.com")

    assert removed is True
    assert not manager.engine.contains("example.com")
    assert manager.engine.contains("192.168.1.10")

def test_remove_unknown_target(tmp_path: Path):
    scope_file = tmp_path / "scope.yaml"

    manager = ScopeManager(scope_file)

    manager.add("example.com")

    removed = manager.remove("unknown.example.com")

    assert removed is False