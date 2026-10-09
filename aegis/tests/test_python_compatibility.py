"""Import and annotation regressions across the supported Python versions."""

import subprocess
import sys
from pathlib import Path
from typing import get_type_hints

from aegis.change_store import ChangeStore
from aegis.models import AssetRelation, ChangeRecord
from aegis.relation_store import RelationStore


def test_all_package_modules_import_in_fresh_interpreter():
    # Include namespace plugin directories, which pkgutil.walk_packages skips.
    package = Path(__file__).resolve().parents[1] / "aegis"
    modules = sorted(
        ".".join(("aegis", *path.relative_to(package).with_suffix("").parts))
        for path in package.rglob("*.py")
        if path.name != "__init__.py"
    )
    result = subprocess.run(
        [sys.executable, "-c", "import importlib, sys; "
         "[importlib.import_module(name) for name in sys.argv[1:]]", *modules],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_store_annotations_resolve_to_builtin_lists():
    assert get_type_hints(ChangeStore.find)["return"] == list[ChangeRecord]
    assert get_type_hints(RelationStore.find)["return"] == list[AssetRelation]
    assert get_type_hints(RelationStore.walk_from)["return"] == list[
        tuple[int, AssetRelation]
    ]
