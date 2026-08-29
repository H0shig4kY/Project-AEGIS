from pathlib import Path

from aegis.models import Target
from aegis.scope import ScopeEngine
from aegis.storage import ScopeStorage

class ScopeManager:
    def __init__(self, scope_file: Path):
        self.engine = ScopeEngine()
        self.storage = ScopeStorage(scope_file)

        self._load()

    def _load(self) -> None:
        targets = self.storage.load()

        for target in targets:
            self.engine.add(target.value)

    def add(self, value: str) -> Target:
        target = self.engine.add(value)
        self._save()

        return target

    def list(self) -> list[Target]:
        return self.engine.list()

    def remove(self, value: str) -> bool:
        targets = self.engine.list()

        remaining = [
            target
            for target in targets
            if target.value != value
        ]

        if len(remaining) == len(targets):
            return False

        self.engine = ScopeEngine()

        for target in remaining:
            self.engine.add(target.value)

        self._save()

        return True

    def _save(self) -> None:
        self.storage.save(self.engine.list())