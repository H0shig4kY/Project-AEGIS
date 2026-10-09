from aegis.atomic_storage import atomic_write_text

from pathlib import Path

import yaml

from aegis.models import Target, TargetType

class ScopeStorage:
    def __init__(self, path: Path):
        self.path = path

    def save(self, targets: list[Target]) -> None:
        data = {
            "targets": [
                {
                    "value": target.value,
                    "type": target.type.value,
                }
                for target in targets
            ]
        }

        atomic_write_text(self.path, yaml.safe_dump(data, sort_keys=False))

    def load(self) -> list[Target]:
        if not self.path.exists():
            return []

        with self.path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file) or {}

        return [
            Target(
                value=item["value"],
                type=TargetType(item["type"]),
            )
            for item in data.get("targets", [])
        ]