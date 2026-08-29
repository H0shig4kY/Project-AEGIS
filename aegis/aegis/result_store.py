import json
from datetime import datetime, timezone
from pathlib import Path

from aegis.results import PluginResult

class ResultStore:
    def __init__(self, directory: Path):
        self.directory = directory
        self.directory.mkdir(
            parents=True,
            exist_ok=True,
        )

    def save(self, result: PluginResult) -> Path:
        timestamp = datetime.now(
            timezone.utc
        ).strftime("%Y%m%d-%H%M%S-%f")

        filename = (
            f"{result.plugin}-{timestamp}.json"
        )

        path = self.directory / filename

        path.write_text(
            result.model_dump_json(indent=2),
            encoding="utf-8",
        )

        return path

    def list(self) -> list[Path]:
        return sorted(
            self.directory.glob("*.json")
        )

    def load(self, path: Path) -> PluginResult:
        data = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )

        return PluginResult.model_validate(data)