from pathlib import Path

import yaml

class AegisConfig:
    def __init__(self, root: Path):
        self.root = root
        self.config_file = root / "aegis.yaml"

    def create(self) -> None:
        config = {
            "name": self.root.name,
            "version": "0.1",
            "type": "pentest-campaign",
        }

        with self.config_file.open("w", encoding="utf-8") as file:
            yaml.safe_dump(config, file, sort_keys=False)