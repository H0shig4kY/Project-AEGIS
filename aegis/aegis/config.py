from aegis.atomic_storage import atomic_write_text

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

        atomic_write_text(self.config_file, yaml.safe_dump(config, sort_keys=False))