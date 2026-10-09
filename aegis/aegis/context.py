from pathlib import Path


class CampaignContext:
    def __init__(self, path: Path):
        self.path = path.resolve()

    @property
    def config_file(self) -> Path:
        return self.path / "aegis.yaml"

    @property
    def scope_file(self) -> Path:
        return self.path / "scope.yaml"

    @property
    def data_dir(self) -> Path:
        return self.path / "data"

    @property
    def findings_dir(self) -> Path:
        return (
            self.data_dir
            / "findings"
        )

    @property
    def finding_history_dir(self) -> Path:
        return (
            self.data_dir
            / "finding_history"
        )

    @property
    def finding_triage_history_dir(self) -> Path:
        return self.data_dir / "finding_triage_history"

    @property
    def evidence_dir(self) -> Path:
        return self.path / "evidence"

    @property
    def reports_dir(self) -> Path:
        return self.path / "reports"

    def is_valid(self) -> bool:
        return self.config_file.exists()


def find_campaign(
    start: Path | None = None,
) -> CampaignContext | None:
    current = (
        start or Path.cwd()
    ).resolve()

    for directory in [
        current,
        *current.parents,
    ]:
        config = (
            directory
            / "aegis.yaml"
        )

        if config.exists():
            return CampaignContext(
                directory
            )

    return None