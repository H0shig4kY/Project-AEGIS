import hashlib
from pathlib import Path

from aegis.models import (
    ChangeRecord,
)


class ChangeStore:
    def __init__(
        self,
        directory: Path,
    ):
        self.directory = directory

        self.directory.mkdir(
            parents=True,
            exist_ok=True,
        )

    def _change_id(
        self,
        change: ChangeRecord,
    ) -> str:
        if change.relation_type is not None:
            identity_parts = [
                change.change_type.value,
                "relation",
                change.relation_type.value,
                (
                    change.source_type.value
                    if change.source_type
                    else ""
                ),
                change.source_value or "",
                (
                    change.target_type.value
                    if change.target_type
                    else ""
                ),
                change.target_value or "",
                change.plugin,
                change.target,
                change.current_result or "",
            ]

        else:
            identity_parts = [
                change.change_type.value,
                "asset",
                (
                    change.asset_type.value
                    if change.asset_type
                    else ""
                ),
                change.asset_value or "",
                change.plugin,
                change.target,
                change.current_result or "",
            ]

        identity = "|".join(
            identity_parts
        )

        return hashlib.sha256(
            identity.encode("utf-8")
        ).hexdigest()

    def _filename(
        self,
        change: ChangeRecord,
    ) -> str:
        return (
            f"{self._change_id(change)}.json"
        )

    def save(
        self,
        change: ChangeRecord,
    ) -> Path:
        self.directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        path = (
            self.directory
            / self._filename(change)
        )

        path.write_text(
            change.model_dump_json(
                indent=2
            ),
            encoding="utf-8",
        )

        return path

    def load(
        self,
        path: Path,
    ) -> ChangeRecord:
        return ChangeRecord.model_validate_json(
            path.read_text(
                encoding="utf-8"
            )
        )

    def list(
        self,
    ) -> list[Path]:
        return sorted(
            self.directory.glob(
                "*.json"
            )
        )

    def find(
        self,
        asset_type=None,
        asset_value: str | None = None,
        change_type=None,
        relation_type=None,
        source_type=None,
        source_value: str | None = None,
        target_type=None,
        target_value: str | None = None,
    ) -> list[ChangeRecord]:
        changes: list[ChangeRecord] = []

        for path in self.list():
            change = self.load(path)

            if (
                asset_type is not None
                and change.asset_type
                != asset_type
            ):
                continue

            if (
                asset_value is not None
                and change.asset_value
                != asset_value
            ):
                continue

            if (
                change_type is not None
                and change.change_type
                != change_type
            ):
                continue

            if (
                relation_type is not None
                and change.relation_type
                != relation_type
            ):
                continue

            if (
                source_type is not None
                and change.source_type
                != source_type
            ):
                continue

            if (
                source_value is not None
                and change.source_value
                != source_value
            ):
                continue

            if (
                target_type is not None
                and change.target_type
                != target_type
            ):
                continue

            if (
                target_value is not None
                and change.target_value
                != target_value
            ):
                continue

            changes.append(
                change
            )

        return changes