from __future__ import annotations

import json

from pathlib import Path

from aegis.models import (
    AssetType,
    FindingRecord,
    FindingState,
)


class FindingStore:
    """
    Persistent store for exposure finding lifecycle records.

    Each finding is stored as an individual JSON file using its
    deterministic finding ID as the filename.
    """

    def __init__(
        self,
        path: Path,
    ):
        self.path = Path(
            path
        )

        self.path.mkdir(
            parents=True,
            exist_ok=True,
        )

    # -------------------------------------------------
    # SERIALIZATION
    # -------------------------------------------------

    @staticmethod
    def _serialize(
        record: FindingRecord,
    ) -> dict:
        return {
            "finding_id": (
                record.finding_id
            ),
            "rule_id": (
                record.rule_id
            ),
            "severity": (
                record.severity
            ),
            "title": (
                record.title
            ),
            "description": (
                record.description
            ),
            "asset_type": (
                record.asset_type.value
            ),
            "asset_value": (
                record.asset_value
            ),
            "affected_service": (
                record.affected_service
            ),
            "plugin": (
                record.plugin
            ),
                        "coverage_plugins": list(
                record.coverage_plugins
            ),
            "state": (
                record.state.value
            ),
            "first_seen": (
                record.first_seen.isoformat()
                if record.first_seen
                else None
            ),
            "last_seen": (
                record.last_seen.isoformat()
                if record.last_seen
                else None
            ),
            "last_confirmed": (
                record.last_confirmed.isoformat()
                if record.last_confirmed
                else None
            ),
            "seen_count": (
                record.seen_count
            ),
            "missing_count": (
                record.missing_count
            ),
            "active": (
                record.active
            ),
        }

    @staticmethod
    def _deserialize(
        data: dict,
    ) -> FindingRecord:
        from datetime import (
            datetime,
        )

        first_seen = (
            datetime.fromisoformat(
                data["first_seen"]
            )
            if data.get(
                "first_seen"
            )
            else None
        )

        last_seen = (
            datetime.fromisoformat(
                data["last_seen"]
            )
            if data.get(
                "last_seen"
            )
            else None
        )

        last_confirmed = (
            datetime.fromisoformat(
                data["last_confirmed"]
            )
            if data.get(
                "last_confirmed"
            )
            else None
        )

        return FindingRecord(
            finding_id=(
                data["finding_id"]
            ),
            rule_id=(
                data["rule_id"]
            ),
            severity=(
                data["severity"]
            ),
            title=(
                data["title"]
            ),
            description=(
                data["description"]
            ),
            asset_type=AssetType(
                data["asset_type"]
            ),
            asset_value=(
                data["asset_value"]
            ),
            affected_service=(
                data.get(
                    "affected_service"
                )
            ),
            plugin=(
                data.get(
                    "plugin"
                )
            ),
            coverage_plugins=tuple(
                data.get(
                    "coverage_plugins",
                    [],
                )
            ),
            state=FindingState(
                data.get(
                    "state",
                    FindingState.ACTIVE.value,
                )
            ),
            first_seen=(
                first_seen
            ),
            last_seen=(
                last_seen
            ),
            last_confirmed=(
                last_confirmed
            ),
            seen_count=int(
                data.get(
                    "seen_count",
                    0,
                )
            ),
            missing_count=int(
                data.get(
                    "missing_count",
                    0,
                )
            ),
            active=bool(
                data.get(
                    "active",
                    True,
                )
            ),
        )

    # -------------------------------------------------
    # PATH
    # -------------------------------------------------

    def _record_path(
        self,
        finding_id: str,
    ) -> Path:
        return (
            self.path
            / f"{finding_id}.json"
        )

    # -------------------------------------------------
    # SAVE
    # -------------------------------------------------

    def save(
        self,
        record: FindingRecord,
    ) -> Path:
        path = self._record_path(
            record.finding_id
        )

        payload = self._serialize(
            record
        )

        path.write_text(
            json.dumps(
                payload,
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )

        return path

    # -------------------------------------------------
    # GET
    # -------------------------------------------------

    def get(
        self,
        finding_id: str,
    ) -> FindingRecord | None:
        path = self._record_path(
            finding_id
        )

        if not path.exists():
            return None

        try:
            data = json.loads(
                path.read_text(
                    encoding="utf-8",
                )
            )
        except (
            OSError,
            json.JSONDecodeError,
        ):
            return None

        return self._deserialize(
            data
        )

    # -------------------------------------------------
    # FIND
    # -------------------------------------------------

    def find(
        self,
    ) -> list[FindingRecord]:
        records: list[
            FindingRecord
        ] = []

        if not self.path.exists():
            return records

        for path in sorted(
            self.path.glob(
                "*.json"
            )
        ):
            try:
                data = json.loads(
                    path.read_text(
                        encoding="utf-8",
                    )
                )

                record = (
                    self._deserialize(
                        data
                    )
                )

            except (
                OSError,
                json.JSONDecodeError,
                KeyError,
                TypeError,
                ValueError,
            ):
                continue

            records.append(
                record
            )

        return records

    # -------------------------------------------------
    # PREFIX LOOKUP
    # -------------------------------------------------

    def find_by_id(
        self,
        finding_id: str,
    ) -> FindingRecord | None:
        """
        Resolve a complete finding ID or a unique ID prefix.
        """

        normalized = (
            finding_id
            .strip()
            .lower()
        )

        if not normalized:
            return None

        matches = [
            record
            for record
            in self.find()
            if (
                record.finding_id
                .lower()
                .startswith(
                    normalized
                )
            )
        ]

        if len(
            matches
        ) != 1:
            return None

        return matches[0]