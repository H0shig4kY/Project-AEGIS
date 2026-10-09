from aegis.atomic_storage import atomic_write_text, locked_directory, read_json, StorageIntegrityError

import json

from datetime import datetime
from pathlib import Path

from aegis.models import (
    AssetType,
    FindingEvent,
    FindingEventType,
    FindingState,
)


class FindingHistoryStore:
    def __init__(
        self,
        directory: Path,
    ):
        self.directory = directory

        self.directory.mkdir(
            parents=True,
            exist_ok=True,
        )

    @locked_directory("directory")
    def save(
        self,
        event: FindingEvent,
    ) -> Path:
        path = (
            self.directory
            / f"{event.event_id}.json"
        )

        payload = {
            "event_id": (
                event.event_id
            ),
            "finding_id": (
                event.finding_id
            ),
            "event_type": (
                event.event_type.value
            ),
            "from_state": (
                event.from_state.value
                if event.from_state
                else None
            ),
            "to_state": (
                event.to_state.value
            ),
            "detected_at": (
                event.detected_at.isoformat()
            ),
            "plugin": (
                event.plugin
            ),
            "rule_id": (
                event.rule_id
            ),
            "asset_type": (
                event.asset_type.value
                if event.asset_type
                else None
            ),
            "asset_value": (
                event.asset_value
            ),
        }

        if path.exists():
            if read_json(path) != payload:
                raise StorageIntegrityError(f"Conflicting technical event: {path}")
            return path

        atomic_write_text(path,
            json.dumps(
                payload,
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )

        return path

    def get(
        self,
        event_id: str,
    ) -> FindingEvent | None:
        path = (
            self.directory
            / f"{event_id}.json"
        )

        if not path.exists():
            return None

        return self._load(
            path
        )

    def find(
        self,
    ) -> list[FindingEvent]:
        events = [
            self._load(path)
            for path
            in self.directory.glob(
                "*.json"
            )
        ]

        events.sort(
            key=lambda event: (
                event.detected_at,
                event.event_id,
            )
        )

        return events

    def find_by_finding_id(
        self,
        finding_id: str,
    ) -> list[FindingEvent]:
        return [
            event
            for event
            in self.find()
            if (
                event.finding_id
                == finding_id
            )
        ]

    def _load(
        self,
        path: Path,
    ) -> FindingEvent:
        payload = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )

        from_state = (
            FindingState(
                payload["from_state"]
            )
            if payload.get(
                "from_state"
            )
            is not None
            else None
        )

        asset_type = (
            AssetType(
                payload["asset_type"]
            )
            if payload.get(
                "asset_type"
            )
            is not None
            else None
        )

        return FindingEvent(
            event_id=(
                payload["event_id"]
            ),
            finding_id=(
                payload["finding_id"]
            ),
            event_type=(
                FindingEventType(
                    payload[
                        "event_type"
                    ]
                )
            ),
            from_state=(
                from_state
            ),
            to_state=(
                FindingState(
                    payload[
                        "to_state"
                    ]
                )
            ),
            detected_at=(
                datetime.fromisoformat(
                    payload[
                        "detected_at"
                    ]
                )
            ),
            plugin=(
                payload.get(
                    "plugin"
                )
            ),
            rule_id=(
                payload.get(
                    "rule_id"
                )
            ),
            asset_type=(
                asset_type
            ),
            asset_value=(
                payload.get(
                    "asset_value"
                )
            ),
        )