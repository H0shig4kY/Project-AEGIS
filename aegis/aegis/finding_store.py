from __future__ import annotations

import json
from contextlib import contextmanager

from aegis.atomic_storage import (
    atomic_write_text, directory_lock, read_json, StorageIntegrityError,
)

from pathlib import Path

from aegis.models import (
    AssetType,
    FindingRecord,
    FindingState,
    FindingTriageState,
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

    @contextmanager
    def transaction(self):
        """Cooperative finding read/modify/write scope with journal recovery."""
        with directory_lock(self.path) as nested:
            if not nested:
                from aegis.triage_journal import recover
                recover(self)
            yield

    def save(self, record: FindingRecord) -> Path:
        with self.transaction():
            from aegis.triage_journal import validate_save
            validate_save(self, record)
            return self._save(record)

    def get(self, finding_id: str) -> FindingRecord | None:
        with self.transaction():
            return self._get(finding_id)

    def find(self) -> list[FindingRecord]:
        with self.transaction():
            return self._find()

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
            "triage_state": (
                record.triage_state.value
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
            triage_state=FindingTriageState(
                data.get(
                    "triage_state",
                    FindingTriageState.OPEN.value,
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

    def _save(
        self,
        record: FindingRecord,
    ) -> Path:
        path = self._record_path(
            record.finding_id
        )

        if path.exists():
            self._get(record.finding_id)

        payload = self._serialize(
            record
        )

        atomic_write_text(path,
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

    def _get(
        self,
        finding_id: str,
    ) -> FindingRecord | None:
        path = self._record_path(
            finding_id
        )

        if not path.exists():
            return None

        try:
            record = self._deserialize(read_json(path))
            if record.finding_id != finding_id:
                raise ValueError("Finding ID mismatch")
            return record
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            raise StorageIntegrityError(f"Invalid finding in {path}: {error}") from error

    # -------------------------------------------------
    # FIND
    # -------------------------------------------------

    def _find(
        self,
    ) -> list[FindingRecord]:
        records: list[
            FindingRecord
        ] = []

        if not self.path.exists():
            return records

        for path in sorted(self.path.glob("*.json")):
            try:
                record = self._deserialize(read_json(path))
                if record.finding_id != path.stem:
                    raise ValueError("Finding ID mismatch")
            except (KeyError, TypeError, ValueError, AttributeError) as error:
                raise StorageIntegrityError(f"Invalid finding in {path}: {error}") from error
            records.append(record)

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