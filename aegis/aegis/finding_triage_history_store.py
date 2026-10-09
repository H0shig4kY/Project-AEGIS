import json
import re
from datetime import datetime, timezone
from pathlib import Path

from aegis.models import FindingTriageEvent, FindingTriageEventType, FindingTriageState


class FindingTriageHistoryStore:
    """Dedicated operational history; never use the technical history directory."""

    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def _event_path(self, event_id: str) -> Path:
        if not isinstance(event_id, str) or not re.fullmatch(r"[0-9a-f]{32}", event_id):
            raise ValueError("event_id must be a UUID hex string")
        return self.directory / f"{event_id}.json"

    def save(self, event: FindingTriageEvent) -> Path:
        path = self._event_path(event.event_id)
        if event.detected_at.tzinfo is None or event.detected_at.utcoffset() is None:
            raise ValueError("detected_at must be timezone-aware")
        payload = {
            "event_id": event.event_id,
            "finding_id": event.finding_id,
            "event_type": event.event_type.value,
            "from_state": event.from_state.value,
            "to_state": event.to_state.value,
            "detected_at": event.detected_at.astimezone(timezone.utc).isoformat(),
            "actor": event.actor,
            "reason": event.reason,
        }
        content = json.dumps(payload, indent=2, sort_keys=True)
        # Exclusive creation protects existing events against accidental overwrite.
        with path.open("x", encoding="utf-8") as stream:
            try:
                stream.write(content)
            except OSError:
                path.unlink(missing_ok=True)
                raise
        return path

    def get(self, event_id: str) -> FindingTriageEvent | None:
        path = self._event_path(event_id)
        return self._load(path) if path.exists() else None

    def find(self) -> list[FindingTriageEvent]:
        events = [self._load(path) for path in self.directory.glob("*.json")]
        return sorted(events, key=lambda event: (event.detected_at, event.event_id))

    def find_by_finding_id(self, finding_id: str) -> list[FindingTriageEvent]:
        return [event for event in self.find() if event.finding_id == finding_id]

    @staticmethod
    def _load(path: Path) -> FindingTriageEvent:
        payload = json.loads(path.read_text(encoding="utf-8"))
        detected_at = datetime.fromisoformat(payload["detected_at"])
        if detected_at.tzinfo is None or detected_at.utcoffset() is None:
            raise ValueError("detected_at must be timezone-aware")
        return FindingTriageEvent(
            event_id=payload["event_id"], finding_id=payload["finding_id"],
            event_type=FindingTriageEventType(payload["event_type"]),
            from_state=FindingTriageState(payload["from_state"]),
            to_state=FindingTriageState(payload["to_state"]),
            detected_at=detected_at.astimezone(timezone.utc),
            actor=payload["actor"], reason=payload["reason"],
        )
