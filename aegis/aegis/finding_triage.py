import re
from datetime import datetime, timezone
from uuid import uuid4

from aegis.finding_store import FindingStore
from aegis.finding_triage_history_store import FindingTriageHistoryStore
from aegis.models import (
    FindingRecord, FindingTriageEvent, FindingTriageEventType, FindingTriageState,
)


class InvalidTriageTransition(ValueError):
    """The operation is not allowed from the persisted operational state."""


class FindingTriageManager:
    """Manage triage without changing technical lifecycle fields.

    Calls require a complete SHA-256 finding ID. Audit persistence is mandatory.
    This manager follows the existing single-writer JSON store model.
    """

    def __init__(self, store: FindingStore, history_store: FindingTriageHistoryStore):
        if store.path.resolve() == history_store.directory.resolve():
            raise ValueError("Finding and triage history directories must be different")
        self.store = store
        self.history_store = history_store

    def acknowledge(self, finding_id: str, *, actor: str, reason: str) -> FindingRecord:
        return self._transition(finding_id, actor, reason, FindingTriageEventType.ACKNOWLEDGE,
                                (FindingTriageState.OPEN,), FindingTriageState.ACKNOWLEDGED)

    def suppress(self, finding_id: str, *, actor: str, reason: str) -> FindingRecord:
        return self._transition(finding_id, actor, reason, FindingTriageEventType.SUPPRESS,
                                (FindingTriageState.OPEN, FindingTriageState.ACKNOWLEDGED),
                                FindingTriageState.SUPPRESSED)

    def unsuppress(self, finding_id: str, *, actor: str, reason: str) -> FindingRecord:
        return self._transition(finding_id, actor, reason, FindingTriageEventType.UNSUPPRESS,
                                (FindingTriageState.SUPPRESSED,), FindingTriageState.OPEN)

    @staticmethod
    def _text(value: str, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} must be a non-empty string")
        return value.strip()

    def _transition(
        self, finding_id: str, actor: str, reason: str,
        operation: FindingTriageEventType, allowed: tuple[FindingTriageState, ...],
        next_state: FindingTriageState,
    ) -> FindingRecord:
        finding_id = self._text(finding_id, "finding_id")
        if not re.fullmatch(r"[0-9a-f]{64}", finding_id):
            raise ValueError("finding_id must be a complete lowercase SHA-256 hex ID")
        actor = self._text(actor, "actor")
        reason = self._text(reason, "reason")
        record = self.store.get(finding_id)
        if record is None:
            raise LookupError(f"Finding not found: {finding_id}")
        previous = record.triage_state
        if previous not in allowed:
            raise InvalidTriageTransition(
                f"Cannot {operation.value} finding {finding_id} from {previous.value}"
            )
        event = FindingTriageEvent(
            event_id=uuid4().hex, finding_id=record.finding_id, event_type=operation,
            from_state=previous, to_state=next_state,
            detected_at=datetime.now(timezone.utc), actor=actor, reason=reason,
        )
        record.triage_state = next_state
        self.store.save(record)
        try:
            self.history_store.save(event)
        except OSError:
            # Best-effort compensation; two JSON files are not a transaction.
            record.triage_state = previous
            self.store.save(record)
            raise
        return record
