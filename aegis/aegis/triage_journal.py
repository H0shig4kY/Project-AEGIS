"""Retained triage intents/receipts. Caller must hold FindingStore.transaction()."""

import json
import os
import re
from pathlib import Path

from aegis.atomic_storage import atomic_write_text, read_json, sync_directory, StorageIntegrityError
from aegis.finding_triage_history_store import FindingTriageHistoryStore
from aegis.models import FindingTriageState


def _entries(store):
    directory = store.path / ".triage-journal"
    if not directory.exists():
        return []
    entries = []
    for path in directory.glob("*.txn"):
        try:
            data = read_json(path)
            event = data["event"]
            if (data["version"] != 1 or data["status"] not in
                    {"pending", "done", "abort", "aborted"} or
                    not isinstance(data["sequence"], int) or data["sequence"] < 1 or
                    not re.fullmatch(r"[0-9a-f]{32}", event["event_id"]) or
                    path.stem != event["event_id"] or
                    not re.fullmatch(r"[0-9a-f]{64}", event["finding_id"]) or
                    not isinstance(data["history_directory"], str) or
                    Path(data["history_directory"]).is_absolute()):
                raise ValueError("invalid journal fields")
            FindingTriageState(event["from_state"])
            FindingTriageState(event["to_state"])
            # Validate all event fields before any recovery writes.
            if FindingTriageHistoryStore._serialize(_decode_event(event)) != event:
                raise ValueError("noncanonical journal event")
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            raise StorageIntegrityError(f"Invalid triage journal {path}: {error}") from error
        entries.append((path, data))
    entries.sort(key=lambda item: item[1]["sequence"])
    sequences = [data["sequence"] for _, data in entries]
    if len(set(sequences)) != len(sequences):
        raise StorageIntegrityError(f"Duplicate journal sequence in {directory}")
    expected = {}
    for path, data in entries:
        event = data["event"]
        finding_id = event["finding_id"]
        if finding_id in expected and event["from_state"] != expected[finding_id]:
            raise StorageIntegrityError(f"Contradictory triage journal chain: {path}")
        expected[finding_id] = (event["from_state"] if data["status"] in
                                {"abort", "aborted"} else event["to_state"])
    return entries


def _decode_event(payload):
    from datetime import datetime, timezone
    from aegis.models import FindingTriageEvent, FindingTriageEventType
    timestamp = datetime.fromisoformat(payload["detected_at"])
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("journal timestamp must be timezone-aware")
    for field in ("actor", "reason"):
        if not isinstance(payload[field], str) or not payload[field].strip():
            raise ValueError(f"invalid journal {field}")
    event = FindingTriageEvent(
        event_id=payload["event_id"], finding_id=payload["finding_id"],
        event_type=FindingTriageEventType(payload["event_type"]),
        from_state=FindingTriageState(payload["from_state"]),
        to_state=FindingTriageState(payload["to_state"]),
        detected_at=timestamp.astimezone(timezone.utc),
        actor=payload["actor"], reason=payload["reason"],
    )
    allowed = {
        "acknowledge": {( "open", "acknowledged")},
        "suppress": {("open", "suppressed"), ("acknowledged", "suppressed")},
        "unsuppress": {("suppressed", "open")},
    }
    if (event.from_state.value, event.to_state.value) not in allowed[event.event_type.value]:
        raise ValueError("invalid journal transition")
    return event


def begin(store, history, event):
    entries = _entries(store)
    directory = store.path / ".triage-journal"
    directory.mkdir(parents=True, exist_ok=True)
    sync_directory(store.path)
    path = directory / f"{event.event_id}.txn"
    data = {
        "version": 1, "sequence": max((d["sequence"] for _, d in entries), default=0) + 1,
        "status": "pending",
        "history_directory": os.path.relpath(history.directory.resolve(), store.path.resolve()),
        "event": history._serialize(event),
    }
    atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True), exclusive=True)
    return path, data


def finish(path, data, status="done"):
    updated = dict(data, status=status)
    atomic_write_text(path, json.dumps(updated, indent=2, sort_keys=True))
    data["status"] = status


def _history(store, data):
    return FindingTriageHistoryStore((store.path / data["history_directory"]).resolve())


def event_exists(store, data):
    history = _history(store, data)
    path = history._event_path(data["event"]["event_id"])
    if not path.exists():
        return False
    existing = read_json(path)
    if existing != data["event"]:
        raise StorageIntegrityError(f"Conflicting triage event: {path}")
    return True


def _set_state(store, data, state):
    finding_id = data["event"]["finding_id"]
    path = store._record_path(finding_id)
    if not path.exists():
        raise StorageIntegrityError(f"Missing finding for triage recovery: {path}")
    payload = read_json(path)
    try:
        record = store._deserialize(payload)
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        raise StorageIntegrityError(f"Invalid finding during recovery: {path}") from error
    if record.finding_id != finding_id:
        raise StorageIntegrityError(f"Finding ID mismatch during recovery: {path}")
    if record.triage_state.value not in (data["event"]["from_state"], data["event"]["to_state"]):
        raise StorageIntegrityError(f"Unexpected finding state during recovery: {path}")
    if record.triage_state.value != state:
        # Preserve current technical fields, unknown JSON fields, and evidence.
        payload["triage_state"] = state
        atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True))


def abort(store, path, data):
    # Abort only if there is no published audit event. Never delete an event.
    if event_exists(store, data):
        return False
    finish(path, data, "abort")
    _set_state(store, data, data["event"]["from_state"])
    finish(path, data, "aborted")
    return True


def recover(store):
    entries = _entries(store)
    latest = {}
    for path, data in entries:
        status = data["status"]
        if status == "abort":
            if event_exists(store, data):
                raise StorageIntegrityError(f"Aborted operation has an audit event: {path}")
            _set_state(store, data, data["event"]["from_state"])
            finish(path, data, "aborted")
            status = "aborted"
        if status == "aborted":
            if event_exists(store, data):
                raise StorageIntegrityError(f"Aborted operation has an audit event: {path}")
            latest[data["event"]["finding_id"]] = data
            continue
        present = event_exists(store, data)
        if status == "pending":
            _set_state(store, data, data["event"]["to_state"])
        history = _history(store, data)
        if not present:
            history.save(_decode_event(data["event"]))
        if status == "pending":
            finish(path, data)
        latest[data["event"]["finding_id"]] = data
    for finding_id, data in latest.items():
        record = store._get(finding_id)
        expected = (data["event"]["from_state"] if data["status"] == "aborted"
                    else data["event"]["to_state"])
        if record is None or record.triage_state.value != expected:
            raise StorageIntegrityError(f"Finding/journal state divergence: {finding_id}")


def validate_save(store, record):
    latest = None
    for _, data in _entries(store):
        if data["event"]["finding_id"] == record.finding_id:
            latest = data
    expected = None if latest is None else (
        latest["event"]["from_state"] if latest["status"] in {"abort", "aborted"}
        else latest["event"]["to_state"])
    if latest and record.triage_state.value != expected:
        raise StorageIntegrityError(f"Refusing stale triage state write: {record.finding_id}")
