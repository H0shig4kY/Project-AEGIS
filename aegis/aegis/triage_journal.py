"""Retained triage intents/receipts. Caller must hold FindingStore.transaction()."""

import json
import os
import re
import threading
from contextlib import contextmanager
from pathlib import Path

from aegis.atomic_storage import atomic_write_text, read_json, sync_directory, StorageIntegrityError
from aegis.finding_triage_history_store import FindingTriageHistoryStore
from aegis.models import FindingTriageState


class _Cache:
    """Disposable per-store cache. Source bytes, never metadata, validate reuse."""

    def __init__(self, root):
        self.pid = os.getpid()
        self.root = root
        self.receipts = {}
        self.entries = None
        self.latest = {}
        self.sequence = 0
        self.events = {}


class _View:
    """One validated snapshot held only while the finding lock is held."""

    def __init__(self, entries, cache):
        self.cache = cache
        self.event_keys = set()
        self.entries = entries
        self.latest = {}
        self.sequence = 0
        self.histories = {}
        if entries is cache.entries:
            self.latest = dict(cache.latest)
            self.sequence = cache.sequence
        else:
            for _, data in entries:
                self.latest[data["event"]["finding_id"]] = data
                self.sequence = max(self.sequence, data["sequence"])


_scopes = threading.local()


@contextmanager
def transaction_view(store):
    """Share the view across store instances under the same directory lock.

    A caught nested failure invalidates the scope, so the next public operation
    recovers source files before reusing any view. Caller holds directory_lock.
    """
    if getattr(_scopes, "pid", None) != os.getpid():
        _scopes.pid = os.getpid()
        _scopes.active = {}
    key = os.path.normcase(str(store.path.resolve()))
    active = _scopes.active
    scope = active.get(key)
    owner = scope is None
    if owner:
        scope = active[key] = {"view": None, "dirty": True}
    # Only an active nested scope may own a previous view.
    previous = None if owner else getattr(store, "_triage_view", None)
    try:
        if scope["dirty"]:
            recover(store)
            scope["view"] = store._triage_view
            scope["dirty"] = False
        store._triage_view = scope["view"]
        yield
    except BaseException:
        scope["dirty"] = True
        raise
    finally:
        store._triage_view = previous
        if owner:
            active.pop(key, None)


def _cache(store):
    root = str(store.path.resolve())
    cache = getattr(store, "_triage_cache", None)
    if not isinstance(cache, _Cache) or cache.pid != os.getpid() or cache.root != root:
        cache = store._triage_cache = _Cache(root)
    return cache


def _parse(raw, path):
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as error:
        raise StorageIntegrityError(f"Invalid JSON in {path}: {error}") from error


def _validate_receipt(path, data):
    try:
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
        if FindingTriageHistoryStore._serialize(_decode_event(event)) != event:
            raise ValueError("noncanonical journal event")
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise StorageIntegrityError(f"Invalid triage journal {path}: {error}") from error


def _summarize(entries):
    latest = {}
    for _, data in entries:
        latest[data["event"]["finding_id"]] = data
    sequence = entries[-1][1]["sequence"] if entries else 0
    return latest, sequence


def _entries(store):
    cache = _cache(store)
    directory = store.path / ".triage-journal"
    current = {}
    entries = []
    changed = cache.entries is None
    try:
        scan = os.scandir(directory)
    except FileNotFoundError:
        cache.receipts = {}
        cache.entries = []
        cache.latest = {}
        cache.sequence = 0
        return cache.entries
    with scan:
        for item in scan:
            if not item.name.endswith(".txn"):
                continue
            # Read even when size/mtime/inode match: metadata is not a generation.
            with open(item.path, "rb") as stream:
                raw = stream.read()
            old = cache.receipts.get(item.name)
            if old is not None and old[1] == raw:
                path, _, data = old
                current[item.name] = old
            else:
                changed = True
                path = Path(item.path)
                data = _parse(raw, path)
                _validate_receipt(path, data)
                current[item.name] = (path, raw, data)
            entries.append((path, data))
    if not changed and len(current) == len(cache.receipts):
        # Every current source byte and the complete filename set matched.
        # Reuse the proof for this exact set, not a metadata-based assertion.
        return cache.entries
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
    # Build all derived data before replacing a previous validated snapshot.
    latest, sequence = _summarize(entries)
    cache.receipts = current
    cache.entries = entries
    cache.latest = latest
    cache.sequence = sequence
    return entries


def _view(store):
    view = getattr(store, "_triage_view", None)
    return view if view is not None else _View(_entries(store), _cache(store))


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
    view = _view(store)
    directory = store.path / ".triage-journal"
    directory.mkdir(parents=True, exist_ok=True)
    sync_directory(store.path)
    path = directory / f"{event.event_id}.txn"
    data = {
        "version": 1, "sequence": view.sequence + 1,
        "status": "pending",
        "history_directory": os.path.relpath(history.directory.resolve(), store.path.resolve()),
        "event": history._serialize(event),
    }
    atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True), exclusive=True)
    view.sequence = data["sequence"]
    view.latest[event.finding_id] = data
    return path, data


def finish(path, data, status="done"):
    updated = dict(data, status=status)
    atomic_write_text(path, json.dumps(updated, indent=2, sort_keys=True))
    data["status"] = status


def _history(store, data):
    # Resolved once per relative directory per outer transaction. Do not cache
    # resolved symlink targets across transactions.
    view = getattr(store, "_triage_view", None)
    key = data["history_directory"]
    if view is not None and key in view.histories:
        return view.histories[key]
    history = FindingTriageHistoryStore((store.path / key).resolve())
    if view is not None:
        view.histories[key] = history
    return history


def event_exists(store, data):
    history = _history(store, data)
    # Receipt validation (or the manager) has already validated the UUID.
    path = os.path.join(str(history.directory), data["event"]["event_id"] + ".json")
    view = getattr(store, "_triage_view", None)
    cache = view.cache if view is not None else _cache(store)
    key = path
    if view is not None:
        view.event_keys.add(key)
    try:
        with open(path, "rb") as stream:
            raw = stream.read()
    except FileNotFoundError:
        cache.events.pop(key, None)
        return False
    old = cache.events.get(key)
    existing = old[1] if old is not None and old[0] == raw else _parse(raw, path)
    if existing != data["event"]:
        raise StorageIntegrityError(f"Conflicting triage event: {path}")
    # Equality was checked above. Keep the validated receipt's canonical object
    # rather than a duplicate parsed dictionary and strings for every event.
    cache.events[key] = (raw, data["event"])
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
    view = _View(entries, _cache(store))
    store._triage_view = view
    latest = {}
    for path, data in entries:
        status = data["status"]
        if status in {"pending", "abort"}:
            # finish() changes status. Never mutate the byte-validated cache.
            data = dict(data)
            view.latest[data["event"]["finding_id"]] = data
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
        if not present:
            _history(store, data).save(_decode_event(data["event"]))
        if status == "pending":
            finish(path, data)
        latest[data["event"]["finding_id"]] = data
    for finding_id, data in latest.items():
        record = store._get(finding_id)
        expected = (data["event"]["from_state"] if data["status"] == "aborted"
                    else data["event"]["to_state"])
        if record is None or record.triage_state.value != expected:
            raise StorageIntegrityError(f"Finding/journal state divergence: {finding_id}")
    view.cache.events = {key: value for key, value in view.cache.events.items()
                         if key in view.event_keys}
    return view


def validate_save(store, record):
    latest = _view(store).latest.get(record.finding_id)
    expected = None if latest is None else (
        latest["event"]["from_state"] if latest["status"] in {"abort", "aborted"}
        else latest["event"]["to_state"])
    if latest and record.triage_state.value != expected:
        raise StorageIntegrityError(f"Refusing stale triage state write: {record.finding_id}")


def inspect_completed(directory):
    """Validate receipts without recovery, filesystem creation or cache reuse.

    Caller holds the finding directory lock and must check corresponding events
    and finding states before using the snapshot. Incomplete intents are errors.
    """
    from types import SimpleNamespace
    entries = _entries(SimpleNamespace(path=Path(directory)))
    for path, data in entries:
        if data["status"] not in {"done", "aborted"}:
            raise StorageIntegrityError(
                f"Triage recovery required before reporting: {path}")
    return entries
