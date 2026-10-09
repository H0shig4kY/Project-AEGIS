"""Functional cache/integrity contracts; intentionally no machine-speed assertions."""
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from aegis import triage_journal
from aegis.atomic_storage import StorageIntegrityError
from aegis.finding_store import FindingStore
from aegis.finding_triage import FindingTriageManager, InvalidTriageTransition
from aegis.finding_triage_history_store import FindingTriageHistoryStore
from aegis.models import AssetType, FindingRecord, FindingTriageState


@pytest.fixture
def campaign(tmp_path):
    store = FindingStore(tmp_path / "findings")
    history = FindingTriageHistoryStore(tmp_path / "triage")
    record = FindingRecord(finding_id="a" * 64, rule_id="TEST", severity="medium",
        title="test", description="test", asset_type=AssetType.SERVICE, asset_value="test:80")
    store.save(record)
    return store, history, record, FindingTriageManager(store, history)


def receipts(store):
    return sorted((store.path / ".triage-journal").glob("*.txn"),
                  key=lambda p: json.loads(p.read_text())["sequence"])


def rewrite_same_metadata(path, content):
    previous = path.stat()
    path.write_bytes(content)
    os.utime(path, ns=(previous.st_atime_ns, previous.st_mtime_ns))


def test_unchanged_receipts_do_not_repeat_semantic_parsing(campaign, monkeypatch):
    store, _, record, manager = campaign
    manager.suppress(record.finding_id, actor="operator", reason="review")
    store.get(record.finding_id)  # warm a completed receipt
    calls = []
    original = triage_journal._decode_event
    def decode(payload):
        calls.append(payload)
        return original(payload)
    monkeypatch.setattr(triage_journal, "_decode_event", decode)
    for _ in range(3):
        assert store.get(record.finding_id).triage_state == FindingTriageState.SUPPRESSED
    assert calls == []


def test_transition_uses_one_validated_receipt_snapshot(campaign, monkeypatch):
    store, _, record, manager = campaign
    manager.suppress(record.finding_id, actor="operator", reason="review")
    calls = []
    original = triage_journal._entries
    def entries(value):
        calls.append(value)
        return original(value)
    monkeypatch.setattr(triage_journal, "_entries", entries)
    manager.unsuppress(record.finding_id, actor="operator", reason="review")
    assert len(calls) == 1


@pytest.mark.parametrize("target", ["receipt", "event"])
def test_same_size_external_change_with_restored_mtime_is_detected(campaign, target):
    store, history, record, manager = campaign
    manager.suppress(record.finding_id, actor="operator", reason="review")
    store.get(record.finding_id)
    path = receipts(store)[0] if target == "receipt" else next(history.directory.glob("*.json"))
    changed = path.read_bytes().replace(b"review", b"edited")
    rewrite_same_metadata(path, changed)
    with pytest.raises(StorageIntegrityError, match="Conflicting"):
        store.get(record.finding_id)
    assert path.read_bytes() == changed


@pytest.mark.parametrize("content", [b"{", b"[]", b"null", b"\xff"])
def test_warm_cache_never_hides_invalid_receipt(campaign, content):
    store, _, record, manager = campaign
    manager.suppress(record.finding_id, actor="operator", reason="review")
    store.get(record.finding_id)
    path = receipts(store)[0]
    rewrite_same_metadata(path, content)
    with pytest.raises(StorageIntegrityError):
        store.get(record.finding_id)
    assert path.read_bytes() == content


def test_cached_chain_still_detects_contradiction_before_reconstruction(campaign):
    store, history, record, manager = campaign
    manager.suppress(record.finding_id, actor="operator", reason="review")
    manager.unsuppress(record.finding_id, actor="operator", reason="review")
    store.get(record.finding_id)
    path = receipts(store)[1]
    data = json.loads(path.read_text())
    data["event"].update(event_type="acknowledge", from_state="open", to_state="acknowledged")
    path.write_text(json.dumps(data))
    event_path = history.directory / (data["event"]["event_id"] + ".json")
    event_path.unlink()
    with pytest.raises(StorageIntegrityError, match="chain"):
        store.get(record.finding_id)
    assert not event_path.exists()


def test_warm_cache_still_detects_duplicate_sequence(campaign):
    store, _, record, manager = campaign
    manager.suppress(record.finding_id, actor="operator", reason="review")
    manager.unsuppress(record.finding_id, actor="operator", reason="review")
    store.get(record.finding_id)
    path = receipts(store)[1]
    data = json.loads(path.read_text())
    data["sequence"] = 1
    path.write_text(json.dumps(data))
    with pytest.raises(StorageIntegrityError, match="Duplicate"):
        store.get(record.finding_id)


def test_deleted_cached_event_restored_once(campaign):
    store, history, record, manager = campaign
    manager.suppress(record.finding_id, actor="operator", reason="review")
    store.get(record.finding_id)
    path = next(history.directory.glob("*.json"))
    original = path.read_bytes()
    path.unlink()
    for _ in range(3):
        store.get(record.finding_id)
    assert path.read_bytes() == original
    assert len(history.find()) == 1


def test_other_process_updates_are_seen_by_warm_store(campaign):
    store, history, record, manager = campaign
    manager.suppress(record.finding_id, actor="operator", reason="review")
    store.get(record.finding_id)
    code = """
import sys
from pathlib import Path
from aegis.finding_store import FindingStore
from aegis.finding_triage import FindingTriageManager
from aegis.finding_triage_history_store import FindingTriageHistoryStore
FindingTriageManager(FindingStore(Path(sys.argv[1])),
    FindingTriageHistoryStore(Path(sys.argv[2]))).unsuppress(
    sys.argv[3], actor="process", reason="review")
"""
    result = subprocess.run([sys.executable, "-c", code, str(store.path),
        str(history.directory), record.finding_id], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert store.get(record.finding_id).triage_state == FindingTriageState.OPEN
    assert len(history.find()) == 2


def test_shared_store_threads_have_one_winner(campaign):
    store, history, record, manager = campaign
    store.get(record.finding_id)
    def acknowledge(index):
        try:
            manager.acknowledge(record.finding_id, actor=str(index), reason="review")
            return True
        except InvalidTriageTransition:
            return False
    with ThreadPoolExecutor(max_workers=8) as executor:
        assert sum(executor.map(acknowledge, range(8))) == 1
    assert len(history.find()) == 1


def test_invalid_snapshot_can_be_repaired_without_stale_cache(campaign):
    store, _, record, manager = campaign
    manager.suppress(record.finding_id, actor="operator", reason="review")
    store.get(record.finding_id)
    path = receipts(store)[0]
    original = path.read_bytes()
    path.write_bytes(b"{")
    with pytest.raises(StorageIntegrityError):
        store.get(record.finding_id)
    path.write_bytes(original)
    assert store.get(record.finding_id).triage_state == FindingTriageState.SUPPRESSED
    reopened = FindingStore(store.path)
    assert reopened.get(record.finding_id).triage_state == FindingTriageState.SUPPRESSED


@pytest.mark.parametrize("count", [0, 2, 100, 1000])
def test_legacy_receipt_volumes_reopen_and_repeat(campaign, count):
    store, history, record, _ = campaign
    directory = store.path / ".triage-journal"
    directory.mkdir()
    for index in range(count):
        event = dict(event_id=f"{index:032x}", finding_id=record.finding_id,
            event_type="suppress" if index % 2 == 0 else "unsuppress",
            from_state="open" if index % 2 == 0 else "suppressed",
            to_state="suppressed" if index % 2 == 0 else "open",
            detected_at="2026-10-09T00:00:00+00:00", actor="operator", reason="review")
        (history.directory / (event["event_id"] + ".json")).write_text(json.dumps(event))
        (directory / (event["event_id"] + ".txn")).write_text(json.dumps(dict(
            version=1, sequence=index + 1, status="done", history_directory="../triage", event=event)))
    before = {path.name: path.read_bytes() for path in directory.glob("*.txn")}
    for current in (store, store, FindingStore(store.path)):
        assert current.get(record.finding_id).triage_state == FindingTriageState.OPEN
        assert len(history.find()) == count
    assert {path.name: path.read_bytes() for path in directory.glob("*.txn")} == before


def test_failed_derived_snapshot_build_is_retryable(campaign, monkeypatch):
    store, history, record, manager = campaign
    manager.suppress(record.finding_id, actor="operator", reason="review")
    store.get(record.finding_id)
    other = FindingTriageManager(FindingStore(store.path), history)
    other.unsuppress(record.finding_id, actor="operator", reason="review")
    original = {path.name: path.read_bytes() for path in receipts(store)}
    monkeypatch.setattr(triage_journal, "_summarize",
                        lambda entries: (_ for _ in ()).throw(MemoryError("derived snapshot")))
    with pytest.raises(MemoryError, match="derived snapshot"):
        store.get(record.finding_id)
    assert getattr(store, "_triage_view", None) is None
    assert {path.name: path.read_bytes() for path in receipts(store)} == original
    monkeypatch.undo()
    assert store.get(record.finding_id).triage_state == FindingTriageState.OPEN
    assert len(history.find()) == 2


def test_discarded_cache_is_reconstructed(campaign):
    store, history, record, manager = campaign
    manager.suppress(record.finding_id, actor="operator", reason="review")
    store.get(record.finding_id)
    store._triage_cache = None
    assert store.get(record.finding_id).triage_state == FindingTriageState.SUPPRESSED
    assert len(history.find()) == 1


@pytest.mark.parametrize("phase", ["pending", "abort", "published"])
def test_interrupted_recovery_does_not_poison_warm_cache(campaign, monkeypatch, phase):
    store, history, record, manager = campaign
    manager.suppress(record.finding_id, actor="operator", reason="review")
    store.get(record.finding_id)
    original_save = store.save
    original_history = history.save
    class Crash(BaseException):
        pass
    if phase == "pending":
        def save(value):
            original_save(value)
            raise Crash()
        monkeypatch.setattr(store, "save", save)
    elif phase == "published":
        def save_event(value):
            original_history(value)
            raise Crash()
        monkeypatch.setattr(history, "save", save_event)
    else:
        monkeypatch.setattr(history, "save", lambda event: (_ for _ in ()).throw(OSError("audit")))
        original_finish = triage_journal.finish
        def finish(path, data, status="done"):
            original_finish(path, data, status)
            if status == "abort":
                raise Crash()
        monkeypatch.setattr(triage_journal, "finish", finish)
    with pytest.raises(Crash):
        manager.unsuppress(record.finding_id, actor="operator", reason="review")
    assert getattr(store, "_triage_view", None) is None
    monkeypatch.undo()
    expected = FindingTriageState.SUPPRESSED if phase == "abort" else FindingTriageState.OPEN
    for _ in range(3):
        assert store.get(record.finding_id).triage_state == expected
    assert len(history.find()) == (1 if phase == "abort" else 2)


@pytest.mark.skipif(os.name != "posix", reason="portable symlink privilege unavailable on Windows")
def test_history_symlink_target_is_resolved_again_after_cache(campaign):
    store, history, record, manager = campaign
    manager.suppress(record.finding_id, actor="operator", reason="review")
    alias = store.path.parent / "history-alias"
    alias.symlink_to(history.directory, target_is_directory=True)
    path = receipts(store)[0]
    data = json.loads(path.read_text())
    data["history_directory"] = "../history-alias"
    path.write_text(json.dumps(data))
    store.get(record.finding_id)
    other = store.path.parent / "other-history"
    other.mkdir()
    event = dict(data["event"], reason="changed")
    (other / (event["event_id"] + ".json")).write_text(json.dumps(event))
    alias.unlink()
    alias.symlink_to(other, target_is_directory=True)
    with pytest.raises(StorageIntegrityError, match="Conflicting"):
        store.get(record.finding_id)


def test_multiple_findings_keep_independent_latest_states(campaign):
    store, history, record, manager = campaign
    other = FindingRecord(finding_id="b" * 64, rule_id="TEST", severity="medium",
        title="other", description="test", asset_type=AssetType.SERVICE, asset_value="other:80")
    store.save(other)
    manager.suppress(record.finding_id, actor="operator", reason="review")
    manager.acknowledge(other.finding_id, actor="operator", reason="review")
    store.get(record.finding_id)
    manager.unsuppress(record.finding_id, actor="operator", reason="review")
    for _ in range(3):
        assert store.get(record.finding_id).triage_state == FindingTriageState.OPEN
        assert store.get(other.finding_id).triage_state == FindingTriageState.ACKNOWLEDGED
    assert len(history.find()) == 3


@pytest.mark.skipif(os.name != "posix", reason="fork is POSIX only")
def test_fork_discards_inherited_validated_cache(campaign):
    store, history, record, manager = campaign
    manager.suppress(record.finding_id, actor="operator", reason="review")
    code = """
import os, sys
from pathlib import Path
from aegis import triage_journal
from aegis.finding_store import FindingStore
store = FindingStore(Path(sys.argv[1]))
store.get(sys.argv[2])
pid = os.fork()
if pid == 0:
    def must_reparse(payload):
        raise RuntimeError("fresh child validation")
    triage_journal._decode_event = must_reparse
    try:
        store.get(sys.argv[2])
    except RuntimeError as error:
        os._exit(0 if str(error) == "fresh child validation" else 9)
    os._exit(8)
_, status = os.waitpid(pid, 0)
assert os.waitstatus_to_exitcode(status) == 0
store.get(sys.argv[2])
"""
    result = subprocess.run([sys.executable, "-c", code, str(store.path), record.finding_id],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert len(history.find()) == 1


def test_warm_snapshot_does_not_override_technical_fields(campaign):
    store, history, record, manager = campaign
    manager.suppress(record.finding_id, actor="operator", reason="review")
    store.get(record.finding_id)
    with FindingStore(store.path).transaction():
        current = FindingStore(store.path).get(record.finding_id)
        current.seen_count = 42
        current.missing_count = 7
        FindingStore(store.path).save(current)
    manager.unsuppress(record.finding_id, actor="operator", reason="review")
    current = store.get(record.finding_id)
    assert (current.seen_count, current.missing_count) == (42, 7)
    assert len(history.find()) == 2


def test_nested_store_instances_share_current_sequence(campaign):
    store, history, record, manager = campaign
    other = FindingTriageManager(FindingStore(store.path), history)
    with store.transaction():
        other.suppress(record.finding_id, actor="other", reason="review")
        manager.unsuppress(record.finding_id, actor="owner", reason="review")
    assert store.get(record.finding_id).triage_state == FindingTriageState.OPEN
    assert [json.loads(path.read_text())["sequence"] for path in receipts(store)] == [1, 2]
    assert len(history.find()) == 2


def test_caught_intent_publication_failure_refreshes_outer_view(campaign, monkeypatch):
    store, history, record, manager = campaign
    original = triage_journal.atomic_write_text
    failed = False
    def publish_then_fail(path, content, **kwargs):
        nonlocal failed
        original(path, content, **kwargs)
        if path.suffix == ".txn" and kwargs.get("exclusive") and not failed:
            failed = True
            raise OSError("intent published, sync failed")
    monkeypatch.setattr(triage_journal, "atomic_write_text", publish_then_fail)
    with store.transaction():
        with pytest.raises(OSError, match="intent published"):
            manager.suppress(record.finding_id, actor="operator", reason="review")
        assert store.get(record.finding_id).triage_state == FindingTriageState.SUPPRESSED
        manager.unsuppress(record.finding_id, actor="operator", reason="review")
    assert store.get(record.finding_id).triage_state == FindingTriageState.OPEN
    assert [json.loads(path.read_text())["sequence"] for path in receipts(store)] == [1, 2]
    assert len(history.find()) == 2


def test_nested_alias_update_rejects_stale_triage_save(campaign):
    store, history, record, manager = campaign
    manager.suppress(record.finding_id, actor="operator", reason="review")
    other = FindingTriageManager(FindingStore(store.path), history)
    with store.transaction():
        stale = store.get(record.finding_id)
        other.unsuppress(record.finding_id, actor="other", reason="review")
        with pytest.raises(StorageIntegrityError, match="stale"):
            store.save(stale)
        assert store.get(record.finding_id).triage_state == FindingTriageState.OPEN
    assert len(history.find()) == 2


@pytest.mark.parametrize("phase", ["state", "event", "receipt"])
def test_caught_nested_crash_recovers_before_next_operation(campaign, monkeypatch, phase):
    store, history, record, manager = campaign
    class Crash(BaseException):
        pass
    original_save, original_event, original_finish = store.save, history.save, triage_journal.finish
    def save(value):
        result = original_save(value)
        if phase == "state":
            raise Crash()
        return result
    def event(value):
        result = original_event(value)
        if phase == "event":
            raise Crash()
        return result
    def finish(path, data, status="done"):
        original_finish(path, data, status)
        if phase == "receipt":
            raise Crash()
    monkeypatch.setattr(store, "save", save)
    monkeypatch.setattr(history, "save", event)
    monkeypatch.setattr(triage_journal, "finish", finish)
    with store.transaction():
        with pytest.raises(Crash):
            manager.suppress(record.finding_id, actor="operator", reason="review")
        monkeypatch.undo()
        for _ in range(3):
            assert store.get(record.finding_id).triage_state == FindingTriageState.SUPPRESSED
            assert len(history.find()) == 1
        assert json.loads(receipts(store)[0].read_text())["status"] == "done"
        manager.unsuppress(record.finding_id, actor="operator", reason="review")
    assert len(history.find()) == 2
    assert [json.loads(path.read_text())["sequence"] for path in receipts(store)] == [1, 2]


def test_event_cache_accepts_equivalent_json_and_rejects_changed_payload(campaign):
    store, history, record, manager = campaign
    manager.suppress(record.finding_id, actor="operator", reason="review")
    store.get(record.finding_id)
    path = next(history.directory.glob("*.json"))
    payload = json.loads(path.read_text())
    path.write_text(json.dumps(payload))  # Different bytes, same complete event.
    assert store.get(record.finding_id).triage_state == FindingTriageState.SUPPRESSED
    before = path.read_bytes()
    rewrite_same_metadata(path, before.replace(b"review", b"edited"))
    with pytest.raises(StorageIntegrityError, match="Conflicting"):
        store.get(record.finding_id)
    path.write_bytes(before)
    assert store.get(record.finding_id).triage_state == FindingTriageState.SUPPRESSED
    assert len(history.find()) == 1
