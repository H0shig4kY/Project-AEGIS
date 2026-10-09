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
