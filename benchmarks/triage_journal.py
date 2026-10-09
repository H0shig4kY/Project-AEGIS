"""Reproducible local-file microbenchmark; no timing assertions or external targets.

python benchmarks/triage_journal.py --source ./aegis --output /tmp/after.json
Use an extracted baseline commit as --source for an identical before measurement.
Cold means a fresh store/cache, NOT a cold operating-system disk cache.
"""
import argparse
import cProfile
import json
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def timed(function):
    start = time.perf_counter()
    value = function()
    return value, (time.perf_counter() - start) * 1000


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("aegis"))
    parser.add_argument("--counts", type=int, nargs="+", default=[100, 1000, 10000])
    parser.add_argument("--repeats", type=int, default=7)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("repeats must be positive")
    sys.path.insert(0, str(args.source.resolve()))
    from aegis.atomic_storage import atomic_write_text, directory_lock
    from aegis.finding_store import FindingStore
    from aegis.finding_triage import FindingTriageManager
    from aegis.finding_triage_history_store import FindingTriageHistoryStore
    from aegis.models import AssetType, FindingRecord
    from aegis import triage_journal

    rows = []
    for count in args.counts:
        if count < 0 or count % 2:
            parser.error("counts must be nonnegative and even (fixture ends OPEN)")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = FindingStore(root / "findings")
            history = FindingTriageHistoryStore(root / "triage")
            record = FindingRecord(finding_id="a" * 64, rule_id="BENCH",
                severity="medium", title="benchmark", description="benchmark",
                asset_type=AssetType.SERVICE, asset_value="benchmark:80")
            store.save(record)
            journal = store.path / ".triage-journal"
            journal.mkdir()
            # Fixture creation excluded. Deterministic canonical legacy JSON.
            for index in range(count):
                event = dict(event_id=f"{index:032x}", finding_id=record.finding_id,
                    event_type="suppress" if index % 2 == 0 else "unsuppress",
                    from_state="open" if index % 2 == 0 else "suppressed",
                    to_state="suppressed" if index % 2 == 0 else "open",
                    detected_at="2026-10-09T00:00:00+00:00", actor="operator", reason="benchmark")
                (history.directory / (event["event_id"] + ".json")).write_text(
                    json.dumps(event, indent=2, sort_keys=True), encoding="utf-8")
                (journal / (event["event_id"] + ".txn")).write_text(json.dumps(
                    dict(version=1, sequence=index + 1, status="done",
                         history_directory="../triage", event=event), indent=2, sort_keys=True),
                    encoding="utf-8")

            # Isolate read, parse, event validation, ordering and global chain costs.
            paths = list(journal.glob("*.txn"))
            raws, read_ms = timed(lambda: [path.read_bytes() for path in paths])
            payloads, parse_ms = timed(lambda: [json.loads(raw) for raw in raws])
            _, validate_ms = timed(lambda: [
                history._serialize(triage_journal._decode_event(data["event"])) for data in payloads])
            ordered, sort_ms = timed(lambda: sorted(payloads, key=lambda data: data["sequence"]))
            def chain():
                expected = {}
                sequences = set()
                for data in ordered:
                    assert data["sequence"] not in sequences
                    sequences.add(data["sequence"])
                    event = data["event"]
                    if event["finding_id"] in expected:
                        assert event["from_state"] == expected[event["finding_id"]]
                    expected[event["finding_id"]] = event["to_state"]
            _, chain_ms = timed(chain)
            _, first_ms = timed(lambda: store.get(record.finding_id))
            repeats = [timed(lambda: store.get(record.finding_id))[1] for _ in range(args.repeats)]
            restarts = [timed(lambda: FindingStore(store.path).get(record.finding_id))[1]
                        for _ in range(3)]
            # Actual process restarts: imports/startup are outside the query timer.
            restart_code = """
import sys, time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from aegis.finding_store import FindingStore
start = time.perf_counter()
FindingStore(Path(sys.argv[2])).get(sys.argv[3])
print((time.perf_counter() - start) * 1000)
"""
            process_restarts = []
            for _ in range(3):
                process = subprocess.run([sys.executable, "-c", restart_code,
                    str(args.source.resolve()), str(store.path), record.finding_id],
                    check=True, capture_output=True, text=True)
                process_restarts.append(float(process.stdout.strip()))
            # Standalone recovery probe excludes finding-lock acquisition cost.
            with directory_lock(store.path):
                _, recovery_ms = timed(lambda: triage_journal.recover(store))
                store._triage_view = None
            # Profile end-to-end recovery separately (profile timings have overhead).
            profile = cProfile.Profile()
            profile.runcall(store.get, record.finding_id)
            hotspots = []
            for entry in profile.getstats():
                code = entry.code
                name = code if isinstance(code, str) else f"{Path(code.co_filename).name}:{code.co_name}"
                hotspots.append(dict(function=name, calls=entry.callcount,
                                     self_ms=round(entry.inlinetime * 1000, 3)))
            transitions = []
            manager = FindingTriageManager(store, history)
            for index in range(args.repeats):
                operation = manager.suppress if index % 2 == 0 else manager.unsuppress
                transitions.append(timed(lambda: operation(record.finding_id,
                    actor="operator", reason="benchmark"))[1])
            # Reopened stores approximate independent CLI processes (no object cache).
            independent = []
            for index in range(args.repeats):
                operation = "unsuppress" if (args.repeats + index) % 2 else "suppress"
                def transition():
                    current = FindingStore(store.path)
                    getattr(FindingTriageManager(current, history), operation)(
                        record.finding_id, actor="operator", reason="benchmark")
                independent.append(timed(transition)[1])
            _, write_ms = timed(lambda: atomic_write_text(journal / ".benchmark.tmp", "{}"))
            rows.append(dict(receipts=count, stages_ms=dict(read=read_ms, parse=parse_ms,
                event_validation=validate_ms, sort=sort_ms, global_chain=chain_ms,
                atomic_write=write_ms, recovery=recovery_ms), first_query_ms=first_ms,
                reopened_query_median_ms=statistics.median(restarts),
                process_restart_query_median_ms=statistics.median(process_restarts),
                repeated_query_median_ms=statistics.median(repeats),
                transition_median_ms=statistics.median(transitions),
                independent_transition_median_ms=statistics.median(independent),
                profile_top_self=sorted(hotspots, key=lambda x: x["self_ms"], reverse=True)[:12]))
    result = dict(python=sys.version, platform=platform.platform(), source=str(args.source.resolve()),
                  repeats=args.repeats, clock="perf_counter", rows=rows)
    output = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
