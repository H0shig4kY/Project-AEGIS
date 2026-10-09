# Sprint 4: triage journal performance decision

## Profiling before implementation

Baseline: main 03f17c7 (PR #4 merged), 551 local Linux tests executed successfully.
Benchmark: benchmarks/triage_journal.py, Python 3.12, temporary local files,
7 repeated operations, 3 reopened queries. A reopened query has a fresh object
cache but warm OS disk cache; this is not a physical cold-disk measurement.

At 10,000 receipts the original repeated query median was 882.1 ms, reopened
946.98 ms, same-store transition 1,488.2 ms and independent-store transition
1,515.3 ms. Receipt read: 63.2 ms; JSON parse: 40.7 ms; event semantic validation:
50.5 ms; sort: 1.94 ms; sequence/chain validation: 7.41 ms. Stage probes isolate
components and do not add up to a whole operation. Atomic write: 0.23 ms on this
temporary filesystem; not a general disk-durability cost.

cProfile of one 10,000-receipt query found 2,001 path resolutions, 80,003 lstat,
50,006 stat and 20,002 opens. History constructors and repeated mkdir/resolve
dominate over sorting. recover calls _entries; begin and validate_save call it
again within the SAME finding transaction. Each receipt's history is constructed
once by event_exists and again by recover even if its event is already present.

## Alternatives and decision before implementation

- Persistent index/checkpoint: would reduce parsing after restart but still needs
  byte verification of every source file to preserve external-modification
  detection. Introduces derived-file atomicity/corruption/version/crash concerns.
  Not justified by the observed path-resolution bottleneck.
- Stat/mtime-based cache: rejected. Same-size changes can restore mtime; Windows
  creation time is not a reliable modification generation.
- OS change notification: no uniform, loss-free stdlib mechanism across Windows/
  Linux; dropped notifications and process downtime need a rescan anyway.
- Byte-validated in-memory cache plus one transaction snapshot: chosen. Every
  outer finding transaction enumerates receipt names and reads every receipt and
  receipted event. Only EXACTLY unchanged bytes reuse parsed/validated objects.
  New/changed bytes are parsed and validated. Global duplicate sequence and chain
  continuity validation run on every new/changed snapshot. Their proof is reused
  only after the entire filename set and every source byte match exactly.
  No timestamps are trusted.
  History paths/instances are resolved once per distinct directory per recovery,
  not once per receipt. begin/save reuse the already validated snapshot under the
  unchanged finding lock and maintain its latest-by-finding/sequence lookup.

The cache is per FindingStore, derived, nonpersistent and dispensable. Restart
reconstructs it from original JSON; no index is introduced and no receipt is
removed. Threads sharing a store are serialized by the existing finding lock;
independent stores/processes validate their own complete byte snapshot. A PID
change discards inherited caches. A failed parse/validation never installs a new
receipt snapshot. Publication/recovery exceptions discard the active transaction
view; the next outer transaction reads source bytes again. Original write ordering,
abort decisions, event preservation and locking remain unchanged.

## Explicit limits

No safe portable sublinear scan was identified with the existing external-write
contract. Content reads remain O(receipts + events), as does memory for cached
raw bytes and parsed data. First access/restart still parses every receipt.
External noncooperating writes DURING an operation remain outside the original
lock contract; modifications completed BETWEEN transactions are checked even
with restored timestamps. A coherent rewrite of receipt AND event is not detected
as historical tampering: the files have never been authenticated or signed.
No compaction, persisted-index migration, watcher, new dependency or plugin/network
feature is introduced. Existing durability and nontransactional pipeline limits
from storage-integrity.md still apply.


## Final measured results

Final paired run: CPython 3.12.14, Linux x86_64, same benchmark script/fixture and
environment before/after, warm OS filesystem cache. Seven samples per repeated
query/transition and three fresh FindingStore samples. All times below are ms.
The deterministic fixture has one finding, alternating valid transitions, all
receipts done, and one persisted event per receipt. Production workloads with
many findings, pending recovery or cold disks are not covered by these timings.

| Receipts | Repeated query before → after | Speedup | Same-store transition before → after | Speedup |
| --- | --- | --- | --- | --- |
| 100 | 8.90 → 1.36 | 6.56× | 15.28 → 2.70 | 5.66× |
| 1,000 | 84.90 → 12.85 | 6.61× | 135.11 → 14.23 | 9.49× |
| 10,000 | 883.30 → 158.75 | 5.56× | 1,419.09 → 189.62 | 7.48× |

| Receipts | First query in reopened store (median) before → after | Independent-store transition before → after |
| --- | --- | --- |
| 100 | 8.48 → 3.45 | 16.48 → 4.66 |
| 1,000 | 84.47 → 32.08 | 135.54 → 33.61 |
| 10,000 | 885.21 → 400.59 | 1,400.32 → 438.11 |

At 10,000 receipts standalone warmed recovery (lock acquisition excluded) went
from 894.45 to 157.97 ms. The full stage probes and cProfile data are retained in
benchmarks/results/sprint4-linux-before.json and sprint4-linux-after.json.
The micro-stage probes deliberately parse/validate every payload even in the
optimized source: they isolate unavoidable cold work, not warmed cache behavior.
Functional call-count tests verify unchanged receipts avoid repeated semantic
parsing and transitions take only one validated receipt snapshot.

Indicative goals were reached IN THIS measurement: repeated queries ≥5×,
same-store and independent-store transitions ≥3× at 10,000, and no >20% operation
regression at 100. This is not a performance guarantee for Windows, other
Python versions, physical disks or different receipt/finding distributions.
Index/checkpoint decisions should be revisited if cold-start or byte-I/O costs
become dominant. Cache memory is linear; original receipts continue to grow.

## Reproduce

From the repository root with project dev dependencies installed:

    mkdir -p /tmp/aegis-s4-baseline
    git archive 03f17c7bd4e2ac7481845b1e04fb2a25b229dcdc | tar -x -C /tmp/aegis-s4-baseline
    python benchmarks/triage_journal.py --source /tmp/aegis-s4-baseline/aegis --repeats 7 --output /tmp/before.json
    python benchmarks/triage_journal.py --source ./aegis --repeats 7 --output /tmp/after.json

The Python benchmark is Windows/Linux compatible. On Windows extract the same
baseline commit into a separate folder and pass that folder's aegis directory as
--source. Extraction syntax above uses POSIX tools. Results are informational,
outside pytest; CI never fails because a machine misses a latency target.

## Regression coverage

27 added functional test cases cover byte reuse, one transaction snapshot,
same-size changes with restored timestamps, invalid UTF-8/JSON/schema,
contradictions and duplicate sequences, missing event reconstruction, absent
cache, failed derived snapshot construction, valid legacy volumes, independent
process updates, shared-store threads, recovery interruptions and repeated
recovery, technical-field independence, symlink retargeting and fork cache reset.
The last two cases require POSIX and are skipped on Windows.
All 551 existing test cases are retained. Local Python 3.12/3.13: 578 passed each.
Final CI outcomes are recorded in the PR/report after publication.
