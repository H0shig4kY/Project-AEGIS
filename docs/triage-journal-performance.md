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
  continuity validation remain on each snapshot. No timestamps are trusted.
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
