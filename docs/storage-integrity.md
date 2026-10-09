# Storage integrity decision (Sprint 3)

## Audit before implementation

Main baseline: `6223d13` (PRs 1–3 integrated). Stores examined: AssetStore,
RelationStore, ChangeStore, ResultStore, IntegrityStore, FindingStore,
FindingHistoryStore, FindingTriageHistoryStore and ScopeStorage.

| Severity | Location | Risk |
| --- | --- | --- |
| P0 | All JSON store save methods and asset/relation set_active | Direct truncate/write can destroy the old record or expose partial JSON. |
| P0 | FindingTriageManager._transition | State and operational event are separate writes; best-effort rollback cannot resolve crashes. |
| P0 | FindingStore.get/find | Invalid JSON is returned as missing or silently skipped. |
| P1 | FindingLifecycleManager.process vs triage | Read/modify/save can overwrite a concurrent technical or operational update. |
| P1 | AssetStore/RelationStore.save and IntegrityStore.upsert/mark_verified | Concurrent read/modify/write can lose provenance or manifest entries. |
| P1 | Operational history save/read | Exclusive creation protects old IDs, but exposes unfinished new records. |

Other multi-file flows: observation processing saves assets/relations, change
processing saves changes and updates lifecycle state, finding technical lifecycle
writes finding records and technical events, plugin execution saves results plus
integrity/provenance. These flows are not currently campaign-wide transactions.

## Alternatives and chosen scope

Atomic replacement alone fixes partial files but not multi-file consistency.
Native POSIX/Windows locks need distinct APIs and same-thread reentrancy handling.
A global SQLite migration would offer transactions but change all storage formats
and public assumptions. Chosen: JSON remains in place, same-directory staged
writes + file fsync + atomic replace, cooperative directory locks using stdlib
SQLite BEGIN IMMEDIATE, and a small retained JSON triage journal.

The lock database contains no domain records: SQLite provides portable
thread/process mutual exclusion and releases locks when a process dies. Reentrant
calls share a connection per thread. Lock waits are bounded, not indefinite.

A triage intent is persisted before changing state. Incomplete intents are replayed
forward on restart. Ordinary I/O failures before event publication can record an
abort decision and restore the old triage state; recovery retries the recorded
abort. If an event was published, it must be preserved and the operation completed.
Completed intents are retained as receipts, allowing a missing operational event
to be restored exactly, or conflicting/corrupt JSON to be reported without deletion.
Technical lifecycle uses the finding lock across its read/modify/write operation.

## Limits to preserve in implementation and tests

No simultaneous multi-file visibility for raw filesystem readers. No global
transaction for technical history, asset/change/result pipelines. No guaranteed
power-loss durability on Windows (directory fsync unavailable) or on unreliable
filesystems/storage hardware. Only cooperating writers are serialized; separate
get/save calls need an explicit transaction context. Legacy JSON with no journal
receipt remains readable but a historical event never recorded cannot be invented.
Corrupt existing records and journals must be retained and explicitly reported.
Abandoned temporary files are ignored and not automatically deleted on startup.

## Implemented guarantees

All existing JSON store publication, scope YAML and configuration creation use
same-directory temporary files. The order is write, flush, file fsync, replace,
then directory fsync on POSIX. Journal directory creation also syncs its parent.
A failure before replace leaves the previous target intact. A sync error after
replace may mean the new target is already visible: it is not a rollback.
Temps end in .tmp and are excluded from record and receipt enumeration.

Asset/relation provenance updates, integrity manifest updates and lifecycle
read/modify/write operations are serialized. FindingStore.transaction() is an
additive context manager for callers needing a complete read/modify/write scope.
The lock order in internal triage is findings, then history or journal; history
store methods do not acquire the finding lock. Callers must follow that order.
Independent get/save sequences without the context are not protected as a unit.

Triage receipts are ordered by a sequence assigned under the finding lock.
Recovery validates receipts, completes pending operations, retries recorded aborts,
restores missing receipted events and checks the latest committed triage state.
Conflicting existing events are checked before pending state publication.
Stale triage-state saves are rejected. State recovery changes only triage_state,
preserving technical and unknown JSON fields. Finding ID/filename mismatches,
invalid finding JSON/schema and invalid journals raise StorageIntegrityError.
This intentionally replaces FindingStore's previous silent skip/missing behavior.
Public command schemas and persisted domain record formats remain unchanged.

## Recovery procedure

A normal FindingStore.get/find/save or triage CLI operation triggers recovery.
The triage-history CLI reads the finding and operational events in the same scope.
A process crash with a pending intent is completed forward, even if the original
caller never received success. An ordinary OSError with no published event
records an abort before restoration; a published event forces completion.
After an error, inspect/recover before retrying rather than assume it failed.

For an integrity error:
1. Stop cooperating writers and retain a copy of the entire assessment, including
   hidden journals/lock files, events and abandoned temps.
2. Inspect the explicit file path in the error. Do not delete journals or replace
   corrupt records automatically. Compare backup and temporary files offline.
3. Restore only verified data with operator approval, then reopen the store.
   Missing events with retained valid receipts are reconstructed automatically.
   Missing findings and conflicting data require operator intervention.
4. Verify triage state and history before resuming operations.

The lock database stores no domain data. Do not remove it while writers run.
A lock timeout is an explicit error, not an instruction to delete a stale lock.

## Evidence and residual risks

Regression tests inject failures in write/fsync/replace, state/event/receipt and
abort phases; restart stores; kill real subprocesses; check lock release/timeouts;
and exercise thread/process contention. CI tests Python 3.12 and 3.13 on Linux
and Windows. These are process-interruption tests, not physical power-cut tests.

Receipts are retained indefinitely and scanned on each outer finding operation;
compaction/indexing is outside scope. Raw readers can observe intermediate files.
Manual edits, removed receipts, filesystem aliases and noncooperating writers can
bypass guarantees. Legacy missing events cannot be inferred. Technical history and
other multi-file flows remain nontransactional. Records are neither authenticated
nor cryptographically tamper-evident. Network filesystems are not a tested deployment
target. Filesystem fsync/replace guarantees and hardware behavior limit durability;
Windows has no portable directory fsync. No unconditional power-loss guarantee
or campaign-wide ACID transaction is claimed.


## PR #4 integration review

Review reproduced and corrected three P1 defects: inherited reentrancy after
POSIX fork bypassed the parent's process lock; aborted-only receipts failed to
detect state divergence; and individually valid but contradictory receipt chains
could reconstruct an impossible missing event. Reentrancy is now PID-scoped.
Receipt chains are checked before recovery writes, and aborted receipts establish
the expected state used by recovery and stale-save validation.

Six additional regressions cover those defects, post-replace directory-sync
failure, published-event I/O failure with ten repeated recoveries, and nested
lock exception release verified by a fresh process. Local Python 3.12 and 3.13:
551 passed each. The fork regression is intentionally skipped on Windows.

Synthetic local Linux benchmark (Python 3.12, warm filesystem cache, one finding,
five get calls, one transition; setup writes are excluded):
| Retained receipts per finding-store directory | Median get | Maximum get | Transition |
| --- | --- | --- | --- |
| 100 | 9.9 ms | 17.0 ms | 17.1 ms |
| 1,000 | 98.3 ms | 98.6 ms | 161.6 ms |
| 10,000 | 960.6 ms | 1,057.7 ms | 1,562.1 ms |

These are observed timings, not portable service guarantees. Recommend an initial
operational budget of 1,000 receipts per finding-store directory for interactive
use, followed by measurements on actual Windows/Linux storage and workloads.
At 10,000 receipts or sustained latency above 500 ms, plan a separate indexing/
compaction design before scaling. Do not delete receipts to meet that budget.
Cold disks, antivirus, multiple findings and serialized contention can be slower;
repeated per-finding calls in a batch can multiply the scan cost.
No compaction or new storage feature was implemented in this review.
