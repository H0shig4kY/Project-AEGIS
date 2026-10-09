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
