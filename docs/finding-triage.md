# Operational finding triage

`FindingTriageManager` changes only `FindingRecord.triage_state`. It does not
change technical `state`, activity, counters, evidence or technical history.
No CLI commands are introduced by this sprint.

```python
from pathlib import Path
from aegis.finding_store import FindingStore
from aegis.finding_triage import FindingTriageManager
from aegis.finding_triage_history_store import FindingTriageHistoryStore

store = FindingStore(Path("data/findings"))
history = FindingTriageHistoryStore(Path("data/finding_triage_history"))
manager = FindingTriageManager(store, history)
record = manager.acknowledge(finding_id, actor="analyst", reason="Evidence reviewed")
record = manager.suppress(finding_id, actor="analyst", reason="Accepted exposure")
record = manager.unsuppress(finding_id, actor="analyst", reason="Reassessment needed")
```

All three operations return the persisted `FindingRecord`. `actor` and `reason`
are mandatory keyword arguments, must be non-empty strings, and are trimmed.
`finding_id` must be the complete lowercase SHA-256 hex ID (64 characters);
prefix lookup is deliberately not part of this new write interface.

| Operation | Allowed previous state | Next state |
| --- | --- | --- |
| acknowledge | OPEN | ACKNOWLEDGED |
| suppress | OPEN or ACKNOWLEDGED | SUPPRESSED |
| unsuppress | SUPPRESSED | OPEN |

Every other transition, including immediately repeating an operation, raises
`InvalidTriageTransition` (a `ValueError`) without writing state or audit events.
Invalid arguments raise `ValueError`; unknown findings raise `LookupError`.
Filesystem errors propagate. Legacy findings without `triage_state` retain the
existing `FindingStore` default of OPEN. Existing public interfaces are unchanged.

## Audit persistence

`FindingTriageEvent` and `FindingTriageEventType` are additive models, separate
from the technical `FindingEvent` and its enum. The dedicated history store is
required: a successful transition cannot intentionally omit its audit event.
Use a directory separate from both findings and technical history. The manager
rejects sharing the finding directory; the caller must choose a separate
technical-history directory as well.

Each JSON event contains a UUID hex `event_id`, full `finding_id`, operation in
`event_type`, `from_state`, `to_state`, UTC `detected_at`, `actor` and `reason`.
UUIDs preserve distinct legitimate cycles even when timestamps are equal.
Exclusive file creation rejects overwriting an event. `get(event_id)`, `find()`
and `find_by_finding_id(finding_id)` mirror the existing history store interface.
Events sort by timestamp, then ID; equal timestamps have deterministic ordering,
which does not imply causal ordering. Corrupt audit files raise errors rather
than being silently omitted.

The manager writes state first and then the event. If audit writing raises an
`OSError`, it attempts to restore the previous operational state and propagates
the error. This is best-effort compensation, not a multi-file transaction.
A crash, partial disk write or failed rollback can leave inconsistency. There is
no locking between concurrent triage or technical lifecycle writers. Use a
single writer; crash recovery and concurrency control are outside this sprint.

The actor is supplied by the caller, not authenticated by this component. JSON
audit files are not cryptographically tamper-evident and contain actor/reason
text in plaintext. Directory permissions remain the deployment's responsibility.

## Validation

Baseline on current main (`b96eed6`): 380 tests passed locally on Python 3.12.
Tests were committed before implementation and initially failed with
`ModuleNotFoundError: aegis.finding_triage`. New tests cover the full transition
matrix, input validation, missing findings, repeated operations, reopening stores,
event fields/order, legacy JSON, technical lifecycle independence, timestamp
collisions, write failures and audit corruption.
