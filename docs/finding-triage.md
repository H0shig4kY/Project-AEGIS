# Operational finding triage

`FindingTriageManager` changes only `FindingRecord.triage_state`. It does not
change technical `state`, activity, counters, evidence or technical history.
Operational triage is also available through the CLI described below.

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

The manager records a retained intent before state and event publication. Finding
store operations recover interrupted intents under a cooperative directory lock;
technical lifecycle updates use the same lock. Published events are never removed
during error handling. See [storage integrity and recovery](storage-integrity.md)
for failure semantics, operator recovery and limits.

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


## CLI usage

Run inside a campaign containing `aegis.yaml`, or any of its subdirectories.
Use the complete lowercase 64-character finding ID. Existing `findings show`
and technical `findings history` retain their existing prefix behavior.

```bash
aegis findings acknowledge <finding-id> --actor "Carlos" --reason "Evidence reviewed"
aegis findings suppress <finding-id> --actor "Carlos" --reason "Accepted exposure" --json
aegis findings unsuppress <finding-id> --actor "Carlos" --reason "Reassessment needed" --json
aegis findings triage-history <finding-id> --json
```

`--json` is available on all four commands. State changes emit a single object:

```json
{"id": "<full finding ID>", "state": "active", "triage_state": "suppressed", "active": true}
```

`state` and `active` describe technical detection; reopening operational triage
does not reactivate a technically resolved finding.

History emits `{ "finding": <same state object>, "timeline": [...] }`. Each
entry has `event_id`, `finding_id`, `event_type`, `from_state`, `to_state`,
`detected_at`, `actor` and `reason`. An existing finding without operational
events returns an empty timeline and exit code 0. Without `--json`, history
prints timestamps, operations, previous/next states, actors and reasons.

Successful JSON output contains no banners or success messages. Normal command
errors go to stderr with exit code 1 and no JSON on stdout. Missing required
arguments/options are handled by Typer with exit code 2. Missing campaigns,
unknown findings, invalid parameters/transitions, storage failures and malformed
audit data produce concise errors without stack traces.

The CLI discovers the assessment through the existing campaign lookup and stores
operational events in `<campaign>/data/finding_triage_history/`, separate from
`data/findings/` and technical `data/finding_history/`. It delegates changes to
`FindingTriageManager` and preserves the existing persisted formats.
