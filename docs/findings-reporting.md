# Finding reports: read model and integrity decision

Reports project existing assessment JSON into schema version 1. They never call
AssessmentContext or FindingStore.find/get/transaction: constructing the full
assessment creates unrelated stores, and normal finding reads recover the triage
journal, potentially changing finding state, events and receipts.

The dedicated read path acquires existing cooperative directory locks (finding
first, then history directories), without creating missing directories or lock
files. A legacy directory with no lock can be read, but appearance of a writer's
lock during that read invalidates the snapshot. Existing lock databases are used
only for locking, not data writes. Atomic-storage recovery and writers remain
unchanged. The journal parser/chain validator is reused; pending/abort intentions,
missing audit events, contradictory events and finding-state divergence produce
an explicit error, without repairing or deleting data. Complete source JSON is
validated before rendering or exporting anything.

Available finding fields are rule_id, severity, title, description, asset type
and value, affected_service, plugin, coverage_plugins, technical state, triage
state, lifecycle timestamps, counters and active. Severity is copied, never
reclassified. There is no modeled CVSS, recommendation or finding-evidence link.
Unknown existing JSON fields are retained as opaque source_extensions, including
an evidence field if one is actually stored; they are not verified evidence and
no files or scan results are inferred to belong to a finding.

The assessment exposes a configured name, not a guaranteed unique ID. The report
includes that name when present, preserving explicit null. Generation time is UTC.
Each finding includes its normalized record, original source_fields (to distinguish
absent keys from explicit values/null), source_extensions, technical_history and
triage_history. Findings sort by complete ID; events sort by timestamp and ID.
Offset-aware times are compared in UTC. Legacy naive technical-event timestamps
are preserved and sorted as wall-clock values; their timezone cannot be inferred.

Output is built fully in memory. JSON has sorted keys, UTF-8, strict finite JSON
numbers and a trailing newline. Markdown renders all existing fields and histories
as escaped literal data, not executable HTML, links or injected Markdown blocks.
No report is generated during an integrity or serialization failure.

File export writes and fsyncs a complete sibling temporary file, then publishes
via an exclusive hard link. Existing files/symlinks are never replaced, including
concurrent destination creation. Failures before publication remove the temporary
and preserve the destination. No parent directories are created. Filesystems that
do not support hard links fail explicitly; no unsafe overwrite fallback is used.
The report destination cannot be inside assessment data/evidence or its config
files, nor alias an input through a symlink. Output is an export artifact, not an
assessment-store update. This guarantees complete publication, not portable power
loss durability: directory fsync is not claimed and Windows has no portable
standard-library equivalent.

## CLI usage

Run inside an assessment or a nested directory. JSON is the default format.

```console
aegis findings report --format json
aegis findings report --format markdown
aegis findings report --format json --output report.json
aegis findings report --format markdown --output report.md
```

Without --output, stdout contains only the complete report. With --output,
stdout is empty, including on success. Errors go to stderr. Operational errors
exit 1; invalid CLI option values exit 2. There is deliberately no overwrite flag.
Create the output parent directory separately if needed. Destination suffix does
not select the format; --format does. Output cannot use reserved SQLite lock names
(case-insensitively), nor any history directory referenced by a retained receipt,
including paths outside assessment data.

## JSON version 1

Top-level keys are always schema_version (integer 1), assessment (object),
generated_at (UTC ISO 8601 string), summary (object) and findings (array).
Assessment name is omitted when absent; explicit null is preserved. No synthetic
assessment ID is created from a directory name or path.

Summary contains total, by_state (active, candidate_missing, resolved), and
by_triage_state (open, acknowledged, suppressed), with integer counts including
zero-count states. Each finding has exactly record, source_fields,
source_extensions, technical_history, triage_history. Record contains all fields
from FindingStore._serialize; its existing legacy defaults are unchanged. Original
key presence is recorded in source_fields, and unknown keys/values are copied only
into source_extensions. A missing evidence extension remains missing; an existing
evidence extension is opaque source data, not a modeled or verified evidence link.
Histories contain only stored events and their actual fields, ordered by timestamp
and event_id. Aborted receipts have no published event and do not become invented
audit events. Unknown history fields are preserved without interpretation.

An empty assessment with a configured name produces:

```json
{
  "schema_version": 1,
  "assessment": {"name": "Test assessment"},
  "generated_at": "2026-10-09T20:00:00+00:00",
  "summary": {
    "total": 0,
    "by_state": {"active": 0, "candidate_missing": 0, "resolved": 0},
    "by_triage_state": {"open": 0, "acknowledged": 0, "suppressed": 0}
  },
  "findings": []
}
```

JSON object keys are sorted by the exporter; array ordering is deterministic.
Generation time naturally changes between independent invocations. UTF-8 text is
preserved, while NaN, Infinity and invalid Unicode are rejected before output.
Markdown is a presentation of the same data, with escaped literal values and
visible U+XXXX markers for control characters. It does not calculate CVSS,
recommendations, evidence attribution or new severity classifications.

## Locking, recovery and limits

Existing SQLite lock databases are opened in mode=rw solely to acquire the same
BEGIN IMMEDIATE lock as cooperating writers; mode=ro does not exclude those
writers. No SQL data changes are executed. SQLite may create/remove transient
lock-journal sidecars while holding the lock; no missing persistent lock database
or data directory is initialized. Byte contents and modification times of stored
inputs and existing lock databases are checked for preservation in the tests.

Pre-existing journal/WAL/shared-memory sidecars cause an explicit busy/unsettled
metadata error: reporting does not open and implicitly recover them. This can
conservatively reject a concurrent writer; retry after it finishes. Never delete
sidecars, receipts or audit events to make reporting succeed. A pending triage
operation, missing event or divergent state must be inspected/recovered through
the existing store workflow separately; this command will not do it.

Locks are cooperative and local-filesystem based. Raw mutations bypassing locks,
concurrent hostile symlink changes, network-filesystem locking semantics, and
cryptographic tamper proof are outside the guarantees. Technical history is
validated for format, identity and finding linkage, not reconstructed or used to
invent missing technical events. Legacy naive timestamps cannot establish absolute
chronology against timezone-aware events; the wall-clock ordering convention is
explicit rather than inventing a UTC offset.

The snapshot and complete output are held in memory; cost grows with findings,
histories and receipts. File export requires same-directory hard-link support.
After successful publication a failure removing the temporary link can still
produce an error with a complete destination present; no rollback or power-loss
durability is claimed. Source data remains unchanged. Exported opaque fields may
contain sensitive assessment content; consumers should treat it as source data.

## Validation

Baseline: 585 Linux cases (582 passed, 3 platform skips on Windows).
70 new functional cases were written before the associated implementation/fixes.
The initial red run failed because the reporting module did not yet exist;
subsequent red runs reproduced nonfinite data, protected destinations and stream
failure handling before correction. Coverage includes all nine state combinations,
both histories, legacy records, empty assessments, Markdown injection, format and
schema stability, real subprocess CLI invocation, existing/concurrent destinations,
partial write/fsync/publication failures, descriptors, integrity failures, source
preservation and thread/process coordination. Timing is not an acceptance gate.
Final Python 3.12/3.13 Linux and Windows outcomes are recorded in the PR after CI.
