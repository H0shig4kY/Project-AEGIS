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
