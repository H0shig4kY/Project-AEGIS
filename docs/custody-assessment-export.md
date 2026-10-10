# Evidence custody and portable assessment packages

## Scope and trust

Custody is explicitly activated per assessment. It is independent of technical
findings, operational triage, their histories and the triage recovery journal.
Existing evidence associations are inventoried, not attributed retroactively to
new capture events. SHA-256 verifies bytes and internal relationships, not an
operator's identity, historical authenticity or certified time.

This implementation assumes cooperating AEGIS writers and an assessment on a
local filesystem supporting exclusive hard-link publication. A writer controlling
all files can rewrite the chain or remove a complete suffix and its associations.
A previously trusted external checkpoint detects a different final head. Without
such a checkpoint, a consistent prefix remains internally valid. Clock regressions
are reported as anomalies; sequence numbers are authoritative.

## CLI

```bash
aegis assessment custody init --actor operator --reason 'Activate custody'
aegis findings evidence add-file <finding-id> capture.bin --actor operator --reason 'Capture'
aegis findings evidence custody-history <evidence-id> --json
aegis assessment custody verify --json
aegis assessment custody verify --checkpoint trusted-checkpoint.json --json
aegis assessment custody recover --actor operator --reason 'Interrupted publication'
aegis assessment export --output /external/share.zip
aegis assessment export --output /external/forensic.zip --profile forensic
aegis assessment export --output /external/with-objects.zip --profile forensic --include-objects
aegis assessment package inspect /external/share.zip --json
aegis assessment package verify /external/with-objects.zip --json
aegis assessment package verify /external/with-objects.zip --expected-sha256 <trusted-hash> --json
```

Package commands work without a local assessment. Successful command outputs are
JSON; errors and the mandatory forensic plaintext warning go to stderr. Reading
custody, reporting and package verification never initializes directories or
recovers pending operations. Export writes only outside the assessment and never
records the consultation/export in its source chain.

`CustodyReader.verify`, `list_events` and `inventory` are read-only.
`CustodyManager.initialize` and `recover` are explicit writes. Evidence attachment
continues through `EvidenceManager`. After activation, the public
`EvidenceStore.publish_record` refuses direct publication; `commit_record` requires
the finding, assessment and managed-evidence writer locks and creates an intent.
Private publication primitives are implementation details, not security boundaries
against hostile Python code or external writers.

## Storage and publication

`evidence/custody-v1/` contains `genesis.json`, `baseline.json`, `events/`,
`intents/`, `completions/`, and `staging/`. Published JSON is immutable. Events are
hashed with a versioned domain separator and canonical JSON excluding the event's
own hash. The canonical form is AEGIS-specific, not a claim of RFC 8785 compliance.

Attachments publish/revalidate the object, publish the full immutable intent,
publish the association, publish the chained event, then publish completion.
Readers refuse incomplete intents. Recovery revalidates content, association,
finding existence and current content quotas; it never replaces conflicting data.
Recovery retains the original declared actor/time and does not invent a recovery
custody event. Recovery actor/reason are validated request parameters, not a
separate authenticated audit trail of administrators.

Before an initialization intent is published, retrying explicit `init` may finish
an empty layout while preserving temporary files. Once an intent exists, use
explicit `recover`. Interrupted publication may leave objects or temporaries for
inspection. No automatic deletion, compaction or destructive repair is provided.
An error after publication/fsync has an uncertain outcome: inspect before retrying;
never assume a rollback. POSIX directory fsync is attempted. Windows has no portable
stdlib directory-fsync equivalent; no universal power-loss durability is claimed.
Private directories/files use POSIX modes 0700/0600; Windows ACLs must be configured
externally. Path checks reject symlinks/reparse points but are not a guarantee
against hostile simultaneous parent-directory substitution.

Lock order: findings -> histories (or observation integrity/results) -> assessment
-> managed evidence -> custody. Custody-only readers acquire only managed evidence
then custody and never acquire an earlier lock. No same-thread lock upgrades are
introduced. Existing read-only SQLite sidecar checks may fail a competing operation
conservatively; callers retry explicitly. Tests exercise graph order, threads and
spawned processes. Published receipts/intents grow without compaction; custody
intent/event/completion metadata is bounded at 256 MiB for new publications.
Old AEGIS versions do not understand custody: a new out-of-protocol association is
an integrity error in updated readers. Do not mix writer versions after activation.

## Profiles and privacy

`share` is the default and accepts no objects. It is minimization, not anonymization:
IDs, content hashes, sizes, state and counts remain correlatable. Findings contain
only `finding_id`, `state`, `triage_state`. Evidence projections contain only
`projection_schema_version`, `evidence_id`, `finding_id`, `kind`, `representation`,
`content_sha256`, `content_size`, `source_integrity`, `association_sha256`, and
`verification` (`metadata_status`, `content_status`). Operators, reasons, URLs,
source names, timestamps, plugins, observations, free text and extensions are omitted.
The hash of an original association is a commitment, not verification of omitted
metadata. The genesis/chain head appears only as a checkpoint.

`forensic` must be explicitly selected and warns about plaintext. It includes
original findings, histories, evidence records, genesis/baseline/events/completions,
and portable completed triage receipts. Objects require `--include-objects`.
Original records and blobs may contain credentials, personal information or other
sensitive data; this profile does not redact them. Neither profile includes full
configuration, scope, plugin-result directories, locks, temporaries, or orphan
objects. The package is a snapshot of the declared scope, not a full forensic disk
image or complete workspace backup. Legacy opaque fields never become managed
verified evidence.

## Manifest and verification

`manifest.json` has exactly: `package_schema_version` (1), `package_type`
(`aegis-assessment-export`), `profile`, `generated_at`, `assessment` (`chain_id`),
`coverage`, `custody`, `summary`, `limits`, and `members`. Members have exactly
`path`, `category`, `size`, `sha256`, sorted by path. Manifest does not inventory
itself. Package SHA-256 is computed externally; the reader accepts an expected
hash/checkpoint supplied by a separately trusted channel.

Verification separates `package_integrity`, `custody.status`,
`custody.external_checkpoint_match`, `evidence[].metadata_status`, and
`evidence[].content_status`. A failed attempt raises an integrity exception and is
classified as `verification_failed`, never a valid package result.

* `not_initialized`: no activated source chain.
* `checkpoint_only`: events omitted; no independent chain verification.
* `chain_verified`: transported chain checked, without identity authentication.
* `projection_only`: only the transported projection verified, not original metadata.
* `content_not_included`: captured bytes omitted, even when their hash is declared.
* `reference_only`: declarative external reference; no network verification.
* `content_verified`: included bytes/hash/size and applicable observation semantics checked.

Only stored, unencrypted ZIP members are accepted. Verification checks central
inventory count before ZipFile allocation, names/types/flags, actual streamed byte
counts/hashes, category schemas, summary counts and cross-document relationships.
It never extracts, imports, executes or requests URLs. Unknown, duplicate,
case-colliding, linked, special, compressed, overflowing, contradictory or excessive
members are rejected. Output files are published exclusively after verification.
ZIP64 is supported within local limits. Given the same snapshot/options/generation
time, ZIP members and metadata are normalized for byte determinism.

Limits: total content including manifest 2 GiB; 100,000 members including manifest;
manifest 16 MiB; evidence association/event 64 KiB; completion 128 KiB;
genesis/baseline and finding/history/portable receipt 16 MiB per document;
object 50 MiB by default; aggregate package metadata 256 MiB; physical ZIP
2 GiB + 256 MiB; internal ASCII path 128 characters. `PackageLimits` can supply an
explicit trusted local policy; a manifest cannot increase reader limits. Oversize
legacy records fail explicitly without truncation. External historical directories
and linked storage are rejected for portable export rather than silently omitted.

## Compatibility and validation

Reporting schema 1 stays default and unchanged. Schema 2 retains its fields and
rejects pending/inconsistent custody through its evidence reader. Existing evidence
JSON and objects are not rewritten on activation. Findings/state/triage_state,
histories and triage journal formats remain unchanged.

Tests cover immutable baseline, no retroactive events, all publication boundaries,
explicit idempotent recovery, corruption, checkpoint/truncation limitations, clock
anomalies, lock order, threads/spawned processes, deterministic exports, read-only
source bytes/mtime, profiles, actual limits, malicious ZIP and sanitized errors.
The CI matrix is Python 3.12/3.13 on Linux and Windows. Three existing Windows skips
remain associated with fork and symlink privilege tests from earlier sprints.

## PR #8 audit corrections

Export recognizes only the exact `.triage-journal` directory already validated
and bounded separately; unknown directories and linked/reparse storage remain errors.
A completed triage operation can be exported without changing its source records.

Direct `CustodyManager.commit_record` calls require the documented writer locks
and revalidate the complete association, existing finding, deduplication key,
current assessment configuration quotas and captured content before publishing
any intent. Finding decoding is a bounded pure read under the existing finding
lock; it does not acquire earlier history locks or recover a triage operation.
Idempotent attachments continue through `EvidenceManager`.

Package preflight counts actual central-directory headers with constant additional
memory before constructing any `ZipInfo`. It reconciles EOCD and ZIP64 values,
checks boundaries and limits the number of header reads. Each central entry is
bounded to 512 bytes (including at most 128 filename bytes). Exactly 65,535 ordinary
entries and legitimate ZIP64 archives are supported within local policy. These
bounds do not claim a fixed total process-memory ceiling for all JSON decoding.

Source and package readers share the object-only baseline validator and the pure
legacy technical-history decoder. Optional history fields and naive legacy
timestamps retain the source store's existing behavior. Invalid CLI profiles are
reported with allowed options without echoing the supplied value.

## Supported physical ZIP layouts

The portable AEGIS format accepts a single-disk, unencrypted `ZIP_STORED` archive
with local members in the same order as the central directory. The first local
header starts at byte zero. Every local header, filename, extra field and payload
must end exactly where the next member starts, and the last payload must end at
the central directory. Headers must agree on filename, required version, flags,
timestamps, CRC and sizes. Gaps, overlapping regions, orphan payloads, prefixes,
trailing data and inconsistent offsets are rejected before `ZipFile` allocation.
Payload CRCs and manifest hashes are subsequently verified through bounded reads.

Before constructing `ZipFile`, both physical filenames must be identical ASCII
bytes, at most 128 characters, and match `manifest.json` or an allowed AEGIS
member path. NUL, controls (including DEL), backslashes, absolute paths,
drive/ADS syntax, empty/dot/traversal components, Windows reserved device names,
forbidden Windows characters and trailing dots/spaces are rejected, never
normalized. `ZipInfo.orig_filename` must also equal `ZipInfo.filename` as an
additional defense. Rejection messages do not include the supplied filename.
The generic `preflight` helper validates physical-name safety; package readers
always additionally enable the closed AEGIS path grammar.

Data descriptors, including otherwise valid streaming ZIP layouts, are not
supported. Descriptor flags are rejected explicitly; there is no permissive
fallback. Canonical AEGIS exports use seekable output and do not need descriptors.

Archive and member comments are forbidden in both share and forensic. Local and
central extra fields must be empty unless a single `0x0001` ZIP64 field is needed
for a sentinel size or offset. Its length, field order and decoded values must
match the headers; redundant, duplicate, unknown and malformed fields are errors.
ZIP64 follows the canonical Python writer threshold (`ZIP64_LIMIT`, 2 GiB minus
one byte) for sizes/offsets. Minimal ZIP64 EOCD/locator records with version 45 are
accepted only when the member count exceeds 65,535 or a central offset/size exceeds
that threshold. Local policy limits still apply and cannot be raised by a package.

Physical-layout validation and actual entry counting retain constant additional
memory and bounded header reads before inventory materialization. Declared payload
sizes are summed during this pass, including the manifest. Bytes outside the
inventoried layout are rejected rather than excluded from content accounting.
These restrictions define the AEGIS subset; general-purpose ZIP variants outside
it are unsupported, even if another ZIP reader accepts them.
