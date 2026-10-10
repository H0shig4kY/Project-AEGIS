# Evidence management and provenance (Sprint 6)

Evidence is an explicit operator association, not a new finding lifecycle state.
The supported Python interfaces are `EvidenceManager` and `EvidenceReader`.
Finding JSON, technical/triage states, histories and triage receipts are never
updated by these interfaces. No scans, HTTP requests or automatic imports run.
Actors are declared operator identities, not authenticated accounts.

## Storage and immutable records

Only this new namespace is managed; older evidence files remain untouched:

```text
evidence/managed-v1/
  objects/<sha256>.blob
  records/<uuid32>.json
  staging/object-<random>.tmp
  staging/metadata-<random>.tmp
```

SHA-256 identifies exact captured bytes. Each frozen schema-1 record has its own
UUID, finding ID, discriminated origin, UTC registration timestamp, optional UTC
observed timestamp, actor/reason, representation, content digest/size, source
baseline quality and versioned association key. No source path controls storage
names. Local origins store only a restricted plain basename, not an absolute path.
Observation origins identify the result filename, raw result SHA-256, existing
result/observation IDs, observation index, plugin/version and source timestamp.
When verifying `observation-json-v1`, readers parse the conserved snapshot,
compare every embedded origin field with the association, and recompute the
selected observation ID. Invalid structure, nonfinite values, duplicate JSON members and mismatches
stop verification and schema-2 export. This checks internal consistency, not
authentication of the source or reconstruction of the full original result.
The occurrence includes the result and index: repeated equal observations are not
silently collapsed. Naive source timestamps are retained in the origin; they do
not become an invented UTC observed timestamp.

The association key includes finding, kind, origin and captured digest. Repeating
that association with the same actor/reason/observed timestamp returns the original
UUID. Conflicting audit metadata fails. Associations for different findings remain
independent while identical content shares one object within the assessment.
There is no edit, delete, unlink, garbage collection, signing or encryption API.

SHA-256 verifies equality against the recorded bytes; it does **not** authenticate
an origin or provide tamper-proof custody. A filesystem owner able to replace both
metadata and bytes can defeat unsigned hashes. Metadata immutability is enforced
by the cooperating API's exclusive publication, not WORM storage or signatures.

## Capture modes

* Local file: capture a stable regular file into bounded memory, reject symlinks,
  linked parent directories, reparse points, devices and pipes, compare descriptor
  identity and observable size/timestamps before/after reading. Hostile raw source
  modifications that defeat these observations are outside the guarantee.
* Stored observation: read and validate an existing JSON plugin result, select one
  index, check a matching existing integrity-manifest baseline if present, and
  capture a strict canonical UTF-8 JSON snapshot containing the selected raw
  observation and its provenance. Other observations are not copied. The existing
  result ID is not a digest of the complete original file. Manifest baselines are
  `original` or `retrospective`; absent baselines are `unknown`. No retrospective
  baseline is silently created. Source results are bounded by the configured object
  limit; oversized results cannot be processed by this capture interface.
* External reference: declarative HTTP(S) locator, with no userinfo, query,
  fragment, whitespace or controls. It has no content hash or blob. Verification
  returns `reference_only`, never `verified`. No external availability is inferred.

Local names use the restricted ASCII plain-filename format used for safe source
metadata. Result selectors are basenames inside `data/results`; arbitrary paths
are rejected. A copied observation remains verifiable if the source result later
disappears; its provenance records the source snapshot, not current availability.

Observation capture checks lexical components from the already-resolved assessment
root through `data`, `results`, `integrity` and the selected files before resolving
locks or opening inputs. Symlinks, reparse points and inappropriate file types are
rejected. Missing results fail; an absent integrity manifest remains legitimate
unknown provenance. Components above the resolved assessment root are not rejected,
preserving existing assessment-location behaviour. Checks are repeated before
reading, but do not guarantee protection against hostile concurrent directory swaps.

## Limits and confidentiality

Optional `aegis.yaml` configuration (defaults shown):

```yaml
evidence:
  max_object_bytes: 52428800       # 50 MiB
  max_assessment_bytes: 1073741824 # 1 GiB
```

Limits are strict positive integer byte counts; the object limit cannot exceed the
assessment limit. The object limit applies without truncation to captured bytes.
Quota counts physical content in `objects` and abandoned object staging, including
orphans. Hard-linked names count once using device/inode identity; unknown identity
fails accounting. JSON records and metadata staging are outside the content quota;
records have a separate 64 KiB maximum. There is no total metadata-count quota.

All quota inspection and publication are serialized by the managed-root lock.
Existing objects are read and verified before reuse. A full quota permits exact
reuse without another physical content copy. Failure to establish safe accounting
fails the operation before a new association is published. The assessment lock
also protects configuration from cooperative changes throughout capture and
publication. Raw filesystem edits and hostile noncooperating writers are outside
this cooperative contract. Lowering a quota does not delete data.

Captures and snapshots can contain credentials, personal information and other
sensitive material. They are plaintext, not encrypted. Do not publish the evidence
directory in Git or share it indiscriminately. An operator must review locators and
free-text audit fields: rejecting URI credential components cannot identify every
secret embedded in a URL path, actor or reason.

New managed directories use mode 0700 and staging/object/record files originate
from private temporary files (0600) on Linux. Existing non-private managed
directories are rejected rather than silently chmodded. The existing assessment
and legacy evidence directories are not rewritten. On Windows, inherited ACLs
control access; POSIX mode bits do not provide equivalent isolation. Configure a
private assessment ACL externally. Tests cover Windows publication, reads,
cooperative processes and reparse-point rejection; they do not certify deployment
ACLs or protection against administrators. Object capture is bounded in memory;
raising configured limits raises memory requirements.

## Publication, locks and failure semantics

The finding lock protects validated finding existence. `finding_snapshot` reuses
the existing complete schema-1 read projection; it never invokes finding-store
recovery. This deliberately favours correctness over a faster single-finding read.
Observation capture additionally holds existing result/manifest locks. The evidence
root lock protects quota, deduplication and exclusive publication. Writers hold
the assessment lock from limit validation through publication. No evidence-root
lock is acquired before finding validation. Report schema 2 acquires evidence
locking after the established finding/history/assessment locks.

Content is completely written, flushed and fsynced in staging, then published with
an exclusive hard link. Its bytes are verified before the JSON record is published
the same way. The JSON record is the authoritative association and audit commit
marker; there is no separate multi-file audit write and no evidence WAL.
Successful publication removes only its own temporary link. A failed write,
publication or synchronization preserves remaining temporaries and orphan objects.

There is no guaranteed rollback after publication. A directory-sync failure after
record publication can return an error with a complete association already present.
Retrying/re-querying discovers the original UUID without duplicating the record.
Readers reject invalid metadata, duplicate association keys, missing/corrupt blobs,
invalid layout, inaccessible storage and enumeration failures. An existing managed
root missing required directories is incomplete and is not reinitialized. A wholly
absent managed namespace is legitimate legacy absence. Reading never repairs,
deletes or initializes persisted storage.

Inspect retained staging/orphans manually before any administrative recovery.
Do not delete objects to make quota checks succeed. Same-volume hard-link support
is required. Locks are cooperative and local-filesystem based. Existing SQLite
sidecars can cause an explicit busy/unsettled error instead of metadata recovery;
retry after the competing writer finishes. This applies to queries and validated
write preconditions. There is no cache that substitutes size/mtime for byte checks.
POSIX directory synchronization is attempted; Windows has no portable equivalent
in the existing helper. Tests demonstrate injected failure boundaries, not
power-cut durability or network-filesystem guarantees.

## Python and CLI

```python
manager = EvidenceManager(campaign)
record = manager.attach_file(finding_id, path, actor="operator", reason="review")
manager.attach_observation(finding_id, result_filename, 0,
                           actor="operator", reason="review")
manager.attach_reference(finding_id, "https://example.test/report",
                         actor="operator", reason="source reference")
reader = EvidenceReader(campaign)
reader.list_for_finding(finding_id)
reader.get(record.evidence_id)
reader.verify(record.evidence_id)
```

```console
aegis findings evidence add-file <finding-id> capture.bin --actor analyst --reason "manual review" --json
aegis findings evidence add-observation <finding-id> --result dns-<timestamp>.json --index 0 --actor analyst --reason "stored observation" --json
aegis findings evidence add-reference <finding-id> --source https://example.test/report --actor analyst --reason "public reference" --json
aegis findings evidence list <finding-id> --json
aegis findings evidence show <evidence-id> --json
aegis findings evidence verify <evidence-id> --json
```

Read commands return metadata only. Verification is transient and never persists a
verified timestamp. JSON stdout contains no decorative messages. Normal errors
use stderr and exit 1; CLI argument errors exit 2. File inputs and observations are
explicitly chosen by the operator, not automatically attributed to findings.
Validation diagnostics omit input values, validator context and parser excerpts.
Only known schema field names and error categories are displayed; unknown mapping
keys are redacted. Symlink-resolution cycles produce a controlled, path-free error
in both Python 3.12 and 3.13. Unrelated RuntimeError exceptions are not masked.

## Opt-in reporting schema 2

```console
aegis findings report --schema-version 2 --format json
aegis findings report --schema-version 2 --format markdown --output evidence-report.md
```

Schema 1 remains the default and does not inspect the new evidence namespace.
Schema 2 adds each finding's `evidence` array, with `metadata` and `verification`,
and `summary.evidence` counts of associations, captures and external references.
Captured bytes are re-read and verified; missing/corrupt/inaccessible content or
an association to a missing finding stops export. No blob/base64 content is
exported. Source/result basenames are omitted from this public report projection.
Ordering is by UTC registration timestamp and UUID. Existing Markdown literal
escaping is reused. All existing exclusive output/protected-input rules remain.

Legacy opaque `source_extensions`, including an old `evidence` field, remain
opaque and are never promoted to managed/verified evidence. They retain their
previous export behaviour and may themselves contain sensitive source data.
There is no migration of finding JSON, histories, triage journal or old evidence.

## Validation and review

Baseline: commit 203eaa6, 695 Linux cases (692 passed, 3 skips on Windows).
Tests were added before the associated behaviour, with red runs for absent modules,
observation methods, CLI/schema 2, incomplete storage, timestamp overflow,
oversized records, silent short writes and linked source parents. Fault injection
uses temporary assessments only. Coverage includes real subprocess CLI, threads
and spawned processes, quotas, read-only source bytes/mtime, retained orphans,
post-publication failures, legacy schema 1 and verified schema 2.
Final suite/CI results are reported in the PR. An independent audit is required
before recommending integration; no merge is authorized by this sprint.
