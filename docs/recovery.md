# Integrity diagnosis and recovery

## Preserve first

Stop cooperating writers before diagnosis. Preserve a consistent copy of the
assessment and diagnostic output under private access controls. Do not alter
permissions on originals, edit JSON/hash fields, remove lock databases, delete
objects/receipts or clear staging to make checks pass. Retained temporaries and
orphans may be useful evidence. This guide provides no destructive repair command.

## Start with dedicated readers

Run in the assessment:

```console
aegis assessment custody verify --json
aegis findings report --format json
aegis findings report --schema-version 2 --format json
```

Schema 1 does not inspect managed evidence/custody; it is not a substitute for
schema 2 or custody verification. Use actual IDs for evidence `show`/`verify`.
These dedicated paths do not initialize stores or automatically recover. A failure
is not an empty assessment or proof that nothing was published.
Traditional `findings list/show/history/triage-history`, `status` and other store
queries are not strict forensic readers: they may create operational directories
or locks, and finding transactions can recover the separate triage journal.

## Pending custody operations

1. Preserve source data and stop competing writers.
2. Verify custody and identify that the failure is a pending operation, not merely
   malformed data, inaccessible storage or contradictory content. The CLI may give
   a sanitized generic error; inspect a preserved copy when further diagnosis is needed.
3. If a consistent published intent remains, request explicit recovery:

```console
aegis assessment custody recover --actor analyst --reason "Inspect interrupted publication" --json
aegis assessment custody verify --json
aegis findings report --schema-version 2 --format json
```

4. Verify again before export. Consistent completed recovery is idempotent; conflicting
   objects/records/events, missing findings or invalid current quotas fail rather than
   being overwritten. Recovery retains original event actor/time; the recovery request
   is not a separate authenticated administrative audit event.

For interrupted initialization before any intent, retrying explicit `custody init`
can finish an empty layout while preserving temporary files. Once an initialization
intent exists, use explicit `recover`. Do not guess from a CLI error that publication
rolled back; a fsync failure can have an uncertain post-publication outcome.

## Triage is a separate recovery mechanism

The triage journal coordinates finding state and operational history. Normal
FindingStore transactions automatically recover consistent pending intentions.
There is **no dedicated triage-recover CLI command**. Custody recovery does not
repair that journal. For preservation-first inspection use reporting, which validates
triage receipts without recovery. See [storage integrity](storage-integrity.md) for
technical behaviour; do not use a normal finding query as a promise of no writes.

## Failures that should not be repaired automatically

| Failure | Action |
|---|---|
| Missing/corrupt blob, invalid record, mismatched provenance or chain | Preserve artifacts; identify the cause on a copy. Recovery must not replace contradictory data. |
| Permission/ACL failure or enumeration error | Verify authorized account access and deployment configuration. Do not treat inaccessible storage as empty. |
| Busy/unsettled SQLite lock metadata | Wait for cooperating writers to exit, retry dedicated readers; preserve sidecars. Do not manually delete locks. |
| Quota exceeded | Inspect configured limits and counted orphans/staging. Do not delete evidence to bypass accounting. |
| Unsupported hard links/filesystem | Use a supported local deployment; do not introduce unsafe copy/overwrite fallback. |
| Existing export destination | Choose a new absolute external destination without `..` or linked components and preserve any existing artifact. |
| Package verification failure | Keep the package, reject it for use, obtain a valid snapshot through a trusted process. There is no package repair/import command. |

## Independent package checks

These work outside an assessment and never extract or recover:

```console
aegis assessment package inspect package.zip --json
aegis assessment package verify package.zip --json
```

For external trust options see [checkpoints](security.md#external-checkpoints).
Normal custody/package operational failures exit nonzero with stderr; no valid
verification result is returned. Avoid sharing diagnostics containing private data.
