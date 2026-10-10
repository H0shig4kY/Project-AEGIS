# Architecture

## Assessment context

An assessment (also called a campaign in existing interfaces) is a directory with
`aegis.yaml`. Discovery uses the nearest ancestor containing that file.
`CampaignContext` locates paths; `AssessmentContext` constructs traditional stores
and processors and can initialize storage. A configured name is not a guaranteed
unique assessment identifier.

## Data flow and independent domains

| Component | Stored data / role | Important boundary |
|---|---|---|
| Scope | `scope.yaml` | Authorization policy, not proof of permission |
| Plugin results/integrity | `data/results`, `data/integrity` | Original or retrospective result baselines |
| Assets/relations/changes | `data/assets`, `data/relations`, `data/changes` | Accepted observations and lifecycle change records |
| Findings | `data/findings/<finding_id>.json` | Rule finding and technical/operational states |
| Technical history | `data/finding_history` | Stored technical lifecycle events |
| Triage history/journal | `data/finding_triage_history`, `data/findings/.triage-journal` | Operational audit and recoverable state/event publication |
| Managed evidence | `evidence/managed-v1` | Immutable association records, SHA-256 content objects and staging |
| Custody | `evidence/custody-v1` | Explicit genesis/inventory, events, intents and completions |
| Exports | External report/package destination | Derived output; no source export event is added |

Findings have technical `state`: `active`, `candidate_missing`, `resolved`.
Independent `triage_state` is `open`, `acknowledged`, `suppressed`.
Triage does not change technical resolution. Evidence/custody operations do not
change either state, technical history or the triage journal.

## Evidence and custody

Managed records explicitly connect an evidence UUID to a complete finding ID.
Objects use SHA-256 filenames and deduplicate physical content within an assessment.
Associations retain independent declared provenance and audit metadata. Legacy opaque
evidence fields remain opaque; no automatic migration infers verified associations.

Custody activation creates genesis and an initial inventory of existing associations.
Subsequent attachments follow object validation/publication -> intent -> association
-> chained event -> completion. A published association without completion is not
accepted as a completed operation. Explicit recovery completes consistent pending
operations without replacing contradictions; consultation does not recover them.

## Reads, locks and publication

Traditional store constructors may create directories; normal FindingStore reads
run a transaction that can recover the triage journal. This behaviour is distinct
from dedicated report/evidence/custody/package readers, which validate without
initialization or automatic recovery.

Cooperative lock order is findings -> histories (or result/integrity locks for an
observation) -> assessment -> managed evidence -> custody. SQLite is a lock provider,
not the domain database. Locks do not constrain hostile raw filesystem writers.

Complete JSON replacement uses atomic-storage helpers. Immutable evidence/custody
publication uses exclusive hard links. Errors after publication or fsync can leave
an uncertain outcome, complete published data, temporaries or orphan objects.
There is no guaranteed multi-file rollback or universal power-loss durability.

## Reporting and portable verification

Findings report schema 1 is the default, preserving existing records and histories.
Explicit schema 2 adds verified managed-evidence metadata without blobs. It is
separate from **package_schema_version 1**, which describes ZIP exports.

The ZIP manifest inventories exact member paths, sizes and hashes. Share transports
allowlisted projections/checkpoints; forensic transports covered original records,
chain documents and optional objects. The independent reader performs bounded
physical ZIP preflight before ZipInfo materialization, then byte/hash/schema and
cross-document validation. It never extracts, executes, imports or contacts URLs.

See [security](security.md), [recovery](recovery.md), [storage integrity](storage-integrity.md),
[evidence](evidence-management.md) and [custody/export](custody-assessment-export.md)
for detailed guarantees and limitations.
