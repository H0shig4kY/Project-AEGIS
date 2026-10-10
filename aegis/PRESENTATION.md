# Project AEGIS: framework presentation

## Purpose and terminology

Project AEGIS combines cybersecurity research with practical tooling. AEGIS is its
stateful authorized-assessment framework. ARGUS is the reconnaissance/observation
layer used by that framework, not a separately installed product.

An assessment records what was observed, how technical findings change and what
operators decide operationally. Evidence management and custody add explicit
associations and traceability. Export packages allow a recipient to verify a
transported snapshot without importing it or contacting external systems.

## Implemented workflow

1. Define authorized scope: domains, wildcards, IP addresses or CIDR networks.
2. Run selected DNS/HTTP/service/TLS plugins against an authorized environment.
3. Persist raw results and baselines; process accepted observations into assets,
   relations, changes and findings according to the implemented rules.
4. Query technical lifecycle and independently acknowledge, suppress or reopen
   operational triage. Suppression does not mean technical resolution.
5. Explicitly associate captured files, observation snapshots or declarative references.
6. Optionally activate custody, inventory prior evidence and record subsequent attachments.
7. Produce findings reports or portable assessment packages with explicit coverage.

There is no guarantee that a plugin run yields a finding, nor a CLI command that
manually creates one. The [quickstart](../docs/quickstart.md) uses a labeled offline
fixture for a deterministic walkthrough without network activity.

## Three separate deliverables

| Deliverable | Purpose | Boundary |
|---|---|---|
| Findings report schema 1 | Existing records and histories, JSON/Markdown | Default; opaque legacy fields are not verified evidence |
| Findings report schema 2 | Adds verified managed-evidence metadata | Explicit; no captured blob contents |
| Assessment ZIP package schema 1 | Portable snapshot with manifest and independent verification | Different schema namespace; share/forensic profiles |

`share` uses a closed allowlist and omits objects, free text and original custody
events. It retains correlatable IDs/hashes, so it is not anonymization.
`forensic` is explicitly selected, preserves covered original records and warns of
plaintext. Captured objects additionally require `--include-objects`.
Neither profile is a complete workspace or disk-image backup.

## Custody and verification

Custody is an independent opt-in namespace. Activation inventories existing evidence
without inventing historical capture events. Future attachments use intents,
immutable associations, chained events and completion receipts. Incomplete operations
fail reading/export rather than appearing complete. Recovery is explicit and
idempotent for consistent pending data; it is not destructive repair.

Package integrity, custody status, external-checkpoint match, evidence metadata
status and content status are separate results. Hashes establish internal byte
consistency; they do not authenticate an operator, origin or timestamp. A consistent
truncated chain requires an independently trusted checkpoint to detect truncation.

## Deployment and limitations

- Python packaging requires >=3.12; CI covers 3.12/3.13 on Linux/Windows.
- Local filesystems must support the publication primitives; deployment ACLs need review.
- Locks coordinate cooperating writers, not hostile filesystem owners.
- Evidence/forensic output can contain secrets in plaintext; no encryption or signing is provided.
- Verification does not extract, import, execute members or make network requests.
- Byte/member limits do not establish a fixed process-RSS ceiling.
- There is no universal power-loss durability guarantee or automatic destructive cleanup.

## Documentation and direction

Start with [installation](../docs/installation.md), [quickstart](../docs/quickstart.md)
and [commands](COMMANDS.md). Review [architecture](../docs/architecture.md),
[security](../docs/security.md) and [recovery](../docs/recovery.md) before operational use.

Sprints 1–7 are integrated at documentation baseline
`36e914a44f68f7560711c323c15d525a0eb67378`. Historical benchmark/test results remain
in their technical guides; current validation is identified by its Actions run and
commit. [Roadmap](../ROADMAP.md) separates deliveries from proposals. Research
interests in identity security, Windows internals and cyberintelligence are not
claims of implemented plugins, autonomous agents or real-time defensive systems.
