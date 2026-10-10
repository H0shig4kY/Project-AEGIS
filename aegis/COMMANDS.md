# AEGIS command reference

This reference covers all 51 leaf commands registered at baseline
`36e914a44f68f7560711c323c15d525a0eb67378`. Signatures/options were inventoried
from the CLI and checked with each command's `--help`. It changes no CLI behaviour.

## Conventions and effects

Run assessment commands inside the assessment or a nested directory; discovery
uses the nearest ancestor containing `aegis.yaml`. Package commands, version,
info, commands, help and plugin-list do not require a local assessment.
`FINDING_ID`, `EVIDENCE_ID` and `*_FILE.json` in examples are substitution labels,
not literal working IDs/filenames. Select actual persisted values. Triage/evidence
writes require complete lowercase 64-hex finding IDs; evidence IDs are 32-hex UUIDs.
The [offline quickstart](../docs/quickstart.md) provides a concrete fixture.

Examples show valid syntax/preconditions, not invented scan results. Network-capable
`plugin run` is never required to validate documentation. Only run it in your
explicitly authorized lab. Scope supports domain, wildcard, IP and CIDR, not URL
or host:port. Quoting `"*.example.test"` prevents POSIX glob expansion.

**Effect classes:** dedicated readers (report/evidence/custody/package) do not
initialize or recover source storage. Traditional store queries may create operational
directories/locks or recover triage; query names alone do not guarantee no writes.
Attachment/triage/custody commands are explicit writers. Export/report output is
exclusive; packages must be outside the assessment. See [recovery](../docs/recovery.md).

`--json` is available only where listed. Custody/package commands and assessment
export always return JSON on success, including without their accepted `--json` flag.
Operational evidence/custody/package/report failures exit 1; parser errors generally
exit 2. Invalid export profiles exit 2 without echoing the supplied value. Legacy
commands have command-specific output/errors and are not all JSON/stderr interfaces.
Result verification's exit 2 can also mean unknown integrity, as noted below.

`aegis --help` and `aegis GROUP COMMAND --help` are current discovery tools.
`aegis commands` remains a partial convenience view. Updating it and `aegis info`
requires a separately approved Python change ([roadmap](../ROADMAP.md)).

## Root options and domain values

`aegis --compact COMMAND` changes terminal layout only. Root `--help` reads help.
Typer also exposes `--show-completion` (prints a completion script) and
`--install-completion` (can write shell configuration); installing completion is
not a read-only inspection command.

Asset types are domain, ip, url, service and certificate; these are distinct from
the narrower scope target types. Relation types are resolves_to, exposes and
presents. Change types are new, confirmed, candidate_missing, inactive and
reactivated. Finding severity filters accept info, low, medium, high and critical.
Technical finding states are active, candidate_missing and resolved.
There is no `--triage-state` filter in `findings list` at this baseline.

## Shell examples

Single-line commands with double-quoted reasons work in POSIX, PowerShell and CMD:

```console
aegis relations history domain example.test resolves_to ip 192.0.2.1
aegis changes list --target-value 192.0.2.1
```

For multiline syntax, POSIX uses a backslash, PowerShell a backtick and CMD a caret.
For example, after replacing FINDING_ID:

```bash
aegis findings acknowledge FINDING_ID \
  --actor analyst --reason "Manual review"
```

```powershell
aegis findings acknowledge FINDING_ID `
  --actor analyst --reason "Manual review"
```

```bat
aegis findings acknowledge FINDING_ID ^
  --actor analyst --reason "Manual review"
```

Use existing absolute external destinations such as `/absolute/export/share.zip`
on POSIX or `"C:\AEGIS-Exports\share.zip"` on PowerShell/CMD. Substitute your own
private directory. Export rejects paths containing `..` and linked components;
never place an assessment package inside the assessment.
Installation/activation syntax is in [installation](../docs/installation.md).

## Overview and assessments

### `aegis version`

Show AEGIS / ARGUS version.

**Syntax:** `aegis version`

**Effects:** Read-only; no assessment needed.

**Result:** Prints the CLI version.

```console
aegis version
```

### `aegis info`

Show AEGIS / ARGUS capabilities.

**Syntax:** `aegis info`

**Effects:** Read-only; no assessment needed.

**Result:** Prints a capability presentation. Its legacy scope wording is not authoritative: only domain/wildcard/IP/CIDR scope is supported.

```console
aegis info
```

### `aegis commands`

Show common AEGIS / ARGUS commands and examples.

**Syntax:** `aegis commands`

**Effects:** Read-only; no assessment needed.

**Result:** Prints a partial convenience reference; recent triage/evidence/assessment operations are omitted in the current Python implementation.

```console
aegis commands
```

### `aegis exposure`

Show the current assessed exposure surface.

**Syntax:** `aegis exposure [OPTIONS]`

| Option | Requirement / default |
|---|---|
| `--json` | optional; default off |

**Effects:** Traditional query; may initialize assessment stores or lock metadata. Paths using finding transactions may recover triage. Not a preservation-first reader.

**Result:** Show the current assessed exposure surface. Computes the current persisted exposure projection; --json is available.

```console
aegis exposure --json
```

### `aegis status`

Show an operational overview of the current campaign.

**Syntax:** `aegis status [OPTIONS]`

| Option | Requirement / default |
|---|---|
| `--json` | optional; default off |

**Effects:** Traditional query; may initialize assessment stores or lock metadata. Paths using finding transactions may recover triage. Not a preservation-first reader.

**Result:** Show an operational overview of the current campaign. Summarizes stored scope/exposure/changes/integrity; --json is available.

```console
aegis status --json
```

### `aegis init`

Create a new AEGIS / ARGUS assessment campaign.

**Syntax:** `aegis init <name>`

**Required arguments:** `name`.

**Effects:** Writes a new assessment directory/configuration; rejects an existing directory.

**Result:** Creates data/evidence/reports directories and aegis.yaml. Enter the new directory afterwards.

```console
aegis init demo-assessment
```

## Scope and reconnaissance

### `aegis scope add`

Add a target to the current campaign scope.

**Syntax:** `aegis scope add <value>`

**Required arguments:** `value`.

**Effects:** Writes scope.yaml and can initialize traditional assessment stores.

**Result:** Adds a validated target; wildcard examples need quoting, e.g. `aegis scope add "*.example.test"`. URLs and host:port are rejected.

```console
aegis scope add 127.0.0.1
```

### `aegis scope list`

List all targets in the assessment scope.

**Syntax:** `aegis scope list`

**Effects:** Query; not a network operation. Uses the existing scope interface, not a forensic snapshot API.

**Result:** Lists scope entries.

```console
aegis scope list
```

### `aegis scope remove`

Remove a target from the assessment scope.

**Syntax:** `aegis scope remove <target>`

**Required arguments:** `target`.

**Effects:** Writes scope.yaml when removing a target.

**Result:** Removes an existing scope value.

```console
aegis scope remove 127.0.0.1
```

### `aegis plugin list`

List installed AEGIS / ARGUS plugins.

**Syntax:** `aegis plugin list`

**Effects:** Read-only registry query; no scan.

**Result:** Lists registered plugins: dns, http, service and tls.

```console
aegis plugin list
```

### `aegis plugin run`

Execute an AEGIS / ARGUS plugin against the current campaign.

**Syntax:** `aegis plugin run <name>`

**Required arguments:** `name`.

**Effects:** Network-capable assessment writer. Requires an authorized lab and configured scope.

**Result:** Persists results/baselines and processes observations/lifecycle/findings. No finding count or discovery outcome is guaranteed.

```console
aegis plugin run dns
```

## Assets and relations

### `aegis assets show`

Show a discovered asset.

**Syntax:** `aegis assets show <filename>`

**Required arguments:** `filename`.

**Effects:** Traditional query; may initialize assessment stores or lock metadata. Paths using finding transactions may recover triage. Not a preservation-first reader.

**Result:** Show a discovered asset.

```console
aegis assets show ASSET_FILE.json
```

### `aegis assets list`

List discovered assets.

**Syntax:** `aegis assets list [OPTIONS]`

| Option | Requirement / default |
|---|---|
| `--type VALUE` | optional; default unset |
| `--source VALUE` | optional; default unset |

**Effects:** Traditional query; may initialize assessment stores or lock metadata. Paths using finding transactions may recover triage. Not a preservation-first reader.

**Result:** List discovered assets.

```console
aegis assets list --type service
```

### `aegis assets graph`

Show outgoing asset relations recursively.

**Syntax:** `aegis assets graph <value> [OPTIONS]`

**Required arguments:** `value`.

| Option | Requirement / default |
|---|---|
| `--type VALUE` | optional; default unset |
| `--details` | optional; default off |

**Effects:** Traditional query; may initialize assessment stores or lock metadata. Paths using finding transactions may recover triage. Not a preservation-first reader.

**Result:** Show outgoing asset relations recursively.

```console
aegis assets graph example.test --type domain --details
```

### `aegis assets related`

Show incoming and outgoing relations for an asset.

**Syntax:** `aegis assets related <asset-type> <value>`

**Required arguments:** `asset-type`, `value`.

**Effects:** Traditional query; may initialize assessment stores or lock metadata. Paths using finding transactions may recover triage. Not a preservation-first reader.

**Result:** Show incoming and outgoing relations for an asset.

```console
aegis assets related service example.test:443
```

### `aegis assets history`

Show the lifecycle and change history of an asset.

**Syntax:** `aegis assets history <asset-type> <value> [OPTIONS]`

**Required arguments:** `asset-type`, `value`.

| Option | Requirement / default |
|---|---|
| `--json` | optional; default off |

**Effects:** Traditional query; may initialize assessment stores or lock metadata. Paths using finding transactions may recover triage. Not a preservation-first reader.

**Result:** Show the lifecycle and change history of an asset.

```console
aegis assets history service example.test:443 --json
```

### `aegis relations list`

List discovered asset relations.

**Syntax:** `aegis relations list`

**Effects:** Traditional query; may initialize assessment stores or lock metadata. Paths using finding transactions may recover triage. Not a preservation-first reader.

**Result:** List discovered asset relations.

```console
aegis relations list
```

### `aegis relations show`

Show a stored asset relation.

**Syntax:** `aegis relations show <filename>`

**Required arguments:** `filename`.

**Effects:** Traditional query; may initialize assessment stores or lock metadata. Paths using finding transactions may recover triage. Not a preservation-first reader.

**Result:** Show a stored asset relation.

```console
aegis relations show RELATION_FILE.json
```

### `aegis relations from`

List relations originating from an asset.

**Syntax:** `aegis relations from <asset-type> <value>`

**Required arguments:** `asset-type`, `value`.

**Effects:** Traditional query; may initialize assessment stores or lock metadata. Paths using finding transactions may recover triage. Not a preservation-first reader.

**Result:** List relations originating from an asset.

```console
aegis relations from domain example.test
```

### `aegis relations to`

List relations pointing to an asset.

**Syntax:** `aegis relations to <asset-type> <value>`

**Required arguments:** `asset-type`, `value`.

**Effects:** Traditional query; may initialize assessment stores or lock metadata. Paths using finding transactions may recover triage. Not a preservation-first reader.

**Result:** List relations pointing to an asset.

```console
aegis relations to ip 192.0.2.1
```

### `aegis relations history`

Show the lifecycle and change history of a relation.

**Syntax:** `aegis relations history <source-type> <source-value> <relation-type> <target-type> <target-value> [OPTIONS]`

**Required arguments:** `source-type`, `source-value`, `relation-type`, `target-type`, `target-value`.

| Option | Requirement / default |
|---|---|
| `--json` | optional; default off |

**Effects:** Traditional query; may initialize assessment stores or lock metadata. Paths using finding transactions may recover triage. Not a preservation-first reader.

**Result:** Show the lifecycle and change history of a relation.

```console
aegis relations history domain example.test resolves_to ip 192.0.2.1 --json
```

## Changes and results

### `aegis changes list`

List detected changes in the current campaign.

**Syntax:** `aegis changes list [OPTIONS]`

| Option | Requirement / default |
|---|---|
| `--json` | optional; default off |
| `--type VALUE` | optional; default unset |
| `--asset-type VALUE` | optional; default unset |
| `--asset VALUE` | optional; default unset |
| `--relation-type VALUE` | optional; default unset |
| `--source-type VALUE` | optional; default unset |
| `--source VALUE` | optional; default unset |
| `--target-type VALUE` | optional; default unset |
| `--target-value VALUE` | optional; default unset |
| `--plugin VALUE` | optional; default unset |

**Effects:** Traditional query; may initialize assessment stores or lock metadata. Paths using finding transactions may recover triage. Not a preservation-first reader.

**Result:** List detected changes in the current campaign.

```console
aegis changes list --target-value 192.0.2.1 --json
```

### `aegis changes show`

Show a stored change.

**Syntax:** `aegis changes show <filename>`

**Required arguments:** `filename`.

**Effects:** Traditional query; may initialize assessment stores or lock metadata. Paths using finding transactions may recover triage. Not a preservation-first reader.

**Result:** Show a stored change.

```console
aegis changes show CHANGE_FILE.json
```

### `aegis results list`

List stored plugin results.

**Syntax:** `aegis results list`

**Effects:** Traditional query; may initialize assessment stores or lock metadata. Paths using finding transactions may recover triage. Not a preservation-first reader.

**Result:** List stored plugin results.

```console
aegis results list
```

### `aegis results show`

Show a stored plugin result.

**Syntax:** `aegis results show <filename>`

**Required arguments:** `filename`.

**Effects:** Traditional query; may initialize assessment stores or lock metadata. Paths using finding transactions may recover triage. Not a preservation-first reader.

**Result:** Show a stored plugin result.

```console
aegis results show RESULT_FILE.json
```

### `aegis results verify`

Verify the integrity of a stored plugin result.

**Syntax:** `aegis results verify <filename>`

**Required arguments:** `filename`.

**Effects:** Writes verified_at for successful known/baselined results; can initialize traditional stores.

**Result:** Displays hash/status. Exit 0 for OK/BASELINED, 2 for UNKNOWN, 1 for failure/conflict or operational error. Not a strict read-only verifier.

```console
aegis results verify RESULT_FILE.json
```

### `aegis results verify-all`

Verify integrity of all stored plugin results.

**Syntax:** `aegis results verify-all`

**Effects:** Writes verification metadata for successful results; can initialize traditional stores.

**Result:** Displays statuses/counts: exit 1 if failure/conflict, otherwise 2 if unknown, otherwise 0 (including empty results).

```console
aegis results verify-all
```

### `aegis results baseline-legacy`

Create retrospective integrity baselines for legacy results.

**Syntax:** `aegis results baseline-legacy`

**Effects:** Writes retrospective integrity baselines and eligible asset provenance.

**Result:** Baselines currently unknown results; cannot establish their historical authenticity. Existing baselines are not silently promoted to original.

```console
aegis results baseline-legacy
```

### `aegis results integrity-summary`

Show a summary of the campaign integrity manifest.

**Syntax:** `aegis results integrity-summary`

**Effects:** Traditional query; may initialize assessment stores or lock metadata. Paths using finding transactions may recover triage. Not a preservation-first reader.

**Result:** Show a summary of the campaign integrity manifest.

```console
aegis results integrity-summary
```

### `aegis results integrity-show`

Show an integrity manifest record.

**Syntax:** `aegis results integrity-show <filename>`

**Required arguments:** `filename`.

**Effects:** Traditional query; may initialize assessment stores or lock metadata. Paths using finding transactions may recover triage. Not a preservation-first reader.

**Result:** Show an integrity manifest record.

```console
aegis results integrity-show RESULT_FILE.json
```

## Findings and triage

### `aegis findings list`

List persisted exposure findings.

**Syntax:** `aegis findings list [OPTIONS]`

| Option | Requirement / default |
|---|---|
| `--severity VALUE` | optional; default unset |
| `--state VALUE` | optional; default unset |
| `--rule VALUE` | optional; default unset |
| `--asset-type VALUE` | optional; default unset |
| `--asset-value VALUE` | optional; default unset |
| `--json` | optional; default off |

**Effects:** Traditional store query; may initialize directories/locks and recover pending triage transactions. Not strict forensic read-only.

**Result:** Lists persisted findings with filters; --json provides structured output. Technical states are active, candidate_missing and resolved.

```console
aegis findings list --state active --json
```

### `aegis findings show`

Show detailed information about a persisted finding.

**Syntax:** `aegis findings show <finding-id> [OPTIONS]`

**Required arguments:** `finding-id`.

| Option | Requirement / default |
|---|---|
| `--json` | optional; default off |

**Effects:** Traditional store query; may initialize directories/locks and recover pending triage transactions. Not strict forensic read-only.

**Result:** Shows one finding; unambiguous ID prefixes are supported by this query.

```console
aegis findings show FINDING_ID --json
```

### `aegis findings history`

Show the lifecycle history of a persisted finding.

**Syntax:** `aegis findings history <finding-id> [OPTIONS]`

**Required arguments:** `finding-id`.

| Option | Requirement / default |
|---|---|
| `--json` | optional; default off |

**Effects:** Traditional store query; may initialize directories/locks and recover pending triage transactions. Not strict forensic read-only.

**Result:** Shows stored technical lifecycle events; --json gives a finding/timeline projection.

```console
aegis findings history FINDING_ID --json
```

### `aegis findings acknowledge`

Acknowledge an OPEN finding without changing its technical state.

**Syntax:** `aegis findings acknowledge <finding-id> --actor <actor> --reason <reason> [OPTIONS]`

**Required arguments:** `finding-id`.

| Option | Requirement / default |
|---|---|
| `--actor VALUE` | required |
| `--reason VALUE` | required |
| `--json` | optional; default off |

**Effects:** Writes triage state, audit event and triage journal; technical state unchanged.

**Result:** Only open -> acknowledged. Actor/reason must be nonempty; invalid/repeated transitions fail without another event.

```console
aegis findings acknowledge FINDING_ID --actor analyst --reason "Operational review" --json
```

### `aegis findings suppress`

Suppress an OPEN or ACKNOWLEDGED finding.

**Syntax:** `aegis findings suppress <finding-id> --actor <actor> --reason <reason> [OPTIONS]`

**Required arguments:** `finding-id`.

| Option | Requirement / default |
|---|---|
| `--actor VALUE` | required |
| `--reason VALUE` | required |
| `--json` | optional; default off |

**Effects:** Writes triage state, audit event and triage journal; technical state unchanged.

**Result:** Only open/acknowledged -> suppressed. Actor/reason must be nonempty; rejected transitions do not add events.

```console
aegis findings suppress FINDING_ID --actor analyst --reason "Operational review" --json
```

### `aegis findings unsuppress`

Reopen a SUPPRESSED finding's operational triage state.

**Syntax:** `aegis findings unsuppress <finding-id> --actor <actor> --reason <reason> [OPTIONS]`

**Required arguments:** `finding-id`.

| Option | Requirement / default |
|---|---|
| `--actor VALUE` | required |
| `--reason VALUE` | required |
| `--json` | optional; default off |

**Effects:** Writes triage state, audit event and triage journal; technical state unchanged.

**Result:** Only suppressed -> open, not technical reopening. Rejected transitions do not add events.

```console
aegis findings unsuppress FINDING_ID --actor analyst --reason "Operational review" --json
```

### `aegis findings triage-history`

Show operational audit events in chronological order.

**Syntax:** `aegis findings triage-history <finding-id> [OPTIONS]`

**Required arguments:** `finding-id`.

| Option | Requirement / default |
|---|---|
| `--json` | optional; default off |

**Effects:** Traditional store query; may initialize directories/locks and recover pending triage transactions. Not strict forensic read-only.

**Result:** Shows operational events chronologically; --json includes finding/timeline, actor, reason, timestamp and states.

```console
aegis findings triage-history FINDING_ID --json
```

## Reporting and evidence

### `aegis findings report`

Export a validated findings snapshot without scans, recovery or state changes.

**Syntax:** `aegis findings report [OPTIONS]`

| Option | Requirement / default |
|---|---|
| `--format VALUE` | optional; default `json`; json or markdown |
| `--output VALUE` | optional; default unset |
| `--schema-version VALUE` | optional; default `1`; 1 or 2 |

**Effects:** Read-only source projection; --output writes an exclusive report file. No source recovery/initialization.

**Result:** Defaults: JSON, schema 1. Schema 2 explicitly verifies managed evidence metadata without blobs. Without --output, the report alone goes to stdout; with it, success stdout is empty. Destination must pass protected-input checks and must not exist.

```console
aegis findings report --schema-version 2 --format markdown --output ../findings.md
```

### `aegis findings evidence add-file`

Capture a regular local file and associate it with a finding.

**Syntax:** `aegis findings evidence add-file <finding-id> <path> --actor <actor> --reason <reason> [OPTIONS]`

**Required arguments:** `finding-id`, `path`.

| Option | Requirement / default |
|---|---|
| `--actor VALUE` | required |
| `--reason VALUE` | required |
| `--json` | optional; default off |

**Effects:** Evidence writer; after custody activation also publishes recoverable custody documents. Does not change finding states/histories.

**Result:** Captures a regular file under configured quotas, rejecting linked/special paths. Returns association metadata, not blob contents.

```console
aegis findings evidence add-file FINDING_ID capture.txt --actor analyst --reason "Local capture" --json
```

### `aegis findings evidence add-observation`

Snapshot one explicitly selected stored observation.

**Syntax:** `aegis findings evidence add-observation <finding-id> --result <result-filename> --index <observation-index> --actor <actor> --reason <reason> [OPTIONS]`

**Required arguments:** `finding-id`.

| Option | Requirement / default |
|---|---|
| `--result VALUE` | required |
| `--index VALUE` | required; integer >=0 |
| `--actor VALUE` | required |
| `--reason VALUE` | required |
| `--json` | optional; default off |

**Effects:** Evidence/custody writer; reads the selected stored result. Does not modify the original result.

**Result:** --result is an existing result basename; --index is zero-based and nonnegative. Captures only the selected observation and its provenance; no network requests.

```console
aegis findings evidence add-observation FINDING_ID --result RESULT_FILE.json --index 0 --actor analyst --reason "Stored observation" --json
```

### `aegis findings evidence add-reference`

Associate a declarative external reference without fetching it.

**Syntax:** `aegis findings evidence add-reference <finding-id> --source <source> --actor <actor> --reason <reason> [OPTIONS]`

**Required arguments:** `finding-id`.

| Option | Requirement / default |
|---|---|
| `--source VALUE` | required |
| `--actor VALUE` | required |
| `--reason VALUE` | required |
| `--json` | optional; default off |

**Effects:** Evidence/custody writer; no network request.

**Result:** Stores a declarative HTTP(S) locator with no credentials/query/fragment. It remains reference_only, not verified captured content.

```console
aegis findings evidence add-reference FINDING_ID --source https://example.test/reference --actor analyst --reason "Reference" --json
```

### `aegis findings evidence list`

List associations after reading and verifying captured bytes.

**Syntax:** `aegis findings evidence list <finding-id> [OPTIONS]`

**Required arguments:** `finding-id`.

| Option | Requirement / default |
|---|---|
| `--json` | optional; default off |

**Effects:** Dedicated read-only evidence/finding projection; no initialization/recovery.

**Result:** Lists associations after captured-byte validation. --json produces an array; text mode lists IDs/kinds/timestamps.

```console
aegis findings evidence list FINDING_ID --json
```

### `aegis findings evidence show`

Show verified metadata, never captured content.

**Syntax:** `aegis findings evidence show <evidence-id> [OPTIONS]`

**Required arguments:** `evidence-id`.

| Option | Requirement / default |
|---|---|
| `--json` | optional; default off |

**Effects:** Dedicated read-only evidence validation; no initialization/recovery.

**Result:** Returns verified association metadata, never captured content; corruption fails explicitly.

```console
aegis findings evidence show EVIDENCE_ID --json
```

### `aegis findings evidence verify`

Verify bytes without persisting verification timestamps or repairs.

**Syntax:** `aegis findings evidence verify <evidence-id> [OPTIONS]`

**Required arguments:** `evidence-id`.

| Option | Requirement / default |
|---|---|
| `--json` | optional; default off |

**Effects:** Dedicated read-only content validation; no persisted verification timestamp or repair.

**Result:** Captured bytes can be verified; external references remain reference_only. Returns verification metadata.

```console
aegis findings evidence verify EVIDENCE_ID --json
```

### `aegis findings evidence custody-history`

List custody events by sequence without recording this consultation.

**Syntax:** `aegis findings evidence custody-history <evidence-id> [OPTIONS]`

**Required arguments:** `evidence-id`.

| Option | Requirement / default |
|---|---|
| `--json` | optional; default off |

**Effects:** Dedicated read-only custody query.

**Result:** Returns chained events for the selected evidence by sequence as JSON; does not record the consultation.

```console
aegis findings evidence custody-history EVIDENCE_ID --json
```

## Custody, export and packages

### `aegis assessment export`

Export outside the assessment. Share is minimization, not anonymization.

**Syntax:** `aegis assessment export --output <output> [OPTIONS]`

| Option | Requirement / default |
|---|---|
| `--output VALUE` | required |
| `--profile VALUE` | optional; default `share`; share or forensic |
| `--include-objects` | optional; default off |
| `--json` | optional; default off |

**Effects:** Read-only source snapshot; publishes an exclusive ZIP outside the assessment. No recovery or source audit event.

**Result:** Defaults to share; rejects --include-objects in share. Explicit forensic warns of plaintext on stderr; objects require --include-objects. Success stdout is JSON even without --json. Output parent must exist; no overwrite.

```console
aegis assessment export --output /absolute/export/share.zip
```

### `aegis assessment custody init`

Explicitly activate custody with an inventory of existing evidence.

**Syntax:** `aegis assessment custody init --actor <actor> --reason <reason> [OPTIONS]`

| Option | Requirement / default |
|---|---|
| `--actor VALUE` | required |
| `--reason VALUE` | required |
| `--json` | optional; default off |

**Effects:** Explicit custody writer.

**Result:** Activates a chain with genesis/inventory and an initialization event. Existing evidence is inventoried, not retroactively attributed. Success is JSON even without --json.

```console
aegis assessment custody init --actor analyst --reason "Activate custody" --json
```

### `aegis assessment custody recover`

Complete a valid pending intent; never overwrite contradictory data.

**Syntax:** `aegis assessment custody recover --actor <actor> --reason <reason> [OPTIONS]`

| Option | Requirement / default |
|---|---|
| `--actor VALUE` | required |
| `--reason VALUE` | required |
| `--json` | optional; default off |

**Effects:** Explicit recovery writer; never replaces contradictions.

**Result:** Completes consistent pending intentions, revalidating current preconditions. Repeated completed recovery is idempotent. Success is JSON even without --json; this is not triage recovery.

```console
aegis assessment custody recover --actor analyst --reason "Interrupted publication" --json
```

### `aegis assessment custody verify`

Read and verify the chain; an external checkpoint must already be trusted.

**Syntax:** `aegis assessment custody verify [OPTIONS]`

| Option | Requirement / default |
|---|---|
| `--checkpoint VALUE` | optional; default unset |
| `--json` | optional; default off |

**Effects:** Dedicated read-only chain validation; no initialization/recovery.

**Result:** Returns JSON with custody status, checkpoint, external checkpoint match and temporal anomalies. --checkpoint consumes the checkpoint object from a trusted prior snapshot; absence of custody is not_initialized.

```console
aegis assessment custody verify --json
```

### `aegis assessment package verify`

Verify independently; hashes do not authenticate the package origin.

**Syntax:** `aegis assessment package verify <path> [OPTIONS]`

**Required arguments:** `path`.

| Option | Requirement / default |
|---|---|
| `--expected-sha256 VALUE` | optional; default unset |
| `--checkpoint VALUE` | optional; default unset |
| `--json` | optional; default off |

**Effects:** Independent read-only package reader; no assessment, extraction, import or network required.

**Result:** Returns JSON with package integrity, custody and evidence statuses. --expected-sha256 and --checkpoint must come from independently trusted sources. Failure returns nonzero rather than a verified result.

```console
aegis assessment package verify share.zip --json
```

### `aegis assessment package inspect`

Validate and show the manifest without extracting files.

**Syntax:** `aegis assessment package inspect <path> [OPTIONS]`

**Required arguments:** `path`.

| Option | Requirement / default |
|---|---|
| `--json` | optional; default off |

**Effects:** Independent read-only reader; validates without extraction or recovery.

**Result:** Validates and returns the manifest as JSON even without --json; not a shortcut that accepts an invalid package.

```console
aegis assessment package inspect share.zip --json
```

## Additional workflows

Forensic selection is explicit; objects are not included without the extra option:

```console
aegis assessment export --output /absolute/export/forensic.zip --profile forensic
aegis assessment export --output /absolute/export/forensic-objects.zip --profile forensic --include-objects
aegis assessment package verify /absolute/export/forensic-objects.zip --json
```

For independently trusted checkpoints/hashes, see [security](../docs/security.md#external-checkpoints).
There are no CLI commands for manual finding creation, package import, evidence
editing/deletion, transfer, signing, encryption or triage-journal recovery.
Custody recovery is the explicit command documented above, not automatic repair.
See [technical guides](../docs/README.md#technical-guides) for schemas, quotas,
ZIP subset and platform guarantees.
