# AEGIS / ARGUS Command Reference

This document describes the command-line interface currently exposed by AEGIS.

General syntax:

```bash
aegis [OPTIONS] COMMAND [ARGS]...
```

Run the main interface:

```bash
aegis
```

Get command-specific help:

```bash
aegis <command> --help
aegis <group> <command> --help
```

## General commands

### `aegis version`

Display the installed AEGIS / ARGUS version.

```bash
aegis version
```

### `aegis info`

Display the platform capabilities, tracked relationships, and lifecycle model.

```bash
aegis info
```

### `aegis commands`

Display common commands and practical examples.

```bash
aegis commands
```

## Campaigns

### `aegis init <name>`

Create a new assessment campaign.

```bash
aegis init assessment
cd assessment
```

The command creates the campaign root and initializes AEGIS configuration and the `data`, `evidence`, and `reports` directories.

Most assessment commands must be executed from inside an AEGIS / ARGUS campaign.

---

## Scope

Scope defines the targets the assessment is authorized to process.

### `aegis scope add <value>`

Add a supported target to the current campaign.

```bash
aegis scope add example.com
```

The scope layer supports the target types recognized by the current AEGIS scope implementation, including domains, IP addresses, URLs, and supported service targets.

### `aegis scope list`

List all current scope targets.

```bash
aegis scope list
```

### `aegis scope remove <target>`

Remove a target from scope.

```bash
aegis scope remove example.com
```

---

## Plugins

### `aegis plugin list`

List installed reconnaissance plugins, their versions, and descriptions.

```bash
aegis plugin list
```

### `aegis plugin run <name>`

Execute a plugin against the current campaign.

```bash
aegis plugin run dns
aegis plugin run service
aegis plugin run tls
aegis plugin run http
```

The plugin run pipeline persists the result, processes lifecycle changes, establishes result integrity, promotes accepted observations into assessment state, and reports detected changes.

Current common plugins:

| Plugin | Purpose |
| --- | --- |
| `dns` | Resolve in-scope domains and produce DNS observations. |
| `service` | Discover exposed services and service metadata. |
| `tls` | Inspect TLS services and certificate information. |
| `http` | Probe HTTP endpoints. |

---

## Assets

### `aegis assets list`

List discovered assets.

```bash
aegis assets list
```

Filter by asset type:

```bash
aegis assets list --type service
```

Filter by discovery source:

```bash
aegis assets list --source service
```

Options:

```text
--type <asset-type>
--source <source>
```

### `aegis assets show <filename>`

Show a persisted asset record, including lifecycle, metadata, and provenance when available.

```bash
aegis assets show <filename>
```

### `aegis assets graph <value>`

Recursively walk outgoing relations from a root asset.

```bash
aegis assets graph example.com
aegis assets graph example.com --type domain
aegis assets graph example.com --type domain --details
```

Options:

```text
--type <asset-type>   Root asset type.
--details             Show lifecycle details for each relation.
```

### `aegis assets related <asset-type> <value>`

Show both outgoing and incoming relationships for an asset.

```bash
aegis assets related domain example.com
aegis assets related service example.com:443
```

### `aegis assets history <asset-type> <value>`

Show lifecycle history for an asset.

```bash
aegis assets history service example.com:443
```

---

## Relations

AEGIS models relationships between discovered assets, including:

```text
DOMAIN  --resolves_to--> IP
DOMAIN  --exposes----->  SERVICE
SERVICE --presents---->  CERTIFICATE
```

### `aegis relations list`

List persisted asset relationships.

```bash
aegis relations list
```

### `aegis relations show <filename>`

Show a stored relationship, including lifecycle and provenance where available.

```bash
aegis relations show <filename>
```

### `aegis relations from <asset-type> <value>`

List relations originating from an asset.

```bash
aegis relations from domain example.com
```

### `aegis relations to <asset-type> <value>`

List relations pointing to an asset.

```bash
aegis relations to service example.com:443
```

### `aegis relations history <source-type> <source-value> <relation-type> <target-type> <target-value>`

Show lifecycle history for one relationship.

```bash
aegis relations history \
  domain example.com \
  resolves_to \
  ip 
```

Windows CMD example:

```bat
aegis relations history domain example.com resolves_to ip 
```

---

## Changes

### `aegis changes list`

List detected lifecycle changes.

```bash
aegis changes list
```

Filter by lifecycle transition:

```bash
aegis changes list --type candidate_missing
aegis changes list --type inactive
aegis changes list --type reactivated
```

Filter asset changes:

```bash
aegis changes list --asset-type service
aegis changes list --asset example.com:443
```

Filter relation changes:

```bash
aegis changes list --relation-type resolves_to
aegis changes list --source-type domain
aegis changes list --source example.com
aegis changes list --target-type ip
aegis changes list --target-value 
```

Filter by plugin:

```bash
aegis changes list --plugin dns
aegis changes list --plugin service
aegis changes list --plugin tls
```

Available options exposed by the current command:

```text
--json
--type <change-type>
--asset-type <asset-type>
--asset <asset-value>
--relation-type <relation-type>
--source-type <asset-type>
--source <source-value>
--target-type <asset-type>
--target-value <target-value>
--plugin <plugin>
```

### JSON output

```bash
aegis changes list --json
```

Asset change records contain fields such as:

```json
{
  "kind": "asset",
  "change_type": "inactive",
  "asset_type": "service",
  "asset_value": "example.com:443",
  "plugin": "service",
  "target": "example.com",
  "detected_at": "...",
  "previous_result": "...",
  "current_result": "..."
}
```

Relation change records additionally identify the relation, source, and target.

### `aegis changes show <filename>`

Show a persisted change record.

```bash
aegis changes show <filename>
```

---

## Results and integrity

### `aegis results list`

List persisted plugin result files.

```bash
aegis results list
```

### `aegis results show <filename>`

Inspect a stored plugin result.

```bash
aegis results show <filename>
```

The command displays plugin metadata, execution status, timestamp, and observations.

### `aegis results verify <filename>`

Verify the SHA-256 integrity of one persisted result.

```bash
aegis results verify <filename>
```

Possible integrity states include:

```text
OK
BASELINED
FAILED
UNKNOWN
CONFLICT
```

### `aegis results verify-all`

Verify all stored plugin results.

```bash
aegis results verify-all
```

Exit behavior is significant for automation:

```text
0  verification completed without failed/conflicting/unknown results
1  FAILED or CONFLICT detected
2  UNKNOWN result detected
```

### `aegis results baseline-legacy`

Create retrospective integrity baselines for legacy results that currently have no baseline.

```bash
aegis results baseline-legacy
```

The command stores a `RETROSPECTIVE` integrity baseline and can enrich existing asset provenance with the result SHA-256 where applicable.

### `aegis results integrity-summary`

Show a summary of the campaign integrity manifest.

```bash
aegis results integrity-summary
```

The summary reports:

```text
Records
Original
Retrospective
Verified
Unverified
```

### `aegis results integrity-show <filename>`

Show the integrity manifest record associated with a result.

```bash
aegis results integrity-show <filename>
```

The record includes the stored SHA-256, baseline type, creation time, and verification time.

---

## Typical assessment workflow

```bash
aegis init assessment
cd assessment

aegis scope add example.com
aegis scope list

aegis plugin list
aegis plugin run dns
aegis plugin run service
aegis plugin run tls
aegis plugin run http

aegis assets list
aegis assets graph example.com --type domain --details
aegis relations list

aegis changes list
aegis changes list --type inactive
aegis changes list --type reactivated

aegis results list
aegis results verify-all
aegis results integrity-summary
```

## Lifecycle investigation workflow

When an asset disappears from a covered execution:

```bash
aegis changes list --type candidate_missing
```

After repeated absence causes inactivation:

```bash
aegis changes list --type inactive
```

If it is observed again:

```bash
aegis changes list --type reactivated
```

Investigate the asset and its graph:

```bash
aegis assets related service example.com:443
aegis assets history service example.com:443
aegis assets graph example.com --type domain --details
```

## Machine-readable workflow

For scripting or external processing:

```bash
aegis changes list --json
```

Other CLI output is currently primarily human-readable unless the corresponding command explicitly exposes a machine-readable option.

## Safety and authorization

AEGIS is designed for authorized assessment. Add only explicitly authorized targets to campaign scope and follow the applicable rules of engagement.
