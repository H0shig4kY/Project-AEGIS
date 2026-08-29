# AEGIS / ARGUS

**Authorized Reconnaissance, Asset Discovery and Lifecycle Analysis Engine**

AEGIS is an evidence-driven security assessment framework for authorized reconnaissance, asset discovery, provenance tracking, relationship analysis, integrity verification, and temporal change detection.

**ARGUS** is the reconnaissance and observation layer used by AEGIS to execute plugins and turn observations into persistent assessment state.

> AEGIS is intended for systems and environments where you have explicit authorization to perform security assessment and reconnaissance.

## Why AEGIS?

Traditional reconnaissance commonly produces isolated snapshots. AEGIS is designed to preserve state between executions so an assessment can answer not only **what exists now**, but also:

- What was discovered?
- Where did the evidence come from?
- Which assets are related?
- What disappeared?
- Was the disappearance transient or persistent?
- What became inactive?
- What later reappeared?
- Which stored result supports the observation?
- Has that stored result changed since it was recorded?

## Current capabilities

- Explicit campaign scope management
- Plugin-based reconnaissance
- DNS resolution
- HTTP probing
- Service discovery and fingerprinting
- TLS and certificate inspection
- Typed asset inventory
- Asset metadata and provenance
- Relationship graph
- Asset and relation lifecycle tracking
- Candidate-missing detection
- Inactivation after repeated absence
- Reactivation detection
- Change history
- SHA-256 result integrity baselines
- Integrity verification
- Retrospective baselining of legacy results
- Human-readable Rich terminal interface
- JSON output for change records

## Core model

AEGIS turns plugin observations into a persistent assessment model:

```text
Authorized Scope
      |
      v
 ARGUS Plugin
      |
      v
  Observation
      |
      +------------------+
      |                  |
      v                  v
    Asset  ----------> Relation
      |                  |
      +--------+---------+
               |
               v
           Lifecycle
               |
               v
             Change
               |
               v
     Evidence / Provenance
```

### Tracked relationships

Current relationship modelling includes:

```text
DOMAIN  --resolves_to-->  IP
DOMAIN  --exposes----->   SERVICE
SERVICE --presents---->   CERTIFICATE
```

## Lifecycle model

AEGIS deliberately distinguishes a first missing observation from confirmed inactivation.

```text
ACTIVE
  |
  | first covered execution where object is absent
  v
CANDIDATE_MISSING
  |
  | repeated covered absence
  v
INACTIVE
  |
  | observed again
  v
REACTIVATED
  |
  v
ACTIVE
```

This model applies to tracked assets and relationships where the relevant plugin execution provides sufficient coverage.

## Built-in reconnaissance

The current CLI exposes the following plugin workflow:

```bash
aegis plugin list

aegis plugin run dns
aegis plugin run service
aegis plugin run tls
aegis plugin run http
```

Plugin execution persists the raw result, establishes an integrity baseline, processes accepted observations into assets and relations, and integrates lifecycle change processing.

## Installation

From the project root, install the package using the packaging configuration in `pyproject.toml`.

For development, install the project and its development dependencies according to your local Python workflow, then verify the CLI:

```bash
aegis
aegis version
aegis info
```

## Quick start

Create a campaign:

```bash
aegis init assessment
cd assessment
```

Add an authorized target:

```bash
aegis scope add example.com
aegis scope list
```

Inspect available plugins:

```bash
aegis plugin list
```

Run reconnaissance:

```bash
aegis plugin run dns
aegis plugin run service
aegis plugin run tls
aegis plugin run http
```

Inspect the resulting assessment state:

```bash
aegis assets list
aegis relations list
aegis changes list
aegis results list
```

Inspect a graph rooted at a domain:

```bash
aegis assets graph example.com --type domain
```

Inspect related assets:

```bash
aegis assets related domain example.com
```

Inspect lifecycle history:

```bash
aegis assets history service example.com:443
aegis relations history domain example.com resolves_to ip 
```

Verify persisted evidence:

```bash
aegis results verify-all
aegis results integrity-summary
```

## Campaign structure

`aegis init <name>` creates a campaign directory and initializes the AEGIS configuration together with campaign data directories, including:

```text
assessment/
├── aegis.yaml
├── data/
├── evidence/
└── reports/
```

Additional persisted stores are managed by the application within the campaign.

## CLI

Running:

```bash
aegis
```

opens the Rich-based AEGIS / ARGUS command interface.

Top-level command groups include:

```text
version
info
commands
init
scope
plugin
assets
relations
changes
results
```

For a practical command reference, see [`COMMANDS.md`](COMMANDS.md).

## Assets and provenance

Discovered assets are persisted as typed objects. Depending on the observation, an asset may include:

- Type and value
- Discovery source
- Metadata
- First-seen and last-seen timestamps
- Last-confirmed timestamp
- Seen count
- Active/inactive state
- Observation provenance
- Plugin and plugin version
- Result file
- Result identifier
- Result SHA-256

This allows an asset to remain linked to the evidence that produced it.

## Relations

AEGIS stores relationships independently from assets and gives them their own lifecycle and provenance.

Examples:

```text
DOMAIN example.com
  --resolves_to--> IP 

DOMAIN example.com
  --exposes--> SERVICE example.com:443

SERVICE example.com:443
  --presents--> CERTIFICATE <sha256>
```

Relations can be queried directly, traversed from assets, and inspected historically.

## Change detection

The change engine processes missing and reactivated state transitions around observation processing.

This ordering is important:

```text
1. Execute plugin
2. Persist current raw result
3. Locate previous comparable result where applicable
4. Detect covered objects that are missing
5. Apply candidate-missing / inactive lifecycle logic
6. Calculate and store result integrity baseline
7. Process current observations
8. Promote accepted assets and relations
9. Detect reactivations
10. Present execution summary
```

Change records can reference both the previous and current result files.

## Result integrity

New plugin results receive an **ORIGINAL** SHA-256 baseline.

AEGIS can:

```bash
aegis results verify <filename>
aegis results verify-all
aegis results integrity-summary
aegis results integrity-show <filename>
```

Legacy results without an existing integrity baseline can be given a retrospective baseline:

```bash
aegis results baseline-legacy
```

Integrity verification distinguishes states such as:

```text
OK
BASELINED
FAILED
UNKNOWN
CONFLICT
```

## JSON output

Lifecycle changes can be consumed programmatically:

```bash
aegis changes list --json
```

The JSON representation distinguishes asset changes from relation changes and includes lifecycle state, plugin, target, timestamps, and previous/current result references.

## Development and testing

Run the complete test suite:

```bash
pytest
```

Run a focused test module:

```bash
pytest tests/test_change_engine.py -v
```

The current development state has been validated with **283 passing tests**.

## Project status

AEGIS is currently under active development and is versioned as **0.1.0** in the CLI.

The current implementation already provides the foundations of a stateful assessment engine:

```text
Scope
  -> Reconnaissance
  -> Observations
  -> Assets
  -> Relations
  -> Provenance
  -> Lifecycle
  -> Changes
  -> Integrity
```

The goal is not merely to collect scan output. The goal is to maintain an evidence-backed historical model of an assessed attack surface.

## Documentation

- [`COMMANDS.md`](COMMANDS.md) — CLI command reference and examples.
- [`PRESENTATION.md`](PRESENTATION.md) — project overview and presentation narrative.

## Responsible use

Use AEGIS only against systems, infrastructure, and environments for which you have explicit authorization. Scope enforcement is a core design principle of the project, but authorization remains the operator's responsibility.
