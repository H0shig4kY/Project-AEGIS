# AEGIS / ARGUS framework

AEGIS is the implemented authorized-assessment framework in [Project AEGIS](../README.md).
ARGUS is its reconnaissance and observation layer. The Python distribution is
`aegis-pentest`; the installed executable is `aegis`.

## Capabilities

The framework manages authorized scope, plugin results and integrity baselines,
assets/relations and lifecycle changes, findings and technical history. Operational
triage is independent of technical resolution. Managed evidence, optional custody
and portable assessment exports extend these records without changing finding states.

- Scope accepts domain, wildcard, IP and CIDR targets, not URLs or `host:port` targets.
- Plugins cover DNS, HTTP, services and TLS. Running a plugin can access the network.
- Findings support querying, technical history and acknowledge/suppress/unsuppress.
- Reports use JSON or Markdown; schema 1 is default, schema 2 explicitly verifies managed evidence metadata.
- Evidence supports local files, snapshots of existing observations and non-fetched external references.
- Custody is opt-in, uses declared identities and hash-chained events, and recovers only explicitly.
- ZIP exports use `share` by default or explicit `forensic`, with objects only when explicitly requested.

## Installation

Python >=3.12 is required by `pyproject.toml`. CI tests Python 3.12/3.13 on Linux
and Windows. From the **repository root**:

```console
python -m pip install -e ./aegis
aegis --help
aegis version
```

Use a virtual environment. See the complete [installation guide](../docs/installation.md)
for Linux, PowerShell and CMD. If already inside this `aegis/` directory, the
editable install path is `.` instead of `./aegis`.

## Usage and command discovery

Run assessment commands inside a directory containing `aegis.yaml`, or below it.
The nearest ancestor with that file determines the assessment. Package verification
and inspection work independently of a local assessment.

```console
aegis init demo-assessment
cd demo-assessment
aegis scope add 127.0.0.1
aegis scope list
aegis findings report --format json
aegis findings --help
aegis assessment --help
```

See the [offline quickstart](../docs/quickstart.md) for findings, triage, evidence,
custody and export. For existing records, representative query syntax is:

```console
aegis assets history service example.test:443
aegis relations history domain example.test resolves_to ip 192.0.2.1
aegis changes list --target-value 192.0.2.1
```

These values are illustrative; no records or scan results are promised.
`aegis` prints a landing/reference view, not an interactive shell.
`aegis commands` is a partial convenience list and does not yet include all recent
operations. The [complete command reference](COMMANDS.md) and each command's
`--help` are authoritative for this baseline.

## Storage and effects

An assessment contains `aegis.yaml`, authorized scope, `data/`, `evidence/` and
`reports/`. Technical finding state and operational triage state are separate.
Normal store queries can initialize directories/locks or recover pending triage
operations. They are not forensic read-only projections.

Findings reporting, managed-evidence readers, custody readers and package readers
use dedicated non-recovering paths. Assessment export reads the source and writes
an exclusive package outside it. See [architecture](../docs/architecture.md) and
[recovery](../docs/recovery.md) for the boundaries.

## Development and validation

From the repository root in an activated virtual environment:

```console
python -m pip install -e "./aegis[dev]"
cd aegis
python -m pytest -v
python -m pytest tests/test_change_engine.py -v
```

Counts belong to individual runs, not a permanent release guarantee. The
[CI workflow](../.github/workflows/tests.yml) runs the suite on Linux/Windows and
Python 3.12/3.13. Historical counts in sprint documents describe their original
baselines. This documentation refresh changes no Python, tests or workflow.

## Further reading

- [Commands](COMMANDS.md) and [presentation](PRESENTATION.md).
- [Documentation index](../docs/README.md).
- [Security](../docs/security.md): authorized use, plaintext, unsigned hashes,
  checkpoints, cooperative locks and platform limitations.
- [Roadmap](../ROADMAP.md): completed deliveries and uncommitted proposals.
