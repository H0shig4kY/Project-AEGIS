# Project AEGIS

**Research • Understand • Protect**

Project AEGIS is a cybersecurity research initiative and a repository of practical
security tooling. Its implemented framework, **AEGIS**, supports authorized security
assessments: collect observations, track assets and findings, manage evidence and
export verifiable assessment snapshots. **ARGUS** is the reconnaissance and
observation layer within AEGIS, not a separate installation or CLI executable.
Research interests such as Windows internals, identity security and cyberintelligence
are broader than the capabilities currently implemented here.

## Implemented capabilities

- Authorized scope: domains, wildcard domains, IP addresses and CIDR networks.
- DNS, HTTP, service and TLS reconnaissance plugins; persisted results and integrity baselines.
- Assets, relations, lifecycle changes, finding records and technical history.
- Independent operational triage: acknowledge, suppress and unsuppress, with audit history.
- Findings reports in JSON/Markdown: schema 1 by default, schema 2 explicitly for verified evidence metadata.
- Explicit evidence capture from regular local files or stored observations, and declarative external references without fetching them.
- Assessment-local SHA-256 object deduplication and immutable evidence associations.
- Explicitly activated evidence custody with chained events and explicit recovery.
- Portable ZIP assessment export: minimized `share` by default, explicit plaintext `forensic`; independent verification without extraction or network access.

See [commands](aegis/COMMANDS.md), [architecture](docs/architecture.md) and the
[documentation index](docs/README.md). There is no GUI, automatic package import,
operator authentication, digital signing or evidence encryption in this release.

## Install and check

Packaging requires **Python 3.12 or newer**. The CI compatibility matrix is
**Python 3.12/3.13 on Linux and Windows**; the packaging declaration alone does
not establish support for every newer Python version.

From the cloned repository root, on Linux/POSIX:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ./aegis
aegis --help
```

[Installation](docs/installation.md) includes PowerShell, CMD, development dependencies
and troubleshooting. The packaging file is `aegis/pyproject.toml`.

## Start safely

Create a disposable assessment in a separate working directory, then enter it:

```console
aegis init demo-assessment
cd demo-assessment
aegis scope add 127.0.0.1
aegis scope list
aegis findings report --format json
```

These commands do not run reconnaissance. Adding scope is not proof of permission.
Use only targets you own or are explicitly authorized to assess. An empty assessment
has no findings; the CLI has no manual `findings create` command. Follow the
[quickstart](docs/quickstart.md) for an offline synthetic fixture and the complete
triage/evidence/custody/export workflow. Real plugin runs may perform network activity
and are outside that offline tutorial.

## Security and trust

SHA-256 establishes byte integrity against a recorded digest, not authenticated
origin, operator identity or certified time. Cooperative locks and exclusive
publication are not protection against an administrator rewriting all stored data.
`share` minimizes fields but does **not** anonymize IDs or hashes. `forensic` and
captured evidence may contain credentials or personal data in plaintext.

Read [security](docs/security.md) before capturing or sharing evidence. Use
[recovery](docs/recovery.md) for pending operations: custody recovery is explicit,
while traditional finding-store reads may recover the separate triage journal.
No universal power-loss durability or hostile concurrent filesystem protection is claimed.

## Documentation and project status

- [Command reference](aegis/COMMANDS.md): all registered commands and their effects.
- [Installation](docs/installation.md) and [quickstart](docs/quickstart.md).
- [Architecture](docs/architecture.md), [security](docs/security.md), [recovery](docs/recovery.md).
- [Technical guides](docs/README.md#technical-guides), [presentation](aegis/PRESENTATION.md) and [roadmap](ROADMAP.md).

Documentation was checked against baseline `36e914a44f68f7560711c323c15d525a0eb67378`
after Sprint 7. Test results are execution-specific; consult the
[Actions runs](https://github.com/H0shig4kY/Project-AEGIS/actions) rather than a static test count.
No license is added by this documentation update; distribution/licensing policy
requires a separate explicit decision.
