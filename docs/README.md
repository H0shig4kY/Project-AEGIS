# Documentation

## Start here

1. [Project overview](../README.md).
2. [Installation](installation.md): Linux, PowerShell, CMD and development setup.
3. [Offline quickstart](quickstart.md): synthetic finding, triage, evidence, custody and export.
4. [Command reference](../aegis/COMMANDS.md): full current CLI and persistent effects.

## Understand and operate

- [Architecture](architecture.md): independent states, stores, evidence and custody.
- [Security](security.md): trust, privacy, checkpoints, resource/platform limitations.
- [Recovery](recovery.md): preservation-first diagnosis and explicit custody recovery.
- [Framework overview](../aegis/README.md) and [presentation](../aegis/PRESENTATION.md).
- [Roadmap](../ROADMAP.md): completed deliveries versus proposals.

## Technical guides

| Guide | Scope |
|---|---|
| [Finding triage](finding-triage.md) | Operational transitions, audit events and CLI |
| [Storage integrity](storage-integrity.md) | Atomic writes, cooperative locks and triage recovery |
| [Triage journal performance](triage-journal-performance.md) | Design trade-offs and historical reproducible benchmarks |
| [Findings reporting](findings-reporting.md) | Read projection, schema 1, escaping and exclusive output |
| [Evidence management](evidence-management.md) | Immutable associations, capture, quota and reporting schema 2 |
| [Custody and assessment export](custody-assessment-export.md) | Recovery protocol, profiles, manifest, ZIP subset and verifier limits |

Historical measurements/counts in technical guides describe their original runs,
not current test results. Documentation baseline: `36e914a44f68f7560711c323c15d525a0eb67378`.
The [`aegis commands` convenience view](../ROADMAP.md#proposals-requiring-separate-approval)
is incomplete at that baseline; consult `--help` and the command reference.
