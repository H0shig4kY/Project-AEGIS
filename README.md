🛡️ Project AEGIS

Research. Understand. Protect.

Project AEGIS is my long-term cybersecurity research initiative focused on offensive security, Windows Internals, Active Directory, Microsoft Entra ID, Red Team operations, defensive insights, and original security research.

The objective is to build practical tools, document experiments, publish technical articles, and eventually contribute research to the cybersecurity community through conference talks and open-source projects.

Current Areas

Active Directory
Windows Internals
Microsoft Entra ID
Python
PowerShell
Steganography
Detection Engineering
Red Team Research


## Finding triage CLI

Inside an assessment campaign, use `aegis findings acknowledge`, `suppress`,
`unsuppress` and `triage-history`. State changes require `--actor` and `--reason`;
all four commands support `--json`. See [usage and audit persistence](docs/finding-triage.md#cli-usage).

## Findings reporting

Export existing findings and both histories without scans or automatic recovery:

```console
aegis findings report --format json
aegis findings report --format markdown --output report.md
```

Existing output files are rejected. Integrity errors stop export without repairing
assessment data. See [report formats, examples and limits](docs/findings-reporting.md).

## Evidence management

Explicitly capture local files, snapshot stored observations or associate external
references without network requests. Findings and triage states are unchanged.

```console
aegis findings evidence add-file <finding-id> capture.bin --actor analyst --reason "review" --json
aegis findings evidence list <finding-id> --json
aegis findings report --schema-version 2 --format json
```

Report schema 1 remains the default. Evidence schema 2 exports verified metadata,
never captured blobs. See [limits, provenance, security and failure behaviour](docs/evidence-management.md).
