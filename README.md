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
