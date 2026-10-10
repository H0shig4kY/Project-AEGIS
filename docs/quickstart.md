# Offline quickstart

This walkthrough uses a disposable assessment and **synthetic** local content.
It does not scan or infer vulnerabilities. Install AEGIS first using
[installation](installation.md), and keep the same activated environment.

## 1. Create a separate workspace

From a new, empty directory **outside the repository**, run:

```console
aegis init demo-assessment
cd demo-assessment
aegis scope add 127.0.0.1
aegis scope list
aegis plugin list
aegis findings report --format json
```

The last command reports the empty assessment. These commands make no target
requests. Scope accepts domains, wildcards, IPs and CIDRs, not URLs or `host:port`.
A scope entry is not evidence of legal authorization.

## 2. Obtain a finding

For an existing authorized lab assessment, use `aegis findings list --json` and
select a complete finding ID. There is no `findings create` CLI command. Real
findings result from the implemented observation/rule/lifecycle pipeline; a scan
is not guaranteed to produce them. Do not run plugins against public example
hosts just to populate this walkthrough.

For this **new disposable demo only**, an offline Python fixture makes the later
steps deterministic. Save the following as `seed_demo.py` inside `demo-assessment`
and run `python seed_demo.py`. It uses the existing Python model/store and refuses
a nonempty findings directory. It is tutorial setup, not a production capture or
an automatically detected security finding.

```python
from pathlib import Path
from aegis.context import CampaignContext
from aegis.finding_store import FindingStore
from aegis.models import AssetType, FindingRecord

root = Path.cwd()
assert root.name == "demo-assessment" and (root / "aegis.yaml").is_file()
findings = root / "data" / "findings"
assert not findings.exists() or not any(findings.iterdir()), "Use a fresh disposable demo"
campaign = CampaignContext(root)
record = FindingRecord(
    finding_id="a" * 64,
    rule_id="DEMO_ONLY",
    severity="medium",
    title="Synthetic tutorial finding",
    description="Offline fixture; not an observed vulnerability",
    asset_type=AssetType.SERVICE,
    asset_value="127.0.0.1:443",
)
FindingStore(campaign.findings_dir).save(record)
with (root / "capture.txt").open("x", encoding="utf-8") as output:
    output.write("Synthetic tutorial evidence\n")
```

## 3. Inspect and triage

The fixed ID below belongs only to that fixture. Replace it with a real complete
ID when operating on your own authorized records. Run each transition once:

```console
aegis findings list --json
aegis findings show aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --json
aegis findings acknowledge aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --actor analyst --reason "Offline review" --json
aegis findings suppress aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --actor analyst --reason "Tutorial suppression" --json
aegis findings unsuppress aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --actor analyst --reason "Reopen tutorial" --json
aegis findings triage-history aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --json
```

Operational state follows `open -> acknowledged -> suppressed -> open`.
Technical state is not resolved by those operations. Repeating an invalid
transition fails rather than creating another event.

## 4. Activate custody, then attach evidence

```console
aegis assessment custody init --actor analyst --reason "Activate demo custody" --json
aegis findings evidence add-file aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa capture.txt --actor analyst --reason "Synthetic local capture" --json
aegis findings evidence add-reference aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --source https://example.test/reference --actor analyst --reason "Declarative example" --json
aegis findings evidence list aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --json
aegis assessment custody verify --json
aegis findings report --schema-version 2 --format json
```

The reference is **not fetched**. Copy an actual `evidence_id` from the attachment
response for `evidence show`, `verify` or `custody-history` (see
[commands](../aegis/COMMANDS.md)). Local objects are verified by reading bytes;
external references remain `reference_only`. Activation inventories any prior
evidence and does not invent retrospective capture events.

An observation attachment instead requires a real stored result filename and
zero-based observation index; the fixture above creates neither. See
[evidence capture](evidence-management.md#capture-modes) before using that mode.

## 5. Export and independently verify

Use an existing external directory, with an absolute path containing no `..` or
linked components. The examples below use `/absolute/export` on POSIX and
`C:\AEGIS-Exports` on Windows as substitution paths: create/select your own private
external directory first. Destinations must not already exist.

POSIX:

```bash
aegis assessment export --output /absolute/export/demo-share.zip
aegis assessment export --output /absolute/export/demo-forensic.zip --profile forensic
aegis assessment export --output /absolute/export/demo-forensic-objects.zip --profile forensic --include-objects
cd /absolute/export
aegis assessment package inspect demo-share.zip --json
aegis assessment package verify demo-share.zip --json
aegis assessment package verify demo-forensic.zip --json
aegis assessment package verify demo-forensic-objects.zip --json
```

PowerShell and CMD (the same single-line syntax works in both):

```console
aegis assessment export --output "C:\AEGIS-Exports\demo-share.zip"
aegis assessment export --output "C:\AEGIS-Exports\demo-forensic.zip" --profile forensic
aegis assessment export --output "C:\AEGIS-Exports\demo-forensic-objects.zip" --profile forensic --include-objects
```

In PowerShell, use `Set-Location "C:\AEGIS-Exports"` before the package commands.
In CMD, use `cd /d "C:\AEGIS-Exports"` so a drive change also takes effect.
The package commands above are otherwise the same.

Share contains projections, not original records/objects; expect checkpoint-only
custody when a chain exists. Forensic preserves covered originals and can verify
its chain. Captured content is verifiable only when included; references stay
reference-only. Consult the separate statuses, not just `package_integrity`.
The forensic warning appears on stderr: these ZIPs are plaintext, unencrypted.
Package commands work here without an assessment and do not extract or import.

See [security](security.md#external-checkpoints) for trusted external checkpoints.
Do not use a hash delivered only alongside an untrusted package as proof of origin.

## 6. Understand failures

Do not re-run all write steps blindly: existing destinations, invalid transitions
and conflicting audit metadata are intentionally rejected. Inspect with dedicated
readers; use [recovery](recovery.md) for pending custody operations. Never delete
objects, receipts or journals to force a successful export.

Real network reconnaissance requires a separate authorized lab plan. It is not
part of this offline guide or its documentation validation.
