# Security and trust boundaries

## Authorized use and sensitive data

Only assess systems you own or are explicitly authorized to test. Scope entries
cannot establish permission. Plugins may contact targets. Evidence snapshots,
result files, reports and audit fields can contain secrets or personal information.
Do not commit assessments or publish forensic artifacts indiscriminately.

`share` uses a closed allowlist, excludes objects and free text, but retains IDs,
hashes, sizes, states and counts. These are correlatable: it is **not anonymization**.
`forensic` is explicit and emits a plaintext warning; it does not redact covered
original records. Objects require `--include-objects`. Neither ZIP profile is encrypted.
Reports are not the share profile: schema 1 can carry opaque source extensions;
schema 2 can carry evidence audit metadata. Review reports before disclosure.

## Integrity is not authenticity

SHA-256 verifies bytes against a recorded digest. Unsigned hashes and chained events
do not authenticate an operator or origin, certify time, or stop an owner rewriting
the entire chain and its records. Actor identities are declared strings.
Sequence is authoritative; clock regressions are signalled, not reordered.
External references are declarative and not fetched or content-verified.

Verification separates package integrity, custody status/checkpoint match and
evidence metadata/content statuses. A share projection is not verification of
omitted originals. An omitted blob's hash is not verification of its bytes.
For the exact statuses, see [manifest verification](custody-assessment-export.md#manifest-and-verification).

## External checkpoints

`aegis assessment custody verify --json` returns a `checkpoint` when initialized.
A checkpoint is the nested checkpoint object, **not the entire verification response**.
Save it outside the assessment and establish trust independently before use:

```console
aegis assessment custody verify --checkpoint trusted-checkpoint.json --json
aegis assessment package verify forensic.zip --checkpoint trusted-checkpoint.json --json
aegis assessment package verify forensic.zip --expected-sha256 TRUSTED_SHA256 --json
```

`TRUSTED_SHA256` stands for a real independently obtained 64-hex digest, not literal
input. The checkpoint compares the exact final head, so a later legitimate append
also changes it. Retain checkpoints with their snapshot/context. Share includes a
checkpoint but omits original chain documents; do not call that chain verification.
A trusted earlier checkpoint can expose truncation/rewrite of the expected final
state. Without independent trust, a consistently rewritten/truncated prefix may
still pass internal verification. This is not a signing or authentication protocol.

## Filesystem, concurrency and durability

Writers cooperate through local locks. Do not mix custody-unaware older writer
versions after activation. Reads do not certify protection against hostile concurrent
parent-directory swaps or an administrator modifying raw storage.
Captures reject symlinks, relevant reparse points and special files, with observable
source-stability checks; these are not universal TOCTOU guarantees.

Private managed storage uses POSIX 0700/0600. On Windows, inherited ACLs determine
access; mode bits are not equivalent isolation. Configure deployment ACLs externally.
Exclusive hard-link publication requires filesystem support and same-volume staging.
No permissive overwrite fallback is promised for unsupported filesystems.

Synchronization tests and injected failures establish specific publication behaviour,
not portable power-cut durability. Windows lacks a portable standard-library directory
fsync equivalent. An exception after publication can leave a complete artifact:
inspect before retrying and preserve uncertain outcomes.

## Limits and memory

Evidence defaults are 50 MiB per object and 1 GiB physical content per assessment,
including counted object staging/orphans. Quotas apply to cooperating writers;
metadata is governed separately. Captures/report generation use memory proportional
to inputs, and increasing limits increases memory requirements.

Package verification defaults: 2 GiB content including manifest; 100,000 members;
16 MiB manifest; 256 MiB aggregate metadata; physical ZIP <=2 GiB +256 MiB.
Additional category limits and 128-ASCII-character paths apply. See the
[complete limit policy](custody-assessment-export.md#manifest-and-verification).
Preflight uses bounded constant additional memory before inventory materialization.
The full verifier still materializes inventory and decodes documents; these byte
limits are **not a fixed RSS ceiling**. Use locally trusted resource policy and
appropriate process isolation for untrusted packages. A package cannot raise limits.

## Malicious packages and operational errors

The verifier accepts only the documented stored, single-disk ZIP subset. Physical
names are validated before zipfile normalization. Traversal, control/non-ASCII names,
links/special types, opaque comments/extras, descriptors, hidden physical regions,
contradictory ZIP64, invalid JSON and nonfinite numbers are rejected.
It does not extract, execute, import or access a network.

New evidence/custody/package paths sanitize expected validation errors. This does not
promise that every legacy CLI error is path-free or every diagnostic is safe to publish.
Avoid putting secrets in selectors/arguments, and review stdout/stderr before sharing.
Follow [recovery](recovery.md) rather than removing evidence or bypassing validation.
Signing, encryption, authenticated identities and key management remain unimplemented.
