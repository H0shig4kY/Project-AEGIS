# Project AEGIS roadmap

This document distinguishes delivered functionality from proposals. It contains no
release-date promises. Documentation baseline: `36e914a44f68f7560711c323c15d525a0eb67378`.

## Completed deliveries

- Reconnaissance/observations, assets, relations, lifecycle changes and result baselines.
- Sprint 1: FindingTriageManager and operational audit persistence.
- Sprint 2: finding triage CLI.
- Sprint 3: storage integrity and deterministic triage recovery.
- Sprint 4: triage journal performance improvements, with reproducible benchmarks.
- Sprint 5: JSON/Markdown findings reporting.
- Sprint 6: immutable managed evidence and declared provenance; reporting schema 2.
- Sprint 7: explicit custody, recoverable attachments, portable ZIP export and independent verification.

See the [technical guides](docs/README.md#technical-guides) for guarantees and limits,
not just feature names.

## Work in evaluation

The post-Sprint-7 documentation refresh is proposed for review. It modernizes
navigation, command coverage, examples and trust explanations without implementing
another sprint. Integration remains subject to independent review.

## Proposals requiring separate approval

- Bring `aegis commands` and `aegis info` into parity with the current command tree.
  This requires Python changes and is deliberately outside this documentation PR.
- Decide a distribution/license policy; no license is inferred or created here.
- Evaluate authenticated identities, signatures, key management and encryption.
- Evaluate declared transfers, import, additional archive formats and retention/compaction.

These are proposals, not available capabilities or scheduled work. No Sprint 8
implementation is started by this change. Wider research themes (Windows internals,
identity and cyberintelligence) do not imply corresponding implemented plugins.
