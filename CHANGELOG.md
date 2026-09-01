# Changelog

All notable changes to `@intyga/verify` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

- **`verifyEvidenceBundle` no longer reports false ANCHOR DIVERGENCE on a multi-day export.** The
  caller's flat `anchors` list was offered as divergence evidence to every checkpoint root in the
  bundle, so a genuine anchor for one day read as a conflicting anchor for another — a fatal verdict
  on sound evidence. Caller anchors are now attributed to a checkpoint first, and `anchors` also
  accepts the keyed form `{ [checkpointIdOrRoot]: SignedAnchor[] }` for an exact per-checkpoint
  verdict. The flat form still works and still declares divergence for an anchor over a root the
  bundle does not claim.
- **Refuse a forward-dated offline proof or delegation (DIV §5a.3 rule 3, §5a.6 step 1).** The
  window caps bounded a proof's WIDTH but never its POSITION, so a quorum-signed proof dated years
  ahead with a compliant 60-minute (or 72-hour) window verified today and kept verifying until that
  date. The check is unconditional — the audit/`allowExpired` override re-examines a proof that was
  valid and has lapsed, and does not reach one dated in the future.
- **Refuse a signed `requirement.requiredApprovals` below 1 (DIV §4.3.2).** §5 step 7's "at least
  `requiredApprovals`" is satisfied vacuously by 0, so the minimum is now enforced explicitly
  instead of by an undocumented floor.

## [1.0.0]

Initial public release.

- Offline approval-receipt verification (ES256 and WebAuthn) against a caller-supplied trust
  anchor — no Intyga secret, no network. `AUTO_APPROVED` receipts are refused by default.
- DIV canonical payload builders and verification codes, pinned by shared cross-language golden
  vectors.
- DEWP ledger verification: inclusion proofs with mandatory bounds checks, §5.2 anchor signatures,
  §5.3 anchor-quorum evaluation, §5.4 checkpoint continuity chain, and evidence bundles.
- Zero runtime dependencies (Node ≥ 18, `node:crypto` only).
