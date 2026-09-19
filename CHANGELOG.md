# Changelog

All notable changes to `@intyga/verify` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

- **Wire format: the DIV Intent Payload gained a REQUIRED `evidence` field, and it must be `null`.**
  `div-intent-verification` and `div-offline-intent` now carry `"evidence":null` in the signed bytes
  (DIV §4.3.4); `div-delegation`, `div-agent-authority` and `div-platform-intent` deliberately do
  not. `null` is signed and load-bearing, exactly as `requester.attestation`'s null is: it is the
  payload's explicit statement that the authorization was not conditioned on any external fact.
  Verification refuses a payload whose `evidence` key is absent, and refuses any non-`null` value
  rather than treating it as unconditioned — the same fail-closed-on-unknown rule as the
  `signerClass` registry, and checked before Local Payload Reconstruction so an unsupported payload
  shape does not surface as a parameter mismatch. Absent and `null` are distinguished explicitly;
  collapsing them would make the check a no-op. All golden vectors were regenerated.

- Align cross-language receipt and audit verification: platform receipts, agent-authority seals,
  self-certifying DID trust, single/multi-event bundles, embedded ES256 signatures, tenant sequence
  checks, checkpoint continuity, anchor quorum and Rekor. Shared executable fixtures cover valid
  artifacts and refusals; no wire format changes.
- Refuse unknown witness signature algorithms. Require identity-bound trust when the signed
  `requesterCannotApprove` rule is set; key-only trust cannot enforce requester identity.
- **`verifyRootsChain` range-checks the FIRST entry.** The non-integer and self-inverted seq-range
  checks were gated on having a predecessor, so the first entry was never range-checked — and a
  single-entry `roots.jsonl` (a new tenant, or the first day after a truncation) is exactly where
  the first entry is the only one. Such a file verified clean here while Go and Rust refused it.
  Only the overlap check is relational now. New `single-entry-inverted-seq-range` and
  `single-entry-non-integer-seq-range` parity vectors pin it in all five ports.
- Decide the `requesterCannotApprove` + key-set-anchor refusal BEFORE the witness loop. It sat
  inside the loop, after a witness had matched, so a receipt where nothing matched reported "quorum
  not met" instead of naming the trust-anchor shape. Verdict unchanged; reason now matches the
  other four ports and DIV §5 step 3b.

- Recheck cached delegation expiry when verifying an approval, using the same evaluation clock,
  skew allowance and explicit forensic override as a fresh verification.
- A configured DEWP anchor quorum now gates the single-proof `ok` verdict, including when anchor
  material is missing. Both proof and evidence bundles refuse a configured policy without its
  required key resolver.
- Reject sparse JavaScript arrays instead of signing or accepting bytes for a different array.
  Canonical bytes for valid JSON are unchanged across the language ports.
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
