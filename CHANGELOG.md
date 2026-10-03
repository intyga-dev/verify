# Changelog

All notable changes to `@intyga/verify` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

## [1.1.0]

- No code change. The matched set moves together (`pnpm test:versions`); this release carries the
  new `@intyga/sdk` CLI options and the `require-approval` Action update.

## [1.0.0]

- Packaging: disable source maps in the workspace build and clean old output before compiling,
  matching the standalone build and the tarball's build-output-only contract.

- Verify profile-carried WebAuthn audit signatures with caller-trusted signer keys, origin and RP ID.
  Report explicit per-event signature status and key trust; add strict signature acceptance for
  single and bulk evidence. Audit signature checks do not replace full approval-receipt verification.

- **DIV/DEWP 1.0 pre-release correction (2026-09-27 review L15-L19, I7, I8):** signed timestamps
  are parsed under one strict RFC 3339 grammar (four-digit year, uppercase `T`/`Z`, seconds, a 1-9
  digit fraction, `Z` or `±hh:mm`, a date that exists, no leap second) instead of bare `Date.parse`,
  which accepted date-only and zone-less values and rolled 30 February into March. `stableStringify`
  refuses a string with an unpaired surrogate (`NonCanonicalValue`) instead of escaping it (DIV §4.1).
  A WebAuthn `topOrigin` differing from `origin` is refused like `crossOrigin: true`.
  `verifyPlatformReceipt` requires user verification even when `requireUserVerification: false` is
  passed (DIV §5c.3). A key mapped to two DIDs counts once toward a quorum (DIV §4.4.6). A malformed
  trust anchor (`approvers: {}`) refuses instead of throwing; `agentReceiptDigest` projects an absent
  witness field to `null` and the chain verifiers refuse rather than throw. RSA-PSS anchors require a
  32-byte salt and a 2048-bit modulus, and `signAnchor` now signs with a 32-byte salt (**breaking**
  for RSA-PSS anchors signed with the maximum salt). Divergence evidence is held to the quorum's
  seq-range and witness-time rules, and a Rekor entry establishes divergence only under pinned
  submitter keys. Pinned in all five languages by the `verifierInputHardening` parity vectors; no canonical bytes change for valid input.
- **DIV 1.0 pre-release correction (H1):** add `expected.requirement` (`RequirementFloor`:
  `requiredApprovals`, optional `requesterCannotApprove` / `requireHardwareKey`) to
  `verifyApprovalReceipt`, `verifyDelegation`, `verifyAgentAuthority` and the `agentAuthorityChain`
  links, and export `WEAKER_REQUIREMENT_REASON`. The signed `requirement` is authored by the signers,
  so one approver (possibly the requester) could self-compose a 1-of-1 receipt for a 3-of-3 four-eyes
  action and it verified. A weaker signed requirement is now refused before any signature is counted
  when the caller supplies its own rule (DIV §5 step 3d), on approval, offline, delegation and
  agent-authority verification; the reason starts "signed requirement is weaker than the relying
  party's policy". Omitting the floor keeps the previous behaviour, which proves only the quorum the
  signers stated. No signed byte changes; shared parity vectors pin it in all five languages.
- **DEWP evidence verification (1.0 pre-release correction, Sep 2026):** an entry that carries a
  canonical preimage reads `tenantSeq` only from it (`null` ⇒ no counter) and fails when its
  redaction record's counter disagrees; a tenant-bound entry fails in a bundle that declares no (or
  another) tenant; a preimage under an unknown profile fails the bundle; a repeated leaf or `seq`, or
  leaf counts inconsistent with each other or the checkpoint's `entryCount`, fail; a checkpoint with
  no `chainHash`/`anchoredAt` is never anchored. New `trustedCheckpoints` (evidence) and
  `trustedCheckpoint` (single proof) options take caller-held roots-file records: a contradicting
  bundle checkpoint fails and anchors are held to the record; a single proof counts a Rekor/TSA anchor
  only against one. `isWellFormedAnchor` requires `algorithm` ∈ ES256/Ed25519/RSA-PSS. Pinned in all
  five languages by the `dewpEvidenceHardening` parity vectors.
- **DIV 1.0 pre-release correction (PK-11):** under a signed `requireHardwareKey`, a WEBAUTHN witness
  whose signed authenticatorData carries the Backup Eligible or Backup State flag no longer counts
  toward the quorum (DIV §4.4.5 rule 6) — a relying party now catches an issuer that let a synced
  passkey sign a hardware-pinned action. No signed byte changes; shared parity vectors pin it in all
  five languages.
- Add `verifyWebAuthnWitness(witness, expectation)`: the DIV §4.4.5 checks on ONE WebAuthn assertion
  (payload binding, origin, RP ID, UP/UV, crossOrigin, signature under a caller-supplied COSE or SPKI
  P-256 key) without a receipt around it — for re-verifying a single stored witness. It is the same
  implementation every receipt verifier runs, not a copy, and it enforces no quorum, window or policy.
- **Breaking (DEWP 1.0 pre-release correction):** the anchored preimage is now
  `[dailyRoot, timestamp, issuer, algorithm, seqStart, seqEnd, chainHash]`; anchors lacking the
  position fields never verify. External witness times (Rekor `integratedTime`, TSA `genTime`) must
  fall within `maxAnchorLagSeconds` (default 86400) after — or 300 s before — the checkpoint's claimed
  time; anchors must match the checkpoint's seq range, chain hash and `anchoredAt`; evidence-bundle
  chain hashes are recomputed; verdicts expose per-issuer witness times; an optional pinned Rekor
  submitter key is enforced. A supplied root is reported as `rootSource: "caller-supplied"` (was
  `"independent"`).
- A non-empty `allowedAaguids` is refused exactly like `requireHardwareKey`: bare-key witnesses do not
  count and offline proofs are rejected (DIV §4.3.2/§5a.3).

- Add optional OpenSSL 3 RFC 3161 verification with issuer-specific certificate pins, offline CRL policy, shared cross-language vectors and quorum/divergence integration.

- Enforce DIV §5 identity trust for multi-approver quorums; preserve DIV §4.4.2 ES256
  compatibility for absent/null/unknown witness labels, while refusing AUTO_APPROVED witnesses.
- Validate DEWP protocol, version and declared hash/serialization/Merkle algorithms before
  accepting proof or evidence bundles. Legacy numeric revisions 1/2 remain supported without
  a protocol declaration. Shared cross-language fixtures cover these contracts.

- Packaging: the published type entry is `dist/index.d.ts` (and `dist/approval-policy.d.ts` for
  the subpath) instead of the raw `src/*.ts`. Pointing `types` at source made every consumer compile
  this package under THEIR `tsconfig`: on `lib` below ES2022 that produced TS2550 on `Object.hasOwn`
  and `Array.at` from inside the package, unfixable from the consumer side because `skipLibCheck`
  only skips `.d.ts` files. `engines.node` is `>=18`, and a Node-18-targeted `lib` is exactly the
  case that broke.
- Packaging: the tarball is `dist` only — no `src`, no tests, no vectors, no source maps (24 files,
  82.6 kB, down from 62 and 245 kB). The source shipped alongside the build could not verify it:
  no `tsconfig.json` ships, so nobody could rebuild `dist` from it and compare, which made it an
  audit artifact that bound nothing. The source, the vectors and a CI run of the full suite are in
  the public repository, tagged at each released version; what binds a released tarball to that tag
  is the passkey-signed approval receipt over its sha256, not a copy of the source. No runtime or
  canonical-byte change.
- **Wire format: DIV v1 agent intents now sign `action`, `agent`, `session`, `nbf`, and `exp` instead of ordinary `expiresAt`; `div-agent-authority` requires `parentReceiptHash` (null for a root).** Older §5b seals lacking that key cannot verify under this pre-release profile and must be re-sealed. All canonical producers, five verifier ports and vectors must move together; the ordinary HUMAN/SERVICE intent keeps `expiresAt`.

- The shared approval-policy resolver supports internal tenant policy version 3: one `*` baseline, exact case-sensitive
  action IDs, at most one rule per ID, and an explicit unknown-action choice. This changes no
  canonical receipt bytes or historical verification.

- Add the dependency-free `@intyga/verify/approval-policy` subpath for shared approval-rule
  conflict checks. A higher-ranked rule cannot discard another matching constraint in strict mode.
  This adds no fields to canonical receipt payloads and does not change historical signatures.

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


Initial public release.

- Offline approval-receipt verification (ES256 and WebAuthn) against a caller-supplied trust
  anchor — no INTYGA secret, no network. `AUTO_APPROVED` receipts are refused by default.
- DIV canonical payload builders and verification codes, pinned by shared cross-language golden
  vectors.
- DEWP ledger verification: inclusion proofs with mandatory bounds checks, §5.2 anchor signatures,
  §5.3 anchor-quorum evaluation, §5.4 checkpoint continuity chain, and evidence bundles.
- Zero runtime dependencies (Node ≥ 18, `node:crypto` only).
