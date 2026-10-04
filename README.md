# @intyga/verify

[![Release gated by INTYGA](https://www.intyga.com/badges/release-gated-by-intyga.svg)](https://www.intyga.com/use-cases/package-publishing)

**Independently confirm that a human cryptographically approved exactly the action you're about to run — with no INTYGA secret.**

When INTYGA returns an approval, it hands you a **receipt**: the exact canonical payload the human's key signed, plus the signature and public key. This library lets your own code re-derive that payload from *your* parameters, check it byte-for-byte against what was signed, and verify the signature — entirely offline. You don't have to trust INTYGA's word that the approval is real; you check the math yourself.

- **Zero npm runtime dependencies.** Receipt verification uses Node cryptography. Optional RFC 3161 timestamp verification additionally requires an installed OpenSSL 3 executable.
- **No INTYGA secret required.** Verification uses approver keys **you** resolve — never a key read out of the receipt (see [Whose key?](#whose-key-the-trust-anchor)).
- Verifies both **WebAuthn** approvals (passkey / hardware security key — the normal path) and **raw P-256** signatures (legacy/headless signer keys), plus policy `AUTO_APPROVED` receipts.

```ts
import { verifyApprovalReceipt } from "@intyga/verify";

// `receipt` came back from INTYGA when the human approved.
const check = verifyApprovalReceipt(receipt, {
  target: "prod-payments-eu",                           // YOUR service identifier — see below
  actionType: "wipe_production",
  params: { target: "prod-db-1", region: "eu-north-1" }, // what you're ACTUALLY about to do
  nonce, // the challenge YOU issued — see "Replay" below
  approvers: {                       // WHOSE signature you accept — see "Whose key?" below
    dids: ["did:intyga:cfo-alice", "did:intyga:cto-bob"],
    resolveKey: (did) => APPROVER_KEYS[did] ?? null,    // from YOUR config/directory
  },
  // YOUR approval rule for this action — see "Whose quorum?" below. Without it you verify only the
  // quorum the signers themselves wrote into the receipt.
  requirement: { requiredApprovals: 2, requesterCannotApprove: true },
}, {
  // REQUIRED for passkey receipts (the normal flow): your approval console's exact origin and RP ID,
  // from the trust-anchor file exported in the console (its `webauthn` block). Without them a passkey
  // receipt is refused — see "WebAuthn receipts need an origin and an RP ID" below.
  expectedOrigin: process.env.INTYGA_WEBAUTHN_ORIGIN!,
  expectedRpId: process.env.INTYGA_WEBAUTHN_RP_ID!,
});

if (!check.ok) throw new Error(`Refusing to proceed: ${check.reason}`);
// ✅ A human signed off on THIS exact instruction. Safe to execute.
```

Why re-pass the params? So the approval can't be swapped: if what you're about to execute differs by a
single byte from what the human saw and signed, `verifyApprovalReceipt` returns `{ ok: false }`. This is
your defense-in-depth even against a compromised INTYGA gateway.

`target` is **required and must come from your own configuration, never from the receipt**. It is what
rejects an approval that was minted for a *different* service (DIV Target Isolation): if the verifier
read the target out of the receipt, the receipt would be defining the scope it is checked against, and
a proof harvested from another relying party would verify. Omitting it is refused rather than defaulted.

## Whose key? (the trust anchor)

`approvers` is **required**, and it is the single most important input. Everything else this library
does is arithmetic; this is the part that decides *whose* approval counts.

Verification never uses `receipt.signerPublicKey`. If it did, the receipt would be vouching for its own
signer: anyone able to hand you a receipt — and under the DIV threat model that includes the untrusted
agent — could generate a keypair, sign a payload over the nonce you issued and the params you are about
to run, put any string in `signerDid`, and be told a human approved. Everything would check out, because
the signature really would verify against the key in the object.

So you supply the keys. Three forms:

```ts
// A pinned allowlist. Simplest, and the identity IS the key — the receipt's signerDid is not trusted.
approvers: { publicKeys: [ALICE_SPKI_B64, BOB_SPKI_B64] }

// Or a DID allowlist plus your own resolver (directory lookup, enrollment record, config map).
approvers: { dids: [...], resolveKey: (did) => myDirectory.get(did) ?? null }

// Or self-certifying DIDs alone — no resolver, no key distribution at all.
approvers: { dids: ["did:intyga:key:tSNSCM0v6Qs…"] }
```

**Self-certifying DIDs.** A pinned DID of the form `did:intyga:key:<base64url(sha256(key bytes))>`
is itself a commitment to the enrolled public key: the receipt carries the key, and verification
accepts it exactly when it hashes to the pinned DID (`selfCertifyingDid()` exports the derivation).
**Precedence: an explicit mapping always wins.** If `resolveKey` returns keys for the DID, those
keys are the anchor and the commitment is not consulted — that is what lets you extend the identity
to credentials enrolled after the DID was minted, and (the direction that matters for security)
*narrow* it away from a compromised credential by re-exporting the anchor without it. The bare
commitment applies only when the anchor names no keys, which is what makes a plain DID list a
complete anchor with zero key distribution. Pinned DIDs that are NOT self-certifying still require
`resolveKey`; verification fails closed with an explicit reason otherwise. Self-certifying
validation and explicit-mapping precedence are also implemented in the Go, Rust, Java and Python
ports and exercised by shared verifier fixtures.

**Where the key must come from.** Somewhere you control and that an attacker who can forge a receipt
cannot also change: your deployment config, your secrets manager, your own IdP/directory, or keys you
pinned at enrollment.

**Where it must NOT come from.** Fetching approver keys from the INTYGA gateway at verification time
defeats the entire property — a compromised gateway would then supply both the receipt and the key that
validates it, and this library would happily agree. If you are going to trust the gateway for keys, you
do not need this library; you can just trust its answer.

## Whose quorum? (the requirement floor)

The signed payload carries a `requirement` — `requiredApprovals`, `requesterCannotApprove`,
`requireHardwareKey` — and verification counts **distinct** approvers whose signature verifies under a
key you resolved against it. But that requirement is **the signers' own statement**. Its signature stops
a third party from altering it; it does not stop the people it constrains from writing a weaker one.
Whoever composes the bytes chooses the requirement, so one approver — including one who is also the
requester — can compose `{ requiredApprovals: 1, requesterCannotApprove: false }` for an action your
policy gates at 3-of-3 with four-eyes, sign it alone, and hand you a receipt that verifies. A
compromised gateway can do the same at issuance.

**Without a floor, "quorum met" means only "the quorum the signers stated was met".** If you know the
rule — from a trust bundle, your own configuration, or anywhere you control — pass it as
`expected.requirement`:

```ts
verifyApprovalReceipt(receipt, { ...expected, requirement: { requiredApprovals: 3, requesterCannotApprove: true } })
// → { ok: false, reason: "signed requirement is weaker than the relying party's policy: it requires 1 approval(s), the policy 3 (DIV §5 step 3d)" }
```

A signed requirement weaker on any field — fewer approvals, no four-eyes where you require it, no
hardware key where you require it — is refused before any signature is counted (DIV §5 step 3d). An
equal or stricter one passes, and the signed value is then what is enforced. A malformed floor (a quorum
below 1, say) is refused rather than treated as absent. `allowedAaguids` is not floored; express a model
restriction as `requireHardwareKey`. The same `requirement` field exists on `verifyDelegation` (pass the
ordinary rule the delegation was sealed against) and `verifyAgentAuthority` (your sealing policy); under
an offline delegation, pass the ordinary rule to `verifyApprovalReceipt` too. Omitting it keeps the
previous behaviour, for compatibility — which is exactly the weaker guarantee described above.

Key-only trust is refused when the signed `requiredApprovals` exceeds 1 or `requesterCannotApprove` is
true. Use the DID form for those policies: multiple credentials for one DID count as one person
(DIV §5 step 3b).

## Expiry and replay: what this does and does not prove

`ok: true` proves a human key signed **exactly this action, with exactly these params, for exactly the
target and nonce you passed**, and that the proof **has not expired**. The signed `expiresAt` is enforced
fail-closed by default (±30s clock-skew tolerance); pass `{ allowExpired: true }` only for post-hoc
audit/forensic re-verification, where confirming a signature that was valid *at the time* is the point.

Expiry bounds how long a proof is valid, but it does **not** prove the approval hasn't already been used
*within* that window. Single-use enforcement is separate: it lives in the gateway's `/authorize/verify`,
which atomically marks the challenge `CONSUMED`. This library is a companion to that call, not a
replacement for it. If you verify offline and skip the consume step, **you** must record redeemed nonces
yourself — which is why `nonce` is a required part of the expectation rather than something read out of
the receipt.

## WebAuthn receipts need an origin and an RP ID

A WebAuthn assertion says "this credential signed these bytes" — it does not, by itself, say *which
relying party asked*. So for `sigAlg: "WEBAUTHN"` you must pin both, or verification is refused:

```ts
verifyApprovalReceipt(receipt, expected, {
  expectedOrigin: "https://app.example.com", // exact clientDataJSON origin
  expectedRpId: "app.example.com",           // hashed into authenticatorData
});
```

The verifier then checks the assertion is a `webauthn.get` (not a registration), that its origin matches,
that `authenticatorData`'s rpIdHash matches your RP ID, that the assertion was **not** produced inside a
cross-origin frame (`crossOrigin: true`, or a `topOrigin` that differs from `origin`), and that the user
was present **and verified** (biometric/PIN). Pass `requireUserVerification: false` only if you
consciously accept mere possession; `verifyPlatformReceipt` ignores it, because a platform receipt
always requires user verification (DIV §5c.3).

The cross-origin refusal is on by default and `origin` alone cannot substitute for it: inside a
cross-origin iframe the browser reports the *frame's* origin — the RP's own — and rpIdHash matches too,
so a third-party embedder with `publickey-credentials-get` delegated could drive the whole ceremony
while every other check passes. If your approval UI is legitimately framed, opt in with
`allowCrossOrigin: true`.

When the signed policy sets `requireHardwareKey`, a WebAuthn witness whose signed `authenticatorData`
has the Backup Eligible or Backup State flag set is not counted (DIV §4.4.5 rule 6): a synced passkey
cannot satisfy a hardware-key policy, and the flags are covered by the signature. Clear flags are the
authenticator's claim, not attestation — the authenticator model still comes only from enrollment.

## Policy auto-approvals (break-glass / pre-approval windows)

Some receipts are `sigAlg: "AUTO_APPROVED"` — the action was pre-authorized by a policy window, so **no
human signed it and there is nothing to cryptographically verify**. Such a receipt is trivially
forgeable, so `verifyApprovalReceipt` **refuses it by default** (`{ ok: false, autoApproved: true }`) —
your `if (!verify().ok) throw` correctly blocks it. If your relying party has consciously accepted policy
pre-approval, opt in explicitly:

```ts
verifyApprovalReceipt(receipt, expected, { allowAutoApproved: true }); // → { ok: true, autoApproved: true }
```

`ok: true` without `allowAutoApproved` therefore always means **a real human signature verified**.

## API
- `verifyApprovalReceipt(receipt, { approvers, target, actionType, params, nonce, requesterDid? }, { allowAutoApproved?, allowOffline?, delegation?, expectedOrigin?, expectedRpId?, requireUserVerification?, allowCrossOrigin?, allowExpired?, asOf?, clockSkewSeconds? })` → `{ ok, reason?, autoApproved?, signers? }` — `approvers`, `target` and `nonce` are all required and asserted from your own state, never read from the receipt
- `verifyDelegation(receipt, { approvers, target, actionType, params }, opts?)` → `{ ok, reason?, delegation? }` — checks that the ORDINARY approvers signed away their entitlement (DIV §4.4.6). The result is an input to a later `verifyApprovalReceipt` via `delegation`, never a substitute for one.
- `verifyAgentAuthority(receipt, { approvers, target, agentDid }, opts?)` → `{ ok, reason?, authority? }` — a sealed §5b scope grant, not an approval. Revocation is authoritative online only, so treat a seal like a certificate, not a bearer token.
- `canonicalIntentPayload({ target, actionType, display, params, requester, requirement, nonce, expiresAt })` → the exact signed string (DIV v1). Also exported: `canonicalOfflineIntentPayload` (DIV §5a offline approval), `canonicalDelegationPayload` and `canonicalAgentAuthorityPayload` (DIV §5b). The pre-DIV `canonicalAuthorizationPayload`/`V3` builders were removed with the v2/v3 formats (ADR 005/014); `verifyApprovalReceipt` rejects anything where `v !== 1`.
- `verificationCode(canonical)` → the short `XXXX-XXXX` code shown on the approval screen
- `verifyEcdsaP256(publicKeyB64, payload, signatureB64)` → `boolean`
- `verifyWebAuthnWitness({ signedPayload, publicKey, authenticatorData, clientDataJSON, signature }, { expectedOrigin, expectedRpId, requireUserVerification?, allowCrossOrigin? })` → `{ ok, reason? }` — the DIV §4.4.5 checks on ONE assertion (e.g. a single stored ledger witness), under a COSE or SPKI P-256 key you supply from your own records. It checks the signature binding only: no quorum, window, payload type or signed requirement — verify an approval with `verifyApprovalReceipt`.

> The canonicalization here is byte-for-byte identical to the INTYGA gateway, the approval UI, and
> `@intyga/mcp-schemas`. That identity is the whole point — don't reformat it.

## DIV / DEWP conformance

This is the reference verifier with the broadest surface of the five ports. Beyond the **DEWP Core
Profile** ([`docs/DEWP.md`](../../docs/DEWP.md) §9.1) it implements single-anchor **and**
multi-anchor quorum verification (§5.2/§5.3, including `requiredAnchors`, issuer trust and
divergence detection), the §5.4 checkpoint continuity chain (`0x04` domain tag), proof-bundle
parsing with the §7.1 verification levels, evidence bundles, and gapless `tenantSeq` completeness
validation. All five ports also verify **agent-authority seals** (DIV §5b) and platform receipts
(DIV §5c), in addition to ordinary approval and delegation receipts.
Byte parity with the Go, Rust, Java and Python ports is locked by the shared golden vectors
in `packages/mcp-schemas/vectors/`.

It does **not** implement NDJSON evidence streaming (§6.4), so — like every port, this one
included — it does not claim the §9.2 **Extended Profile**. The narrower ports state their own
limits: [`verify-go`](../verify-go/README.md), [`verify-rust`](../verify-rust/README.md),
[`verify-java`](../verify-java/README.md), [`sdk-python`](../sdk-python/README.md).

Requires Node ≥18 (`node:crypto`).

Apache-2.0 licensed — see [`LICENSE`](./LICENSE).

## RFC 3161 timestamps

All five verifier ports can count verified TSA evidence toward DEWP quorum. In Node, configure
`externalKeys.rfc3161` by issuer when calling `verifyAnchorQuorum`, `verifyBundle`, or
`verifyEvidenceBundle`:

```ts
const externalKeys = {
  rekor: pinnedRekorPublicKey,
  rekorIssuer: "https://rekor.sigstore.dev",
  rfc3161: {
    "https://tsa.example": {
      caPem: trustedCaPem,
      signerCertificateSha256: pinnedSignerCertificateSha256,
      revocation: "crl" as const,
      crlPem: currentOfflineCrlPem,
    },
  },
}
```

An external witness (Rekor, TSA) is time-bounded against the checkpoint's claimed time, and that time
must come from somewhere you trust (DEWP §5.3). Pass the chain-verified roots-file lines you hold as
`trustedCheckpoints` to `verifyEvidenceBundle` (a bundle checkpoint that contradicts one fails, and
anchors are held to your record), and the matching line as `trustedCheckpoint` to `verifyBundle`: a
single proof carries no checkpoint, so without it Rekor/TSA anchors do not count. An evidence
checkpoint with no `chainHash`/`anchoredAt` and no record never counts as anchored.

For policies trusting multiple issuers, `rekorIssuer` explicitly binds the log key to its issuer.
An unscoped legacy Rekor key is accepted only when the policy trusts exactly one issuer. A log
attests arbitrary submitted digests, so its key must not credit a different issuer name.

Obtain the CA and SHA-256 fingerprint of the DER TSA signer certificate independently of the bundle.
The certificate pin is scoped to its issuer: a CA capable of issuing certificates for several TSAs
is not itself proof of a particular TSA's identity. Rotate the pin deliberately when the TSA rotates
its certificate. Extra intermediate certificates can be supplied in `untrustedPem`.

`verifyRfc3161Anchor(anchor, trust)` also verifies individual tokens. It checks the SHA-256 imprint
over the raw DEWP anchor digest, CMS signature, signer pin, timestamping EKU and certificate chain.
CMS signer digests must be SHA-256, SHA-384 or SHA-512; SHA-1 and MD5 are refused.
`verificationTime` is optional Unix seconds; it defaults to the current time rounded up by less than
one second. The token must not claim a later time. Certificates must be valid both at that evaluation
time and at the authenticated TSA time. `revocation: "crl"` requires valid caller-supplied offline
CRLs for the chain; missing, stale or revoked evidence fails. `"unchecked"` is an explicit opt-out
and makes **no revocation assertion**. No CA, CRL, OCSP or intermediate is downloaded.

For historical validation, retain the certificates, applicable CRLs and the relying party's chosen
evaluation time. A past evaluation is an explicit historical claim, not proof of current validity;
this adapter does not implement archival evidence renewal or qualified-timestamp legal validation.
Timestamp evidence establishes that the commitment existed by the TSA time, not when its underlying
action occurred. The anchor's own timestamp remains producer-supplied data bound by the imprint.

The adapter invokes OpenSSL 3 without a shell, with private temporary files and a five-second limit
per command. `opensslPath` can select a caller-controlled executable. Without that runtime or the
required trust configuration, TSA evidence is reported as unverified and never counts toward quorum.
Applications should bound bundle sizes and run large offline audits away from request handlers.


### Audit event signatures

The `trust.intyga.audit.v1` profile carries WebAuthn assertion data in the committed
`canonical.metadata.webauthn.authenticatorData` and `clientDataJSON` fields. Both single-proof and
bulk-evidence verification check these assertions when given caller-owned signer trust. This is a
signature over the exact `signedPayload`, not approval quorum, action authorization, hardware
attestation, current credential status or proof that the deploy executed. Verify the full DIV receipt
against the expected operation and approval policy for those authorization checks.

The per-event signature result distinguishes `verified`, `invalid`, `not_checked` (missing trust,
missing material or unsupported algorithm) and `not_applicable` (unsigned/system or AUTO_APPROVED).
A reason accompanies each status. `trusted: true` requires a valid signature under a caller-supplied
key mapped to that signer DID. WebAuthn requires caller-selected origin and RP ID, user presence and
user verification, and refuses cross-origin assertions. Supply COSE keys for WebAuthn and SPKI keys
for ES256. Multiple keys per DID support deliberate key rotation; the evidence's key is never added
to the caller's trusted set.

Without a signature policy, legacy ES256 checks still use the embedded key and report `trusted: false`;
WebAuthn reports `not_checked`. Diagnostic ledger validity does not imply signature validity. The
strict signature option requires **every selected entry** to have a verified, caller-trusted signature;
unsigned, redacted, incomplete and invalid entries fail that option. Anchor quorum is a separate policy.

Use `signaturePolicy: { trustedSigners: { [did]: [publicKey] }, expectedOrigin, expectedRpId }`
and `requireSignatures: true` in `verifyBundle` / `verifyEvidenceBundle`.
