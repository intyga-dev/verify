# @intyga/verify

**Independently confirm that a human cryptographically approved exactly the action you're about to run — with no Intyga secret.**

When Intyga returns an approval, it hands you a **receipt**: the exact canonical payload the human's key signed, plus the signature and public key. This library lets your own code re-derive that payload from *your* parameters, check it byte-for-byte against what was signed, and verify the signature — entirely offline. You don't have to trust Intyga's word that the approval is real; you check the math yourself.

- **Zero runtime dependencies** (`node:crypto` only). Read the whole thing — under 2,000 lines for receipt verification, under 4,000 including the ledger, anchor-quorum and evidence-bundle code.
- **No Intyga secret required.** Verification uses approver keys **you** resolve — never a key read out of the receipt (see [Whose key?](#whose-key-the-trust-anchor)).
- Verifies both **WebAuthn** approvals (passkey / hardware security key — the normal path) and **raw P-256** signatures (legacy/headless signer keys), plus policy `AUTO_APPROVED` receipts.

```ts
import { verifyApprovalReceipt } from "@intyga/verify";

// `receipt` came back from Intyga when the human approved.
const check = verifyApprovalReceipt(receipt, {
  target: "prod-payments-eu",                           // YOUR service identifier — see below
  actionType: "wipe_production",
  params: { target: "prod-db-1", region: "eu-north-1" }, // what you're ACTUALLY about to do
  nonce, // the challenge YOU issued — see "Replay" below
  approvers: {                       // WHOSE signature you accept — see "Whose key?" below
    dids: ["did:intyga:cfo-alice", "did:intyga:cto-bob"],
    resolveKey: (did) => APPROVER_KEYS[did] ?? null,    // from YOUR config/directory
  },
});

if (!check.ok) throw new Error(`Refusing to proceed: ${check.reason}`);
// ✅ A human signed off on THIS exact instruction. Safe to execute.
```

Why re-pass the params? So the approval can't be swapped: if what you're about to execute differs by a
single byte from what the human saw and signed, `verifyApprovalReceipt` returns `{ ok: false }`. This is
your defense-in-depth even against a compromised Intyga gateway.

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

**Where it must NOT come from.** Fetching approver keys from the Intyga gateway at verification time
defeats the entire property — a compromised gateway would then supply both the receipt and the key that
validates it, and this library would happily agree. If you are going to trust the gateway for keys, you
do not need this library; you can just trust its answer.

For quorum receipts, count is enforced for you: the signed payload carries `requirement.requiredApprovals`
and verification counts **distinct** approvers whose signature verifies under a key you resolved. In
`publicKeys` mode distinctness is by key, because `signerDid` is unverified there — which means the
quorum counts credentials rather than people: one approver whose two registered credentials are both
listed satisfies a 2-of-N alone. A signed `requesterCannotApprove` rule requires DID/identity trust; key-only
anchors are refused because the receipt's signer label cannot establish separation of duties.
For `requiredApprovals` > 1, use the DID form to count people (DIV §4.4.6).

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
cross-origin frame, and that the user was present **and verified** (biometric/PIN). Pass
`requireUserVerification: false` only if you consciously accept mere possession.

The cross-origin refusal is on by default and `origin` alone cannot substitute for it: inside a
cross-origin iframe the browser reports the *frame's* origin — the RP's own — and rpIdHash matches too,
so a third-party embedder with `publickey-credentials-get` delegated could drive the whole ceremony
while every other check passes. If your approval UI is legitimately framed, opt in with
`allowCrossOrigin: true`.

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

> The canonicalization here is byte-for-byte identical to the Intyga gateway, the approval UI, and
> `@intyga/mcp-schemas`. That identity is the whole point — don't reformat it.

## DIV / DEWP conformance

This is the reference verifier with the broadest surface of the five ports. Beyond the **DEWP Core
Profile** ([`docs/DEWP.md`](../../docs/DEWP.md) §9.1) it implements single-anchor **and**
multi-anchor quorum verification (§5.2/§5.3, including `requiredAnchors`, issuer trust and
divergence detection), the §5.4 checkpoint continuity chain (`0x04` domain tag), proof-bundle
parsing with the §7.1 verification levels, evidence bundles, and gapless `tenantSeq` completeness
validation. On the DIV side it is also the only port that verifies **agent-authority seals**
(`verifyAgentAuthority`, DIV §5b) in addition to `verifyApprovalReceipt` and `verifyDelegation`.
Byte parity with the Go, Rust, Java and Python ports is locked by the shared golden vectors
in `packages/mcp-schemas/vectors/`.

It does **not** implement NDJSON evidence streaming (§6.4), so — like every port, this one
included — it does not claim the §9.2 **Extended Profile**. The narrower ports state their own
limits: [`verify-go`](../verify-go/README.md), [`verify-rust`](../verify-rust/README.md),
[`verify-java`](../verify-java/README.md), [`sdk-python`](../sdk-python/README.md).

Requires Node ≥18 (`node:crypto`).

Apache-2.0 licensed — see [`LICENSE`](./LICENSE).
