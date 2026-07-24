# @sakra-trust/verify

**Independently confirm that a human cryptographically approved exactly the action you're about to run — with no SÄKRA secret.**

When SÄKRA returns an approval, it hands you a **receipt**: the exact canonical payload the human's key signed, plus the signature and public key. This library lets your own code re-derive that payload from *your* parameters, check it byte-for-byte against what was signed, and verify the signature — entirely offline. You don't have to trust SÄKRA's word that the approval is real; you check the math yourself.

- **Zero runtime dependencies** (`node:crypto` only). Read the whole thing — ~500 lines for receipt verification, under 1,000 including the Merkle inclusion-proof code.
- **No SÄKRA secret required.** Verification uses only the signer's public key from the receipt.
- Verifies both **WebAuthn** approvals (passkey / hardware security key — the normal path) and **raw P-256** signatures (legacy/headless signer keys), plus policy `AUTO_APPROVED` receipts.

```ts
import { verifyApprovalReceipt } from "@sakra-trust/verify";

// `receipt` came back from SÄKRA when the human approved.
const check = verifyApprovalReceipt(receipt, {
  actionType: "wipe_production",
  params: { target: "prod-db-1", region: "eu-north-1" }, // what you're ACTUALLY about to do
  nonce, // the challenge YOU issued — see "Replay" below
});

if (!check.ok) throw new Error(`Refusing to proceed: ${check.reason}`);
// ✅ A human signed off on THIS exact instruction. Safe to execute.
```

Why re-pass the params? So the approval can't be swapped: if what you're about to execute differs by a
single byte from what the human saw and signed, `verifyApprovalReceipt` returns `{ ok: false }`. This is
your defense-in-depth even against a compromised SÄKRA gateway.

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
that `authenticatorData`'s rpIdHash matches your RP ID, and that the user was present **and verified**
(biometric/PIN). Pass `requireUserVerification: false` only if you consciously accept mere possession.

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
- `verifyApprovalReceipt(receipt, { actionType, params, nonce, requesterDid? }, { allowAutoApproved?, expectedOrigin?, expectedRpId?, requireUserVerification? })` → `{ ok, reason?, autoApproved? }`
- `canonicalAuthorizationPayload({ nonce, actionType, actionDescription, params })` → the exact signed string
- `verificationCode(canonical)` → the short `XXXX-XXXX` code shown on the approval screen
- `verifyEcdsaP256(publicKeyB64, payload, signatureB64)` → `boolean`

> The canonicalization here is byte-for-byte identical to the SÄKRA gateway, the approval UI, and
> `@sakra-trust/mcp-schemas`. That identity is the whole point — don't reformat it.

Requires Node ≥18 (`node:crypto`).

Apache-2.0 licensed — see [`LICENSE`](./LICENSE).
