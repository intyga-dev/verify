import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"
import { test } from "node:test"
import { type ApprovalReceipt, type ApproverTrustAnchor, verifyApprovalReceipt } from "./index.ts"

// The shared WebAuthn golden vector (DIV §4.4.5) was consumed by verify-go, verify-rust,
// verify-java and sdk-python but by NO TypeScript test — so the reference implementation, the one
// the other five ports are held byte-identical to, never actually ran the fixture that pins the
// passkey path. That is the wrong way round: a drift in the reference would have surfaced as four
// simultaneous port failures with the reference looking innocent.
//
// These mirror packages/verify-go/webauthn_test.go so the same fixture is asserted the same way on
// both sides.

interface WebAuthnVector {
  rpId: string
  origin: string
  expected: {
    target: string
    nonce: string
    actionType: string
    params: Record<string, unknown>
    requesterDid: string
  }
  receipt: ApprovalReceipt
}

function loadVector(): WebAuthnVector {
  const file = path.join(import.meta.dirname, "..", "vectors", "webauthn-vector.json")
  return JSON.parse(fs.readFileSync(file, "utf8")) as WebAuthnVector
}

/**
 * The trust anchor is REQUIRED (DIV Invariant 3). For a golden vector the committed file stands in
 * for the enrollment record, so pinning its key is the legitimate resolution step — it still comes
 * from outside the receipt under verification.
 */
function expectationFor(v: WebAuthnVector) {
  const approvers: ApproverTrustAnchor = { publicKeys: [v.receipt.signerPublicKey ?? ""] }
  return {
    target: v.expected.target,
    nonce: v.expected.nonce,
    actionType: v.expected.actionType,
    params: v.expected.params,
    approvers,
  }
}

test("shared WebAuthn vector verifies in the TS reference", () => {
  const v = loadVector()
  const r = verifyApprovalReceipt(v.receipt, expectationFor(v), {
    expectedOrigin: v.origin,
    expectedRpId: v.rpId,
  })
  assert.equal(r.ok, true, `valid WebAuthn receipt should verify: ${r.reason ?? ""}`)
})

test("WebAuthn vector: origin and RP ID are pinned, not advisory (DIV §4.4.5 rules 1)", () => {
  const v = loadVector()
  const wrongOrigin = verifyApprovalReceipt(v.receipt, expectationFor(v), {
    expectedOrigin: "https://evil.example.com",
    expectedRpId: v.rpId,
  })
  assert.equal(wrongOrigin.ok, false, "an assertion harvested at another origin must not verify")

  const wrongRpId = verifyApprovalReceipt(v.receipt, expectationFor(v), {
    expectedOrigin: v.origin,
    expectedRpId: "evil.example.com",
  })
  assert.equal(wrongRpId.ok, false, "an assertion for another RP ID must not verify")
})

test("WebAuthn vector: unpadded base64url is accepted on every wire field (DIV §4.4.2)", () => {
  const v = loadVector()
  // The production gateway emits these three as UNPADDED base64url. Three ports decoded only the
  // standard alphabet and rejected 100% of real passkey receipts while passing a standard-encoded
  // suite; this asserts the reference accepts the wire form the vector actually commits.
  for (const field of ["signature", "authenticatorData", "clientDataJSON"] as const) {
    const value = v.receipt[field]
    assert.equal(typeof value, "string", `${field} present`)
    assert.doesNotMatch(String(value), /[+/=]/, `${field} is unpadded base64url in the committed vector`)
  }
  const r = verifyApprovalReceipt(v.receipt, expectationFor(v), {
    expectedOrigin: v.origin,
    expectedRpId: v.rpId,
  })
  assert.equal(r.ok, true)
})

test("WebAuthn vector: the receipt is bound to its own params (DIV Invariant 1)", () => {
  const v = loadVector()
  const tampered = {
    ...expectationFor(v),
    params: { ...v.expected.params, amount: 99_999 },
  }
  const r = verifyApprovalReceipt(v.receipt, tampered, {
    expectedOrigin: v.origin,
    expectedRpId: v.rpId,
  })
  assert.equal(r.ok, false, "changing an execution parameter must break the signature check")
})

test("WebAuthn vector: the receipt is bound to its target and nonce", () => {
  const v = loadVector()
  const otherTarget = verifyApprovalReceipt(
    v.receipt,
    { ...expectationFor(v), target: "prod-payments-eu" },
    { expectedOrigin: v.origin, expectedRpId: v.rpId },
  )
  assert.equal(otherTarget.ok, false, "cross-target replay must fail (DIV Invariant 5)")

  const otherNonce = verifyApprovalReceipt(
    v.receipt,
    { ...expectationFor(v), nonce: "wa_00000000-0000-4000-8000-000000000000" },
    { expectedOrigin: v.origin, expectedRpId: v.rpId },
  )
  assert.equal(otherNonce.ok, false, "a receipt for another challenge must be refused")
})

test("WebAuthn vector: the key must come from the caller's anchor, never the receipt", () => {
  const v = loadVector()
  const { approvers: _drop, ...rest } = expectationFor(v)
  const r = verifyApprovalReceipt(v.receipt, rest as never, {
    expectedOrigin: v.origin,
    expectedRpId: v.rpId,
  })
  assert.equal(r.ok, false, "no trust anchor means no verdict (DIV Invariant 3)")
})
