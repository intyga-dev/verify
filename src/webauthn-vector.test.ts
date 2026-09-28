import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"
import crypto from "node:crypto"
import { test } from "node:test"
import {
  type ApprovalReceipt,
  type ApproverTrustAnchor,
  canonicalIntentPayload,
  verifyApprovalReceipt,
  verifyWebAuthnWitness,
  type WebAuthnWitness,
} from "./index.ts"

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

// ─── The standalone witness check (verifyWebAuthnWitness) ────────────────────────────────────────
// One assertion without a receipt around it — what the console needs to re-verify a single stored
// ledger witness. It is the same implementation the receipt verifiers run, pinned here against the
// same golden bytes.

function witnessOf(v: WebAuthnVector): WebAuthnWitness {
  return {
    signedPayload: v.receipt.canonicalPayload,
    publicKey: v.receipt.signerPublicKey ?? "",
    authenticatorData: v.receipt.authenticatorData ?? "",
    clientDataJSON: v.receipt.clientDataJSON ?? "",
    signature: v.receipt.signature ?? "",
  }
}

test("verifyWebAuthnWitness: the golden assertion verifies on its own, under its COSE key or the same key as SPKI", () => {
  const v = loadVector()
  const expectation = { expectedOrigin: v.origin, expectedRpId: v.rpId }
  assert.deepEqual(verifyWebAuthnWitness(witnessOf(v), expectation), { ok: true })
  // The same P-256 key re-encoded as DER SPKI, from the COSE x/y coordinates.
  const cose = Buffer.from(v.receipt.signerPublicKey ?? "", "base64")
  const x = cose.subarray(10, 42).toString("base64url")
  const y = cose.subarray(45, 77).toString("base64url")
  const spki = crypto
    .createPublicKey({ format: "jwk", key: { kty: "EC", crv: "P-256", x, y } })
    .export({ format: "der", type: "spki" })
    .toString("base64")
  assert.deepEqual(verifyWebAuthnWitness({ ...witnessOf(v), publicKey: spki }, expectation), { ok: true })
  // A list of acceptable origins (a multi-origin relying party) is accepted too.
  assert.equal(
    verifyWebAuthnWitness(witnessOf(v), {
      expectedOrigin: ["https://other.example", v.origin],
      expectedRpId: v.rpId,
    }).ok,
    true,
  )
})

test("verifyWebAuthnWitness: payload, key, origin, RP ID and signature are each bound", () => {
  const v = loadVector()
  const expectation = { expectedOrigin: v.origin, expectedRpId: v.rpId }
  const refused = (w: WebAuthnWitness, e = expectation) => {
    const r = verifyWebAuthnWitness(w, e)
    assert.equal(r.ok, false)
    return r.ok ? "" : r.reason
  }
  assert.match(refused({ ...witnessOf(v), signedPayload: `${v.receipt.canonicalPayload} ` }), /challenge/)
  const other = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const otherSpki = other.publicKey.export({ format: "der", type: "spki" }).toString("base64")
  assert.match(refused({ ...witnessOf(v), publicKey: otherSpki }), /signature does not verify/)
  const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
  const rsaSpki = rsa.publicKey.export({ format: "der", type: "spki" }).toString("base64")
  assert.match(refused({ ...witnessOf(v), publicKey: rsaSpki }), /not a P-256 key/)
  assert.match(
    refused(witnessOf(v), { ...expectation, expectedOrigin: "https://evil.example.com" }),
    /origin/,
  )
  assert.match(refused(witnessOf(v), { ...expectation, expectedRpId: "evil.example.com" }), /rpIdHash/)
  const sig = Buffer.from(v.receipt.signature ?? "", "base64url")
  sig.writeUInt8(sig.readUInt8(sig.length - 1) ^ 0x01, sig.length - 1)
  assert.equal(refused({ ...witnessOf(v), signature: sig.toString("base64url") }).length > 0, true)
})

test("verifyWebAuthnWitness: fails closed on missing expectations or fields, and never throws", () => {
  const v = loadVector()
  for (const expectation of [
    { expectedOrigin: "", expectedRpId: v.rpId },
    { expectedOrigin: [], expectedRpId: v.rpId },
    { expectedOrigin: v.origin, expectedRpId: "" },
    {} as never,
  ]) {
    const r = verifyWebAuthnWitness(witnessOf(v), expectation)
    assert.equal(r.ok, false)
    assert.match(r.ok ? "" : r.reason, /expectedOrigin and expectedRpId/)
  }
  for (const field of [
    "signedPayload",
    "publicKey",
    "authenticatorData",
    "clientDataJSON",
    "signature",
  ] as const) {
    const r = verifyWebAuthnWitness(
      { ...witnessOf(v), [field]: "" },
      { expectedOrigin: v.origin, expectedRpId: v.rpId },
    )
    assert.equal(r.ok, false, field)
  }
  const garbage = verifyWebAuthnWitness(
    { ...witnessOf(v), publicKey: "AAAA", authenticatorData: "AAAA", clientDataJSON: "e30=" },
    { expectedOrigin: v.origin, expectedRpId: v.rpId },
  )
  assert.equal(garbage.ok, false)
})

// ─── PK-11: signed backup flags under requireHardwareKey (DIV §4.4.5 rule 6) ─────────────────────

/** A WebAuthn receipt over a fresh intent, with the authenticatorData flags byte chosen by the test. */
function syncedReceipt(flags: number, requireHardwareKey: boolean) {
  const rpId = "app.example.com"
  const origin = "https://app.example.com"
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string }
  const cose = Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
    Buffer.from(jwk.x, "base64url"),
    Buffer.from([0x22, 0x58, 0x20]),
    Buffer.from(jwk.y, "base64url"),
  ]).toString("base64")
  const intent = {
    target: "prod-payments",
    nonce: "pk11-nonce",
    actionType: "payments.wire",
    params: { amount: 1 },
    requester: { did: "did:intyga:agent", attestation: null },
    display: "Wire 1",
    expiresAt: "2999-01-01T00:00:00.000Z",
    requirement: {
      requiredApprovals: 1,
      requireHardwareKey,
      allowedAaguids: [],
      requesterCannotApprove: false,
      signerClass: "human",
    },
  }
  const canonicalPayload = canonicalIntentPayload(intent as never)
  const clientDataJSON = Buffer.from(
    JSON.stringify({
      type: "webauthn.get",
      challenge: Buffer.from(canonicalPayload).toString("base64url"),
      origin,
    }),
  )
  const authenticatorData = Buffer.concat([
    crypto.createHash("sha256").update(rpId).digest(),
    Buffer.from([flags, 0, 0, 0, 1]),
  ])
  const signature = crypto.sign(
    "sha256",
    Buffer.concat([authenticatorData, crypto.createHash("sha256").update(clientDataJSON).digest()]),
    privateKey,
  )
  const receipt: ApprovalReceipt = {
    canonicalPayload,
    actionDescription: intent.display,
    params: intent.params,
    signerDid: "did:intyga:human",
    signerPublicKey: cose,
    signature: signature.toString("base64url"),
    sigAlg: "WEBAUTHN",
    authenticatorData: authenticatorData.toString("base64url"),
    clientDataJSON: clientDataJSON.toString("base64url"),
    requester: intent.requester,
    verificationCode: "",
  }
  const expected = {
    target: intent.target,
    nonce: intent.nonce,
    actionType: intent.actionType,
    params: intent.params,
    approvers: { publicKeys: [cose] },
  }
  return verifyApprovalReceipt(receipt, expected, { expectedOrigin: origin, expectedRpId: rpId })
}

test("requireHardwareKey refuses a WebAuthn witness whose signed flags say backup-eligible or backed up", () => {
  const UP_UV = 0x05
  assert.equal(syncedReceipt(UP_UV, true).ok, true, "device-bound flags satisfy the check")
  for (const [flags, label] of [
    [UP_UV | 0x08, "BE"],
    [UP_UV | 0x10, "BS"],
    [UP_UV | 0x18, "BE+BS"],
  ] as const) {
    const r = syncedReceipt(flags, true)
    assert.equal(r.ok, false, label)
    assert.match(r.reason ?? "", /backup-eligible/, label)
    // Without the hardware requirement a synced passkey is an ordinary approver.
    assert.equal(syncedReceipt(flags, false).ok, true, `${label} without requireHardwareKey`)
  }
})
