// verifyPlatformReceipt (DIV §5c.3): a genuinely-signed WebAuthn assertion over the hash-only
// canonical payload, verified and then attacked one field at a time. The refusal messages are part
// of the relying-party contract, so several are pinned by substring.

import assert from "node:assert/strict"
import crypto from "node:crypto"
import { describe, it } from "node:test"
import {
  canonicalPlatformIntentPayload,
  type PlatformReceipt,
  verifyApprovalReceipt,
  verifyPlatformReceipt,
} from "./index.js"

const RP_ID = "platform.example"
const ORIGIN = "https://platform.example"
const NONCE = "b7a1c2d3-0000-4000-8000-abcdef123456"
const PAYLOAD_HASH = crypto.createHash("sha256").update("the platform's canonical payload").digest("hex")
const SUBJECT = "cust-42"
const SIGNED_AT = "2026-08-27T10:00:00.000Z"
const FAR_FUTURE = "2999-01-01T00:00:00.000Z"

const SUBJECT_KEYS = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })

function coseKeyB64(pair: crypto.KeyPairKeyObjectResult): string {
  const jwk = pair.publicKey.export({ format: "jwk" }) as { x: string; y: string }
  return Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
    Buffer.from(jwk.x, "base64url"),
    Buffer.from([0x22, 0x58, 0x20]),
    Buffer.from(jwk.y, "base64url"),
  ]).toString("base64")
}

function makeReceipt(
  over: {
    canonical?: string
    rpIdInAuthData?: string
    origin?: string
    flags?: number
    sigAlg?: string
    signWith?: crypto.KeyPairKeyObjectResult
  } = {},
): PlatformReceipt {
  const canonical =
    over.canonical ??
    canonicalPlatformIntentPayload({
      payloadHash: PAYLOAD_HASH,
      rpId: RP_ID,
      subjectExternalId: SUBJECT,
      signedAt: SIGNED_AT,
      expiresAt: FAR_FUTURE,
      nonce: NONCE,
    })
  const pair = over.signWith ?? SUBJECT_KEYS
  const clientDataJSON = Buffer.from(
    JSON.stringify({
      type: "webauthn.get",
      challenge: Buffer.from(canonical, "utf8").toString("base64url"),
      origin: over.origin ?? ORIGIN,
      crossOrigin: false,
    }),
    "utf8",
  )
  const counter = Buffer.alloc(5)
  counter.writeUInt8(over.flags ?? 0x05, 0) // UP | UV
  const authenticatorData = Buffer.concat([
    crypto
      .createHash("sha256")
      .update(over.rpIdInAuthData ?? RP_ID, "utf8")
      .digest(),
    counter,
  ])
  const signature = crypto.sign(
    "sha256",
    Buffer.concat([authenticatorData, crypto.createHash("sha256").update(clientDataJSON).digest()]),
    { key: pair.privateKey, dsaEncoding: "der" },
  )
  return {
    canonicalPayload: canonical,
    payloadHash: PAYLOAD_HASH,
    rpId: RP_ID,
    subject: { externalId: SUBJECT },
    nonce: NONCE,
    signerDid: "did:intyga:key:subject",
    signerPublicKey: coseKeyB64(pair),
    signature: signature.toString("base64"),
    sigAlg: over.sigAlg ?? "WEBAUTHN",
    authenticatorData: authenticatorData.toString("base64"),
    clientDataJSON: clientDataJSON.toString("base64"),
  }
}

const EXPECTED = {
  approvers: { publicKeys: [coseKeyB64(SUBJECT_KEYS)] },
  payloadHash: PAYLOAD_HASH,
  rpId: RP_ID,
  nonce: NONCE,
}
const OPTS = { expectedOrigin: ORIGIN }

describe("verifyPlatformReceipt", () => {
  it("verifies a genuine receipt and names one signer", () => {
    const verdict = verifyPlatformReceipt(makeReceipt(), EXPECTED, OPTS)
    assert.equal(verdict.ok, true, verdict.reason)
    assert.equal(verdict.signers?.length, 1)
  })

  it("refuses a digest that does not match what was signed", () => {
    const other = crypto.createHash("sha256").update("a different payload").digest("hex")
    const verdict = verifyPlatformReceipt(makeReceipt(), { ...EXPECTED, payloadHash: other }, OPTS)
    assert.equal(verdict.ok, false)
    assert.match(verdict.reason ?? "", /do not match what was signed/)
  })

  it("refuses an uppercase expected digest instead of case-folding it", () => {
    const verdict = verifyPlatformReceipt(
      makeReceipt(),
      { ...EXPECTED, payloadHash: PAYLOAD_HASH.toUpperCase() },
      OPTS,
    )
    assert.equal(verdict.ok, false)
    assert.match(verdict.reason ?? "", /lowercase hex/)
  })

  it("binds the RP: a different expected rpId fails the signed bytes", () => {
    const verdict = verifyPlatformReceipt(makeReceipt(), { ...EXPECTED, rpId: "evil.example" }, OPTS)
    assert.equal(verdict.ok, false)
  })

  it("binds the RP in the assertion: authenticatorData for another rpId is refused", () => {
    const verdict = verifyPlatformReceipt(makeReceipt({ rpIdInAuthData: "evil.example" }), EXPECTED, OPTS)
    assert.equal(verdict.ok, false)
    assert.match(verdict.reason ?? "", /no valid subject signature/)
  })

  it("binds the origin: an assertion harvested elsewhere is refused", () => {
    const verdict = verifyPlatformReceipt(makeReceipt({ origin: "https://evil.example" }), EXPECTED, OPTS)
    assert.equal(verdict.ok, false)
  })

  it("requires user verification", () => {
    const verdict = verifyPlatformReceipt(makeReceipt({ flags: 0x01 }), EXPECTED, OPTS)
    assert.equal(verdict.ok, false)
  })

  it("is bound to one challenge", () => {
    const verdict = verifyPlatformReceipt(makeReceipt(), { ...EXPECTED, nonce: "other-nonce" }, OPTS)
    assert.equal(verdict.ok, false)
    assert.match(verdict.reason ?? "", /different challenge/)
  })

  it("optionally asserts the subject", () => {
    const good = verifyPlatformReceipt(makeReceipt(), { ...EXPECTED, subjectExternalId: SUBJECT }, OPTS)
    assert.equal(good.ok, true, good.reason)
    const bad = verifyPlatformReceipt(makeReceipt(), { ...EXPECTED, subjectExternalId: "cust-43" }, OPTS)
    assert.equal(bad.ok, false)
    assert.match(bad.reason ?? "", /different subject/)
  })

  it("refuses a bare-key witness — this plane is WebAuthn-only", () => {
    const receipt = makeReceipt({ sigAlg: "ES256" })
    const verdict = verifyPlatformReceipt(receipt, EXPECTED, OPTS)
    assert.equal(verdict.ok, false)
    assert.match(verdict.reason ?? "", /WebAuthn-only/)
  })

  it("refuses AUTO_APPROVED with no override", () => {
    const receipt = makeReceipt({ sigAlg: "AUTO_APPROVED" })
    const verdict = verifyPlatformReceipt(receipt, EXPECTED, OPTS)
    assert.equal(verdict.ok, false)
    assert.match(verdict.reason ?? "", /cannot be auto-approved/)
  })

  it("refuses a signature from an untrusted key", () => {
    const stranger = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
    const verdict = verifyPlatformReceipt(makeReceipt({ signWith: stranger }), EXPECTED, OPTS)
    assert.equal(verdict.ok, false)
  })

  it("fails closed on expiry, with an explicit audit override", () => {
    const canonical = canonicalPlatformIntentPayload({
      payloadHash: PAYLOAD_HASH,
      rpId: RP_ID,
      subjectExternalId: SUBJECT,
      signedAt: "2020-01-01T00:00:00.000Z",
      expiresAt: "2020-01-01T00:05:00.000Z",
      nonce: NONCE,
    })
    const receipt = makeReceipt({ canonical })
    assert.equal(verifyPlatformReceipt(receipt, EXPECTED, OPTS).ok, false)
    const audit = verifyPlatformReceipt(receipt, EXPECTED, { ...OPTS, allowExpired: true })
    assert.equal(audit.ok, true, audit.reason)
  })

  it("refuses a challenge frozen in the future", () => {
    const canonical = canonicalPlatformIntentPayload({
      payloadHash: PAYLOAD_HASH,
      rpId: RP_ID,
      subjectExternalId: SUBJECT,
      signedAt: "2998-01-01T00:00:00.000Z",
      expiresAt: FAR_FUTURE,
      nonce: NONCE,
    })
    const verdict = verifyPlatformReceipt(makeReceipt({ canonical }), EXPECTED, OPTS)
    assert.equal(verdict.ok, false)
    assert.match(verdict.reason ?? "", /signed in the future/)
  })

  it("refuses a conflicting rpId override — the RP ID is passed once", () => {
    const verdict = verifyPlatformReceipt(makeReceipt(), EXPECTED, {
      ...OPTS,
      expectedRpId: "other.example",
    })
    assert.equal(verdict.ok, false)
    assert.match(verdict.reason ?? "", /pass the RP ID once/)
  })

  it("each verifier refuses the other's payload kind, by name", () => {
    const platform = makeReceipt()
    const asApproval = verifyApprovalReceipt(
      {
        canonicalPayload: platform.canonicalPayload,
        actionDescription: "",
        params: {},
        verificationCode: "0000-0000",
        signerPublicKey: platform.signerPublicKey,
        signature: platform.signature,
        sigAlg: platform.sigAlg,
      },
      { approvers: EXPECTED.approvers, target: "t", actionType: "a", params: {}, nonce: NONCE },
    )
    assert.equal(asApproval.ok, false)
    assert.match(asApproval.reason ?? "", /verifyPlatformReceipt/)

    const intentish = verifyPlatformReceipt(
      { ...makeReceipt(), canonicalPayload: '{"type":"div-intent-verification","v":1}' },
      EXPECTED,
      OPTS,
    )
    assert.equal(intentish.ok, false)
    assert.match(intentish.reason ?? "", /verifyApprovalReceipt/)
  })
})
