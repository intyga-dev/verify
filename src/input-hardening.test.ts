// Input hardening from the 2026-09-27 review (L15-L19, I7, I8). Cross-language verdicts are pinned by
// the `verifierInputHardening` parity vectors; these cover the TS-only surface and the edge shapes a
// fixture file cannot carry (a raw lone surrogate is not I-JSON, so no vector file can hold one).

import assert from "node:assert/strict"
import crypto from "node:crypto"
import { describe, it } from "node:test"
import {
  type ApprovalReceipt,
  agentReceiptDigest,
  canonicalIntentPayload,
  NonCanonicalValue,
  stableStringify,
  verificationCode,
  verifyApprovalReceipt,
  verifyWebAuthnWitness,
} from "./index.ts"
import { type SignedAnchor, anchorDigest, verifyAnchorSignature } from "./ledger-anchor.ts"

const pair = () => crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
const spki = (k: crypto.KeyObject) => k.export({ format: "der", type: "spki" }).toString("base64")

describe("L17: canonicalization refuses unpaired surrogates", () => {
  it("refuses a lone high or low surrogate in a value or a member name", () => {
    for (const bad of ["\ud800", "a\udc00b", "\udbff", "x\ud83d"]) {
      assert.throws(() => stableStringify({ k: bad }), NonCanonicalValue, JSON.stringify(bad))
      assert.throws(() => stableStringify({ [bad]: 1 }), NonCanonicalValue)
      assert.throws(() => stableStringify([bad]), NonCanonicalValue)
    }
  })
  it("leaves valid text, including astral characters, byte-identical to before", () => {
    const value = { emoji: "😀", plain: "Wire USD 4,200", nested: ["é", " "] }
    assert.equal(
      stableStringify(value),
      JSON.stringify({ emoji: "😀", nested: ["é", " "], plain: "Wire USD 4,200" }),
    )
  })
})

describe("L19: malformed inputs refuse instead of throwing", () => {
  const signer = pair()
  const requester = { did: "did:intyga:agent:1", attestation: null }
  const canonical = canonicalIntentPayload({
    target: "t",
    actionType: "a",
    display: "d",
    params: {},
    requester,
    requirement: {
      requiredApprovals: 1,
      requireHardwareKey: false,
      allowedAaguids: [],
      requesterCannotApprove: false,
      signerClass: "human",
    },
    nonce: "n",
    expiresAt: "2999-01-01T00:00:00.000Z",
  })
  const receipt: ApprovalReceipt = {
    canonicalPayload: canonical,
    target: "t",
    actionType: "a",
    actionDescription: "d",
    params: {},
    requester,
    signerDid: "did:intyga:alice",
    signerPublicKey: spki(signer.publicKey),
    signature: crypto
      .sign("sha256", Buffer.from(canonical), { key: signer.privateKey, dsaEncoding: "ieee-p1363" })
      .toString("base64"),
    sigAlg: "ES256",
    verificationCode: verificationCode(canonical),
  }
  const expected = { target: "t", actionType: "a", params: {}, nonce: "n" }
  it("an empty trust anchor is a refusal", () => {
    const r = verifyApprovalReceipt(receipt, { ...expected, approvers: {} as never })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /trust anchor must be/)
  })
  it("a non-array publicKeys is a refusal", () => {
    const r = verifyApprovalReceipt(receipt, { ...expected, approvers: { publicKeys: "k" } as never })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /publicKeys must be an array/)
  })
  it("the well-formed anchor still verifies", () => {
    assert.equal(
      verifyApprovalReceipt(receipt, { ...expected, approvers: { publicKeys: [spki(signer.publicKey)] } }).ok,
      true,
    )
  })
  it("agentReceiptDigest projects an absent signerPublicKey to null (DIV §4.3.6)", () => {
    const witness = { signerDid: "did:intyga:alice", signature: "c2ln", sigAlg: "ES256" }
    const without = { canonicalPayload: canonical, signatures: [witness] } as unknown as ApprovalReceipt
    const withNull = {
      canonicalPayload: canonical,
      signatures: [{ ...witness, signerPublicKey: null }],
    } as unknown as ApprovalReceipt
    assert.match(agentReceiptDigest(without), /^sha256:[0-9a-f]{64}$/)
    assert.equal(agentReceiptDigest(without), agentReceiptDigest(withNull))
  })
})

describe("L18: topOrigin differing from origin is refused like crossOrigin", () => {
  const key = pair()
  const RP = "app.example.com"
  const ORIGIN = "https://app.example.com"
  const witness = (extra: Record<string, unknown>) => {
    const signedPayload = '{"hello":"world"}'
    const client = Buffer.from(
      JSON.stringify({
        type: "webauthn.get",
        challenge: Buffer.from(signedPayload).toString("base64url"),
        origin: ORIGIN,
        ...extra,
      }),
    )
    const auth = Buffer.concat([
      crypto.createHash("sha256").update(RP).digest(),
      Buffer.from([0x05, 0, 0, 0, 1]),
    ])
    const signature = crypto.sign(
      "sha256",
      Buffer.concat([auth, crypto.createHash("sha256").update(client).digest()]),
      { key: key.privateKey, dsaEncoding: "der" },
    )
    return {
      signedPayload,
      publicKey: spki(key.publicKey),
      authenticatorData: auth.toString("base64url"),
      clientDataJSON: client.toString("base64url"),
      signature: signature.toString("base64url"),
    }
  }
  const expect = { expectedOrigin: ORIGIN, expectedRpId: RP }
  it("accepts an absent or matching topOrigin", () => {
    assert.equal(verifyWebAuthnWitness(witness({}), expect).ok, true)
    assert.equal(verifyWebAuthnWitness(witness({ topOrigin: ORIGIN }), expect).ok, true)
  })
  it("refuses a differing topOrigin unless the caller opts into cross-origin frames", () => {
    const embedded = witness({ topOrigin: "https://embedder.example" })
    const r = verifyWebAuthnWitness(embedded, expect)
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /topOrigin/)
    assert.equal(verifyWebAuthnWitness(embedded, { ...expect, allowCrossOrigin: true }).ok, true)
  })
})

describe("I8: RSA-PSS anchor profile", () => {
  const base = {
    dailyRoot: "a".repeat(64),
    timestamp: "2026-09-01T00:00:00.000Z",
    issuer: "https://rsa.example",
    algorithm: "RSA-PSS" as const,
    seqStart: "1",
    seqEnd: "1",
    chainHash: "b".repeat(64),
    keyId: "r",
  }
  const signed = (bits: number, saltLength: number) => {
    const k = crypto.generateKeyPairSync("rsa", { modulusLength: bits })
    const signature = crypto
      .sign("sha256", anchorDigest(base), {
        key: k.privateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength,
      })
      .toString("base64")
    return { anchor: { ...base, signature } as SignedAnchor, key: k.publicKey }
  }
  it("accepts SHA-256 with a 32-byte salt under a 2048-bit key", () => {
    const { anchor, key } = signed(2048, 32)
    assert.equal(verifyAnchorSignature(anchor, key), true)
  })
  it("refuses any other salt length", () => {
    for (const salt of [0, 20, 64, crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN]) {
      const { anchor, key } = signed(2048, salt)
      assert.equal(verifyAnchorSignature(anchor, key), false, `salt ${salt}`)
    }
  })
  it("refuses a modulus below 2048 bits", () => {
    const { anchor, key } = signed(1024, 32)
    assert.equal(verifyAnchorSignature(anchor, key), false)
  })
})
