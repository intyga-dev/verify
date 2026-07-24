import assert from "node:assert/strict"
import crypto from "node:crypto"
import { test } from "node:test"
import {
  type ApprovalReceipt,
  canonicalAuthorizationPayload,
  verificationCode,
  verifyApprovalReceipt,
} from "./index.ts"

// Build a genuinely-signed ES256 receipt the way the gateway would.
function es256Receipt(input: {
  actionType: string
  actionDescription: string
  params: Record<string, unknown>
}): { receipt: ApprovalReceipt; pubB64: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  })
  const pubB64 = publicKey.export({ format: "der", type: "spki" }).toString("base64")
  const canonical = canonicalAuthorizationPayload({
    nonce: "nonce-1",
    ...input,
  })
  const signature = crypto
    .sign("sha256", Buffer.from(canonical, "utf8"), {
      key: privateKey,
      dsaEncoding: "ieee-p1363",
    })
    .toString("base64")
  return {
    pubB64,
    receipt: {
      canonicalPayload: canonical,
      actionType: input.actionType,
      actionDescription: input.actionDescription,
      params: input.params,
      signerPublicKey: pubB64,
      signature,
      sigAlg: "ES256",
      verificationCode: verificationCode(canonical),
    },
  }
}

/** The action half of an expectation — spread into the receipt builders, which add the nonce. */
const ACTION = {
  actionType: "wipe_production",
  params: { target: "prod-db-1", region: "eu-north-1" },
}
/** Full expectation for receipts built with nonce "nonce-1" (es256Receipt / webauthnReceipt). */
const EXPECTED = { ...ACTION, nonce: "nonce-1" }
/** Full expectation for the hand-built receipts below, which use nonce "n". */
const EXPECTED_N = { ...ACTION, nonce: "n" }

/** WebAuthn pinning the test authenticator answers for. */
const RP_ID = "wallet.example"
const ORIGIN = "https://wallet.example"
const WEBAUTHN_OPTS = { expectedOrigin: ORIGIN, expectedRpId: RP_ID }

test("verifies a genuine ES256 approval receipt", () => {
  const { receipt } = es256Receipt({
    actionDescription: "Wipe production database",
    ...ACTION,
  })
  assert.deepEqual(verifyApprovalReceipt(receipt, EXPECTED), { ok: true })
})

test("rejects when params differ from what was approved", () => {
  const { receipt } = es256Receipt({
    actionDescription: "Wipe production database",
    ...ACTION,
  })
  const r = verifyApprovalReceipt(receipt, {
    actionType: "wipe_production",
    params: { target: "prod-db-2", region: "eu-north-1" },
    nonce: "nonce-1",
  })
  assert.equal(r.ok, false)
  assert.match(r.reason!, /do not match/)
})

test("rejects when actionType differs", () => {
  const { receipt } = es256Receipt({
    actionDescription: "Wipe production database",
    ...ACTION,
  })
  const r = verifyApprovalReceipt(receipt, {
    actionType: "read_only_report",
    params: ACTION.params,
    nonce: "nonce-1",
  })
  assert.equal(r.ok, false)
})

test("rejects a receipt issued for a different challenge nonce", () => {
  const { receipt } = es256Receipt({ actionDescription: "Wipe production database", ...ACTION })
  const r = verifyApprovalReceipt(receipt, { ...ACTION, nonce: "some-other-nonce" })
  assert.equal(r.ok, false)
  assert.match(r.reason!, /different challenge/)
})

test("rejects a signature from a different key", () => {
  const { receipt } = es256Receipt({
    actionDescription: "Wipe production database",
    ...ACTION,
  })
  const other = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  receipt.signerPublicKey = other.publicKey.export({ format: "der", type: "spki" }).toString("base64")
  const r = verifyApprovalReceipt(receipt, EXPECTED)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /does not verify/)
})

test("AUTO_APPROVED is REFUSED by default (no human signature to verify), accepted only on opt-in", () => {
  const canonical = canonicalAuthorizationPayload({
    nonce: "n",
    actionDescription: "deploy",
    ...ACTION,
  })
  const receipt: ApprovalReceipt = {
    canonicalPayload: canonical,
    actionDescription: "deploy",
    params: ACTION.params,
    sigAlg: "AUTO_APPROVED",
    verificationCode: verificationCode(canonical),
  }
  const denied = verifyApprovalReceipt(receipt, EXPECTED_N)
  assert.equal(denied.ok, false)
  assert.equal(denied.autoApproved, true)

  const allowed = verifyApprovalReceipt(receipt, EXPECTED_N, {
    allowAutoApproved: true,
  })
  assert.deepEqual(allowed, { ok: true, autoApproved: true })
})

test("rejects a receipt missing signature material", () => {
  const canonical = canonicalAuthorizationPayload({
    nonce: "n",
    actionDescription: "deploy",
    ...ACTION,
  })
  const receipt: ApprovalReceipt = {
    canonicalPayload: canonical,
    actionDescription: "deploy",
    params: ACTION.params,
    sigAlg: "ES256",
    verificationCode: verificationCode(canonical),
  }
  assert.equal(verifyApprovalReceipt(receipt, EXPECTED_N).ok, false)
})

// ─── WebAuthn / COSE ─────────────────────────────────────────────────────────

/** CBOR head byte(s) for a given major type and length/value (only the short forms COSE_Key needs). */
function cborHead(major: number, value: number): Buffer {
  if (value < 24) return Buffer.from([(major << 5) | value])
  if (value < 0x100) return Buffer.from([(major << 5) | 24, value])
  return Buffer.from([(major << 5) | 25, value >> 8, value & 0xff])
}
const cborUint = (n: number) => cborHead(0, n)
const cborNint = (n: number) => cborHead(1, -1 - n) // -1 → 0x20, -2 → 0x21, -3 → 0x22
const cborBytes = (b: Buffer) => Buffer.concat([cborHead(2, b.length), b])

/** Encode an EC2 COSE_Key. Overrides let a test bend one field at a time. */
function coseKey(
  x: Buffer,
  y: Buffer,
  over: { kty?: number; alg?: number; crv?: number; extra?: Buffer } = {},
): Buffer {
  const entries = [
    Buffer.concat([cborUint(1), cborUint(over.kty ?? 2)]), // kty: EC2
    Buffer.concat([cborUint(3), cborNint(over.alg ?? -7)]), // alg: ES256
    Buffer.concat([cborNint(-1), cborUint(over.crv ?? 1)]), // crv: P-256
  ]
  // `extra` goes BEFORE the coordinates on purpose: a decoy is only a real test of the parser if a
  // naive forward byte-scan would hit it first.
  if (over.extra) entries.push(over.extra)
  entries.push(Buffer.concat([cborNint(-2), cborBytes(x)]), Buffer.concat([cborNint(-3), cborBytes(y)]))
  return Buffer.concat([cborHead(5, entries.length), ...entries])
}

const FLAG_UP = 0x01
const FLAG_UV = 0x04

/**
 * Build REAL authenticatorData: SHA-256(rpId) ‖ flags ‖ signCount. Random bytes would leave the
 * rpIdHash and the presence/verification flags unconstrained, which is exactly the bug these tests
 * now guard — the verifier must reject an assertion made for another RP or without user verification.
 */
function authData(over: { rpId?: string; flags?: number; signCount?: number } = {}): Buffer {
  const rpIdHash = crypto
    .createHash("sha256")
    .update(over.rpId ?? RP_ID, "utf8")
    .digest()
  const rest = Buffer.alloc(5)
  rest.writeUInt8(over.flags ?? FLAG_UP | FLAG_UV, 0)
  rest.writeUInt32BE(over.signCount ?? 1, 1)
  return Buffer.concat([rpIdHash, rest])
}

/** A genuinely-signed WebAuthn receipt, built the way an authenticator + the gateway would. */
function webauthnReceipt(
  input: { actionType: string; actionDescription: string; params: Record<string, unknown> },
  mutateCose?: (x: Buffer, y: Buffer) => Buffer,
  over: { authenticatorData?: Buffer; type?: string; origin?: string } = {},
): ApprovalReceipt {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string }
  const x = Buffer.from(jwk.x, "base64url")
  const y = Buffer.from(jwk.y, "base64url")

  const canonical = canonicalAuthorizationPayload({ nonce: "nonce-1", ...input })
  // The authenticator signs authenticatorData || SHA-256(clientDataJSON); the challenge is the payload.
  const clientDataJSON = Buffer.from(
    JSON.stringify({
      type: over.type ?? "webauthn.get",
      challenge: Buffer.from(canonical, "utf-8").toString("base64url"),
      origin: over.origin ?? ORIGIN,
    }),
    "utf-8",
  )
  const authenticatorData = over.authenticatorData ?? authData()
  const signature = crypto.sign(
    "sha256",
    Buffer.concat([authenticatorData, crypto.createHash("sha256").update(clientDataJSON).digest()]),
    { key: privateKey, dsaEncoding: "der" },
  )

  return {
    canonicalPayload: canonical,
    actionType: input.actionType,
    actionDescription: input.actionDescription,
    params: input.params,
    signerPublicKey: (mutateCose ? mutateCose(x, y) : coseKey(x, y)).toString("base64"),
    signature: signature.toString("base64"),
    sigAlg: "WEBAUTHN",
    authenticatorData: authenticatorData.toString("base64"),
    clientDataJSON: clientDataJSON.toString("base64"),
    verificationCode: verificationCode(canonical),
  }
}

const WEBAUTHN_INPUT = { actionDescription: "Wipe production database", ...ACTION }

test("verifies a genuine WebAuthn receipt end to end", () => {
  const receipt = webauthnReceipt(WEBAUTHN_INPUT)
  assert.deepEqual(verifyApprovalReceipt(receipt, EXPECTED, WEBAUTHN_OPTS), { ok: true })
})

test("WebAuthn verification tolerates trailing bytes after the COSE key", () => {
  // Some wallets slice the COSE key out of attestedCredentialData without trimming what follows.
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, (x, y) =>
    Buffer.concat([coseKey(x, y), crypto.randomBytes(16)]),
  )
  assert.equal(verifyApprovalReceipt(receipt, EXPECTED, WEBAUTHN_OPTS).ok, true)
})

test("WebAuthn verification is not fooled by coordinate byte patterns inside another field", () => {
  // 0x21 0x58 0x20 is what the old scanning parser searched for. Planting it inside an unrelated
  // byte-string value must not be mistaken for the real x coordinate.
  const decoy = Buffer.concat([
    Buffer.from([0x18, 0x63]), // label 99
    cborBytes(Buffer.concat([Buffer.from([0x21, 0x58, 0x20]), crypto.randomBytes(32)])),
  ])
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, (x, y) => coseKey(x, y, { extra: decoy }))
  assert.equal(verifyApprovalReceipt(receipt, EXPECTED, WEBAUTHN_OPTS).ok, true)
})

test("WebAuthn rejects a COSE key with a short coordinate rather than silently truncating", () => {
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, (x, y) => coseKey(x.subarray(0, 31), y))
  const r = verifyApprovalReceipt(receipt, EXPECTED, WEBAUTHN_OPTS)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /must be 32 bytes/)
})

test("WebAuthn rejects a truncated COSE key", () => {
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, (x, y) => {
    const full = coseKey(x, y)
    return full.subarray(0, full.length - 10)
  })
  const r = verifyApprovalReceipt(receipt, EXPECTED, WEBAUTHN_OPTS)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /truncated/)
})

test("WebAuthn rejects a COSE key pinned to another curve or key type", () => {
  const wrongCrv = verifyApprovalReceipt(
    webauthnReceipt(WEBAUTHN_INPUT, (x, y) => coseKey(x, y, { crv: 2 })),
    EXPECTED,
    WEBAUTHN_OPTS,
  )
  assert.equal(wrongCrv.ok, false)
  assert.match(wrongCrv.reason!, /crv P-256/)

  const wrongKty = verifyApprovalReceipt(
    webauthnReceipt(WEBAUTHN_INPUT, (x, y) => coseKey(x, y, { kty: 1 })),
    EXPECTED,
    WEBAUTHN_OPTS,
  )
  assert.equal(wrongKty.ok, false)
  assert.match(wrongKty.reason!, /kty EC2/)
})

test("WebAuthn rejects a signature made by a different key", () => {
  const other = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const jwk = other.publicKey.export({ format: "jwk" }) as { x: string; y: string }
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, () =>
    coseKey(Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")),
  )
  const r = verifyApprovalReceipt(receipt, EXPECTED, WEBAUTHN_OPTS)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /does not verify/)
})

test("WebAuthn rejects a clientDataJSON challenge that is not the canonical payload", () => {
  const receipt = webauthnReceipt(WEBAUTHN_INPUT)
  receipt.clientDataJSON = Buffer.from(
    JSON.stringify({ type: "webauthn.get", challenge: "c29tZXRoaW5nLWVsc2U", origin: ORIGIN }),
    "utf-8",
  ).toString("base64")
  const r = verifyApprovalReceipt(receipt, EXPECTED, WEBAUTHN_OPTS)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /challenge does not match/)
})

test("WebAuthn receipt missing assertion components is rejected", () => {
  const canonical = canonicalAuthorizationPayload({
    nonce: "n",
    actionDescription: "deploy",
    ...ACTION,
  })
  const receipt: ApprovalReceipt = {
    canonicalPayload: canonical,
    actionDescription: "deploy",
    params: ACTION.params,
    signerPublicKey: "AAAA",
    signature: "BBBB",
    sigAlg: "WEBAUTHN",
    verificationCode: verificationCode(canonical),
  }
  const r = verifyApprovalReceipt(receipt, EXPECTED_N, WEBAUTHN_OPTS)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /authenticatorData or clientDataJSON/)
})

// ─── WebAuthn assertion binding (origin / RP ID / user verification) ──────────
// authenticatorData is signed but used to be accepted unread, so an assertion produced at ANY relying
// party — or without the user ever touching the authenticator — verified. These pin it down.

test("WebAuthn refuses to verify without expectedOrigin / expectedRpId", () => {
  const receipt = webauthnReceipt(WEBAUTHN_INPUT)
  const r = verifyApprovalReceipt(receipt, EXPECTED)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /expectedOrigin and expectedRpId/)

  const missingRpId = verifyApprovalReceipt(receipt, EXPECTED, { expectedOrigin: ORIGIN })
  assert.equal(missingRpId.ok, false)
})

test("WebAuthn rejects an assertion made for a different RP ID", () => {
  // A genuine, correctly-signed assertion — but the authenticator answered for attacker.example.
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, undefined, {
    authenticatorData: authData({ rpId: "attacker.example" }),
  })
  const r = verifyApprovalReceipt(receipt, EXPECTED, WEBAUTHN_OPTS)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /rpIdHash does not match/)
})

test("WebAuthn rejects an assertion collected at a different origin", () => {
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, undefined, { origin: "https://attacker.example" })
  const r = verifyApprovalReceipt(receipt, EXPECTED, WEBAUTHN_OPTS)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /origin does not match/)
})

test("WebAuthn rejects a registration (webauthn.create) presented as an approval", () => {
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, undefined, { type: "webauthn.create" })
  const r = verifyApprovalReceipt(receipt, EXPECTED, WEBAUTHN_OPTS)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /not a webauthn\.get/)
})

test("WebAuthn rejects an assertion with the user-present flag clear", () => {
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, undefined, {
    authenticatorData: authData({ flags: FLAG_UV }),
  })
  const r = verifyApprovalReceipt(receipt, EXPECTED, WEBAUTHN_OPTS)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /user-present/)
})

test("WebAuthn requires user verification by default, and can be opted out of explicitly", () => {
  // UP set, UV clear: mere possession, no biometric/PIN. The gateway demands UV, so the offline
  // verifier must too — otherwise verifying yourself is weaker than trusting the gateway.
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, undefined, {
    authenticatorData: authData({ flags: FLAG_UP }),
  })
  const strict = verifyApprovalReceipt(receipt, EXPECTED, WEBAUTHN_OPTS)
  assert.equal(strict.ok, false)
  assert.match(strict.reason!, /user-verified/)

  const relaxed = verifyApprovalReceipt(receipt, EXPECTED, {
    ...WEBAUTHN_OPTS,
    requireUserVerification: false,
  })
  assert.equal(relaxed.ok, true)
})

test("WebAuthn rejects authenticatorData shorter than the fixed 37-byte header", () => {
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, undefined, {
    authenticatorData: authData().subarray(0, 20),
  })
  const r = verifyApprovalReceipt(receipt, EXPECTED, WEBAUTHN_OPTS)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /too short/)
})

// ─── Key-type pinning (ES256 must mean P-256 + SHA-256) ──────────────────────

test("ES256 verification rejects a non-EC key even when the signature is valid for it", () => {
  // An RSA keypair signs the canonical payload correctly. createPublicKey accepts the SPKI and
  // crypto.verify would happily verify under RSA — but the receipt claims ES256, so it must fail.
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
  const canonical = canonicalAuthorizationPayload({ nonce: "n", actionDescription: "deploy", ...ACTION })
  const receipt: ApprovalReceipt = {
    canonicalPayload: canonical,
    actionDescription: "deploy",
    params: ACTION.params,
    signerPublicKey: publicKey.export({ format: "der", type: "spki" }).toString("base64"),
    signature: crypto.sign("sha256", Buffer.from(canonical, "utf8"), privateKey).toString("base64"),
    sigAlg: "ES256",
    verificationCode: verificationCode(canonical),
  }
  const r = verifyApprovalReceipt(receipt, EXPECTED_N)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /does not verify/)
})

test("ES256 verification rejects an EC key on a curve other than P-256", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" })
  const canonical = canonicalAuthorizationPayload({ nonce: "n", actionDescription: "deploy", ...ACTION })
  const receipt: ApprovalReceipt = {
    canonicalPayload: canonical,
    actionDescription: "deploy",
    params: ACTION.params,
    signerPublicKey: publicKey.export({ format: "der", type: "spki" }).toString("base64"),
    signature: crypto
      .sign("sha256", Buffer.from(canonical, "utf8"), { key: privateKey, dsaEncoding: "der" })
      .toString("base64"),
    sigAlg: "ES256",
    verificationCode: verificationCode(canonical),
  }
  const r = verifyApprovalReceipt(receipt, EXPECTED_N)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /does not verify/)
})

test("ES256 accepts both DER and raw IEEE-P1363 signatures over the same payload", () => {
  // The wallet may emit either encoding (WebCrypto/Expo produce raw r||s; node:crypto defaults to
  // DER). The verifier tries both rather than inferring from length: a DER signature is USUALLY 70-72
  // bytes but can in principle be 64 — the same length as raw r||s — so length is not a discriminator.
  // (That collision needs r and s to shed three leading zero bytes each, ~2^-48, so it is not
  // reachable in a test; trying both encodings is what makes the distinction moot.)
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const pubB64 = publicKey.export({ format: "der", type: "spki" }).toString("base64")
  const canonical = canonicalAuthorizationPayload({ nonce: "n", actionDescription: "deploy", ...ACTION })

  const receiptWith = (signature: Buffer): ApprovalReceipt => ({
    canonicalPayload: canonical,
    actionDescription: "deploy",
    params: ACTION.params,
    signerPublicKey: pubB64,
    signature: signature.toString("base64"),
    sigAlg: "ES256",
    verificationCode: verificationCode(canonical),
  })
  const data = Buffer.from(canonical, "utf8")
  const der = crypto.sign("sha256", data, { key: privateKey, dsaEncoding: "der" })
  const p1363 = crypto.sign("sha256", data, { key: privateKey, dsaEncoding: "ieee-p1363" })
  assert.equal(p1363.length, 64)

  assert.equal(verifyApprovalReceipt(receiptWith(der), EXPECTED_N).ok, true)
  assert.equal(verifyApprovalReceipt(receiptWith(p1363), EXPECTED_N).ok, true)
})
