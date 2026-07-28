import assert from "node:assert/strict"
import crypto from "node:crypto"
import { test } from "node:test"
import {
  type ApprovalReceipt,
  canonicalIntentPayload,
  type RequesterIdentity,
  verificationCode,
  verifyApprovalReceipt,
} from "./index.ts"

/** Shared DIV fixtures. `target` and `requester` are bound into every signed payload. */
const TARGET = "prod-db-cluster-01"
const REQUESTER: RequesterIdentity = { did: "did:intyga:agent-1", attestation: null }
/** Far-future expiry so the fail-closed expiry check (DIV §5.8) passes without being time-dependent. */
const FAR_FUTURE = "2999-01-01T00:00:00.000Z"

/** The no-rule-matched DIV policy: single-sig, no hardware requirement, no four-eyes. */
const DEFAULT_REQUIREMENT = {
  requiredApprovals: 1,
  requireHardwareKey: false,
  allowedAaguids: [] as string[],
  requesterCannotApprove: false,
}

/**
 * ONE approver keypair for the whole suite, so the trust anchor can be a constant. Tests that need a
 * key the verifier does NOT trust generate their own locally — which is the point of the anchor.
 */
const APPROVER = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
const APPROVER_SPKI_B64 = APPROVER.publicKey.export({ format: "der", type: "spki" }).toString("base64")
const APPROVER_JWK = APPROVER.publicKey.export({ format: "jwk" }) as { x: string; y: string }

function divPayload(input: {
  actionType: string
  actionDescription: string
  params: Record<string, unknown>
  nonce: string
  expiresAt?: string
  requirement?: typeof DEFAULT_REQUIREMENT
}): string {
  return canonicalIntentPayload({
    target: TARGET,
    actionType: input.actionType,
    display: input.actionDescription,
    params: input.params,
    requester: REQUESTER,
    requirement: input.requirement ?? DEFAULT_REQUIREMENT,
    nonce: input.nonce,
    expiresAt: input.expiresAt ?? FAR_FUTURE,
  })
}

// Build a genuinely-signed ES256 receipt the way the gateway would.
function es256Receipt(input: {
  actionType: string
  actionDescription: string
  params: Record<string, unknown>
  nonce?: string
  expiresAt?: string
  requirement?: typeof DEFAULT_REQUIREMENT
}): { receipt: ApprovalReceipt; pubB64: string } {
  const privateKey = APPROVER.privateKey
  const pubB64 = APPROVER_SPKI_B64
  const canonical = divPayload({ nonce: input.nonce ?? "nonce-1", ...input })
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
      target: TARGET,
      actionType: input.actionType,
      actionDescription: input.actionDescription,
      params: input.params,
      requester: REQUESTER,
      signerPublicKey: pubB64,
      signature,
      sigAlg: "ES256",
      verificationCode: verificationCode(canonical),
    },
  }
}

/** The action half of an expectation — spread into the receipt builders, which add the nonce. */
const ACTION = {
  target: TARGET,
  actionType: "wipe_production",
  params: { host: "prod-db-1", region: "eu-north-1" },
}
/**
 * The approvers this suite trusts. Verification resolves keys from HERE, never from the receipt —
 * without it, a receipt bearing an attacker-minted keypair would verify against itself.
 */
const APPROVERS = { publicKeys: [APPROVER_SPKI_B64] }
/** Full expectation for receipts built with nonce "nonce-1" (es256Receipt / webauthnReceipt). */
const EXPECTED = { ...ACTION, nonce: "nonce-1", approvers: APPROVERS }
/** Full expectation for the hand-built receipts below, which use nonce "n". */
const EXPECTED_N = { ...ACTION, nonce: "n", approvers: APPROVERS }

/** WebAuthn pinning the test authenticator answers for. */
const RP_ID = "wallet.example"
const ORIGIN = "https://wallet.example"
const WEBAUTHN_OPTS = { expectedOrigin: ORIGIN, expectedRpId: RP_ID }

test("verifies a genuine ES256 approval receipt", () => {
  const { receipt } = es256Receipt({
    actionDescription: "Wipe production database",
    ...ACTION,
  })
  assert.equal(verifyApprovalReceipt(receipt, EXPECTED).ok, true)
})

test("rejects when params differ from what was approved", () => {
  const { receipt } = es256Receipt({
    actionDescription: "Wipe production database",
    ...ACTION,
  })
  const r = verifyApprovalReceipt(receipt, {
    target: TARGET,
    actionType: "wipe_production",
    params: { host: "prod-db-2", region: "eu-north-1" },
    nonce: "nonce-1",
    approvers: APPROVERS,
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
    target: TARGET,
    actionType: "read_only_report",
    params: ACTION.params,
    nonce: "nonce-1",
    approvers: APPROVERS,
  })
  assert.equal(r.ok, false)
})

test("rejects a receipt issued for a different challenge nonce", () => {
  const { receipt } = es256Receipt({ actionDescription: "Wipe production database", ...ACTION })
  const r = verifyApprovalReceipt(receipt, { ...ACTION, nonce: "some-other-nonce", approvers: APPROVERS })
  assert.equal(r.ok, false)
  assert.match(r.reason!, /different challenge/)
})

test("rejects a receipt signed by a key the relying party does not trust", () => {
  const { receipt } = es256Receipt({
    actionDescription: "Wipe production database",
    ...ACTION,
  })
  // Re-sign the very same canonical bytes with a key that is NOT in the trust anchor, and advertise
  // that key on the receipt. This is the attacker-minted-receipt case: internally consistent, and
  // still refused, because verification only ever uses a key the caller resolved itself.
  const other = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  receipt.signature = crypto
    .sign("sha256", Buffer.from(receipt.canonicalPayload, "utf8"), {
      key: other.privateKey,
      dsaEncoding: "ieee-p1363",
    })
    .toString("base64")
  receipt.signerPublicKey = other.publicKey.export({ format: "der", type: "spki" }).toString("base64")
  const r = verifyApprovalReceipt(receipt, EXPECTED)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /does not verify/)
})

test("AUTO_APPROVED is REFUSED by default (no human signature to verify), accepted only on opt-in", () => {
  const canonical = divPayload({ nonce: "n", actionDescription: "deploy", ...ACTION })
  const receipt: ApprovalReceipt = {
    canonicalPayload: canonical,
    target: TARGET,
    actionDescription: "deploy",
    params: ACTION.params,
    requester: REQUESTER,
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
  const canonical = divPayload({ nonce: "n", actionDescription: "deploy", ...ACTION })
  const receipt: ApprovalReceipt = {
    canonicalPayload: canonical,
    target: TARGET,
    actionDescription: "deploy",
    params: ACTION.params,
    requester: REQUESTER,
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
  over: {
    authenticatorData?: Buffer
    type?: string
    origin?: string
    crossOrigin?: boolean
    /** Sign with a key OTHER than the trusted approver (for negative tests). */
    signWith?: crypto.KeyPairKeyObjectResult
  } = {},
): ApprovalReceipt {
  const pair = over.signWith ?? APPROVER
  const privateKey = pair.privateKey
  const jwk = pair.publicKey.export({ format: "jwk" }) as { x: string; y: string }
  const x = Buffer.from(jwk.x, "base64url")
  const y = Buffer.from(jwk.y, "base64url")

  const canonical = divPayload({ nonce: "nonce-1", ...input })
  // The authenticator signs authenticatorData || SHA-256(clientDataJSON); the challenge is the payload.
  const clientDataJSON = Buffer.from(
    JSON.stringify({
      type: over.type ?? "webauthn.get",
      challenge: Buffer.from(canonical, "utf-8").toString("base64url"),
      origin: over.origin ?? ORIGIN,
      ...(over.crossOrigin === undefined ? {} : { crossOrigin: over.crossOrigin }),
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
    target: TARGET,
    actionType: input.actionType,
    actionDescription: input.actionDescription,
    params: input.params,
    requester: REQUESTER,
    signerPublicKey: (mutateCose ? mutateCose(x, y) : coseKey(x, y)).toString("base64"),
    signature: signature.toString("base64"),
    sigAlg: "WEBAUTHN",
    authenticatorData: authenticatorData.toString("base64"),
    clientDataJSON: clientDataJSON.toString("base64"),
    verificationCode: verificationCode(canonical),
  }
}

/**
 * WebAuthn witnesses present a COSE key, so the anchor must hold the COSE encoding of the SAME
 * approver key. Defined here rather than beside APPROVERS because coseKey's helpers are const arrows
 * and are not hoisted.
 */
const APPROVERS_COSE = {
  publicKeys: [
    coseKey(Buffer.from(APPROVER_JWK.x, "base64url"), Buffer.from(APPROVER_JWK.y, "base64url")).toString(
      "base64",
    ),
  ],
}
/** Expectation for the WebAuthn receipts below — same action, COSE-encoded trust anchor. */
const EXPECTED_WA = { ...ACTION, nonce: "nonce-1", approvers: APPROVERS_COSE }
/**
 * A WebAuthn expectation whose TRUST ANCHOR is the given COSE bytes. The COSE parser now runs over the
 * key the relying party trusts, not the one the receipt presents, so malformed-key tests belong here:
 * a bad key in the receipt is simply ignored, which is the whole point of the anchor.
 */
const waExpect = (cose: Buffer) => ({
  ...ACTION,
  nonce: "nonce-1",
  approvers: { publicKeys: [cose.toString("base64")] },
})
/** The trusted approver's coordinates, for building anchor keys in the tests below. */
const AX = Buffer.from(APPROVER_JWK.x, "base64url")
const AY = Buffer.from(APPROVER_JWK.y, "base64url")

const WEBAUTHN_INPUT = { actionDescription: "Wipe production database", ...ACTION }

test("verifies a genuine WebAuthn receipt end to end", () => {
  const receipt = webauthnReceipt(WEBAUTHN_INPUT)
  assert.equal(verifyApprovalReceipt(receipt, EXPECTED_WA, WEBAUTHN_OPTS).ok, true)
})

test("WebAuthn verification tolerates trailing bytes after the COSE key", () => {
  // Some wallets slice the COSE key out of attestedCredentialData without trimming what follows.
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, (x, y) =>
    Buffer.concat([coseKey(x, y), crypto.randomBytes(16)]),
  )
  assert.equal(verifyApprovalReceipt(receipt, EXPECTED_WA, WEBAUTHN_OPTS).ok, true)
})

test("WebAuthn verification is not fooled by coordinate byte patterns inside another field", () => {
  // 0x21 0x58 0x20 is what the old scanning parser searched for. Planting it inside an unrelated
  // byte-string value must not be mistaken for the real x coordinate.
  const decoy = Buffer.concat([
    Buffer.from([0x18, 0x63]), // label 99
    cborBytes(Buffer.concat([Buffer.from([0x21, 0x58, 0x20]), crypto.randomBytes(32)])),
  ])
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, (x, y) => coseKey(x, y, { extra: decoy }))
  assert.equal(verifyApprovalReceipt(receipt, EXPECTED_WA, WEBAUTHN_OPTS).ok, true)
})

test("WebAuthn rejects a COSE key with a short coordinate rather than silently truncating", () => {
  const receipt = webauthnReceipt(WEBAUTHN_INPUT)
  const r = verifyApprovalReceipt(receipt, waExpect(coseKey(AX.subarray(0, 31), AY)), WEBAUTHN_OPTS)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /must be 32 bytes/)
})

test("WebAuthn rejects a truncated COSE key", () => {
  const receipt = webauthnReceipt(WEBAUTHN_INPUT)
  const full = coseKey(AX, AY)
  const r = verifyApprovalReceipt(receipt, waExpect(full.subarray(0, full.length - 10)), WEBAUTHN_OPTS)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /truncated/)
})

test("WebAuthn rejects a COSE key pinned to another curve or key type", () => {
  const wrongCrv = verifyApprovalReceipt(
    webauthnReceipt(WEBAUTHN_INPUT),
    waExpect(coseKey(AX, AY, { crv: 2 })),
    WEBAUTHN_OPTS,
  )
  assert.equal(wrongCrv.ok, false)
  assert.match(wrongCrv.reason!, /crv P-256/)

  const wrongKty = verifyApprovalReceipt(
    webauthnReceipt(WEBAUTHN_INPUT),
    waExpect(coseKey(AX, AY, { kty: 1 })),
    WEBAUTHN_OPTS,
  )
  assert.equal(wrongKty.ok, false)
  assert.match(wrongKty.reason!, /kty EC2/)
})

test("WebAuthn rejects a signature made by a key the relying party does not trust", () => {
  // A genuine, well-formed assertion — just produced by a credential the relying party never
  // enrolled. The receipt advertises that key; verification ignores it and uses the anchor's.
  const other = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, undefined, { signWith: other })
  const r = verifyApprovalReceipt(receipt, EXPECTED_WA, WEBAUTHN_OPTS)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /does not verify/)
})

test("WebAuthn rejects a clientDataJSON challenge that is not the canonical payload", () => {
  const receipt = webauthnReceipt(WEBAUTHN_INPUT)
  receipt.clientDataJSON = Buffer.from(
    JSON.stringify({ type: "webauthn.get", challenge: "c29tZXRoaW5nLWVsc2U", origin: ORIGIN }),
    "utf-8",
  ).toString("base64")
  const r = verifyApprovalReceipt(receipt, EXPECTED_WA, WEBAUTHN_OPTS)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /challenge does not match/)
})

test("WebAuthn receipt missing assertion components is rejected", () => {
  const canonical = divPayload({ nonce: "n", actionDescription: "deploy", ...ACTION })
  const receipt: ApprovalReceipt = {
    canonicalPayload: canonical,
    target: TARGET,
    actionDescription: "deploy",
    params: ACTION.params,
    requester: REQUESTER,
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
  const r = verifyApprovalReceipt(receipt, EXPECTED_WA, WEBAUTHN_OPTS)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /rpIdHash does not match/)
})

test("WebAuthn rejects an assertion collected at a different origin", () => {
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, undefined, { origin: "https://attacker.example" })
  const r = verifyApprovalReceipt(receipt, EXPECTED_WA, WEBAUTHN_OPTS)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /origin does not match/)
})

test("WebAuthn rejects a registration (webauthn.create) presented as an approval", () => {
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, undefined, { type: "webauthn.create" })
  const r = verifyApprovalReceipt(receipt, EXPECTED_WA, WEBAUTHN_OPTS)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /not a webauthn\.get/)
})

test("WebAuthn rejects an assertion with the user-present flag clear", () => {
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, undefined, {
    authenticatorData: authData({ flags: FLAG_UV }),
  })
  const r = verifyApprovalReceipt(receipt, EXPECTED_WA, WEBAUTHN_OPTS)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /user-present/)
})

test("WebAuthn requires user verification by default, and can be opted out of explicitly", () => {
  // UP set, UV clear: mere possession, no biometric/PIN. The gateway demands UV, so the offline
  // verifier must too — otherwise verifying yourself is weaker than trusting the gateway.
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, undefined, {
    authenticatorData: authData({ flags: FLAG_UP }),
  })
  const strict = verifyApprovalReceipt(receipt, EXPECTED_WA, WEBAUTHN_OPTS)
  assert.equal(strict.ok, false)
  assert.match(strict.reason!, /user-verified/)

  const relaxed = verifyApprovalReceipt(receipt, EXPECTED_WA, {
    ...WEBAUTHN_OPTS,
    requireUserVerification: false,
  })
  assert.equal(relaxed.ok, true)
})

test("WebAuthn rejects authenticatorData shorter than the fixed 37-byte header", () => {
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, undefined, {
    authenticatorData: authData().subarray(0, 20),
  })
  const r = verifyApprovalReceipt(receipt, EXPECTED_WA, WEBAUTHN_OPTS)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /too short/)
})

// ─── Key-type pinning (ES256 must mean P-256 + SHA-256) ──────────────────────

test("ES256 verification rejects a non-EC key even when the signature is valid for it", () => {
  // An RSA keypair signs the canonical payload correctly. createPublicKey accepts the SPKI and
  // crypto.verify would happily verify under RSA — but the receipt claims ES256, so it must fail.
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
  const canonical = divPayload({ nonce: "n", actionDescription: "deploy", ...ACTION })
  const receipt: ApprovalReceipt = {
    canonicalPayload: canonical,
    target: TARGET,
    actionDescription: "deploy",
    params: ACTION.params,
    requester: REQUESTER,
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
  const canonical = divPayload({ nonce: "n", actionDescription: "deploy", ...ACTION })
  const receipt: ApprovalReceipt = {
    canonicalPayload: canonical,
    target: TARGET,
    actionDescription: "deploy",
    params: ACTION.params,
    requester: REQUESTER,
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
  const privateKey = APPROVER.privateKey
  const pubB64 = APPROVER_SPKI_B64
  const canonical = divPayload({ nonce: "n", actionDescription: "deploy", ...ACTION })

  const receiptWith = (signature: Buffer): ApprovalReceipt => ({
    canonicalPayload: canonical,
    target: TARGET,
    actionDescription: "deploy",
    params: ACTION.params,
    requester: REQUESTER,
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

// ─── Expiration (DIV §5.8/§6.2) ──────────────────────────────────────────────

test("rejects an expired proof by default (fail-closed), even with a valid signature", () => {
  const { receipt } = es256Receipt({
    actionDescription: "Wipe production database",
    ...ACTION,
    expiresAt: "2020-01-01T00:00:00.000Z",
  })
  const r = verifyApprovalReceipt(receipt, EXPECTED)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /expired/)
})

test("allowExpired accepts an otherwise-valid expired proof (audit re-verification)", () => {
  const { receipt } = es256Receipt({
    actionDescription: "Wipe production database",
    ...ACTION,
    expiresAt: "2020-01-01T00:00:00.000Z",
  })
  assert.equal(verifyApprovalReceipt(receipt, EXPECTED, { allowExpired: true }).ok, true)
})

test("asOf evaluates expiry at a chosen instant; skew tolerance is applied", () => {
  const expiresAt = "2026-07-24T12:00:00.000Z"
  const { receipt } = es256Receipt({ actionDescription: "Wipe production database", ...ACTION, expiresAt })
  // 20s past expiry is within the default ±30s skew → still valid.
  assert.equal(
    verifyApprovalReceipt(receipt, EXPECTED, { asOf: new Date("2026-07-24T12:00:20.000Z") }).ok,
    true,
  )
  // 40s past expiry is beyond the skew → rejected.
  assert.equal(
    verifyApprovalReceipt(receipt, EXPECTED, { asOf: new Date("2026-07-24T12:00:40.000Z") }).ok,
    false,
  )
})

test("rejects a proof whose target differs from the relying party's own (Target Isolation)", () => {
  const { receipt } = es256Receipt({ actionDescription: "Wipe production database", ...ACTION })
  const r = verifyApprovalReceipt(receipt, { ...EXPECTED, target: "some-other-service" })
  assert.equal(r.ok, false)
  assert.match(r.reason!, /do not match/)
})

// A plain-JS caller can omit `target` despite the TS signature. Falling back to the receipt's own
// target would let the receipt define the scope it is checked against, so a proof minted for another
// service would sail through — the exact replay Target Isolation exists to prevent.
test("fails closed when the relying party supplies no target at all", () => {
  const { receipt } = es256Receipt({ actionDescription: "Wipe production database", ...ACTION })
  for (const missing of [undefined, ""]) {
    const r = verifyApprovalReceipt(receipt, {
      ...EXPECTED,
      target: missing as unknown as string,
    })
    assert.equal(r.ok, false)
    assert.match(r.reason!, /expected\.target is required/)
  }
})

// ─── Trust anchor, quorum, and frame binding ─────────────────────────────────
// These are the regression tests for the July 2026 review. Before it, verification used the public
// key carried INSIDE the receipt, which proved only that the receipt was internally consistent.

test("REFUSES a fully attacker-minted receipt (the receipt cannot vouch for its own signer)", () => {
  // The whole forgery, end to end: an untrusted party mints a keypair, builds the canonical payload
  // over the nonce the relying party issued and the params it is about to run, signs it, and names
  // itself whatever it likes. Every internal check passes — the signature really does verify against
  // the key in the receipt. Only the trust anchor stops it.
  const attacker = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const canonical = divPayload({ nonce: "nonce-1", actionDescription: "Wipe production database", ...ACTION })
  const forged: ApprovalReceipt = {
    canonicalPayload: canonical,
    target: TARGET,
    actionType: ACTION.actionType,
    actionDescription: "Wipe production database",
    params: ACTION.params,
    requester: REQUESTER,
    signerDid: "did:intyga:cfo-alice",
    signerPublicKey: attacker.publicKey.export({ format: "der", type: "spki" }).toString("base64"),
    signature: crypto
      .sign("sha256", Buffer.from(canonical, "utf8"), {
        key: attacker.privateKey,
        dsaEncoding: "ieee-p1363",
      })
      .toString("base64"),
    sigAlg: "ES256",
    verificationCode: verificationCode(canonical),
  }
  const r = verifyApprovalReceipt(forged, EXPECTED)
  assert.equal(r.ok, false, "an attacker-minted receipt must never verify")
  assert.match(r.reason!, /does not verify/)
})

test("DID-mode anchor refuses a signer outside the allowlist, and a DID whose key does not match", () => {
  const { receipt } = es256Receipt({ actionDescription: "Wipe production database", ...ACTION })
  receipt.signerDid = "did:intyga:cfo-alice"

  const notListed = verifyApprovalReceipt(receipt, {
    ...ACTION,
    nonce: "nonce-1",
    approvers: { dids: ["did:intyga:someone-else"], resolveKey: () => APPROVER_SPKI_B64 },
  })
  assert.equal(notListed.ok, false)
  assert.match(notListed.reason!, /not an authorized approver/)

  // Listed, but our directory hands back a DIFFERENT key than the one that actually signed.
  const other = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const wrongKey = verifyApprovalReceipt(receipt, {
    ...ACTION,
    nonce: "nonce-1",
    approvers: {
      dids: ["did:intyga:cfo-alice"],
      resolveKey: () => other.publicKey.export({ format: "der", type: "spki" }).toString("base64"),
    },
  })
  assert.equal(wrongKey.ok, false)

  const resolved = verifyApprovalReceipt(receipt, {
    ...ACTION,
    nonce: "nonce-1",
    approvers: { dids: ["did:intyga:cfo-alice"], resolveKey: () => APPROVER_SPKI_B64 },
  })
  assert.equal(resolved.ok, true)
  assert.deepEqual(resolved.signers, ["did:intyga:cfo-alice"])
})

/** Sign the same canonical payload with an extra approver keypair. */
function witnessFor(canonical: string, pair: crypto.KeyPairKeyObjectResult, did: string) {
  return {
    signerDid: did,
    signerPublicKey: pair.publicKey.export({ format: "der", type: "spki" }).toString("base64"),
    signature: crypto
      .sign("sha256", Buffer.from(canonical, "utf8"), { key: pair.privateKey, dsaEncoding: "ieee-p1363" })
      .toString("base64"),
    sigAlg: "ES256",
  }
}

test("enforces the quorum recorded in the signed payload", () => {
  const bob = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const carol = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const requirement = { ...DEFAULT_REQUIREMENT, requiredApprovals: 3 }
  const canonical = divPayload({
    nonce: "nonce-1",
    actionDescription: "Wipe production database",
    ...ACTION,
    requirement,
  })
  const base: ApprovalReceipt = {
    canonicalPayload: canonical,
    target: TARGET,
    actionType: ACTION.actionType,
    actionDescription: "Wipe production database",
    params: ACTION.params,
    requester: REQUESTER,
    verificationCode: verificationCode(canonical),
  }
  const anchor = {
    dids: ["did:a", "did:b", "did:c"],
    resolveKey: (did: string) =>
      did === "did:a"
        ? APPROVER_SPKI_B64
        : did === "did:b"
          ? bob.publicKey.export({ format: "der", type: "spki" }).toString("base64")
          : carol.publicKey.export({ format: "der", type: "spki" }).toString("base64"),
  }
  const expectation = { ...ACTION, nonce: "nonce-1", approvers: anchor }

  // Two of three: refused, and the reason names the shortfall rather than blaming the signature.
  const short = verifyApprovalReceipt(
    { ...base, signatures: [witnessFor(canonical, APPROVER, "did:a"), witnessFor(canonical, bob, "did:b")] },
    expectation,
  )
  assert.equal(short.ok, false)
  assert.match(short.reason!, /quorum not met: 2 of 3/)

  const met = verifyApprovalReceipt(
    {
      ...base,
      signatures: [
        witnessFor(canonical, APPROVER, "did:a"),
        witnessFor(canonical, bob, "did:b"),
        witnessFor(canonical, carol, "did:c"),
      ],
    },
    expectation,
  )
  assert.equal(met.ok, true)
  assert.equal(met.signers!.length, 3)
})

test("one approver cannot fill a quorum by signing three times", () => {
  const requirement = { ...DEFAULT_REQUIREMENT, requiredApprovals: 3 }
  const canonical = divPayload({
    nonce: "nonce-1",
    actionDescription: "Wipe production database",
    ...ACTION,
    requirement,
  })
  const one = witnessFor(canonical, APPROVER, "did:a")
  const r = verifyApprovalReceipt(
    {
      canonicalPayload: canonical,
      target: TARGET,
      actionType: ACTION.actionType,
      actionDescription: "Wipe production database",
      params: ACTION.params,
      requester: REQUESTER,
      verificationCode: verificationCode(canonical),
      signatures: [one, one, one],
    },
    {
      ...ACTION,
      nonce: "nonce-1",
      approvers: { dids: ["did:a"], resolveKey: () => APPROVER_SPKI_B64 },
    },
  )
  assert.equal(r.ok, false, "duplicate signatures must count once")
  assert.match(r.reason!, /quorum not met: 1 of 3/)
})

test("enforces four-eyes offline when the signed policy demands it", () => {
  const requirement = { ...DEFAULT_REQUIREMENT, requesterCannotApprove: true }
  const canonical = divPayload({
    nonce: "nonce-1",
    actionDescription: "Wipe production database",
    ...ACTION,
    requirement,
  })
  // The requester signs their own request. The gateway would refuse this; so must the offline verifier.
  const selfSigned = witnessFor(canonical, APPROVER, REQUESTER.did)
  const r = verifyApprovalReceipt(
    {
      canonicalPayload: canonical,
      target: TARGET,
      actionType: ACTION.actionType,
      actionDescription: "Wipe production database",
      params: ACTION.params,
      requester: REQUESTER,
      verificationCode: verificationCode(canonical),
      signatures: [selfSigned],
    },
    {
      ...ACTION,
      nonce: "nonce-1",
      approvers: { dids: [REQUESTER.did], resolveKey: () => APPROVER_SPKI_B64 },
    },
  )
  assert.equal(r.ok, false)
  assert.match(r.reason!, /four-eyes/)
})

test("a bare P-256 key cannot satisfy a signed hardware-key policy", () => {
  const requirement = { ...DEFAULT_REQUIREMENT, requireHardwareKey: true }
  const { receipt } = es256Receipt({
    actionDescription: "Wipe production database",
    ...ACTION,
    requirement,
  })
  const r = verifyApprovalReceipt(receipt, EXPECTED)
  assert.equal(r.ok, false)
  assert.match(r.reason!, /hardware-backed/)
})

test("refuses an assertion produced in a cross-origin frame unless opted in", () => {
  // origin and rpIdHash both match here: an embedded RP frame reports the RP's own origin, so
  // crossOrigin is the only thing separating "approved on our page" from "approved inside someone
  // else's page".
  const receipt = webauthnReceipt(WEBAUTHN_INPUT, undefined, { crossOrigin: true })
  const strict = verifyApprovalReceipt(receipt, EXPECTED_WA, WEBAUTHN_OPTS)
  assert.equal(strict.ok, false)
  assert.match(strict.reason!, /cross-origin/)

  const opted = verifyApprovalReceipt(receipt, EXPECTED_WA, { ...WEBAUTHN_OPTS, allowCrossOrigin: true })
  assert.equal(opted.ok, true)
})

test("reports a non-canonicalizable expected.params as such, not as a params mismatch", () => {
  const { receipt } = es256Receipt({ actionDescription: "Wipe production database", ...ACTION })
  const r = verifyApprovalReceipt(receipt, {
    ...EXPECTED,
    // A Date is the classic case: it used to canonicalize to {} and silently mismatch, sending the
    // caller hunting for a tampering that never happened.
    params: { host: "prod-db-1", when: new Date(0) } as unknown as Record<string, unknown>,
  })
  assert.equal(r.ok, false)
  assert.match(r.reason!, /not canonicalizable/)
})
