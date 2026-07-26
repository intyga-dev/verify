// @sakra-trust/verify — independently confirm that a human cryptographically approved EXACTLY the action
// you are about to run. Zero runtime dependencies (node:crypto only), no network, and NO SÄKRA secret:
// a relying party recomputes the canonical payload from its own params, checks it byte-matches what was
// signed, and verifies the human's P-256 / WebAuthn signature. This is the "inspect-it-yourself" trust
// artifact — the whole point is that you don't have to take SÄKRA's word for it.
//
// The canonicalization + hashing here MUST stay byte-for-byte identical to @sakra-trust/mcp-schemas and the
// mobile wallet, or signatures won't verify. Do not "tidy" the JSON shapes.

import crypto from "node:crypto"

/**
 * A DIV Proof Envelope — a verifiable proof of what the human approved, returned once a challenge is
 * APPROVED. `canonicalPayload` is the exact signed bytes (the DIV Intent Payload); the remaining
 * fields are the signature metadata needed to verify it, extended beyond DIV §4.4's raw-ES256 shape
 * with the WebAuthn assertion components so a passkey approval — the primary approver path — is
 * representable.
 */
export interface ApprovalReceipt {
  canonicalPayload: string // the exact bytes the human's key signed (the DIV Intent Payload)
  // The intended execution TARGET (DIV Target Isolation). Carried for display/telemetry only; the
  // Relying Party asserts its OWN target via expected.target and never trusts this copy.
  target?: string | null
  actionType?: string | null
  actionDescription: string // the DIV `display` field
  params: Record<string, unknown>
  signerDid?: string | null
  signerPublicKey?: string | null // base64 SPKI or base64 COSE public key
  signature?: string | null // base64 signature over canonicalPayload
  sigAlg?: string | null // "ES256" | "WEBAUTHN" | "AUTO_APPROVED"
  authenticatorData?: string | null // base64url (WEBAUTHN only)
  clientDataJSON?: string | null // base64url (WEBAUTHN only)
  // Who REQUESTED the action. Present here so a relying party can recompute the signed bytes and,
  // optionally, assert the requester via expected.requesterDid.
  requester?: RequesterIdentity | null
  verificationCode: string
}

function base64url(str: string | Buffer): string {
  const buf = typeof str === "string" ? Buffer.from(str, "utf-8") : str
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "")
}

// ─── Minimal CBOR reader (COSE_Key only) ─────────────────────────────────────
// Just enough CBOR to walk a COSE_Key map: ints, byte/text strings, arrays, maps. Deliberately NOT a
// general decoder and deliberately not a dependency — this package ships with zero runtime deps so a
// relying party can audit every byte of it. Anything outside that subset is rejected rather than guessed.

type CborValue = number | Buffer | string | CborValue[] | Map<CborValue, CborValue>

function cborFail(detail: string): never {
  throw new Error(`Invalid COSE public key format: ${detail}`)
}

function requireBytes(buf: Buffer, pos: number, len: number) {
  if (pos + len > buf.length) cborFail("truncated CBOR item")
}

function readHead(buf: Buffer, pos: number): { major: number; value: number; pos: number } {
  requireBytes(buf, pos, 1)
  const initial = buf.readUInt8(pos)
  const major = initial >> 5
  const info = initial & 0x1f
  let next = pos + 1
  let value: number
  if (info < 24) value = info
  else if (info === 24) {
    requireBytes(buf, next, 1)
    value = buf.readUInt8(next)
    next += 1
  } else if (info === 25) {
    requireBytes(buf, next, 2)
    value = buf.readUInt16BE(next)
    next += 2
  } else if (info === 26) {
    requireBytes(buf, next, 4)
    value = buf.readUInt32BE(next)
    next += 4
  } else {
    // 27 = 64-bit, 28-30 reserved, 31 = indefinite length. No COSE_Key needs any of them.
    cborFail("unsupported CBOR length encoding")
  }
  return { major, value, pos: next }
}

function decodeItem(buf: Buffer, pos: number): { value: CborValue; pos: number } {
  const head = readHead(buf, pos)
  switch (head.major) {
    case 0: // unsigned int
      return { value: head.value, pos: head.pos }
    case 1: // negative int — COSE labels like -1 (crv), -2 (x), -3 (y)
      return { value: -1 - head.value, pos: head.pos }
    case 2: // byte string
      requireBytes(buf, head.pos, head.value)
      return { value: buf.subarray(head.pos, head.pos + head.value), pos: head.pos + head.value }
    case 3: // text string
      requireBytes(buf, head.pos, head.value)
      return {
        value: buf.toString("utf-8", head.pos, head.pos + head.value),
        pos: head.pos + head.value,
      }
    case 4: {
      const items: CborValue[] = []
      let cursor = head.pos
      for (let i = 0; i < head.value; i++) {
        const item = decodeItem(buf, cursor)
        items.push(item.value)
        cursor = item.pos
      }
      return { value: items, pos: cursor }
    }
    case 5: {
      const map = new Map<CborValue, CborValue>()
      let cursor = head.pos
      for (let i = 0; i < head.value; i++) {
        const key = decodeItem(buf, cursor)
        const val = decodeItem(buf, key.pos)
        map.set(key.value, val.value)
        cursor = val.pos
      }
      return { value: map, pos: cursor }
    }
    default:
      return cborFail(`unsupported CBOR major type ${head.major}`)
  }
}

/**
 * Extract the P-256 coordinates from a WebAuthn COSE_Key. This walks the CBOR structure rather than
 * scanning for the `0x21 0x58 0x20` / `0x22 0x58 0x20` byte patterns: a raw search can match those
 * bytes *inside* another field's payload, and it cannot tell whether the 32 bytes it slices actually
 * exist (a truncated buffer silently yields a short coordinate). We also pin kty/crv so a key for some
 * other curve can never be reinterpreted as P-256.
 */
function parseCosePublicKey(coseBuffer: Buffer): { x: string; y: string } {
  // Decode only the leading item; trailing bytes are tolerated, as some wallets slice the COSE key out
  // of attestedCredentialData without trimming what follows it.
  const { value } = decodeItem(coseBuffer, 0)
  if (!(value instanceof Map)) cborFail("expected a CBOR map")

  const kty = value.get(1)
  if (kty !== 2) cborFail(`expected kty EC2 (2), got ${String(kty)}`)
  const crv = value.get(-1)
  if (crv !== 1) cborFail(`expected crv P-256 (1), got ${String(crv)}`)
  const alg = value.get(3)
  if (alg !== undefined && alg !== -7) cborFail(`expected alg ES256 (-7), got ${String(alg)}`)

  const coordinate = (label: number, name: string): Buffer => {
    const raw = value.get(label)
    if (!Buffer.isBuffer(raw)) cborFail(`missing ${name} coordinate`)
    if (raw.length !== 32) cborFail(`${name} coordinate must be 32 bytes, got ${raw.length}`)
    return raw
  }
  return { x: base64url(coordinate(-2, "x")), y: base64url(coordinate(-3, "y")) }
}

/** Deterministic JSON with recursively sorted keys — identical to mcp-schemas.stableStringify. */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null"
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`
  const obj = value as Record<string, unknown>
  const keys = Object.keys(obj).sort()
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",")}}`
}

/** The requesting workload's identity, as bound into a DIV Intent Payload. Mirrors mcp-schemas. */
export interface RequesterIdentity {
  did: string
  attestation: { method: string; issuer: string; subject: string } | null
}

/** DIV protocol version and type discriminator — identical to mcp-schemas. */
export const DIV_VERSION = 1
export const DIV_INTENT_TYPE = "div-intent-verification"

/**
 * Canonical DIV Intent Payload (docs/DIV.md v1) — byte-identical to
 * mcp-schemas.canonicalIntentPayload. Strict RFC 8785 JCS: the whole object is serialized with every
 * key sorted recursively by UTF-16 code unit via `stableStringify`. Do NOT hand-order keys.
 */
export function canonicalIntentPayload(input: {
  target: string
  actionType: string
  display: string
  params: Record<string, unknown>
  requester: RequesterIdentity
  nonce: string
  expiresAt: string
}): string {
  const a = input.requester.attestation
  return stableStringify({
    v: DIV_VERSION,
    type: DIV_INTENT_TYPE,
    target: input.target,
    actionType: input.actionType,
    display: input.display,
    params: input.params,
    requester: {
      did: input.requester.did,
      attestation: a ? { method: a.method, issuer: a.issuer, subject: a.subject } : null,
    },
    nonce: input.nonce,
    expiresAt: input.expiresAt,
  })
}

/** Short verification code (first 8 hex of SHA-256 of the canonical payload), grouped XXXX-XXXX. */
export function verificationCode(canonical: string): string {
  const hex = crypto
    .createHash("sha256")
    .update(Buffer.from(canonical, "utf8"))
    .digest("hex")
    .slice(0, 8)
    .toUpperCase()
  return `${hex.slice(0, 4)}-${hex.slice(4, 8)}`
}

/** Verify a raw ECDSA P-256 signature (base64, DER or IEEE-P1363) over `payload` against an SPKI key. */
export function verifyEcdsaP256(publicKeyB64: string, payload: string, signatureB64: string): boolean {
  try {
    const keyObject = crypto.createPublicKey({
      key: Buffer.from(publicKeyB64, "base64"),
      format: "der",
      type: "spki",
    })
    // Pin the key to EC / P-256. createPublicKey happily accepts RSA, Ed25519 or P-521 SPKI, and
    // crypto.verify would then verify under THAT algorithm while the receipt is labelled ES256. The
    // key is chosen by whoever enrolled the wallet, so the label must be enforced, not trusted.
    if (keyObject.asymmetricKeyType !== "ec") return false
    if (keyObject.asymmetricKeyDetails?.namedCurve !== "prime256v1") return false

    const signature = Buffer.from(signatureB64, "base64")
    const data = Buffer.from(payload, "utf8")
    // Raw IEEE-P1363 (r||s) is always exactly 64 bytes for P-256. DER is usually 70-72 but can in
    // principle also be 64 (r and s each shedding three leading zero bytes — vanishingly rare, ~2^-48,
    // yet a correctness cliff rather than a graceful one). Try the encodings instead of inferring one
    // from length, so the distinction stops mattering at all.
    const tryEncoding = (dsaEncoding: "der" | "ieee-p1363"): boolean => {
      try {
        return crypto.verify("sha256", data, { key: keyObject, dsaEncoding }, signature)
      } catch {
        return false
      }
    }
    if (signature.length === 64 && tryEncoding("ieee-p1363")) return true
    return tryEncoding("der")
  } catch {
    return false
  }
}

function parseField<T = string>(canonical: string, key: string): T | undefined {
  try {
    return (JSON.parse(canonical) as Record<string, unknown>)[key] as T
  } catch {
    return undefined
  }
}

function parseNonce(canonical: string): string {
  return parseField<string>(canonical, "nonce") ?? ""
}

/** Which DIV version a receipt was signed under. Unparseable/absent ⇒ 0 (rejected). */
function parseVersion(canonical: string): number {
  const v = parseField<unknown>(canonical, "v")
  return typeof v === "number" ? v : 0
}

/** Default clock-skew tolerance for expiry validation (DIV §6.2 RECOMMENDED ±30s). */
export const DEFAULT_CLOCK_SKEW_SECONDS = 30

/** What you assert the receipt must say. `target` and `nonce` are required — see the notes below. */
export interface ReceiptExpectation {
  /**
   * YOUR target identifier — the Relying Party / execution environment this approval must be bound to
   * (DIV Target Isolation). Required and asserted from your own identity, never read from the
   * receipt: this is what rejects an approval minted for a different service (cross-service replay).
   */
  target: string
  actionType: string
  params: Record<string, unknown>
  /**
   * The challenge nonce YOU issued and are redeeming. Required: it is what ties this receipt to one
   * specific request you are tracking. See the replay note on verifyApprovalReceipt.
   */
  nonce: string
  /** Optionally assert WHICH workload the approval was granted to. */
  requesterDid?: string
}

/** Verification options. The WebAuthn expectations are mandatory for a WEBAUTHN receipt. */
export interface VerifyReceiptOptions {
  allowAutoApproved?: boolean
  /** Exact `origin` the assertion must carry, e.g. "https://app.example.com". Required for WEBAUTHN. */
  expectedOrigin?: string
  /** RP ID the authenticatorData must hash to, e.g. "app.example.com". Required for WEBAUTHN. */
  expectedRpId?: string
  /** Demand the User-Verified flag (biometric/PIN, not mere possession). Defaults to true. */
  requireUserVerification?: boolean
  /**
   * Expiry handling (DIV §5.8/§6.2). By DEFAULT this verifier is fail-closed on `expiresAt`: a proof
   * whose expiry is in the past (beyond the skew tolerance) is rejected — the correct behaviour for a
   * pre-execution check. Set `allowExpired: true` ONLY for post-hoc audit/forensic re-verification,
   * where you deliberately want to confirm a signature that was valid at the time even though it has
   * since expired. `asOf` overrides "now" for deterministic/replayed checks.
   */
  allowExpired?: boolean
  /** Wall-clock instant to evaluate expiry against. Defaults to `new Date()`. */
  asOf?: Date
  /** Clock-skew tolerance in seconds for expiry validation. Defaults to DEFAULT_CLOCK_SKEW_SECONDS. */
  clockSkewSeconds?: number
}

// WebAuthn authenticatorData flag bits (WebAuthn L3 §6.1).
const AUTH_DATA_FLAG_UP = 0x01 // User Present
const AUTH_DATA_FLAG_UV = 0x04 // User Verified

/**
 * Independently verify an approval receipt against the instruction you are ABOUT to execute. Recomputes
 * the canonical payload from your params, confirms it byte-matches what was signed, and verifies the
 * human's P-256 or WebAuthn signature — with no SÄKRA secret.
 *
 * WHAT THIS PROVES: that a specific human key signed exactly this action, with exactly these params,
 * for exactly the target and nonce you pass in `expected`, and that the proof has not expired.
 *
 * EXPIRY: the signed `expiresAt` is enforced fail-closed by default (±30s skew) — a lapsed proof is
 * rejected. Pass `{ allowExpired: true }` ONLY for post-hoc audit/forensic re-verification, where
 * confirming a signature that was valid AT THE TIME is the point.
 *
 * WHAT THIS DOES NOT PROVE: that the approval has not ALREADY BEEN USED within its validity window.
 * Expiry bounds how long a proof is valid, but single-use enforcement is separate and lives in the
 * gateway's /authorize/verify (which atomically marks the challenge CONSUMED) — this function is a
 * defense-in-depth companion to that call, not a replacement for it. If you verify offline and skip
 * the consume step, YOU must record redeemed nonces yourself; requiring `expected.nonce` here is what
 * makes that possible, since you cannot call this without having tracked the nonce you issued.
 *
 * Returns `{ ok: false, reason }` on any mismatch.
 */
export function verifyApprovalReceipt(
  receipt: ApprovalReceipt,
  expected: ReceiptExpectation,
  opts: VerifyReceiptOptions = {},
): { ok: boolean; reason?: string; autoApproved?: boolean } {
  const version = parseVersion(receipt.canonicalPayload)
  if (version !== DIV_VERSION)
    return { ok: false, reason: `unsupported DIV payload version (${version || "unparseable"})` }
  if (parseField(receipt.canonicalPayload, "type") !== DIV_INTENT_TYPE)
    return { ok: false, reason: "payload is not a div-intent-verification" }

  // Bind the receipt to the challenge the caller is redeeming, before anything else.
  if (parseNonce(receipt.canonicalPayload) !== expected.nonce)
    return { ok: false, reason: "receipt is for a different challenge" }

  // Rebuild the expected payload (DIV Local Payload Reconstruction). `target`, `actionType` and
  // `params` come from what YOU are about to execute; `display`, `requester`, `nonce` and `expiresAt`
  // are taken from the receipt and MUST byte-match the signed bytes below — a forged value changes the
  // string and fails the comparison, so trusting the receipt for them is not circular.
  if (!receipt.requester) return { ok: false, reason: "receipt missing requester" }
  const expiresAt = parseField<string>(receipt.canonicalPayload, "expiresAt")
  if (typeof expiresAt !== "string" || expiresAt.length === 0)
    return { ok: false, reason: "receipt missing expiresAt" }
  const target = expected.target ?? receipt.target ?? "global"
  const recomputed = canonicalIntentPayload({
    target,
    actionType: expected.actionType,
    display: receipt.actionDescription,
    params: expected.params,
    requester: receipt.requester,
    nonce: parseNonce(receipt.canonicalPayload),
    expiresAt,
  })
  if (recomputed !== receipt.canonicalPayload)
    return {
      ok: false,
      reason: "target/params/actionType do not match what was approved",
    }

  // Expiration (DIV §5.8/§6.2). Fail-closed by default; opt out only for audit re-verification.
  if (!opts.allowExpired) {
    const expiryMs = Date.parse(expiresAt)
    if (Number.isNaN(expiryMs)) return { ok: false, reason: "expiresAt is not a valid RFC3339 timestamp" }
    const nowMs = (opts.asOf ?? new Date()).getTime()
    const skewMs = (opts.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS) * 1000
    if (nowMs > expiryMs + skewMs)
      return {
        ok: false,
        reason: "proof has expired (pass { allowExpired: true } for audit re-verification)",
      }
  }

  // Optional: assert WHICH workload the approval was granted to.
  if (expected.requesterDid !== undefined) {
    if (receipt.requester?.did !== expected.requesterDid)
      return { ok: false, reason: "approval was requested by a different principal" }
  }
  // A policy AUTO_APPROVED receipt carries NO human signature — there is nothing to cryptographically
  // verify, and such a receipt is trivially forgeable. We therefore REFUSE to attest it by default
  // (so `if (!verify().ok) throw` correctly blocks unsigned approvals). A relying party that has
  // consciously accepted policy pre-approval / break-glass must opt in with `allowAutoApproved: true`.
  if (receipt.sigAlg === "AUTO_APPROVED") {
    return opts.allowAutoApproved
      ? { ok: true, autoApproved: true }
      : {
          ok: false,
          autoApproved: true,
          reason:
            "auto-approved by policy — no human signature to verify (pass { allowAutoApproved: true } to accept)",
        }
  }
  if (!receipt.signerPublicKey || !receipt.signature)
    return { ok: false, reason: "receipt missing signature material" }

  const isWebAuthn = receipt.sigAlg === "WEBAUTHN"

  if (isWebAuthn) {
    if (!receipt.authenticatorData || !receipt.clientDataJSON) {
      return {
        ok: false,
        reason: "WebAuthn receipt missing authenticatorData or clientDataJSON",
      }
    }
    // FAIL CLOSED, same rule as the rest of this package: without an expected origin and RP ID there
    // is nothing to pin the assertion to, and an assertion harvested at an attacker's relying party
    // would verify. Refuse rather than check a weaker property.
    if (!opts.expectedOrigin || !opts.expectedRpId) {
      return {
        ok: false,
        reason:
          "WebAuthn receipts require expectedOrigin and expectedRpId — without them an assertion from any relying party would verify",
      }
    }
    try {
      const clientDataBuf = Buffer.from(receipt.clientDataJSON, "base64")
      const clientDataStr = clientDataBuf.toString("utf-8")
      const clientData = JSON.parse(clientDataStr) as {
        challenge: string
        type?: string
        origin?: string
      }

      // An assertion, not a registration: webauthn.create signs a different ceremony over the same
      // challenge bytes, and must never be accepted as approval.
      if (clientData.type !== "webauthn.get")
        return { ok: false, reason: "clientDataJSON is not a webauthn.get assertion" }
      if (clientData.origin !== opts.expectedOrigin)
        return { ok: false, reason: "assertion origin does not match expectedOrigin" }

      const expectedChallenge = base64url(receipt.canonicalPayload)
      const clientChallengeClean = clientData.challenge
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "")
      if (clientChallengeClean !== expectedChallenge) {
        return {
          ok: false,
          reason: "clientDataJSON challenge does not match canonical payload",
        }
      }

      // authenticatorData is signed but was previously never INSPECTED: it carries the RP ID the
      // credential answered for and whether the user was actually present/verified. Skipping these
      // made this verifier strictly weaker than the gateway, which pins both.
      const authData = Buffer.from(receipt.authenticatorData, "base64")
      if (authData.length < 37) return { ok: false, reason: "authenticatorData is too short" }
      const rpIdHash = crypto.createHash("sha256").update(opts.expectedRpId, "utf8").digest()
      if (!crypto.timingSafeEqual(authData.subarray(0, 32), rpIdHash))
        return { ok: false, reason: "authenticatorData rpIdHash does not match expectedRpId" }
      const flags = authData.readUInt8(32)
      if (!(flags & AUTH_DATA_FLAG_UP))
        return { ok: false, reason: "authenticatorData user-present flag is not set" }
      if (opts.requireUserVerification !== false && !(flags & AUTH_DATA_FLAG_UV))
        return { ok: false, reason: "authenticatorData user-verified flag is not set" }

      const coseBuf = Buffer.from(receipt.signerPublicKey, "base64")
      const { x, y } = parseCosePublicKey(coseBuf)
      const keyObject = crypto.createPublicKey({
        format: "jwk",
        key: { kty: "EC", crv: "P-256", x, y },
      })

      const clientDataHash = crypto.createHash("sha256").update(clientDataBuf).digest()
      const signatureVerifyData = Buffer.concat([authData, clientDataHash])

      const signatureBuf = Buffer.from(receipt.signature, "base64")
      // Digest pinned explicitly: ES256 is P-256 + SHA-256 by definition, and leaving it implicit
      // (`undefined`) makes the algorithm a property of the Node version rather than of this code.
      const verified = crypto.verify(
        "sha256",
        signatureVerifyData,
        { key: keyObject, dsaEncoding: "der" },
        signatureBuf,
      )

      if (!verified)
        return {
          ok: false,
          reason: "WebAuthn signature does not verify against signer key",
        }
      return { ok: true }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      return { ok: false, reason: `WebAuthn verification failed: ${msg}` }
    }
  } else {
    if (!verifyEcdsaP256(receipt.signerPublicKey, receipt.canonicalPayload, receipt.signature)) {
      return {
        ok: false,
        reason: "signature does not verify against signer key",
      }
    }
    return { ok: true }
  }
}

// ─── Audit ledger inclusion proofs ───────────────────────────────────────────
// The other half of "inspect-it-yourself": confirm an audit event is committed to SÄKRA's append-only
// Merkle log against an independently anchored daily root. Same zero-dependency, no-secret contract as
// the approval-receipt verifier above. See @sakra-trust/ledger (SPEC.md) for the format and the
// published end-of-day roots. Surfaced on the CLI as `sakra audit-verify`.

export {
  BUNDLE_KIND,
  BUNDLE_KIND_ALIASES,
  type BundleVerification,
  type CheckResult,
  deriveVerificationLevel,
  type ProofBundle,
  type VerificationLevel,
  type VerificationProperties,
  verifyBundle,
  verifyEmbeddedSignature,
  type VerifyOptions,
} from "./ledger-bundle.js"
export {
  EVIDENCE_BUNDLE_KIND,
  EVIDENCE_BUNDLE_KIND_ALIASES,
  type EvidenceBundle,
  type EvidenceEntry,
  type EvidenceVerification,
  type EvidenceVerifyOptions,
  verifyEvidenceBundle,
} from "./ledger-evidence.js"
export {
  type AnchorKeyResolver,
  type AnchorPolicy,
  type AnchorQuorumResult,
  anchorDigest,
  anchorDigestHex,
  anchorPreimage,
  signAnchor,
  type SignedAnchor,
  verifyAnchorQuorum,
  verifyAnchorSignature,
} from "./ledger-anchor.js"
export { type AuditLeaf, canonicalPreimage, leafHash } from "./ledger-leaf.js"
export {
  hashLeaf,
  hashPair,
  merkleProof,
  merkleRoot,
  type ProofStep,
  sha256Hex,
  verifyMerkleProof,
} from "./ledger-merkle.js"
export { type InclusionProof, verifyInclusionProof } from "./ledger-proof.js"
