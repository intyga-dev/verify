// @intyga/verify — independently confirm that a human cryptographically approved EXACTLY the action
// you are about to run. Zero runtime dependencies (node:crypto only), no network, and NO Intyga secret:
// a relying party recomputes the canonical payload from its own params, checks it byte-matches what was
// signed, and verifies the human's P-256 / WebAuthn signature. This is the "inspect-it-yourself" trust
// artifact — the whole point is that you don't have to take Intyga's word for it.
//
// The canonicalization + hashing here MUST stay byte-for-byte identical to @intyga/mcp-schemas and the
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
  /**
   * EVERY witness signature over `canonicalPayload`. A quorum receipt carries one entry per approver;
   * a single-signer receipt carries one. Emitting only the first approval made an M-of-N approval
   * indistinguishable from a 1-of-1 one, so the quorum could not be verified offline at all.
   */
  signatures?: ApprovalWitness[] | null
  // Single-signature fields. Retained for display and for the AUTO_APPROVED case (which has no
  // witness at all); when `signatures` is absent these are read as a one-element witness list.
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

/** One approver's signature over the canonical payload. */
export interface ApprovalWitness {
  signerDid: string
  signerPublicKey: string // base64 SPKI (ES256) or base64 COSE (WEBAUTHN)
  signature: string
  sigAlg?: string | null // "ES256" | "WEBAUTHN"
  authenticatorData?: string | null // base64url (WEBAUTHN only)
  clientDataJSON?: string | null // base64url (WEBAUTHN only)
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

/** Thrown when a value outside the JSON data model is handed to the canonicalizer. */
export class NonCanonicalValue extends Error {}

/**
 * Deterministic JSON with recursively sorted keys — identical to mcp-schemas.stableStringify.
 *
 * STRICT: RFC 8785 defines a mapping over JSON data, so anything outside that domain is REJECTED
 * rather than coerced. The permissive version silently collapsed distinct runtime values onto one
 * canonical string — `new Date(0)`, `{}`, `new Map()` and any class instance all serialized to `{}`,
 * and a `toJSON` method was emitted as a `null`-valued key instead of being honoured. For a function
 * whose entire job is "these bytes are exactly what was signed", quietly mapping several inputs onto
 * one output is the wrong failure mode: the relying party's `expected.params` come from its own live
 * runtime objects, so it is the caller most likely to hand us a Date.
 *
 * Exported so the shared golden vectors can pin THIS copy directly (vectors.test.ts) — every other
 * port pins its canonicalizer against the committed file; the shipped relying-party verifier must
 * not be the one implementation pinned only transitively.
 */
export function stableStringify(value: unknown): string {
  if (value === null) return "null"
  const t = typeof value
  if (t === "string" || t === "boolean") return JSON.stringify(value)
  if (t === "number") {
    const n = value as number
    if (!Number.isFinite(n)) throw new NonCanonicalValue("NaN/Infinity is not JSON")
    // Cross-language portability, not just JSON validity — see isPortableNumber in @intyga/mcp-schemas.
    // A number that serializes differently in the Go/Rust/Python verifiers would make a valid
    // approval read as tampering there, so it is refused rather than signed over.
    if (Object.is(n, -0)) throw new NonCanonicalValue("-0 does not serialize portably across verifiers")
    const abs = Math.abs(n)
    if (n !== 0 && abs >= 1e16) {
      throw new NonCanonicalValue(`${n} is outside the portable range (|x| < 1e16)`)
    }
    if (n !== 0 && !Number.isInteger(n) && abs < 1e-4) {
      throw new NonCanonicalValue(`${n} is outside the portable float range (1e-4 ≤ |x| < 1e16)`)
    }
    return JSON.stringify(n)
  }
  if (t !== "object") {
    throw new NonCanonicalValue(`${t} cannot be canonicalized (RFC 8785 covers JSON data only)`)
  }
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`
  // Reject Dates, Maps, Sets and class instances outright. A plain object (or a null-prototype one,
  // as produced by JSON.parse with a __proto__ key) is the only shape with an unambiguous mapping.
  const proto = Object.getPrototypeOf(value)
  if (proto !== Object.prototype && proto !== null) {
    throw new NonCanonicalValue(
      "only plain objects can be canonicalized (got a class instance, Date, Map or Set)",
    )
  }
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
 * OFFLINE APPROVAL (docs/DIV.md §5a.2): a normal approval, signed by real humans through the normal
 * quorum, but collected OUT OF BAND at incident time because the gateway is unreachable. The relying
 * party builds the challenge itself, the humans review and sign it on a disconnected device, and the
 * result is verified by the ordinary §5 procedure.
 *
 * This deliberately replaces the older pre-signed "sealed break-glass" token. Pre-signing puts a
 * bearer capability on disk and captures a human judgment about a HYPOTHETICAL; moving the ceremony
 * off the network instead keeps the human in the loop for the ACTUAL incident and leaves nothing at
 * rest to steal. See DIV §5a.1.
 *
 * The distinct `type` is the single most important guardrail in the whole mechanism. It sits inside
 * the signed bytes, so:
 *   - an offline proof can NEVER verify as a normal approval, and
 *   - a normal approval can NEVER be replayed as an offline one.
 * Neither direction is possible even with a byte-identical action, because the reconstructed payload
 * differs and the signature comparison fails. Do not "simplify" this into a flag outside the payload.
 */
export const DIV_OFFLINE_INTENT_TYPE = "div-offline-intent"

/**
 * DELEGATION (docs/DIV.md §5a.5): signed in advance by the ordinary quorum, it transfers the
 * AUTHORITY TO APPROVE one pre-declared action to a named set of local operators.
 *
 * A delegation authorizes NOTHING by itself. `verifyApprovalReceipt` refuses this type outright and
 * there is deliberately no opt-in flag that would let it through — see `verifyDelegation`, which is a
 * separate operation for exactly that reason. A delegation that could authorize its own action would
 * be the pre-signed bearer capability DIV §5a.1 rejects.
 */
export const DIV_DELEGATION_TYPE = "div-delegation"

/**
 * Hard ceiling on an offline proof's validity window, enforced at verification and not only at mint.
 * An offline proof is created and redeemed within one incident, so the window is minutes — it exists
 * to bound a proof whose `expiresAt` was minted over-long, which is otherwise indistinguishable at
 * verification time from a correct one (DIV §5a.3).
 */
export const MAX_OFFLINE_WINDOW_MINUTES = 60

/**
 * Ceiling on the witness list this verifier will process. A DIV quorum is single digits — this is a
 * denial-of-service bound, not a policy limit, because verification runs in the relying party's own
 * process on an attacker-supplied receipt immediately before an irreversible action.
 */
export const MAX_WITNESSES = 64

/** How many per-witness failure reasons are folded into the returned `reason` string. */
const MAX_REPORTED_FAILURES = 8

/**
 * Hard ceiling on a delegation's validity window. Hours, not the 30 days the old sealed token
 * allowed: a delegation cannot be revoked at an offline relying party, so the short window IS the
 * revocation story (DIV §5a.6).
 */
export const MAX_DELEGATION_WINDOW_HOURS = 72

/**
 * The approval policy in force for a challenge, frozen at creation and SIGNED as part of the payload.
 *
 * This exists because the gateway enforces a rich requirement (quorum, four-eyes, hardware class) that
 * used to appear nowhere in the signed bytes. A receipt from a 3-of-3, hardware-key-pinned challenge
 * was byte-for-byte indistinguishable from a 1-of-1, no-hardware one — so a relying party doing
 * "offline verification" still had to take the gateway's word for the entire policy, which is the
 * exact class of trust the offline verifier exists to remove. Binding it into the payload also means
 * the APPROVER sees and attests to the policy their signature is being counted toward.
 *
 * What a verifier can check offline, and what it cannot:
 *  - `requiredApprovals` — fully checkable. Counts distinct trusted approver signatures.
 *  - `requesterCannotApprove` — fully checkable. The requester DID is in the same signed payload.
 *  - `requireHardwareKey` — PARTIALLY checkable. A verifier can confirm the witness is a WebAuthn
 *    assertion rather than a bare P-256 key, but an assertion carries no attestation, so it cannot
 *    distinguish a discrete security key from a synced platform passkey.
 *  - `allowedAaguids` — NOT checkable offline. The AAGUID lives in attestedCredentialData, which is
 *    present at REGISTRATION, not in an assertion. Only the gateway (which stored it at enrollment)
 *    can enforce this. It is carried here so the approver signs the policy they were told applied,
 *    not so a relying party can re-derive it.
 */
export interface ApprovalRequirementAttestation {
  requiredApprovals: number
  requireHardwareKey: boolean
  allowedAaguids: string[]
  requesterCannotApprove: boolean
}

/**
 * Canonical DIV Intent Payload (docs/DIV.md v2) — byte-identical to
 * mcp-schemas.canonicalIntentPayload. Strict RFC 8785 JCS: the whole object is serialized with every
 * key sorted recursively by UTF-16 code unit via `stableStringify`. Do NOT hand-order keys.
 */
export function canonicalIntentPayload(input: {
  target: string
  actionType: string
  display: string
  params: Record<string, unknown>
  requester: RequesterIdentity
  requirement: ApprovalRequirementAttestation
  nonce: string
  expiresAt: string
}): string {
  return stableStringify({
    v: DIV_VERSION,
    type: DIV_INTENT_TYPE,
    target: input.target,
    actionType: input.actionType,
    display: input.display,
    params: input.params,
    ...commonSignedFields(input.requester, input.requirement),
    nonce: input.nonce,
    expiresAt: input.expiresAt,
  })
}

/**
 * The requester + requirement projection shared by all three canonical builders.
 *
 * One definition rather than three copies: these bytes are the contract, and a field added to one
 * builder but not the others is precisely the drift the cross-package vectors exist to catch. The
 * golden vectors pin the output, so this factoring is verified rather than assumed.
 */
function commonSignedFields(requester: RequesterIdentity, requirement: ApprovalRequirementAttestation) {
  const a = requester.attestation
  return {
    requester: {
      did: requester.did,
      attestation: a ? { method: a.method, issuer: a.issuer, subject: a.subject } : null,
    },
    requirement: {
      requiredApprovals: requirement.requiredApprovals,
      requireHardwareKey: requirement.requireHardwareKey,
      // Sorted: the set is what matters, and an unordered list would make two identical policies
      // produce different bytes depending on how the rule happened to be written.
      allowedAaguids: [...requirement.allowedAaguids].sort(),
      requesterCannotApprove: requirement.requesterCannotApprove,
    },
  }
}

/**
 * Canonical OFFLINE INTENT payload (DIV §5a.2). Deliberately a separate function rather than a `type`
 * parameter on `canonicalIntentPayload`.
 *
 * A parameter would mean every existing call site could silently produce the wrong kind by passing
 * the wrong argument, and the normal approval path — which is the overwhelmingly common one — would
 * carry a footgun for the sake of a rare one. Two functions cannot be confused: you either called the
 * offline builder or you did not.
 *
 * `challengedAt` is the only extra field, and it exists so the verifier can bound the validity
 * WINDOW. Without it, a payload minted with a 10-year `expiresAt` would be indistinguishable from a
 * correctly minted one at verification time.
 */
export function canonicalOfflineIntentPayload(input: {
  target: string
  actionType: string
  display: string
  params: Record<string, unknown>
  requester: RequesterIdentity
  requirement: ApprovalRequirementAttestation
  nonce: string
  challengedAt: string
  expiresAt: string
}): string {
  return stableStringify({
    v: DIV_VERSION,
    type: DIV_OFFLINE_INTENT_TYPE,
    target: input.target,
    actionType: input.actionType,
    display: input.display,
    params: input.params,
    ...commonSignedFields(input.requester, input.requirement),
    nonce: input.nonce,
    challengedAt: input.challengedAt,
    expiresAt: input.expiresAt,
  })
}

/**
 * Canonical DELEGATION payload (DIV §5a.5) — a signed statement about WHO MAY APPROVE, not about
 * what may run.
 *
 * `delegatedTo` is sorted because it is a SET: the same three operators in a different order must
 * produce the same bytes, exactly as for `allowedAaguids`. `requirement` here describes the quorum
 * that signed this delegation, while `delegatedQuorum` is how many of `delegatedTo` must sign at
 * incident time — two different quorums, which is why both are in the signed bytes.
 */
export function canonicalDelegationPayload(input: {
  target: string
  actionType: string
  display: string
  params: Record<string, unknown>
  requester: RequesterIdentity
  requirement: ApprovalRequirementAttestation
  delegatedTo: string[]
  delegatedQuorum: number
  nonce: string
  sealedAt: string
  expiresAt: string
}): string {
  return stableStringify({
    v: DIV_VERSION,
    type: DIV_DELEGATION_TYPE,
    target: input.target,
    actionType: input.actionType,
    display: input.display,
    params: input.params,
    ...commonSignedFields(input.requester, input.requirement),
    delegatedTo: [...input.delegatedTo].sort(),
    delegatedQuorum: input.delegatedQuorum,
    nonce: input.nonce,
    sealedAt: input.sealedAt,
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

/**
 * The approver identities/keys YOU trust, resolved from your own key-management policy.
 *
 * This is the single most important input to verification. Without it, `verifyApprovalReceipt` would
 * verify a signature using the public key carried INSIDE the receipt — which proves only that the
 * receipt is internally consistent, i.e. nothing. Anyone able to hand you a receipt (per the DIV
 * threat model, that includes the untrusted agent itself) could mint a keypair, sign a payload over
 * the nonce you issued and the params you are about to run, put any string in `signerDid`, and be
 * told the action was approved by a human. DIV §3 Invariant 3 and §5 step 3 require the Approver key
 * to be resolved from deployment key-management policy; this type is that step.
 *
 *  - `{ publicKeys }`  — a direct allowlist of base64 SPKI / COSE keys.
 *  - `{ dids, resolveKey }` — a DID allowlist plus your own resolver (directory lookup, pinned
 *    enrollment record, etc). Return `null` for an unknown DID to reject it.
 *
 * PREFER DID MODE where you can. In `publicKeys` mode the receipt's `signerDid` is an unverified
 * string, so quorum has to count distinct KEYS instead of distinct approvers — and a delegation
 * (DIV §5a.6), which names identities, cannot be enforced at all.
 *
 * `resolveKey` may return SEVERAL keys for one DID. An approver commonly holds a software key plus
 * one or more registered authenticators, and any of them is legitimately theirs; returning them all
 * keeps the identity intact instead of forcing callers to flatten everything into `publicKeys` mode
 * and lose the DID binding. Every key returned for a DID counts as that ONE approver.
 */
export type ApproverTrustAnchor =
  | { publicKeys: string[]; dids?: undefined; resolveKey?: undefined }
  | {
      dids: string[]
      resolveKey: (did: string) => string | string[] | null
      publicKeys?: undefined
    }

/** What you assert the receipt must say. `target`, `nonce` and `approvers` are required. */
export interface ReceiptExpectation {
  /**
   * REQUIRED. The approvers you trust — see ApproverTrustAnchor. There is deliberately no default:
   * a receipt cannot be permitted to vouch for its own signer.
   */
  approvers: ApproverTrustAnchor
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
  /**
   * Accept an OFFLINE APPROVAL (`type: "div-offline-intent"`). Defaults to FALSE — an offline proof is
   * refused on every ordinary call site, exactly like `allowAutoApproved`.
   *
   * Pass this at the SPECIFIC call that is allowed to run under an offline approval, never globally. A
   * process-wide default would mean every gated action in the service silently accepts an
   * out-of-band approval, which is the difference between an emergency mechanism and a hole.
   *
   * Setting it does not weaken any other check: the quorum, four-eyes and target binding signed into
   * the payload are still enforced, the window is capped at MAX_OFFLINE_WINDOW_MINUTES, and a proof
   * whose signed policy demands a hardware key is REFUSED (DIV §5a.3 step 4) because that requirement
   * cannot be satisfied offline.
   */
  allowOffline?: boolean
  /**
   * A delegation that has ALREADY been verified by `verifyDelegation`, substituting the eligible
   * approver set and the quorum for this one verification (DIV §5a.6).
   *
   * Only meaningful together with `allowOffline`. This narrows rather than widens: the delegation's
   * target/actionType/params must equal what you are executing, and the offline payload's signed
   * `requiredApprovals` must equal the delegation's `delegatedQuorum`, so the operators still sign the
   * policy their signatures are counted toward.
   */
  delegation?: VerifiedDelegation
  /** Exact `origin` the assertion must carry, e.g. "https://app.example.com". Required for WEBAUTHN. */
  expectedOrigin?: string
  /** RP ID the authenticatorData must hash to, e.g. "app.example.com". Required for WEBAUTHN. */
  expectedRpId?: string
  /** Demand the User-Verified flag (biometric/PIN, not mere possession). Defaults to true. */
  requireUserVerification?: boolean
  /**
   * Accept an assertion produced inside a cross-origin frame. Defaults to FALSE (refuse).
   *
   * `origin` alone cannot detect this: inside a cross-origin iframe the browser reports the FRAME's
   * origin — which for an embedded RP page is the RP's own origin — and rpIdHash matches too. So with
   * `publickey-credentials-get` delegated, a third-party embedder can drive a high-risk approval
   * ceremony while every other check here passes. `crossOrigin` is the only signal that distinguishes
   * the two (W3C WebAuthn L3 §7.2 step 9).
   */
  allowCrossOrigin?: boolean
  /**
   * Expiry handling (DIV §5 step 8 / §6.2). By DEFAULT this verifier is fail-closed on `expiresAt`: a proof
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
 * The keys we are willing to accept this witness under, drawn ENTIRELY from the caller's trust anchor.
 *
 * `witness.signerPublicKey` is never used as a verification key — only, in DID mode, as a claim about
 * WHICH approver is speaking, which we then answer with our own resolver. Note we do not compare the
 * presented key to the trusted one: there is nothing to gain (a mismatched key simply fails to verify)
 * and byte-equality is actively wrong for COSE, where the same P-256 key has many valid encodings.
 *
 * Each candidate is tagged with the identity that key represents, so quorum counts distinct APPROVERS.
 * In `publicKeys` mode the identity is the key itself: the receipt's `signerDid` is an unverified
 * string there, and counting it would let one approver claim to be three.
 */
function candidateKeys(
  anchor: ApproverTrustAnchor,
  witness: ApprovalWitness,
  /**
   * When a delegation is in force, the eligible approvers are narrowed to the identities it names
   * (DIV §5a.6 step 3). Applied ON TOP of the trust anchor, never instead of it: a delegation says
   * WHO may approve, and the anchor still says which key is actually theirs.
   */
  restrictTo?: string[],
): { keys: { key: string; identity: string }[] } | { reason: string } {
  if (anchor.publicKeys) {
    // A delegation names identities, and in publicKeys mode `signerDid` is an unverified string —
    // enforcing `delegatedTo` against it would be security theatre. Refuse rather than pretend.
    if (restrictTo)
      return {
        reason:
          "a delegation names approver identities, so it requires a DID-mode trust anchor ({ dids, resolveKey }); in publicKeys mode signerDid is unverified and delegatedTo cannot be enforced",
      }
    if (anchor.publicKeys.length === 0) return { reason: "trusted approver allowlist is empty" }
    return { keys: anchor.publicKeys.map((key) => ({ key, identity: key })) }
  }
  if (!witness.signerDid || !anchor.dids.includes(witness.signerDid)) {
    return { reason: `signer ${witness.signerDid || "(unknown)"} is not an authorized approver` }
  }
  if (restrictTo && !restrictTo.includes(witness.signerDid)) {
    return { reason: `signer ${witness.signerDid} is not named in the delegation` }
  }
  const resolved = anchor.resolveKey(witness.signerDid)
  if (!resolved) return { reason: `no trusted key could be resolved for ${witness.signerDid}` }
  // One DID may legitimately hold several keys; all of them identify the SAME approver, so quorum
  // still counts one. Flattening them into separate identities would let one person meet an N-of-M.
  const keys = (Array.isArray(resolved) ? resolved : [resolved]).filter((k) => Boolean(k))
  if (keys.length === 0) return { reason: `no trusted key could be resolved for ${witness.signerDid}` }
  return { keys: keys.map((key) => ({ key, identity: witness.signerDid })) }
}

/** Verify one witness signature over the canonical payload, using an already-TRUSTED key. */
function verifyWitness(
  witness: ApprovalWitness,
  trustedKey: string,
  canonicalPayload: string,
  opts: VerifyReceiptOptions,
): { ok: true } | { ok: false; reason: string } {
  if (witness.sigAlg !== "WEBAUTHN") {
    return verifyEcdsaP256(trustedKey, canonicalPayload, witness.signature)
      ? { ok: true }
      : { ok: false, reason: "signature does not verify against the trusted signer key" }
  }

  if (!witness.authenticatorData || !witness.clientDataJSON) {
    return { ok: false, reason: "WebAuthn witness missing authenticatorData or clientDataJSON" }
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
    const clientDataBuf = Buffer.from(witness.clientDataJSON, "base64")
    const clientData = JSON.parse(clientDataBuf.toString("utf-8")) as {
      challenge: string
      type?: string
      origin?: string
      crossOrigin?: boolean
    }

    // An assertion, not a registration: webauthn.create signs a different ceremony over the same
    // challenge bytes, and must never be accepted as approval.
    if (clientData.type !== "webauthn.get")
      return { ok: false, reason: "clientDataJSON is not a webauthn.get assertion" }
    if (clientData.origin !== opts.expectedOrigin)
      return { ok: false, reason: "assertion origin does not match expectedOrigin" }
    // See VerifyReceiptOptions.allowCrossOrigin: origin and rpIdHash both match for an embedded RP
    // frame, so this flag is the only thing that separates "the human approved on our page" from
    // "the human approved inside someone else's page".
    if (clientData.crossOrigin === true && opts.allowCrossOrigin !== true)
      return { ok: false, reason: "assertion was produced in a cross-origin frame (crossOrigin=true)" }

    const expectedChallenge = base64url(canonicalPayload)
    const clientChallengeClean = clientData.challenge
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "")
    if (clientChallengeClean !== expectedChallenge)
      return { ok: false, reason: "clientDataJSON challenge does not match canonical payload" }

    // authenticatorData is signed but was previously never INSPECTED: it carries the RP ID the
    // credential answered for and whether the user was actually present/verified.
    const authData = Buffer.from(witness.authenticatorData, "base64")
    if (authData.length < 37) return { ok: false, reason: "authenticatorData is too short" }
    const rpIdHash = crypto.createHash("sha256").update(opts.expectedRpId, "utf8").digest()
    if (!crypto.timingSafeEqual(authData.subarray(0, 32), rpIdHash))
      return { ok: false, reason: "authenticatorData rpIdHash does not match expectedRpId" }
    const flags = authData.readUInt8(32)
    if (!(flags & AUTH_DATA_FLAG_UP))
      return { ok: false, reason: "authenticatorData user-present flag is not set" }
    if (opts.requireUserVerification !== false && !(flags & AUTH_DATA_FLAG_UV))
      return { ok: false, reason: "authenticatorData user-verified flag is not set" }

    // The COSE key is parsed from the TRUSTED key, not from the receipt's copy.
    const { x, y } = parseCosePublicKey(Buffer.from(trustedKey, "base64"))
    const keyObject = crypto.createPublicKey({ format: "jwk", key: { kty: "EC", crv: "P-256", x, y } })

    const clientDataHash = crypto.createHash("sha256").update(clientDataBuf).digest()
    const signatureVerifyData = Buffer.concat([authData, clientDataHash])

    // Digest pinned explicitly: ES256 is P-256 + SHA-256 by definition, and leaving it implicit
    // (`undefined`) makes the algorithm a property of the Node version rather than of this code.
    const verified = crypto.verify(
      "sha256",
      signatureVerifyData,
      { key: keyObject, dsaEncoding: "der" },
      Buffer.from(witness.signature, "base64"),
    )
    return verified
      ? { ok: true }
      : { ok: false, reason: "WebAuthn signature does not verify against the trusted signer key" }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err)
    return { ok: false, reason: `WebAuthn verification failed: ${msg}` }
  }
}

/** Normalize a receipt to a witness list: `signatures` if present, else the single-signature fields. */
function witnessesOf(receipt: ApprovalReceipt): ApprovalWitness[] {
  if (receipt.signatures?.length) return receipt.signatures
  if (receipt.signerPublicKey && receipt.signature) {
    return [
      {
        signerDid: receipt.signerDid ?? "",
        signerPublicKey: receipt.signerPublicKey,
        signature: receipt.signature,
        sigAlg: receipt.sigAlg,
        authenticatorData: receipt.authenticatorData,
        clientDataJSON: receipt.clientDataJSON,
      },
    ]
  }
  return []
}

/**
 * Independently verify an approval receipt against the instruction you are ABOUT to execute. Recomputes
 * the canonical payload from your params, confirms it byte-matches what was signed, and verifies the
 * human's P-256 or WebAuthn signature — with no Intyga secret.
 *
 * WHAT THIS PROVES: that enough APPROVERS YOU ALREADY TRUST (`expected.approvers`) signed exactly this
 * action, with exactly these params, for exactly the target and nonce you pass in `expected`; that the
 * number of distinct valid signatures meets the quorum recorded in the signed payload; that the
 * requester did not self-approve when the signed policy forbids it; and that the proof has not expired.
 *
 * THE TRUST ANCHOR IS NOT OPTIONAL. Verification uses the key you resolve for an approver, never the
 * `signerPublicKey` carried in the receipt. A receipt verified against its own embedded key proves
 * only internal consistency — anyone who can hand you a receipt could have minted the keypair.
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
): { ok: boolean; reason?: string; autoApproved?: boolean; signers?: string[] } {
  const version = parseVersion(receipt.canonicalPayload)
  if (version !== DIV_VERSION)
    return { ok: false, reason: `unsupported DIV payload version (${version || "unparseable"})` }
  // Which KIND of proof is this? The type is inside the signed bytes, so this is not spoofable
  // without breaking the signature — and the kinds rebuild through different canonical builders,
  // so none can ever be mistaken for another further down.
  const payloadType = parseField(receipt.canonicalPayload, "type")
  // A DELEGATION authorizes nothing (DIV §5a.5). It is refused here unconditionally — there is
  // deliberately NO option that would let one through, because a delegation that could authorize its
  // own action would be exactly the pre-signed bearer capability the design exists to avoid. Use
  // `verifyDelegation` to check one, then pass the result as `opts.delegation`.
  if (payloadType === DIV_DELEGATION_TYPE)
    return {
      ok: false,
      reason:
        "this is a delegation, which authorizes no action on its own — verify it with verifyDelegation and pass the result as { delegation }, together with an offline approval signed by the delegated operators",
    }
  const offline = payloadType === DIV_OFFLINE_INTENT_TYPE
  if (!offline && payloadType !== DIV_INTENT_TYPE)
    return { ok: false, reason: "payload is not a div-intent-verification" }
  if (offline && !opts.allowOffline)
    return {
      ok: false,
      reason:
        "this is an offline approval; pass { allowOffline: true } at the specific call site permitted to run under one",
    }
  // A delegation only ever substitutes the approver set for an OFFLINE proof. Accepting it against an
  // ordinary gateway-mediated receipt would silently replace the quorum the gateway enforced.
  if (opts.delegation && !offline)
    return { ok: false, reason: "a delegation can only substitute the approver set for an offline approval" }

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
  // FAIL CLOSED on a missing target, like the nonce check above and the WebAuthn pinning below.
  // TypeScript makes `target` required, but this package is shipped to relying parties and is called
  // from plain JS too. Defaulting to the receipt's OWN target would have the receipt vouch for its own
  // scope — exactly the cross-service replay DIV Invariant 5 (Target Isolation) exists to stop.
  if (typeof expected.target !== "string" || expected.target.length === 0)
    return {
      ok: false,
      reason:
        "expected.target is required — it must be YOUR target identifier, asserted independently of the receipt (DIV Target Isolation)",
    }
  if (!expected.approvers)
    return {
      ok: false,
      reason:
        "expected.approvers is required — the Approver key MUST come from your own trust policy, never from the receipt (DIV Invariant 3)",
    }
  // The requirement is part of the SIGNED bytes, so reading it from the payload is not circular: a
  // forged value changes the string and fails the byte comparison below.
  const requirement = parseField<Partial<ApprovalRequirementAttestation>>(
    receipt.canonicalPayload,
    "requirement",
  )
  if (!requirement || typeof requirement.requiredApprovals !== "number")
    return { ok: false, reason: "receipt payload is missing the signed approval requirement" }

  // Offline proofs carry `challengedAt` so the validity WINDOW can be bounded here, not merely at
  // mint. A proof whose window exceeds the cap is refused even though its signature is perfectly
  // good — an offline relying party has no revocation channel, so the short window is the only one.
  let challengedAt = ""
  if (offline) {
    const raw = parseField<string>(receipt.canonicalPayload, "challengedAt")
    if (typeof raw !== "string" || raw.length === 0)
      return { ok: false, reason: "offline proof is missing challengedAt" }
    challengedAt = raw
    const challengedMs = Date.parse(challengedAt)
    if (Number.isNaN(challengedMs))
      return { ok: false, reason: "challengedAt is not a valid RFC3339 timestamp" }
    // An unparseable `expiresAt` must be refused HERE rather than skipping the window cap and relying
    // on the expiry check below — that check is disabled by `allowExpired`, so the combination left
    // the cap unenforced on a proof whose window could not be computed at all.
    const expiryMs = Date.parse(expiresAt)
    if (Number.isNaN(expiryMs)) return { ok: false, reason: "expiresAt is not a valid RFC3339 timestamp" }
    const windowMinutes = (expiryMs - challengedMs) / 60_000
    if (windowMinutes > MAX_OFFLINE_WINDOW_MINUTES)
      return {
        ok: false,
        reason: `offline window is ${windowMinutes.toFixed(1)} minutes, over the ${MAX_OFFLINE_WINDOW_MINUTES}-minute maximum`,
      }
    if (windowMinutes < 0) return { ok: false, reason: "offline proof expires before it was challenged" }

    // A hardware-key policy CANNOT be satisfied offline (DIV §5a.3 step 4, §5a.8). WebAuthn needs a
    // secure context and an RP ID that an offline signing surface will not match, so an offline
    // witness is always a bare key. Accepting the proof anyway would silently downgrade the very
    // policy the approver attested to, so it is refused instead — fail closed, and say why.
    if (requirement.requireHardwareKey === true)
      return {
        ok: false,
        reason:
          "the signed policy requires a hardware-backed WebAuthn credential, which cannot be produced offline — this action cannot be approved out of band (DIV §5a.3)",
      }
  }

  // A delegation substitutes WHO may approve and HOW MANY, and nothing else (DIV §5a.6). Every
  // agreement check below is on the SIGNED bytes of both proofs, so neither can widen the other.
  let delegatedTo: string[] | undefined
  let delegatedQuorum: number | undefined
  if (opts.delegation) {
    const d = opts.delegation
    // The delegation must be for the action actually being executed. `expected.*` is what the caller
    // is about to run, so comparing against it — not against the receipt — is what stops a delegation
    // for one action authorizing another.
    if (d.target !== expected.target)
      return { ok: false, reason: "the delegation was issued for a different target" }
    if (d.actionType !== expected.actionType)
      return { ok: false, reason: "the delegation was issued for a different actionType" }
    let delegationParams: string
    let executingParams: string
    try {
      delegationParams = stableStringify(d.params)
      executingParams = stableStringify(expected.params)
    } catch (err) {
      return { ok: false, reason: `params are not canonicalizable: ${(err as Error).message}` }
    }
    if (delegationParams !== executingParams)
      return { ok: false, reason: "the delegation was issued for different params" }
    // The offline payload's signed quorum must equal the delegated one, so the operators signed the
    // policy their signatures are being counted toward rather than a different one.
    if (requirement.requiredApprovals !== d.delegatedQuorum)
      return {
        ok: false,
        reason: `offline proof declares ${requirement.requiredApprovals} required approval(s) but the delegation delegates a quorum of ${d.delegatedQuorum}`,
      }
    delegatedTo = d.delegatedTo
    delegatedQuorum = d.delegatedQuorum
  }

  const rebuild = {
    target: expected.target,
    actionType: expected.actionType,
    display: receipt.actionDescription,
    params: expected.params,
    requester: receipt.requester,
    requirement: {
      requiredApprovals: requirement.requiredApprovals,
      requireHardwareKey: requirement.requireHardwareKey === true,
      allowedAaguids: Array.isArray(requirement.allowedAaguids) ? requirement.allowedAaguids : [],
      requesterCannotApprove: requirement.requesterCannotApprove === true,
    },
    nonce: parseNonce(receipt.canonicalPayload),
    expiresAt,
  }

  let recomputed: string
  try {
    recomputed = offline
      ? canonicalOfflineIntentPayload({ ...rebuild, challengedAt })
      : canonicalIntentPayload(rebuild)
  } catch (err) {
    // Almost always expected.params containing a Date/Map/class instance — say so, rather than
    // reporting it as a params mismatch and sending the caller hunting for a tampering that isn't there.
    return { ok: false, reason: `expected.params is not canonicalizable: ${(err as Error).message}` }
  }
  if (recomputed !== receipt.canonicalPayload)
    return {
      ok: false,
      reason: "target/params/actionType do not match what was approved",
    }

  // Expiration (DIV §5 step 8 / §6.2). Fail-closed by default; opt out only for audit re-verification.
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
  // consciously accepted policy pre-approval must opt in with `allowAutoApproved: true`.
  //
  // An OFFLINE proof is never auto-approved: the entire point is that humans signed it out of band, so
  // an unsigned one is a contradiction and `allowAutoApproved` must not rescue it.
  if (receipt.sigAlg === "AUTO_APPROVED" && offline) {
    return {
      ok: false,
      autoApproved: true,
      reason: "an offline approval cannot be auto-approved — there is no human signature to verify",
    }
  }
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
  const witnesses = witnessesOf(receipt)
  if (witnesses.length === 0) return { ok: false, reason: "receipt missing signature material" }
  // The witness list is attacker-supplied and every entry costs an ECDSA verification per candidate
  // key. A real quorum is single digits; 20 000 witnesses measured at 3.6s of blocked event loop and
  // a 1.16 MB failure string, in the relying party's process, before the action it gates. Bound it.
  if (witnesses.length > MAX_WITNESSES) {
    return {
      ok: false,
      reason: `receipt carries ${witnesses.length} witnesses, above the ${MAX_WITNESSES} this verifier will process`,
    }
  }

  // Count DISTINCT approvers whose signature verifies under a key we independently trust. Distinct is
  // load-bearing: without it, N copies of one approver's signature would satisfy an N-of-M quorum.
  const verifiedSigners = new Set<string>()
  const failures: string[] = []
  for (const witness of witnesses) {
    const candidates = candidateKeys(expected.approvers, witness, delegatedTo)
    if ("reason" in candidates) {
      failures.push(candidates.reason)
      continue
    }
    // Try each trusted candidate; the one that verifies identifies the approver. In DID mode the
    // candidates are all keys held by that one DID, so a match still counts as a single approver.
    let matched: string | null = null
    let lastReason = "signature does not verify against any trusted approver key"
    for (const candidate of candidates.keys) {
      const attempt = verifyWitness(witness, candidate.key, receipt.canonicalPayload, opts)
      if (attempt.ok) {
        matched = candidate.identity
        break
      }
      lastReason = attempt.reason
    }
    if (matched === null) {
      failures.push(lastReason)
      continue
    }
    // A hardware-key policy is only partially checkable offline (see ApprovalRequirementAttestation):
    // a bare P-256 key carries no attestation at all, so it can never satisfy the requirement, while a
    // WebAuthn assertion is accepted without being able to prove the authenticator's model.
    if (requirement.requireHardwareKey === true && witness.sigAlg !== "WEBAUTHN") {
      failures.push(
        `signer ${witness.signerDid} used a bare key, but the signed policy requires a hardware-backed WebAuthn credential`,
      )
      continue
    }
    // Four-eyes, verified offline against the requester in the same signed payload.
    if (requirement.requesterCannotApprove === true && witness.signerDid === receipt.requester.did) {
      failures.push(`four-eyes: requester ${witness.signerDid} cannot approve their own action`)
      continue
    }
    verifiedSigners.add(matched)
  }

  // Under a delegation the quorum is the DELEGATED one. It was already checked to equal the offline
  // payload's signed `requiredApprovals`, so this is the same number by a different route — stated
  // explicitly so the substitution is visible at the point it takes effect.
  const required = Math.max(1, delegatedQuorum ?? requirement.requiredApprovals)
  if (verifiedSigners.size < required) {
    // Report the first few reasons only. Folding every failure into one string is what turned a long
    // witness list into a megabyte of error text; the leading reasons are the diagnostic ones anyway.
    const shown = failures.slice(0, MAX_REPORTED_FAILURES)
    const elided = failures.length - shown.length
    const detail = shown.length > 0 ? ` (${shown.join("; ")}${elided > 0 ? `; +${elided} more` : ""})` : ""
    return {
      ok: false,
      reason: `quorum not met: ${verifiedSigners.size} of ${required} required approver signatures verified${detail}`,
    }
  }
  // Sorted, not insertion order: verify-go, verify-rust and sdk-python all return this sorted, and
  // Go's type even documents itself as mirroring this field. It is a RESULT, never signed bytes, so
  // ordering cannot affect a verdict — but a caller that logs or diffs it should not see four
  // different answers depending on which SDK produced them.
  return { ok: true, signers: [...verifiedSigners].sort() }
}

/** A delegation whose own signature, quorum and window have been verified by `verifyDelegation`. */
export interface VerifiedDelegation {
  /** Identities permitted to approve at incident time. Enforced against the witness DIDs. */
  delegatedTo: string[]
  /** How many distinct members of `delegatedTo` must sign. */
  delegatedQuorum: number
  /** The single action this delegation covers. All three must equal what is being executed. */
  target: string
  actionType: string
  params: Record<string, unknown>
  /** The delegation's OWN nonce — for the audit trail, never for authorization. */
  nonce: string
  /** Who signed the delegation itself. */
  signers: string[]
  expiresAt: string
}

/**
 * Verify a DELEGATION (DIV §5a.6 step 1) — a statement, signed in advance by the ordinary quorum, that
 * names local operators who may approve one pre-declared action while the gateway is unreachable.
 *
 * Deliberately a SEPARATE function from `verifyApprovalReceipt`, which refuses this payload type
 * outright. A delegation authorizes nothing, and the only way to keep that true structurally is to
 * make it impossible to hand one to the approval verifier and get an `ok: true` back. What you get here
 * is a `VerifiedDelegation` — an input to a later approval check, never a substitute for one.
 *
 * `approvers` MUST be the ORDINARY approver set (from your trust bundle), not the delegated operators:
 * the point of the check is that the people entitled to approve this action are the ones who signed
 * away that entitlement.
 */
export function verifyDelegation(
  receipt: ApprovalReceipt,
  expected: {
    /** The ORDINARY approvers entitled to delegate. Resolved from your own trust policy. */
    approvers: ApproverTrustAnchor
    /** YOUR target identifier, asserted independently of the delegation (DIV Target Isolation). */
    target: string
    actionType: string
    params: Record<string, unknown>
  },
  opts: VerifyReceiptOptions = {},
): { ok: boolean; reason?: string; delegation?: VerifiedDelegation } {
  const version = parseVersion(receipt.canonicalPayload)
  if (version !== DIV_VERSION)
    return { ok: false, reason: `unsupported DIV payload version (${version || "unparseable"})` }
  if (parseField(receipt.canonicalPayload, "type") !== DIV_DELEGATION_TYPE)
    return { ok: false, reason: "payload is not a div-delegation" }

  const delegatedTo = parseField<unknown>(receipt.canonicalPayload, "delegatedTo")
  const delegatedQuorum = parseField<unknown>(receipt.canonicalPayload, "delegatedQuorum")
  if (!Array.isArray(delegatedTo) || delegatedTo.some((d) => typeof d !== "string" || d.length === 0))
    return { ok: false, reason: "delegation is missing a valid delegatedTo set" }
  if (typeof delegatedQuorum !== "number" || !Number.isInteger(delegatedQuorum) || delegatedQuorum < 1)
    return { ok: false, reason: "delegation is missing a valid delegatedQuorum" }
  // Deduplicate before the size check: a delegatedTo listing one operator three times would otherwise
  // appear to support a 3-of-3 quorum that one person could satisfy alone.
  const distinctDelegates = [...new Set(delegatedTo as string[])]
  if (distinctDelegates.length < delegatedQuorum)
    return {
      ok: false,
      reason: `delegation names ${distinctDelegates.length} distinct operator(s) but delegates a quorum of ${delegatedQuorum} — it can never be satisfied`,
    }

  const sealedAt = parseField<string>(receipt.canonicalPayload, "sealedAt")
  const expiresAt = parseField<string>(receipt.canonicalPayload, "expiresAt")
  if (typeof sealedAt !== "string" || sealedAt.length === 0)
    return { ok: false, reason: "delegation is missing sealedAt" }
  if (typeof expiresAt !== "string" || expiresAt.length === 0)
    return { ok: false, reason: "delegation is missing expiresAt" }
  const sealedMs = Date.parse(sealedAt)
  const expiryMs = Date.parse(expiresAt)
  if (Number.isNaN(sealedMs)) return { ok: false, reason: "sealedAt is not a valid RFC3339 timestamp" }
  if (Number.isNaN(expiryMs)) return { ok: false, reason: "expiresAt is not a valid RFC3339 timestamp" }
  const windowHours = (expiryMs - sealedMs) / 3_600_000
  if (windowHours < 0) return { ok: false, reason: "delegation expires before it was sealed" }
  if (windowHours > MAX_DELEGATION_WINDOW_HOURS)
    return {
      ok: false,
      reason: `delegation window is ${windowHours.toFixed(1)} hours, over the ${MAX_DELEGATION_WINDOW_HOURS}-hour maximum`,
    }

  // Reconstruct and check the signature by delegating to the ordinary verifier. Building the expected
  // bytes here and comparing them ourselves would be a second implementation of the check that already
  // exists — and the one place the two could disagree is the place it matters most. The trick is that
  // the reconstruction needs the delegation-specific fields, which `verifyApprovalReceipt` will not
  // produce, so the byte comparison happens here and the CRYPTO happens there.
  const nonce = parseNonce(receipt.canonicalPayload)
  if (!receipt.requester) return { ok: false, reason: "delegation missing requester" }
  const requirement = parseField<Partial<ApprovalRequirementAttestation>>(
    receipt.canonicalPayload,
    "requirement",
  )
  if (!requirement || typeof requirement.requiredApprovals !== "number")
    return { ok: false, reason: "delegation payload is missing the signed approval requirement" }
  if (typeof expected.target !== "string" || expected.target.length === 0)
    return {
      ok: false,
      reason:
        "expected.target is required — it must be YOUR target identifier, asserted independently of the delegation (DIV Target Isolation)",
    }
  if (!expected.approvers)
    return {
      ok: false,
      reason:
        "expected.approvers is required — the delegating approvers MUST come from your own trust policy, never from the delegation (DIV Invariant 3)",
    }

  let recomputed: string
  try {
    recomputed = canonicalDelegationPayload({
      target: expected.target,
      actionType: expected.actionType,
      display: receipt.actionDescription,
      params: expected.params,
      requester: receipt.requester,
      requirement: {
        requiredApprovals: requirement.requiredApprovals,
        requireHardwareKey: requirement.requireHardwareKey === true,
        allowedAaguids: Array.isArray(requirement.allowedAaguids) ? requirement.allowedAaguids : [],
        requesterCannotApprove: requirement.requesterCannotApprove === true,
      },
      delegatedTo: delegatedTo as string[],
      delegatedQuorum,
      nonce,
      sealedAt,
      expiresAt,
    })
  } catch (err) {
    return { ok: false, reason: `expected.params is not canonicalizable: ${(err as Error).message}` }
  }
  if (recomputed !== receipt.canonicalPayload)
    return { ok: false, reason: "target/params/actionType do not match what was delegated" }

  // Expiry, then the signatures and quorum. `allowExpired` is honoured for forensic re-verification,
  // exactly as on the approval path.
  if (!opts.allowExpired) {
    const nowMs = (opts.asOf ?? new Date()).getTime()
    const skewMs = (opts.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS) * 1000
    if (nowMs > expiryMs + skewMs)
      return {
        ok: false,
        reason: "delegation has expired (pass { allowExpired: true } for audit re-verification)",
      }
  }

  if (receipt.sigAlg === "AUTO_APPROVED")
    return {
      ok: false,
      reason:
        "a delegation cannot be auto-approved — delegating approval authority requires human signatures",
    }
  const witnesses = witnessesOf(receipt)
  if (witnesses.length === 0) return { ok: false, reason: "delegation missing signature material" }
  // Same resource bound as the approval path: signature verification is the expensive step, and a
  // delegation is verified in the same process, right before the same irreversible action. Go, Rust
  // and Python bound both paths; leaving this one open re-creates the measured 3.6s event-loop stall
  // one function over.
  if (witnesses.length > MAX_WITNESSES) {
    return {
      ok: false,
      reason: `delegation carries ${witnesses.length} witnesses, above the ${MAX_WITNESSES} this verifier will process`,
    }
  }

  const verifiedSigners = new Set<string>()
  const failures: string[] = []
  for (const witness of witnesses) {
    const candidates = candidateKeys(expected.approvers, witness)
    if ("reason" in candidates) {
      failures.push(candidates.reason)
      continue
    }
    let matched: string | null = null
    let lastReason = "signature does not verify against any trusted approver key"
    for (const candidate of candidates.keys) {
      const attempt = verifyWitness(witness, candidate.key, receipt.canonicalPayload, opts)
      if (attempt.ok) {
        matched = candidate.identity
        break
      }
      lastReason = attempt.reason
    }
    if (matched === null) {
      failures.push(lastReason)
      continue
    }
    if (requirement.requireHardwareKey === true && witness.sigAlg !== "WEBAUTHN") {
      failures.push(
        `signer ${witness.signerDid} used a bare key, but the signed policy requires a hardware-backed WebAuthn credential`,
      )
      continue
    }
    if (requirement.requesterCannotApprove === true && witness.signerDid === receipt.requester.did) {
      failures.push(`four-eyes: requester ${witness.signerDid} cannot delegate to themselves`)
      continue
    }
    verifiedSigners.add(matched)
  }

  const required = Math.max(1, requirement.requiredApprovals)
  if (verifiedSigners.size < required) {
    // Folded like the approval path: an attacker-shaped witness list must not be able to inflate the
    // reason string (the 1.16 MB error the approval path once produced).
    const shown = failures.slice(0, MAX_REPORTED_FAILURES)
    const elided = failures.length - shown.length
    const detail = shown.length > 0 ? ` (${shown.join("; ")}${elided > 0 ? `; +${elided} more` : ""})` : ""
    return {
      ok: false,
      reason: `delegation quorum not met: ${verifiedSigners.size} of ${required} required approver signatures verified${detail}`,
    }
  }

  return {
    ok: true,
    delegation: {
      // The DEDUPLICATED set: this is what gets enforced against witness DIDs later, and a duplicate
      // entry must not create the illusion of a larger eligible pool.
      delegatedTo: distinctDelegates,
      delegatedQuorum,
      target: expected.target,
      actionType: expected.actionType,
      params: expected.params,
      nonce,
      signers: [...verifiedSigners].sort(), // sorted, as in the quorum path above
      expiresAt,
    },
  }
}

// ─── Audit ledger inclusion proofs ───────────────────────────────────────────
// The other half of "inspect-it-yourself": confirm an audit event is committed to Intyga's append-only
// Merkle log against an independently anchored daily root. Same zero-dependency, no-secret contract as
// the approval-receipt verifier above. See docs/DEWP.md for the format and ledger/roots for the
// published end-of-day roots. Surfaced on the CLI as `intyga audit-verify`.

export {
  ALGORITHM_REGISTRY,
  type AlgorithmRegistry,
  AUDIT_PROFILE,
  BUNDLE_KIND,
  type BundleVerification,
  type CheckResult,
  DEWP_PROTOCOL,
  DEWP_VERSION,
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
  type EvidenceBundle,
  type EvidenceEntry,
  type EvidenceVerification,
  type EvidenceVerifyOptions,
  type RedactionRecord,
  verifyEvidenceBundle,
} from "./ledger-evidence.js"
export {
  type AnchorKeyResolver,
  type AnchorPolicy,
  type AnchorQuorumResult,
  type ExternalAnchorKeys,
  anchorDigest,
  anchorDigestHex,
  anchorPreimage,
  signAnchor,
  type SignedAnchor,
  verifyAnchorQuorum,
  verifyAnchorSignature,
} from "./ledger-anchor.js"
export {
  type ChainInput,
  type ChainVerification,
  chainHash,
  chainPreimage,
  GENESIS_PREV_CHAIN_HASH,
  type RootsChainEntry,
  verifyRootsChain,
} from "./ledger-chain.js"
export {
  parseRekorEvidence,
  type RekorEvidence,
  type RekorVerification,
  rekorPayloadHashFor,
  verifyRekorAnchor,
} from "./ledger-rekor.js"
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
