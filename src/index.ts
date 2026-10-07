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
  if (t === "string") return canonicalString(value as string)
  if (t === "boolean") return JSON.stringify(value)
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
  if (Array.isArray(value)) {
    const items: string[] = []
    for (let i = 0; i < value.length; i++) {
      if (!Object.hasOwn(value, i)) throw new NonCanonicalValue("sparse arrays are not JSON data")
      items.push(stableStringify(value[i]))
    }
    return `[${items.join(",")}]`
  }
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
  return `{${keys.map((k) => `${canonicalString(k)}:${stableStringify(obj[k])}`).join(",")}}`
}

// An unpaired UTF-16 surrogate (a high surrogate with no low one after it, or a low one with no high
// one before it). Lookarounds rather than `String.prototype.isWellFormed`, which Node 18 lacks.
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/

/**
 * A string (value or member name) as RFC 8785 serializes it, refusing one that is not valid Unicode.
 * RFC 8785 builds on I-JSON (RFC 7493 §2.1), which forbids unpaired surrogates. `JSON.stringify`
 * would escape one as `\udXXX` — and then a receipt carrying one verified here while Go (U+FFFD),
 * Rust and Python (refusal) could not agree on the same input (DIV §4.1). Mirrors mcp-schemas.
 */
function canonicalString(s: string): string {
  if (LONE_SURROGATE.test(s))
    throw new NonCanonicalValue("a string contains an unpaired UTF-16 surrogate, which is not I-JSON")
  return JSON.stringify(s)
}

/** The requesting workload's identity, as bound into a DIV Intent Payload. Mirrors mcp-schemas. */
export interface RequesterIdentity {
  did: string
  attestation: { method: string; issuer: string; subject: string } | null
}

/** Agent-only DIV v1 claims. Configuration and execution truth are checked by the RP's PEP. */
export interface AgentIntentContext {
  action: {
    reversibility: "reversible" | "irreversible"
    amount: { amount: string; currency: string } | null
  }
  agent: { label: string; configDigest: string; delegatedBy: string | null }
  session: {
    id: string
    seq: string
    prev: string | null
    aggregate: { amount: string; currency: string } | null
  }
  nbf: string
}

const AGENT_DIGEST = /^sha256:[0-9a-f]{64}$/
const AGENT_DECIMAL = /^(?:0|[1-9][0-9]{0,29})(?:\.[0-9]{1,9})?$/
const AGENT_SEQUENCE = /^[1-9][0-9]{0,17}$/
const AGENT_CURRENCY = /^[A-Z]{3}$/

export function validateAgentIntentContext(context: AgentIntentContext, expiresAt: string): void {
  const { action, agent, session, nbf } = context
  if (!action || !["reversible", "irreversible"].includes(action.reversibility))
    throw new Error("invalid agent action reversibility")
  if (!agent?.label || agent.label.length > 200 || !AGENT_DIGEST.test(agent.configDigest))
    throw new Error("invalid agent identity or configuration digest")
  if (agent.label.normalize("NFC") !== agent.label || session?.id?.normalize("NFC") !== session?.id)
    throw new Error("agent labels and session identifiers must be NFC")
  if (
    !Object.hasOwn(agent, "delegatedBy") ||
    (agent.delegatedBy !== null && !AGENT_DIGEST.test(agent.delegatedBy))
  )
    throw new Error("invalid parent authority digest")
  if (!session?.id || !AGENT_DIGEST.test(session.id) || !AGENT_SEQUENCE.test(session.seq))
    throw new Error("invalid agent session identity or sequence")
  if (
    !Object.hasOwn(session, "prev") ||
    (session.seq === "1") !== (session.prev === null) ||
    (session.prev !== null && !AGENT_DIGEST.test(session.prev))
  )
    throw new Error("invalid agent session predecessor")
  if (!Object.hasOwn(action, "amount") || !Object.hasOwn(session, "aggregate"))
    throw new Error("invalid agent monetary amount")
  for (const value of [action.amount, session.aggregate]) {
    if (value && (!AGENT_DECIMAL.test(value.amount) || !AGENT_CURRENCY.test(value.currency)))
      throw new Error("invalid agent monetary amount")
  }
  if (
    (action.amount === null) !== (session.aggregate === null) ||
    (action.amount && session.aggregate && action.amount.currency !== session.aggregate.currency)
  )
    throw new Error("agent monetary amount and aggregate disagree")
  const from = Date.parse(nbf)
  const to = parseRfc3339Ms(expiresAt)
  if (
    !Number.isFinite(from) ||
    !Number.isFinite(to) ||
    to <= from ||
    to - from > 300_000 ||
    new Date(from).toISOString() !== nbf ||
    new Date(to).toISOString() !== expiresAt
  )
    throw new Error("agent intent must use canonical UTC times within five minutes")
}

// RFC 3339 §5.6 `date-time`, strictly: four-digit year, uppercase `T`, seconds present, an optional
// fraction of 1–9 digits, and an explicit `Z` or `±hh:mm` zone. Ranges are checked separately below.
const RFC3339_DATE_TIME =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-](\d{2}):(\d{2}))$/

/**
 * Milliseconds since the epoch for a signed RFC 3339 timestamp, or NaN (DIV §6.2).
 *
 * `Date.parse` alone is far too lenient for signed times: it accepts a bare date, a zone-less time
 * (read in the HOST's timezone, so the verdict moved with the machine's TZ setting), lowercase
 * separators and 30 February, which it rolls into March. Every port applies this same grammar:
 * the date must exist, hours 00–23, minutes and seconds 00–59 (no leap second — Go and ECMAScript
 * refuse `:60`), offset hours 00–23 and minutes 00–59.
 */
export function parseRfc3339Ms(value: unknown): number {
  if (typeof value !== "string") return Number.NaN
  const m = RFC3339_DATE_TIME.exec(value)
  if (!m) return Number.NaN
  const [year, month, day, hour, minute, second] = m.slice(1, 7).map(Number) as [
    number,
    number,
    number,
    number,
    number,
    number,
  ]
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]
  if (days === undefined || day < 1 || day > days || hour > 23 || minute > 59 || second > 59)
    return Number.NaN
  if (m[7] !== undefined && (Number(m[7]) > 23 || Number(m[8]) > 59)) return Number.NaN
  const ms = Date.parse(value)
  return Number.isFinite(ms) ? ms : Number.NaN
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
 * Agent authority (DIV §5b): a quorum-signed statement of STANDING SCOPE for one agent. Authorizes
 * no action on its own; `verifyApprovalReceipt` refuses it outright, and `verifyAgentAuthority` is
 * the only door. Mirrors mcp-schemas.
 */
export const DIV_AGENT_AUTHORITY_TYPE = "div-agent-authority"

/**
 * Platform hash-only intent (DIV §5c): an integrating platform's subject signs the DIGEST of the
 * platform's own canonical payload. `verifyApprovalReceipt` refuses it outright;
 * `verifyPlatformReceipt` is the only door. Mirrors mcp-schemas.
 */
export const DIV_PLATFORM_INTENT_TYPE = "div-platform-intent"

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
 *    assertion rather than a bare P-256 key, and it refuses one whose signed authenticatorData says
 *    Backup Eligible or Backup State (a synced passkey announcing itself). An assertion carries no
 *    attestation, though, so BE=0 is the authenticator's claim, not proof of a discrete security key.
 *  - `allowedAaguids` — NOT checkable offline. The AAGUID lives in attestedCredentialData, which is
 *    present at REGISTRATION, not in an assertion. Only the gateway (which stored it at enrollment)
 *    can enforce the model. What a verifier CAN do is refuse what obviously cannot satisfy it: a
 *    non-empty allowlist is treated exactly like `requireHardwareKey` — a bare-key witness is refused
 *    and an offline proof is refused outright (`requiresHardwareCredential`).
 *  - `signerClass` — PARTIALLY checkable, and differently per witness kind. For a WEBAUTHN witness
 *    the UV flag (already required by `verifyWebAuthnSignature`) is cryptographic evidence a
 *    user-verification ceremony — a human gesture — happened at signing. An ES256 witness carries no
 *    signer-class evidence at all: there the class rests on the issuing deployment's signing-time
 *    enforcement, or, for an offline proof, on the delegation ceremony that named the operators.
 *    The verifier's own obligation is narrower and absolute: REFUSE any value it does not
 *    recognize (only "human" is defined today), so a future signer class can never verify as
 *    human-approved by default. It deliberately does NOT reject ES256 witnesses under
 *    `signerClass: "human"` — humans legitimately sign with raw P-256 keys (offline break-glass);
 *    a deployment wanting cryptographic proof of the ceremony pins `requireHardwareKey`.
 */
/**
 * Whether a signed requirement can only be met by a hardware-backed WebAuthn credential: an explicit
 * `requireHardwareKey`, OR a non-empty `allowedAaguids` model allowlist. The two are the same class of
 * policy for every check a verifier can make — a bare key satisfies neither, and neither can be met
 * offline — so they are refused together. Treating the allowlist as "not checkable, so not checked"
 * let a bare software key satisfy a YubiKey-only rule on every offline path.
 */
export function requiresHardwareCredential(requirement: {
  requireHardwareKey?: unknown
  allowedAaguids?: unknown
}): boolean {
  return (
    requirement.requireHardwareKey === true ||
    (Array.isArray(requirement.allowedAaguids) && requirement.allowedAaguids.length > 0)
  )
}

export interface ApprovalRequirementAttestation {
  requiredApprovals: number
  requireHardwareKey: boolean
  allowedAaguids: string[]
  requesterCannotApprove: boolean
  /** Required signer class — `"human"` is the only value defined today. Unrecognized values are refused. */
  signerClass: string
}

/**
 * The one signer class defined by DIV today (docs/DIV.md §4.3.2). Mirrors mcp-schemas, like
 * DIV_VERSION — this package deliberately imports nothing from it.
 */
export const SIGNER_CLASS_HUMAN = "human"

/** The signer classes this verifier knows how to reason about (DIV §4.3.2). Mirrors mcp-schemas. */
const KNOWN_SIGNER_CLASSES = new Set([SIGNER_CLASS_HUMAN])

/**
 * Extract and validate `requirement.signerClass` from a parsed signed requirement. FAIL CLOSED both
 * ways: a payload with no class predates (or dropped) the field and cannot be verified by this
 * version, and an unrecognized class must never verify as if it were human-approved — that is the
 * entire point of putting the class in the signed bytes.
 */
function parseSignerClass(
  requirement: Partial<ApprovalRequirementAttestation>,
): { ok: true; signerClass: string } | { ok: false; reason: string } {
  const sc = requirement.signerClass
  if (typeof sc !== "string" || sc.length === 0)
    return { ok: false, reason: "the signed requirement is missing signerClass (DIV §4.3.2)" }
  if (!KNOWN_SIGNER_CLASSES.has(sc))
    return {
      ok: false,
      reason: `the signed requirement declares signerClass "${sc}", which this verifier does not recognize — refusing rather than treating it as human-approved (DIV §4.3.2)`,
    }
  return { ok: true, signerClass: sc }
}

/**
 * DIV §4.3.4 / §5-step-3c. `evidence` is REQUIRED in the signed bytes and MUST be `null` in v1.
 *
 * Read out of `canonicalPayload`, never an envelope echo — there is deliberately none (§4.4.1), and
 * a forged value inside the signed bytes fails the byte comparison anyway.
 *
 * `parseField` deliberately is NOT used here: it returns `undefined` for an absent key, for a failed
 * JSON parse, AND for a present `null`, so it cannot express the one distinction this check is made
 * of. Collapsing "absent" into "null" turns the whole reservation into a no-op — an evidence-
 * conditioned payload would then verify as though it were unconditioned, which is the exact outcome
 * §4.3.4 exists to prevent.
 */
function parseEvidence(canonical: string): { ok: true } | { ok: false; reason: string } {
  let parsed: unknown
  try {
    parsed = JSON.parse(canonical)
  } catch {
    return { ok: false, reason: "the signed payload is not valid JSON" }
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, reason: "the signed payload is not a JSON object" }
  }
  if (!("evidence" in parsed)) {
    return { ok: false, reason: "the signed payload is missing evidence (DIV §4.3.4)" }
  }
  if ((parsed as Record<string, unknown>).evidence !== null) {
    return {
      ok: false,
      reason:
        "the signed payload declares an evidence condition, which this verifier does not support — refusing rather than treating it as unconditioned (DIV §4.3.4)",
    }
  }
  return { ok: true }
}

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
  requirement: ApprovalRequirementAttestation
  nonce: string
  expiresAt: string
  agentContext?: AgentIntentContext
}): string {
  if (input.agentContext) validateAgentIntentContext(input.agentContext, input.expiresAt)
  return stableStringify({
    v: DIV_VERSION,
    type: DIV_INTENT_TYPE,
    target: input.target,
    actionType: input.actionType,
    display: input.display,
    params: input.params,
    // DIV §4.3.4. Reserved, and REQUIRED in the bytes: `null` is the payload's explicit statement
    // that no external-evidence condition applied, exactly as `requester.attestation`'s null is.
    // Hardcoded rather than taken from `input` on purpose — an optional field a call site forgets is
    // absent from Object.keys, so stableStringify never sees it and never throws, and the omission
    // surfaces later as an unreproducible signature. Non-null values are a later spec version.
    evidence: null,
    ...commonSignedFields(input.requester, input.requirement),
    nonce: input.nonce,
    // The four agent-extension keys by NAME, never a spread: a context object carrying any other
    // top-level key (`target`, `params`, …) would otherwise overwrite the signed fields above, so a
    // relying party that filled `agentContext` from the receipt itself would verify the receipt
    // against its own bytes. The Go, Rust, Java and Python builders copy exactly these four.
    ...(input.agentContext
      ? {
          action: input.agentContext.action,
          agent: input.agentContext.agent,
          session: input.agentContext.session,
          nbf: input.agentContext.nbf,
          exp: input.expiresAt,
        }
      : { expiresAt: input.expiresAt }),
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
      signerClass: requirement.signerClass,
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
    // DIV §4.3.4. Reserved, and REQUIRED in the bytes: `null` is the payload's explicit statement
    // that no external-evidence condition applied, exactly as `requester.attestation`'s null is.
    // Hardcoded rather than taken from `input` on purpose — an optional field a call site forgets is
    // absent from Object.keys, so stableStringify never sees it and never throws, and the omission
    // surfaces later as an unreproducible signature. Non-null values are a later spec version.
    evidence: null,
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

/**
 * Canonical AGENT AUTHORITY payload (DIV §5b) — byte-identical to
 * mcp-schemas.canonicalAgentAuthorityPayload; parity is enforced by `canonical-parity.test.ts`.
 *
 * Not a delegation: `div-delegation` deliberately covers exactly one action, forbids wildcards and
 * caps its window at 72 hours, because it pre-authorizes WHO MAY APPROVE at incident time. An
 * authority is governance enforced online — it may carry a scope (patterns) and a long validity
 * precisely because it authorizes nothing offline. `actionPatterns` is sorted because it is a SET,
 * exactly as `allowedAaguids` is.
 */
export function canonicalAgentAuthorityPayload(input: {
  target: string
  actionPatterns: string[]
  display: string
  agent: { did: string }
  parentReceiptHash?: string | null
  requester: RequesterIdentity
  requirement: ApprovalRequirementAttestation
  nonce: string
  sealedAt: string
  expiresAt: string
}): string {
  return stableStringify({
    v: DIV_VERSION,
    type: DIV_AGENT_AUTHORITY_TYPE,
    target: input.target,
    actionPatterns: [...input.actionPatterns].sort(),
    display: input.display,
    agent: { did: input.agent.did },
    parentReceiptHash: input.parentReceiptHash ?? null,
    ...commonSignedFields(input.requester, input.requirement),
    nonce: input.nonce,
    sealedAt: input.sealedAt,
    expiresAt: input.expiresAt,
  })
}

/**
 * Canonical PLATFORM HASH-ONLY INTENT payload (DIV §5c.2) — byte-parity with mcp-schemas' copy is
 * enforced by canonical-parity.test.ts. This mirror REPRODUCES bytes and does not validate the
 * digest grammar (producers normalize, verifiers reproduce); `verifyPlatformReceipt` enforces the
 * lowercase-hex rule on the RELYING PARTY's expected value instead.
 */
export function canonicalPlatformIntentPayload(input: {
  payloadHash: string
  rpId: string
  subjectExternalId: string
  signedAt: string
  expiresAt: string
  nonce: string
}): string {
  return stableStringify({
    v: DIV_VERSION,
    type: DIV_PLATFORM_INTENT_TYPE,
    hashAlg: "SHA-256",
    payloadHash: input.payloadHash,
    rpId: input.rpId,
    subject: { externalId: input.subjectExternalId },
    signedAt: input.signedAt,
    expiresAt: input.expiresAt,
    nonce: input.nonce,
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

/** DIV §4.3.2: a signed quorum is an integer ≥ 1. Zero passes §5 step 7's "at least" test vacuously. */
const isValidQuorum = (n: number): boolean => Number.isInteger(n) && n >= 1
const INVALID_QUORUM_REASON =
  "signed requirement.requiredApprovals must be an integer of at least 1 (DIV §4.3.2)"

/**
 * The MINIMUM approval requirement YOUR policy demands for this action (DIV §5 step 3d).
 *
 * The signed `requirement` is authored by whoever composed the bytes the approvers signed — the
 * issuing gateway, or any one approver composing their own payload. Its signature protects it
 * against third parties, NOT against the signers the quorum constrains: an approver who is also
 * the requester can sign `{ requiredApprovals: 1, requesterCannotApprove: false }` alone and, without
 * a floor, that receipt verifies. Supplying the floor makes the verifier refuse any signed
 * requirement weaker than it, before a single signature is counted.
 *
 * Without a floor the verifier proves only the signers' OWN stated quorum. Supply one whenever you
 * hold the approval rule (a trust bundle, a pinned policy, your own configuration).
 *
 * Only strictly weaker values are refused: a signed requirement at least as strict passes, and the
 * signed value is what is then enforced. `allowedAaguids` is not floored — express a model
 * restriction as `requireHardwareKey`, which a verifier can at least partially check.
 */
export interface RequirementFloor {
  /** Integer ≥ 1. The signed `requiredApprovals` must be at least this. */
  requiredApprovals: number
  /** When true, the signed requirement must also forbid the requester approving. Defaults to false. */
  requesterCannotApprove?: boolean
  /** When true, the signed requirement must also demand a hardware key. Defaults to false. */
  requireHardwareKey?: boolean
}

/** The reason stem every port uses when a signed requirement is below the caller's floor. */
export const WEAKER_REQUIREMENT_REASON = "signed requirement is weaker than the relying party's policy"

/**
 * DIV §5 step 3d. `null` when no floor was supplied or the signed requirement meets it. Fails CLOSED
 * on a malformed floor: a floor the caller got wrong must not silently become "no floor".
 */
function requirementFloorProblem(
  signed: Partial<ApprovalRequirementAttestation>,
  floor: RequirementFloor | undefined,
): string | null {
  if (floor === undefined || floor === null) return null
  if (
    typeof floor !== "object" ||
    typeof floor.requiredApprovals !== "number" ||
    !isValidQuorum(floor.requiredApprovals) ||
    (floor.requesterCannotApprove !== undefined && typeof floor.requesterCannotApprove !== "boolean") ||
    (floor.requireHardwareKey !== undefined && typeof floor.requireHardwareKey !== "boolean")
  )
    return "expected.requirement is malformed: requiredApprovals must be an integer of at least 1 and the flags booleans"
  const signedApprovals = signed.requiredApprovals ?? 0
  if (signedApprovals < floor.requiredApprovals)
    return `${WEAKER_REQUIREMENT_REASON}: it requires ${signedApprovals} approval(s), the policy ${floor.requiredApprovals} (DIV §5 step 3d)`
  if (floor.requesterCannotApprove === true && signed.requesterCannotApprove !== true)
    return `${WEAKER_REQUIREMENT_REASON}: it does not forbid the requester approving (DIV §5 step 3d)`
  if (floor.requireHardwareKey === true && signed.requireHardwareKey !== true)
    return `${WEAKER_REQUIREMENT_REASON}: it does not require a hardware key (DIV §5 step 3d)`
  return null
}

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
 *
 * SELF-CERTIFYING DIDs need no resolver. A pinned DID of the form `did:intyga:key:<fingerprint>`
 * (see {@link SELF_CERTIFYING_DID_PREFIX}) is itself a commitment to the enrolled public key, so the
 * witness-carried key can be validated against the DID by hashing — no key distribution at all.
 * `resolveKey` is therefore optional: it is required only for pinned DIDs that are NOT
 * self-certifying, and verification fails closed with an explicit reason when such a DID is
 * encountered without one.
 *
 * PRECEDENCE: when `resolveKey` DOES return keys for a self-certifying DID, those keys are the
 * anchor and the hash commitment is not consulted. That is what lets a deployment widen the DID to
 * the person's later-enrolled credentials, and — the security-relevant direction — NARROW it: a
 * compromised credential is dropped by mapping the DID to the remaining keys, which a
 * commitment-always-wins rule would silently keep trusting.
 */
export type ApproverTrustAnchor =
  | { publicKeys: string[]; dids?: undefined; resolveKey?: undefined }
  | {
      dids: string[]
      resolveKey?: (did: string) => string | string[] | null
      publicKeys?: undefined
    }

/**
 * Prefix of a self-certifying Intyga DID: `did:intyga:key:<base64url(sha256(publicKey bytes))>`.
 * The identifier IS a commitment to the enrolled public key (the issuing gateway's derivation), so a
 * DID of this form can serve as a complete trust anchor entry on its own. The commitment is to the
 * EXACT enrolled key bytes — an approver signing with a different credential (say, a browser passkey
 * registered later) does not match it, and needs a `resolveKey` mapping under a stable DID instead.
 */
export const SELF_CERTIFYING_DID_PREFIX = "did:intyga:key:"

/**
 * Derive the self-certifying DID for a public key (base64; the DECODED bytes are hashed, so padded
 * and unpadded encodings of the same key derive the same DID). Mirrors the gateway's derivation.
 */
export function selfCertifyingDid(publicKeyB64: string): string {
  const digest = crypto
    .createHash("sha256")
    .update(Buffer.from(publicKeyB64, "base64"))
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "")
  return `${SELF_CERTIFYING_DID_PREFIX}${digest}`
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
  /** Independent PEP state for an AI_AGENT receipt. Never copy this from the receipt. */
  agentContext?: AgentIntentContext
  /**
   * STRONGLY RECOMMENDED. The minimum requirement YOUR approval rule demands for this action — see
   * RequirementFloor. Without it this verifier enforces only the quorum the signers themselves
   * stated, which one approver (possibly the requester) can set to 1-of-1. Under a delegation, pass
   * the ORDINARY rule: the delegated quorum must already be at least as strict (DIV §5a.5).
   */
  requirement?: RequirementFloor
}

/** Verification options. The WebAuthn expectations are mandatory for a WEBAUTHN receipt. */
export interface VerifyReceiptOptions {
  allowAutoApproved?: boolean
  /** A complete root-to-leaf, independently trusted chain is mandatory for delegated agent receipts. */
  agentAuthorityChain?: Array<{
    receipt: ApprovalReceipt
    expected: {
      approvers: ApproverTrustAnchor
      target: string
      agentDid: string
      requirement?: RequirementFloor
    }
  }>
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
   * policy their signatures are counted toward. Its expiry is rechecked at this verification's
   * evaluation time even if the successful seal verification was cached.
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
  /**
   * Wall-clock instant to evaluate time against. Defaults to `new Date()`.
   *
   * Also the reference point for the forward-dating rule (DIV §5a.3 rule 3), which — unlike expiry —
   * `allowExpired` does NOT waive: that option re-examines a proof that was valid and has lapsed,
   * which says nothing about accepting one dated in the future.
   */
  asOf?: Date
  /** Clock-skew tolerance in seconds for expiry and forward-dating. Defaults to DEFAULT_CLOCK_SKEW_SECONDS. */
  clockSkewSeconds?: number
}

// WebAuthn authenticatorData flag bits (WebAuthn L3 §6.1).
const AUTH_DATA_FLAG_UP = 0x01 // User Present
const AUTH_DATA_FLAG_UV = 0x04 // User Verified
const AUTH_DATA_FLAG_BE = 0x08 // Backup Eligible — the credential may be synced to other devices
const AUTH_DATA_FLAG_BS = 0x10 // Backup State — the credential is currently backed up

/**
 * The keys we are willing to accept this witness under, drawn ENTIRELY from the caller's trust anchor.
 *
 * `witness.signerPublicKey` is never used as a verification key — only, in DID mode, as a claim about
 * WHICH approver is speaking, which we then answer with our own resolver. The single exception is a
 * pinned SELF-CERTIFYING DID (`did:intyga:key:…`) for which the anchor names NO keys: there the
 * carried key is first PROVEN to be the pinned key by hashing it against the DID's fingerprint — the
 * trust still comes from the pinned identifier, never from the receipt. An anchor that DOES name
 * keys for the DID takes precedence over the commitment (see the precedence note below). Note we do
 * not otherwise compare the presented key to the trusted one: there is nothing to gain (a mismatched
 * key simply fails to verify) and byte-equality is actively wrong for COSE, where the same P-256 key
 * has many valid encodings.
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
  // Plain-JS callers can hand over any shape; a malformed anchor is a refusal, never a TypeError.
  if (typeof anchor !== "object" || anchor === null)
    return { reason: "trust anchor must be { publicKeys } or { dids, resolveKey }" }
  if (anchor.publicKeys !== undefined) {
    if (!Array.isArray(anchor.publicKeys) || anchor.publicKeys.some((k) => typeof k !== "string"))
      return { reason: "trust anchor publicKeys must be an array of base64 key strings" }
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
  if (!Array.isArray(anchor.dids))
    return { reason: "trust anchor must be { publicKeys } or { dids, resolveKey }" }
  if (!witness.signerDid || !anchor.dids.includes(witness.signerDid)) {
    return { reason: `signer ${witness.signerDid || "(unknown)"} is not an authorized approver` }
  }
  if (restrictTo && !restrictTo.includes(witness.signerDid)) {
    return { reason: `signer ${witness.signerDid} is not named in the delegation` }
  }
  // PRECEDENCE: the anchor's own key mapping always wins, self-certifying DID or not. The RP's
  // explicit pin must be able to both WIDEN what a key-derived DID would accept (the person's
  // later-enrolled credentials live under the same DID) and NARROW it (a compromised credential is
  // dropped by re-exporting the anchor without it) — a commitment that overrode the mapping could
  // do neither, and the four Core Profile ports resolve mapped keys the same way.
  const resolved = anchor.resolveKey ? anchor.resolveKey(witness.signerDid) : null
  // One DID may legitimately hold several keys; all of them identify the SAME approver, so quorum
  // still counts one. Flattening them into separate identities would let one person meet an N-of-M.
  const keys = (Array.isArray(resolved) ? resolved : resolved ? [resolved] : []).filter((k) => Boolean(k))
  if (keys.length > 0) {
    return { keys: keys.map((key) => ({ key, identity: witness.signerDid })) }
  }
  // Self-certifying DID fallback: when the anchor names no keys, the pinned identifier itself is
  // the commitment — the carried key is trustworthy exactly when it hashes to the DID. This is what
  // makes a bare DID list a complete anchor with no key distribution at all. Strict by design: the
  // commitment is to the exact enrolled key bytes.
  if (witness.signerDid.startsWith(SELF_CERTIFYING_DID_PREFIX)) {
    if (!witness.signerPublicKey) {
      return {
        reason: `witness carries no public key to validate against self-certifying ${witness.signerDid}`,
      }
    }
    if (selfCertifyingDid(witness.signerPublicKey) !== witness.signerDid) {
      return {
        reason:
          "witness public key does not hash to the pinned self-certifying DID (did:intyga:key), and the trust anchor names no keys for it",
      }
    }
    return { keys: [{ key: witness.signerPublicKey, identity: witness.signerDid }] }
  }
  if (!anchor.resolveKey) {
    return {
      reason: `${witness.signerDid} is not self-certifying (${SELF_CERTIFYING_DID_PREFIX}…) and the trust anchor provides no resolveKey`,
    }
  }
  return { reason: `no trusted key could be resolved for ${witness.signerDid}` }
}

/**
 * One key, one person (DIV §4.4.6). An identity-associating anchor that maps the SAME key to two
 * DIDs (an export bug, or one person enrolled under two identifiers) would otherwise let that key's
 * holder count as two approvers, since quorum counts distinct identities. So a key already counted
 * for one identity cannot count for another: distinct keys AND distinct identities are required.
 * Keys are compared by their decoded bytes, so padded/unpadded and base64/base64url spellings of one
 * encoding match; the same key in a different encoding (COSE vs SPKI) is not detected.
 * Records the key when it is free; returns the refusal reason when it is not.
 */
function sharedKeyProblem(counted: Map<string, string>, key: string, identity: string): string | null {
  const fingerprint = Buffer.from(key, "base64").toString("hex")
  const owner = counted.get(fingerprint)
  if (owner !== undefined && owner !== identity)
    return `signer ${identity} verified under a key already counted for ${owner}; two approver identities sharing one key count once (DIV §4.4.6)`
  counted.set(fingerprint, identity)
  return null
}

/** Verify one witness signature over the canonical payload, using an already-TRUSTED key. */
function verifyWitness(
  witness: ApprovalWitness,
  trustedKey: string,
  canonicalPayload: string,
  opts: VerifyReceiptOptions,
): { ok: true } | { ok: false; reason: string } {
  // DIV §4.4.2: legacy missing/unknown labels use ES256; AUTO_APPROVED never does.
  if (witness.sigAlg === "AUTO_APPROVED" || (witness.sigAlg != null && typeof witness.sigAlg !== "string")) {
    return { ok: false, reason: "unsupported witness signature algorithm" }
  }
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
  return verifyWebAuthnAssertion(
    {
      authenticatorData: witness.authenticatorData,
      clientDataJSON: witness.clientDataJSON,
      signature: witness.signature,
    },
    // The COSE key is parsed from the TRUSTED key, not from the receipt's copy.
    () => coseKeyObject(Buffer.from(trustedKey, "base64")),
    canonicalPayload,
    {
      expectedOrigins: [opts.expectedOrigin],
      expectedRpId: opts.expectedRpId,
      requireUserVerification: opts.requireUserVerification !== false,
      allowCrossOrigin: opts.allowCrossOrigin === true,
    },
  )
}

/** A P-256 COSE_Key as a Node key object. Throws on anything else (see parseCosePublicKey). */
function coseKeyObject(cose: Buffer): crypto.KeyObject {
  const { x, y } = parseCosePublicKey(cose)
  return crypto.createPublicKey({ format: "jwk", key: { kty: "EC", crv: "P-256", x, y } })
}

interface WebAuthnAssertionParts {
  authenticatorData: string
  clientDataJSON: string
  signature: string
}
interface WebAuthnAssertionExpectation {
  expectedOrigins: readonly string[]
  expectedRpId: string
  requireUserVerification: boolean
  allowCrossOrigin: boolean
}

/**
 * The §4.4.5 checks on one assertion: the ceremony type, origin, cross-origin flag, challenge binding,
 * RP ID hash, UP/UV flags and the signature over authenticatorData ‖ SHA-256(clientDataJSON). Shared
 * by every receipt verifier (through verifyWitness) and by the standalone verifyWebAuthnWitness, so
 * there is exactly one implementation of it in this package. `keyOf` is resolved only after the
 * cheaper checks, in the same order as ever, so a refusal names the same reason it always did.
 */
function verifyWebAuthnAssertion(
  parts: WebAuthnAssertionParts,
  keyOf: () => crypto.KeyObject,
  signedPayload: string,
  expect: WebAuthnAssertionExpectation,
): { ok: true } | { ok: false; reason: string } {
  try {
    const clientDataBuf = Buffer.from(parts.clientDataJSON, "base64")
    const clientData = JSON.parse(clientDataBuf.toString("utf-8")) as {
      challenge: string
      type?: string
      origin?: string
      crossOrigin?: boolean
      topOrigin?: unknown
    }

    // An assertion, not a registration: webauthn.create signs a different ceremony over the same
    // challenge bytes, and must never be accepted as approval.
    if (clientData.type !== "webauthn.get")
      return { ok: false, reason: "clientDataJSON is not a webauthn.get assertion" }
    if (typeof clientData.origin !== "string" || !expect.expectedOrigins.includes(clientData.origin))
      return { ok: false, reason: "assertion origin does not match expectedOrigin" }
    // See VerifyReceiptOptions.allowCrossOrigin: origin and rpIdHash both match for an embedded RP
    // frame, so this flag is the only thing that separates "the human approved on our page" from
    // "the human approved inside someone else's page".
    if (clientData.crossOrigin === true && !expect.allowCrossOrigin)
      return { ok: false, reason: "assertion was produced in a cross-origin frame (crossOrigin=true)" }
    // WebAuthn L3 `topOrigin` names the top-level page when the ceremony ran in a frame. One that
    // differs from `origin` is the same embedding as `crossOrigin: true`, reported another way, and
    // is refused exactly like it (DIV §4.4.5 rule 5) — the rule the gateway applies at ingest with
    // `webAuthnCrossOriginRefusal` (@intyga/mcp-schemas), so offline and online verdicts agree.
    if (
      clientData.topOrigin !== undefined &&
      clientData.topOrigin !== clientData.origin &&
      !expect.allowCrossOrigin
    )
      return {
        ok: false,
        reason:
          "assertion was produced in a frame embedded by another origin (topOrigin differs from origin)",
      }

    const expectedChallenge = base64url(signedPayload)
    const clientChallengeClean = clientData.challenge
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "")
    if (clientChallengeClean !== expectedChallenge)
      return { ok: false, reason: "clientDataJSON challenge does not match canonical payload" }

    // authenticatorData is signed but was previously never INSPECTED: it carries the RP ID the
    // credential answered for and whether the user was actually present/verified.
    const authData = Buffer.from(parts.authenticatorData, "base64")
    if (authData.length < 37) return { ok: false, reason: "authenticatorData is too short" }
    const rpIdHash = crypto.createHash("sha256").update(expect.expectedRpId, "utf8").digest()
    if (!crypto.timingSafeEqual(authData.subarray(0, 32), rpIdHash))
      return { ok: false, reason: "authenticatorData rpIdHash does not match expectedRpId" }
    const flags = authData.readUInt8(32)
    if (!(flags & AUTH_DATA_FLAG_UP))
      return { ok: false, reason: "authenticatorData user-present flag is not set" }
    if (expect.requireUserVerification && !(flags & AUTH_DATA_FLAG_UV))
      return { ok: false, reason: "authenticatorData user-verified flag is not set" }

    const keyObject = keyOf()

    const clientDataHash = crypto.createHash("sha256").update(clientDataBuf).digest()
    const signatureVerifyData = Buffer.concat([authData, clientDataHash])

    // Digest pinned explicitly: ES256 is P-256 + SHA-256 by definition, and leaving it implicit
    // (`undefined`) makes the algorithm a property of the Node version rather than of this code.
    const verified = crypto.verify(
      "sha256",
      signatureVerifyData,
      { key: keyObject, dsaEncoding: "der" },
      Buffer.from(parts.signature, "base64"),
    )
    return verified
      ? { ok: true }
      : { ok: false, reason: "WebAuthn signature does not verify against the trusted signer key" }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err)
    return { ok: false, reason: `WebAuthn verification failed: ${msg}` }
  }
}

/**
 * Under a signed `requireHardwareKey`, a WebAuthn witness whose authenticatorData carries the Backup
 * Eligible or Backup State flag cannot count (DIV §4.4.5 rule 6). Both flags are covered by the
 * assertion signature, so a relying party can catch an issuer that let a synced passkey sign a
 * hardware-pinned action. The converse is NOT evidence: BE=0 is the authenticator's own claim, not
 * attestation — the model still comes only from enrollment records (§4.3.2).
 *
 * Only called for a witness that has already verified, so authenticatorData is at least 37 bytes.
 */
function backupFlagsProblem(witness: ApprovalWitness): string | null {
  const flags = Buffer.from(witness.authenticatorData ?? "", "base64").readUInt8(32)
  if (!(flags & (AUTH_DATA_FLAG_BE | AUTH_DATA_FLAG_BS))) return null
  return `signer ${witness.signerDid} used a backup-eligible (synced) passkey — authenticatorData BE/BS flag set — but the signed policy requires a hardware-backed WebAuthn credential`
}

/** One WebAuthn assertion and the exact payload it claims to sign — a single stored witness row. */
export interface WebAuthnWitness {
  /** The string whose UTF-8 bytes were the assertion challenge (the canonical payload), as signed. */
  signedPayload: string
  /**
   * The credential's P-256 public key, base64 or base64url: a COSE_Key (as recorded at registration)
   * or DER SubjectPublicKeyInfo. Supply it from YOUR record of the credential — never from the thing
   * being verified — or any key the presenter chose will do.
   */
  publicKey: string
  /** base64 or base64url, as the browser returned them. */
  authenticatorData: string
  clientDataJSON: string
  /** The DER ECDSA assertion signature. */
  signature: string
}

export interface WebAuthnWitnessExpectation {
  /** The origin(s) the assertion may carry, e.g. "https://app.example.com". Required. */
  expectedOrigin: string | readonly string[]
  /** The RP ID the authenticatorData must hash to, e.g. "app.example.com". Required. */
  expectedRpId: string
  /** Demand the User-Verified flag. Defaults to TRUE; User-Present is always required. */
  requireUserVerification?: boolean
  /** Accept `clientDataJSON.crossOrigin: true`. Defaults to FALSE (DIV §4.4.5 rule 5). */
  allowCrossOrigin?: boolean
}

/**
 * Verify ONE WebAuthn assertion on its own — the §4.4.5 checks every receipt verifier here applies
 * to each WEBAUTHN witness, without a receipt around it: one approver of a quorum, a console step-up,
 * a login approval, a row read back out of an audit ledger. Same implementation, not a copy.
 *
 * It answers only "did the holder of THIS key sign THIS payload, at THIS relying party, with the
 * user present". It knows nothing of quorum, validity windows, payload type, the signed requirement
 * or who the key belongs to: a caller verifying an approval must use verifyApprovalReceipt (or the
 * delegation/agent-authority/platform verifiers), which also enforce those. Never throws.
 */
export function verifyWebAuthnWitness(
  witness: WebAuthnWitness,
  expectation: WebAuthnWitnessExpectation,
): { ok: true } | { ok: false; reason: string } {
  const origins: readonly unknown[] =
    typeof expectation?.expectedOrigin === "string"
      ? [expectation.expectedOrigin]
      : (expectation?.expectedOrigin ?? [])
  // Fail closed, as verifyWitness does: with nothing pinned, an assertion from any RP would verify.
  if (
    origins.length === 0 ||
    !origins.every((o) => typeof o === "string" && o.length > 0) ||
    typeof expectation.expectedRpId !== "string" ||
    !expectation.expectedRpId
  )
    return {
      ok: false,
      reason:
        "a WebAuthn witness requires expectedOrigin and expectedRpId — without them an assertion from any relying party would verify",
    }
  const fields = ["signedPayload", "publicKey", "authenticatorData", "clientDataJSON", "signature"] as const
  for (const field of fields)
    if (typeof witness?.[field] !== "string" || !witness[field])
      return { ok: false, reason: `WebAuthn witness missing ${field}` }
  return verifyWebAuthnAssertion(
    witness,
    () => webAuthnPublicKey(Buffer.from(witness.publicKey, "base64")),
    witness.signedPayload,
    {
      expectedOrigins: origins as readonly string[],
      expectedRpId: expectation.expectedRpId,
      requireUserVerification: expectation.requireUserVerification !== false,
      allowCrossOrigin: expectation.allowCrossOrigin === true,
    },
  )
}

/** A caller-supplied P-256 credential key: DER SPKI (a SEQUENCE, 0x30) or a COSE_Key (a CBOR map). */
function webAuthnPublicKey(der: Buffer): crypto.KeyObject {
  if (der[0] !== 0x30) return coseKeyObject(der)
  const key = crypto.createPublicKey({ key: der, format: "der", type: "spki" })
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1")
    throw new Error("public key is not a P-256 key")
  return key
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
 * THE SIGNED QUORUM IS THE SIGNERS' OWN STATEMENT. The signed `requirement` is authored by whoever
 * composed the bytes — so one approver (possibly the requester) can sign a 1-of-1 payload alone. Pass
 * `expected.requirement` (your own rule, see RequirementFloor) and a weaker signed requirement is
 * refused (DIV §5 step 3d). Without it, "quorum met" means only "the quorum the signers stated".
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
  // Same structural rule as the delegation branch above: an authority is governance evidence, and
  // the only way "it authorizes nothing" stays true is that this function can never say ok to one.
  if (payloadType === DIV_AGENT_AUTHORITY_TYPE)
    return {
      ok: false,
      reason:
        "this is an agent authority, which authorizes no action on its own — verify it with verifyAgentAuthority; execution still requires an approval receipt",
    }
  // A platform hash-only intent (DIV §5c) attests a DIGEST for an integrating platform's subject —
  // different signed shape, different display authority, different trust anchor. Refused here with
  // its own message so an integrator holding one is pointed at the right door.
  if (payloadType === DIV_PLATFORM_INTENT_TYPE)
    return {
      ok: false,
      reason: "this is a platform hash-only intent (DIV §5c) — verify it with verifyPlatformReceipt",
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
  const embeddedAgent = parseField<unknown>(receipt.canonicalPayload, "agent")
  const agentIntent = embeddedAgent !== undefined
  if (agentIntent && !expected.agentContext)
    return { ok: false, reason: "agent receipt requires independently asserted PEP context" }
  if (!agentIntent && expected.agentContext)
    return { ok: false, reason: "agent context was expected but is absent from the signed payload" }
  const expiresAt = parseField<string>(receipt.canonicalPayload, agentIntent ? "exp" : "expiresAt")
  if (typeof expiresAt !== "string" || expiresAt.length === 0)
    return { ok: false, reason: "receipt missing expiration" }
  if (agentIntent) {
    const context = expected.agentContext
    if (!context) return { ok: false, reason: "agent receipt requires independently asserted PEP context" }
    try {
      validateAgentIntentContext(context, expiresAt)
    } catch (error) {
      return {
        ok: false,
        reason: `invalid independently asserted agent context: ${(error as Error).message}`,
      }
    }
    const nowMs = (opts.asOf ?? new Date()).getTime()
    const skewMs = (opts.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS) * 1000
    if (Date.parse(context.nbf) > nowMs + skewMs)
      return { ok: false, reason: "agent approval is not valid yet" }
    if (context.action.reversibility === "irreversible" && receipt.sigAlg === "AUTO_APPROVED")
      return { ok: false, reason: "irreversible agent action requires a human signature" }
    if (context.agent.delegatedBy) {
      if (!expected.requesterDid || !opts.agentAuthorityChain)
        return {
          ok: false,
          reason: "delegated agent receipt requires a trusted root-to-leaf authority chain",
        }
      const authority = verifyAgentDelegationChain(
        opts.agentAuthorityChain,
        {
          target: expected.target,
          actionType: expected.actionType,
          agentDid: expected.requesterDid,
          delegatedBy: context.agent.delegatedBy,
        },
        opts,
      )
      if (!authority.ok) return { ok: false, reason: authority.reason }
    }
  }
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
  // The requirement is part of the SIGNED bytes, so a third party cannot alter it: a forged value
  // changes the string and fails the byte comparison below. It does NOT bind the signers themselves —
  // they authored it — which is why step 3d compares it against the caller's `expected.requirement`.
  const requirement = parseField<Partial<ApprovalRequirementAttestation>>(
    receipt.canonicalPayload,
    "requirement",
  )
  if (!requirement || typeof requirement.requiredApprovals !== "number")
    return { ok: false, reason: "receipt payload is missing the signed approval requirement" }
  // DIV §4.3.2: an integer ≥ 1. Stated as its own refusal rather than clamped silently, because
  // §5 step 7 rejects unless the counted identities are AT LEAST this number — 0 is satisfied by
  // counting nothing, so an unenforced minimum attests an envelope with no valid witness signature.
  if (!isValidQuorum(requirement.requiredApprovals)) return { ok: false, reason: INVALID_QUORUM_REASON }
  const signerClass = parseSignerClass(requirement)
  if (!signerClass.ok) return { ok: false, reason: signerClass.reason }
  // DIV §5 step 3d: the signed requirement is authored by the signers, so it is compared against the
  // caller's own policy BEFORE anything is counted toward it.
  const weaker = requirementFloorProblem(requirement, expected.requirement)
  if (weaker) return { ok: false, reason: weaker }

  // DIV §5-step-3c. Sits with the other signed-bytes structural gates, BEFORE Local Payload
  // Reconstruction. A non-null evidence value would also fail the byte comparison further down, but
  // it would surface as "target/params/actionType do not match what was approved" — a tampering
  // message for what is really an unsupported payload shape, which sends an operator hunting a
  // forgery that is not there.
  const evidence = parseEvidence(receipt.canonicalPayload)
  if (!evidence.ok) return { ok: false, reason: evidence.reason }

  // Offline proofs carry `challengedAt` so the validity WINDOW can be bounded here, not merely at
  // mint. A proof whose window exceeds the cap is refused even though its signature is perfectly
  // good — an offline relying party has no revocation channel, so the short window is the only one.
  let challengedAt = ""
  if (offline) {
    const raw = parseField<string>(receipt.canonicalPayload, "challengedAt")
    if (typeof raw !== "string" || raw.length === 0)
      return { ok: false, reason: "offline proof is missing challengedAt" }
    challengedAt = raw
    const challengedMs = parseRfc3339Ms(challengedAt)
    if (Number.isNaN(challengedMs))
      return { ok: false, reason: "challengedAt is not a valid RFC3339 timestamp" }
    // An unparseable `expiresAt` must be refused HERE rather than skipping the window cap and relying
    // on the expiry check below — that check is disabled by `allowExpired`, so the combination left
    // the cap unenforced on a proof whose window could not be computed at all.
    const expiryMs = parseRfc3339Ms(expiresAt)
    if (Number.isNaN(expiryMs)) return { ok: false, reason: "expiresAt is not a valid RFC3339 timestamp" }
    const windowMinutes = (expiryMs - challengedMs) / 60_000
    if (windowMinutes > MAX_OFFLINE_WINDOW_MINUTES)
      return {
        ok: false,
        reason: `offline window is ${windowMinutes.toFixed(1)} minutes, over the ${MAX_OFFLINE_WINDOW_MINUTES}-minute maximum`,
      }
    if (windowMinutes < 0) return { ok: false, reason: "offline proof expires before it was challenged" }
    // The cap above bounds the window's WIDTH; this bounds its POSITION (DIV §5a.3 rule 3). Without
    // it a proof challenged for a date years out, with a compliant 60-minute window, verifies today
    // and keeps verifying until that date — the pre-signed bearer capability §5a.1 rejects. NOT
    // gated on `allowExpired`: that override re-examines a proof that WAS valid and has lapsed, and
    // says nothing about one dated in the future.
    const nowMs = (opts.asOf ?? new Date()).getTime()
    const skewMs = (opts.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS) * 1000
    if (challengedMs > nowMs + skewMs)
      return { ok: false, reason: "offline proof is challenged in the future (DIV §5a.3)" }

    // A hardware-key policy CANNOT be satisfied offline (DIV §5a.3 step 4, §5a.8). WebAuthn needs a
    // secure context and an RP ID that an offline signing surface will not match, so an offline
    // witness is always a bare key. Accepting the proof anyway would silently downgrade the very
    // policy the approver attested to, so it is refused instead — fail closed, and say why. A
    // non-empty authenticator-model allowlist is the same kind of policy: a bare key has no model at
    // all, and the enrollment record that would name one is not available offline (DIV §4.3.2).
    if (requiresHardwareCredential(requirement))
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
    // A successful seal check can be cached or precede a long signing ceremony. Its expiry must
    // still hold at USE time (DIV §5a.6), under the same clock/forensic policy as this approval.
    const delegationExpiryMs = parseRfc3339Ms(d.expiresAt)
    if (!Number.isFinite(delegationExpiryMs))
      return { ok: false, reason: "delegation expiresAt is not a valid RFC3339 timestamp" }
    const nowMs = (opts.asOf ?? new Date()).getTime()
    const skewMs = (opts.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS) * 1000
    if (!opts.allowExpired && nowMs > delegationExpiryMs + skewMs)
      return {
        ok: false,
        reason: "delegation has expired (pass { allowExpired: true } for audit re-verification)",
      }
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
      signerClass: signerClass.signerClass,
    },
    nonce: parseNonce(receipt.canonicalPayload),
    expiresAt,
    ...(agentIntent ? { agentContext: expected.agentContext } : {}),
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
    const expiryMs = parseRfc3339Ms(expiresAt)
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
  // A signed four-eyes rule cannot be enforced against a key-set anchor: PublicKeys mode never
  // authenticates signerDid, so "this signer is not the requester" is unverifiable. Decided BEFORE
  // the loop so the receipt is refused for the reason that actually applies — the caller's anchor is
  // the wrong shape for the signed policy, which is not a quorum shortfall. It used to sit inside
  // the loop, after a witness had matched, so a receipt where nothing matched reported "quorum not
  // met" instead. Go, Rust, Java and Python all decide it here.
  if (requirement.requiredApprovals > 1 && "publicKeys" in expected.approvers) {
    return { ok: false, reason: "multi-approver quorum requires a DID-mode trust anchor (DIV §5 step 3b)" }
  }
  if (requirement.requesterCannotApprove === true && "publicKeys" in expected.approvers) {
    return {
      ok: false,
      reason:
        "requesterCannotApprove requires a DID-mode trust anchor; key-only mode cannot authenticate requester identity",
    }
  }

  const verifiedSigners = new Set<string>()
  const countedKeys = new Map<string, string>()
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
    let matchedKey = ""
    let lastReason = "signature does not verify against any trusted approver key"
    for (const candidate of candidates.keys) {
      const attempt = verifyWitness(witness, candidate.key, receipt.canonicalPayload, opts)
      if (attempt.ok) {
        matched = candidate.identity
        matchedKey = candidate.key
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
    if (requiresHardwareCredential(requirement) && witness.sigAlg !== "WEBAUTHN") {
      failures.push(
        `signer ${witness.signerDid} used a bare key, but the signed policy requires a hardware-backed WebAuthn credential`,
      )
      continue
    }
    // The assertion's signed BE/BS flags can prove a synced passkey signed (DIV §4.4.5 rule 6).
    const synced = requirement.requireHardwareKey === true ? backupFlagsProblem(witness) : null
    if (synced) {
      failures.push(synced)
      continue
    }
    // Four-eyes, verified offline against the requester in the same signed payload.
    if (requirement.requesterCannotApprove === true && witness.signerDid === receipt.requester.did) {
      failures.push(`four-eyes: requester ${witness.signerDid} cannot approve their own action`)
      continue
    }
    const shared = sharedKeyProblem(countedKeys, matchedKey, matched)
    if (shared) {
      failures.push(shared)
      continue
    }
    verifiedSigners.add(matched)
  }

  // Under a delegation the quorum is the DELEGATED one. It was already checked to equal the offline
  // payload's signed `requiredApprovals`, so this is the same number by a different route — stated
  // explicitly so the substitution is visible at the point it takes effect. Both numbers were
  // refused above unless they are integers ≥ 1, so no floor is applied here.
  const required = delegatedQuorum ?? requirement.requiredApprovals
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

/** A platform hash-only receipt (DIV §5c) as issued by the gateway's platform plane. */
export interface PlatformReceipt {
  /** The exact bytes the subject's passkey signed (the §5c.2 payload). */
  canonicalPayload: string
  /** Display copies only — verification reconstructs from the RELYING PARTY's own values. */
  payloadHash?: string | null
  rpId?: string | null
  subject?: { externalId?: string | null } | null
  signedAt?: string | null
  expiresAt?: string | null
  nonce?: string | null
  signatures?: ApprovalWitness[] | null
  signerDid?: string | null
  signerPublicKey?: string | null
  signature?: string | null
  sigAlg?: string | null
  authenticatorData?: string | null
  clientDataJSON?: string | null
  verificationCode?: string
}

export interface PlatformReceiptExpectation {
  /** REQUIRED. The subject keys you trust — same modes as ReceiptExpectation.approvers. */
  approvers: ApproverTrustAnchor
  /**
   * REQUIRED. The SHA-256 (lowercase hex) YOU recompute from your own copy of the canonical
   * payload — never read from the receipt. This is the §5c data-minimization anchor: the payload
   * itself never traveled, so this digest is the entire content binding.
   */
  payloadHash: string
  /** REQUIRED. YOUR registered WebAuthn RP ID — used for the signed-bytes binding AND as the
   *  assertion's expected rpIdHash. Asserted from your own configuration, never the receipt. */
  rpId: string
  /** REQUIRED. The signing challenge nonce you are redeeming. */
  nonce: string
  /** Optionally assert WHICH of your subjects signed. */
  subjectExternalId?: string
}

/**
 * Verify a PLATFORM HASH-ONLY receipt (DIV §5c.3). Deliberately a separate function:
 * `verifyApprovalReceipt` refuses the `div-platform-intent` type outright, and this function
 * refuses every other type, so neither proof kind can ever pass through the other's door.
 *
 * Every witness must be a WebAuthn assertion (this plane's subjects only ever sign with enrolled
 * passkeys on the platform's registered origin), so `opts.expectedOrigin` is REQUIRED and the RP ID
 * expectation comes from `expected.rpId`. `AUTO_APPROVED` is refused with no override — policy
 * pre-approval does not exist on this plane.
 */
export function verifyPlatformReceipt(
  receipt: PlatformReceipt,
  expected: PlatformReceiptExpectation,
  opts: VerifyReceiptOptions = {},
): { ok: boolean; reason?: string; signers?: string[] } {
  const version = parseVersion(receipt.canonicalPayload)
  if (version !== DIV_VERSION)
    return { ok: false, reason: `unsupported DIV payload version (${version || "unparseable"})` }
  const payloadType = parseField(receipt.canonicalPayload, "type")
  if (payloadType !== DIV_PLATFORM_INTENT_TYPE) {
    return {
      ok: false,
      reason:
        payloadType === DIV_INTENT_TYPE || payloadType === DIV_OFFLINE_INTENT_TYPE
          ? "this is an ordinary approval receipt — verify it with verifyApprovalReceipt"
          : "payload is not a div-platform-intent",
    }
  }

  if (parseNonce(receipt.canonicalPayload) !== expected.nonce)
    return { ok: false, reason: "receipt is for a different challenge" }

  if (!expected.approvers)
    return {
      ok: false,
      reason:
        "expected.approvers is required — the subject's key MUST come from your own trust policy, never from the receipt (DIV Invariant 3)",
    }
  // Refused rather than case-folded: two spellings of one digest would be two different signed byte
  // strings (the Merkle hex-case lesson, DIV §5c.2).
  if (typeof expected.payloadHash !== "string" || !/^[0-9a-f]{64}$/.test(expected.payloadHash))
    return {
      ok: false,
      reason: "expected.payloadHash must be the 64-character lowercase hex SHA-256 you recomputed yourself",
    }
  if (typeof expected.rpId !== "string" || expected.rpId.length === 0)
    return {
      ok: false,
      reason:
        "expected.rpId is required — it must be YOUR registered RP ID, asserted independently of the receipt",
    }
  // One rpId, used twice (signed bytes + rpIdHash). A conflicting override would silently verify
  // the assertion against a different RP than the bytes name.
  if (opts.expectedRpId !== undefined && opts.expectedRpId !== expected.rpId)
    return { ok: false, reason: "opts.expectedRpId conflicts with expected.rpId — pass the RP ID once" }
  // User verification is UNCONDITIONAL on this plane (DIV §5c.3): `requireUserVerification: false`
  // is an ordinary-receipt option and is overridden here, never honoured.
  const effOpts: VerifyReceiptOptions = {
    ...opts,
    expectedRpId: expected.rpId,
    requireUserVerification: true,
  }

  const signedAt = parseField<string>(receipt.canonicalPayload, "signedAt")
  const expiresAt = parseField<string>(receipt.canonicalPayload, "expiresAt")
  if (typeof signedAt !== "string" || signedAt.length === 0)
    return { ok: false, reason: "receipt missing signedAt" }
  if (typeof expiresAt !== "string" || expiresAt.length === 0)
    return { ok: false, reason: "receipt missing expiresAt" }
  const subject = parseField<{ externalId?: unknown }>(receipt.canonicalPayload, "subject")
  const subjectExternalId = subject && typeof subject.externalId === "string" ? subject.externalId : null
  if (!subjectExternalId) return { ok: false, reason: "receipt missing subject.externalId" }
  if (expected.subjectExternalId !== undefined && subjectExternalId !== expected.subjectExternalId)
    return { ok: false, reason: "receipt was signed by a different subject" }

  // Local Payload Reconstruction: digest, RP and nonce from YOUR state; signedAt/expiresAt/subject
  // from the signed bytes (a forged value changes the string and fails the comparison).
  let recomputed: string
  try {
    recomputed = canonicalPlatformIntentPayload({
      payloadHash: expected.payloadHash,
      rpId: expected.rpId,
      subjectExternalId,
      signedAt,
      expiresAt,
      nonce: expected.nonce,
    })
  } catch (err) {
    return { ok: false, reason: `platform payload is not canonicalizable: ${(err as Error).message}` }
  }
  if (recomputed !== receipt.canonicalPayload)
    return { ok: false, reason: "payloadHash/rpId do not match what was signed" }

  // Timestamp sanity, then expiry — fail closed (DIV §6.2), opt out only for audit re-verification.
  const signedMs = parseRfc3339Ms(signedAt)
  const expiryMs = parseRfc3339Ms(expiresAt)
  if (Number.isNaN(signedMs)) return { ok: false, reason: "signedAt is not a valid RFC3339 timestamp" }
  if (Number.isNaN(expiryMs)) return { ok: false, reason: "expiresAt is not a valid RFC3339 timestamp" }
  if (expiryMs < signedMs) return { ok: false, reason: "receipt expires before it was signed" }
  const nowMs = (opts.asOf ?? new Date()).getTime()
  const skewMs = (opts.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS) * 1000
  // Position bound, like the offline rule (§5a.3 rule 3): a challenge frozen in the future was not
  // live now, whatever its window. Not gated on allowExpired, which only re-examines lapsed proofs.
  if (signedMs > nowMs + skewMs) return { ok: false, reason: "receipt is signed in the future (DIV §5c.3)" }
  if (!opts.allowExpired && nowMs > expiryMs + skewMs)
    return {
      ok: false,
      reason: "proof has expired (pass { allowExpired: true } for audit re-verification)",
    }

  // No override exists on purpose: there is no policy pre-approval on this plane, so an unsigned
  // platform receipt is a contradiction, not a configuration.
  if (receipt.sigAlg === "AUTO_APPROVED")
    return {
      ok: false,
      reason: "a platform receipt cannot be auto-approved — there is no signature to verify",
    }

  const witnesses = witnessesOf(receipt as ApprovalReceipt)
  if (witnesses.length === 0) return { ok: false, reason: "receipt missing signature material" }
  if (witnesses.length > MAX_WITNESSES)
    return {
      ok: false,
      reason: `receipt carries ${witnesses.length} witnesses, above the ${MAX_WITNESSES} this verifier will process`,
    }

  const verifiedSigners = new Set<string>()
  const countedKeys = new Map<string, string>()
  const failures: string[] = []
  for (const witness of witnesses) {
    // §5c.3: every witness is a WebAuthn assertion. A bare-key signature has no origin/RP binding,
    // which is the entire trust boundary of this plane — refuse it rather than verify less.
    if (witness.sigAlg !== "WEBAUTHN") {
      failures.push(`signer ${witness.signerDid} used a bare key; platform receipts are WebAuthn-only`)
      continue
    }
    const candidates = candidateKeys(expected.approvers, witness)
    if ("reason" in candidates) {
      failures.push(candidates.reason)
      continue
    }
    let matched: string | null = null
    let matchedKey = ""
    let lastReason = "signature does not verify against any trusted subject key"
    for (const candidate of candidates.keys) {
      const attempt = verifyWitness(witness, candidate.key, receipt.canonicalPayload, effOpts)
      if (attempt.ok) {
        matched = candidate.identity
        matchedKey = candidate.key
        break
      }
      lastReason = attempt.reason
    }
    if (matched === null) {
      failures.push(lastReason)
      continue
    }
    const shared = sharedKeyProblem(countedKeys, matchedKey, matched)
    if (shared) {
      failures.push(shared)
      continue
    }
    verifiedSigners.add(matched)
  }

  if (verifiedSigners.size < 1) {
    const shown = failures.slice(0, MAX_REPORTED_FAILURES)
    const elided = failures.length - shown.length
    const detail = shown.length > 0 ? ` (${shown.join("; ")}${elided > 0 ? `; +${elided} more` : ""})` : ""
    return { ok: false, reason: `no valid subject signature${detail}` }
  }
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
    /**
     * STRONGLY RECOMMENDED. The ORDINARY approval rule for the delegated action: the delegation's
     * sealing requirement must be at least this strict (DIV §5a.5, §5 step 3d). Without it only the
     * sealers' own stated quorum is enforced.
     */
    requirement?: RequirementFloor
  },
  opts: VerifyReceiptOptions = {},
): { ok: boolean; reason?: string; delegation?: VerifiedDelegation } {
  const version = parseVersion(receipt.canonicalPayload)
  if (version !== DIV_VERSION)
    return { ok: false, reason: `unsupported DIV payload version (${version || "unparseable"})` }
  if (parseField(receipt.canonicalPayload, "type") !== DIV_DELEGATION_TYPE)
    return { ok: false, reason: "payload is not a div-delegation" }

  // DIV §4.4.6: a Delegation REQUIRES an identity-associating anchor and MUST be refused under a
  // key-set anchor — at seal verification too, not only when delegatedTo is enforced at use time.
  // The sealing quorum names PEOPLE; in publicKeys mode it would count credentials instead.
  if (expected.approvers && "publicKeys" in expected.approvers && expected.approvers.publicKeys)
    return {
      ok: false,
      reason:
        "a delegation requires a DID-mode trust anchor ({ dids, resolveKey }); a key-set anchor cannot associate identities (DIV §4.4.6)",
    }

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
  const sealedMs = parseRfc3339Ms(sealedAt)
  const expiryMs = parseRfc3339Ms(expiresAt)
  if (Number.isNaN(sealedMs)) return { ok: false, reason: "sealedAt is not a valid RFC3339 timestamp" }
  if (Number.isNaN(expiryMs)) return { ok: false, reason: "expiresAt is not a valid RFC3339 timestamp" }
  const windowHours = (expiryMs - sealedMs) / 3_600_000
  if (windowHours < 0) return { ok: false, reason: "delegation expires before it was sealed" }
  if (windowHours > MAX_DELEGATION_WINDOW_HOURS)
    return {
      ok: false,
      reason: `delegation window is ${windowHours.toFixed(1)} hours, over the ${MAX_DELEGATION_WINDOW_HOURS}-hour maximum`,
    }
  // Position, not just width (DIV §5a.6 step 1, mirroring §5a.3 rule 3). A forward-dated `sealedAt`
  // slides the 72-hour window arbitrarily far out, and §5a.8 names that cap as Delegation's ONLY
  // mitigation. Unconditional, like the offline mirror: `allowExpired` does not reach it.
  const nowMs = (opts.asOf ?? new Date()).getTime()
  const skewMs = (opts.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS) * 1000
  if (sealedMs > nowMs + skewMs)
    return { ok: false, reason: "delegation is sealed in the future (DIV §5a.6)" }

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
  if (!isValidQuorum(requirement.requiredApprovals)) return { ok: false, reason: INVALID_QUORUM_REASON }
  const signerClass = parseSignerClass(requirement)
  if (!signerClass.ok) return { ok: false, reason: signerClass.reason }
  const weaker = requirementFloorProblem(requirement, expected.requirement)
  if (weaker) return { ok: false, reason: weaker }
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
        signerClass: signerClass.signerClass,
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

  // A signed four-eyes rule cannot be enforced against a key-set anchor: PublicKeys mode never
  // authenticates signerDid, so "this signer is not the requester" is unverifiable. Decided BEFORE
  // the loop so the receipt is refused for the reason that actually applies — the caller's anchor is
  // the wrong shape for the signed policy, which is not a quorum shortfall. It used to sit inside
  // the loop, after a witness had matched, so a receipt where nothing matched reported "quorum not
  // met" instead. Go, Rust, Java and Python all decide it here.
  if (requirement.requiredApprovals > 1 && "publicKeys" in expected.approvers) {
    return { ok: false, reason: "multi-approver quorum requires a DID-mode trust anchor (DIV §5 step 3b)" }
  }
  if (requirement.requesterCannotApprove === true && "publicKeys" in expected.approvers) {
    return {
      ok: false,
      reason:
        "requesterCannotApprove requires a DID-mode trust anchor; key-only mode cannot authenticate requester identity",
    }
  }

  const verifiedSigners = new Set<string>()
  const countedKeys = new Map<string, string>()
  const failures: string[] = []
  for (const witness of witnesses) {
    const candidates = candidateKeys(expected.approvers, witness)
    if ("reason" in candidates) {
      failures.push(candidates.reason)
      continue
    }
    let matched: string | null = null
    let matchedKey = ""
    let lastReason = "signature does not verify against any trusted approver key"
    for (const candidate of candidates.keys) {
      const attempt = verifyWitness(witness, candidate.key, receipt.canonicalPayload, opts)
      if (attempt.ok) {
        matched = candidate.identity
        matchedKey = candidate.key
        break
      }
      lastReason = attempt.reason
    }
    if (matched === null) {
      failures.push(lastReason)
      continue
    }
    if (requiresHardwareCredential(requirement) && witness.sigAlg !== "WEBAUTHN") {
      failures.push(
        `signer ${witness.signerDid} used a bare key, but the signed policy requires a hardware-backed WebAuthn credential`,
      )
      continue
    }
    // The assertion's signed BE/BS flags can prove a synced passkey signed (DIV §4.4.5 rule 6).
    const synced = requirement.requireHardwareKey === true ? backupFlagsProblem(witness) : null
    if (synced) {
      failures.push(synced)
      continue
    }
    if (requirement.requesterCannotApprove === true && witness.signerDid === receipt.requester.did) {
      failures.push(`four-eyes: requester ${witness.signerDid} cannot delegate to themselves`)
      continue
    }
    const shared = sharedKeyProblem(countedKeys, matchedKey, matched)
    if (shared) {
      failures.push(shared)
      continue
    }
    verifiedSigners.add(matched)
  }

  const required = requirement.requiredApprovals
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

/** An agent authority whose sealing signatures, quorum and window verified (`verifyAgentAuthority`). */
export interface VerifiedAgentAuthority {
  /** The agent the authority is ABOUT — from the signed bytes, asserted by the caller. */
  agentDid: string
  target: string
  /**
   * The signed scope, deduplicated. Case-insensitive substring patterns over the machine
   * `actionType` ONLY — deliberately NOT the human-readable description, which is authored by the
   * agent being bounded and would let an out-of-scope request cover itself by quoting a pattern
   * (DIV §5b.2). "*" = all.
   */
  actionPatterns: string[]
  parentReceiptHash: string | null
  /** The authority's OWN nonce — for the audit trail, never for authorization. */
  nonce: string
  /** Who sealed it. */
  signers: string[]
  sealedAt: string
  expiresAt: string
}

/**
 * Verify an AGENT AUTHORITY (DIV §5b) — a statement, sealed by a human quorum, of the standing scope
 * one agent may operate under.
 *
 * Deliberately a SEPARATE function from `verifyApprovalReceipt`, which refuses this payload type
 * outright — the same structural rule as delegations. What you get back is governance EVIDENCE:
 * "these named humans granted this agent this scope, and the grant was live at `asOf`". It is never
 * an approval; executing an action still requires an ordinary receipt.
 *
 * Two things the caller asserts and never reads from the artifact (DIV Invariant 3):
 * `expected.approvers` (the sealing quorum's keys, from your own trust policy) and
 * `expected.target` / `expected.agentDid` (what YOU are checking authority over). Revocation is
 * authoritative online only — an offline verifier sees validity, not revocation; treat a seal like
 * a certificate, not a bearer token.
 */
export function verifyAgentAuthority(
  receipt: ApprovalReceipt,
  expected: {
    /** The sealing approvers entitled to grant. Resolved from your own trust policy. */
    approvers: ApproverTrustAnchor
    /** YOUR target identifier, asserted independently of the artifact (DIV Target Isolation). */
    target: string
    /** The agent whose authority you are checking, asserted independently of the artifact. */
    agentDid: string
    /**
     * STRONGLY RECOMMENDED. YOUR sealing policy for agent authority: the signed sealing requirement
     * must be at least this strict (DIV §5b.3, §5 step 3d). Without it only the sealers' own stated
     * quorum is enforced.
     */
    requirement?: RequirementFloor
  },
  opts: VerifyReceiptOptions = {},
): { ok: boolean; reason?: string; authority?: VerifiedAgentAuthority } {
  const version = parseVersion(receipt.canonicalPayload)
  if (version !== DIV_VERSION)
    return { ok: false, reason: `unsupported DIV payload version (${version || "unparseable"})` }
  if (parseField(receipt.canonicalPayload, "type") !== DIV_AGENT_AUTHORITY_TYPE)
    return { ok: false, reason: "payload is not a div-agent-authority" }

  const actionPatterns = parseField<unknown>(receipt.canonicalPayload, "actionPatterns")
  const parentReceiptHash = parseField<unknown>(receipt.canonicalPayload, "parentReceiptHash")
  if (
    parentReceiptHash !== null &&
    (typeof parentReceiptHash !== "string" || !AGENT_DIGEST.test(parentReceiptHash))
  )
    return { ok: false, reason: "authority is missing a valid parent receipt commitment" }
  if (
    !Array.isArray(actionPatterns) ||
    actionPatterns.length === 0 ||
    actionPatterns.some((p) => typeof p !== "string" || p.length === 0)
  )
    return { ok: false, reason: "authority is missing a valid actionPatterns set" }

  const sealedAt = parseField<string>(receipt.canonicalPayload, "sealedAt")
  const expiresAt = parseField<string>(receipt.canonicalPayload, "expiresAt")
  if (typeof sealedAt !== "string" || sealedAt.length === 0)
    return { ok: false, reason: "authority is missing sealedAt" }
  if (typeof expiresAt !== "string" || expiresAt.length === 0)
    return { ok: false, reason: "authority is missing expiresAt" }
  const sealedMs = parseRfc3339Ms(sealedAt)
  const expiryMs = parseRfc3339Ms(expiresAt)
  if (Number.isNaN(sealedMs)) return { ok: false, reason: "sealedAt is not a valid RFC3339 timestamp" }
  if (Number.isNaN(expiryMs)) return { ok: false, reason: "expiresAt is not a valid RFC3339 timestamp" }
  // No 72-hour cap here, deliberately: that cap exists because a delegation pre-authorizes offline
  // APPROVAL and cannot be revoked at an offline relying party. An authority authorizes nothing and
  // is enforced (and revoked) online, so its window is deployment policy, not a verifier rule.
  if (expiryMs < sealedMs) return { ok: false, reason: "authority expires before it was sealed" }
  // The position rule still applies (DIV §5b.2): §5b.3's evidence claim is that the grant was live
  // at the evaluation time, and a seal dated after it was not. Unconditional, as in §5a.3 rule 3.
  const nowMs = (opts.asOf ?? new Date()).getTime()
  const skewMs = (opts.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS) * 1000
  if (sealedMs > nowMs + skewMs) return { ok: false, reason: "authority is sealed in the future (DIV §5b.2)" }

  const nonce = parseNonce(receipt.canonicalPayload)
  if (!receipt.requester) return { ok: false, reason: "authority missing requester" }
  const requirement = parseField<Partial<ApprovalRequirementAttestation>>(
    receipt.canonicalPayload,
    "requirement",
  )
  if (!requirement || typeof requirement.requiredApprovals !== "number")
    return { ok: false, reason: "authority payload is missing the signed approval requirement" }
  if (!isValidQuorum(requirement.requiredApprovals)) return { ok: false, reason: INVALID_QUORUM_REASON }
  const signerClass = parseSignerClass(requirement)
  if (!signerClass.ok) return { ok: false, reason: signerClass.reason }
  const weaker = requirementFloorProblem(requirement, expected.requirement)
  if (weaker) return { ok: false, reason: weaker }
  if (typeof expected.target !== "string" || expected.target.length === 0)
    return {
      ok: false,
      reason:
        "expected.target is required — it must be YOUR target identifier, asserted independently of the authority (DIV Target Isolation)",
    }
  if (typeof expected.agentDid !== "string" || expected.agentDid.length === 0)
    return {
      ok: false,
      reason: "expected.agentDid is required — name the agent whose authority you are checking",
    }
  if (!expected.approvers)
    return {
      ok: false,
      reason:
        "expected.approvers is required — the sealing approvers MUST come from your own trust policy, never from the artifact (DIV Invariant 3)",
    }

  // Local Payload Reconstruction: the byte comparison pins target, agent DID and the pattern set at
  // once, so the crypto below never runs against bytes the caller has not re-derived.
  let recomputed: string
  try {
    recomputed = canonicalAgentAuthorityPayload({
      target: expected.target,
      actionPatterns: actionPatterns as string[],
      display: receipt.actionDescription,
      agent: { did: expected.agentDid },
      parentReceiptHash,
      requester: receipt.requester,
      requirement: {
        requiredApprovals: requirement.requiredApprovals,
        requireHardwareKey: requirement.requireHardwareKey === true,
        allowedAaguids: Array.isArray(requirement.allowedAaguids) ? requirement.allowedAaguids : [],
        requesterCannotApprove: requirement.requesterCannotApprove === true,
        signerClass: signerClass.signerClass,
      },
      nonce,
      sealedAt,
      expiresAt,
    })
  } catch (err) {
    return { ok: false, reason: `authority payload is not canonicalizable: ${(err as Error).message}` }
  }
  if (recomputed !== receipt.canonicalPayload)
    return { ok: false, reason: "target/agent/actionPatterns do not match what was sealed" }

  if (!opts.allowExpired) {
    if (nowMs > expiryMs + skewMs)
      return {
        ok: false,
        reason: "authority has expired (pass { allowExpired: true } for audit re-verification)",
      }
  }

  if (receipt.sigAlg === "AUTO_APPROVED")
    return {
      ok: false,
      reason: "an agent authority cannot be auto-approved — granting agent scope requires human signatures",
    }
  const witnesses = witnessesOf(receipt)
  if (witnesses.length === 0) return { ok: false, reason: "authority missing signature material" }
  if (witnesses.length > MAX_WITNESSES) {
    return {
      ok: false,
      reason: `authority carries ${witnesses.length} witnesses, above the ${MAX_WITNESSES} this verifier will process`,
    }
  }

  // A signed four-eyes rule cannot be enforced against a key-set anchor: PublicKeys mode never
  // authenticates signerDid, so "this signer is not the requester" is unverifiable. Decided BEFORE
  // the loop so the receipt is refused for the reason that actually applies — the caller's anchor is
  // the wrong shape for the signed policy, which is not a quorum shortfall. It used to sit inside
  // the loop, after a witness had matched, so a receipt where nothing matched reported "quorum not
  // met" instead. Go, Rust, Java and Python all decide it here.
  if (requirement.requiredApprovals > 1 && "publicKeys" in expected.approvers) {
    return { ok: false, reason: "multi-approver quorum requires a DID-mode trust anchor (DIV §5 step 3b)" }
  }
  if (requirement.requesterCannotApprove === true && "publicKeys" in expected.approvers) {
    return {
      ok: false,
      reason:
        "requesterCannotApprove requires a DID-mode trust anchor; key-only mode cannot authenticate requester identity",
    }
  }

  const verifiedSigners = new Set<string>()
  const countedKeys = new Map<string, string>()
  const failures: string[] = []
  for (const witness of witnesses) {
    const candidates = candidateKeys(expected.approvers, witness)
    if ("reason" in candidates) {
      failures.push(candidates.reason)
      continue
    }
    let matched: string | null = null
    let matchedKey = ""
    let lastReason = "signature does not verify against any trusted approver key"
    for (const candidate of candidates.keys) {
      const attempt = verifyWitness(witness, candidate.key, receipt.canonicalPayload, opts)
      if (attempt.ok) {
        matched = candidate.identity
        matchedKey = candidate.key
        break
      }
      lastReason = attempt.reason
    }
    if (matched === null) {
      failures.push(lastReason)
      continue
    }
    if (requiresHardwareCredential(requirement) && witness.sigAlg !== "WEBAUTHN") {
      failures.push(
        `signer ${witness.signerDid} used a bare key, but the signed policy requires a hardware-backed WebAuthn credential`,
      )
      continue
    }
    // The assertion's signed BE/BS flags can prove a synced passkey signed (DIV §4.4.5 rule 6).
    const synced = requirement.requireHardwareKey === true ? backupFlagsProblem(witness) : null
    if (synced) {
      failures.push(synced)
      continue
    }
    if (requirement.requesterCannotApprove === true && witness.signerDid === receipt.requester.did) {
      failures.push(`four-eyes: requester ${witness.signerDid} cannot seal their own request`)
      continue
    }
    const shared = sharedKeyProblem(countedKeys, matchedKey, matched)
    if (shared) {
      failures.push(shared)
      continue
    }
    verifiedSigners.add(matched)
  }

  const required = requirement.requiredApprovals
  if (verifiedSigners.size < required) {
    const shown = failures.slice(0, MAX_REPORTED_FAILURES)
    const elided = failures.length - shown.length
    const detail = shown.length > 0 ? ` (${shown.join("; ")}${elided > 0 ? `; +${elided} more` : ""})` : ""
    return {
      ok: false,
      reason: `authority sealing quorum not met: ${verifiedSigners.size} of ${required} required approver signatures verified${detail}`,
    }
  }

  return {
    ok: true,
    authority: {
      agentDid: expected.agentDid,
      target: expected.target,
      // Deduplicated + sorted: a duplicate pattern must not suggest a wider scope, and every port
      // that grows this surface later should report the same order.
      actionPatterns: [...new Set(actionPatterns as string[])].sort(),
      parentReceiptHash,
      nonce,
      signers: [...verifiedSigners].sort(),
      sealedAt,
      expiresAt,
    },
  }
}

/** Hash the COMPLETE proof, including every witness. Hashing only the intent would permit a
 * never-approved pending intent to be used as a parent receipt. */
export function agentReceiptDigest(receipt: ApprovalReceipt): string {
  const witnesses = witnessesOf(receipt)
    // Absent fields project to JSON null (DIV §4.3.6). A DID-mode witness may legitimately omit
    // `signerPublicKey` (the key comes from the caller's anchor), and hashing `undefined` used to
    // throw out of every chain verifier that reached this digest.
    .map((w) => ({
      signerDid: w.signerDid ?? null,
      signerPublicKey: w.signerPublicKey ?? null,
      signature: w.signature ?? null,
      sigAlg: w.sigAlg ?? null,
      authenticatorData: w.authenticatorData ?? null,
      clientDataJSON: w.clientDataJSON ?? null,
    }))
    .sort((a, b) => {
      const left = stableStringify(a)
      const right = stableStringify(b)
      return left < right ? -1 : left > right ? 1 : 0
    })
  const content = stableStringify({ canonicalPayload: receipt.canonicalPayload, witnesses })
  return `sha256:${crypto.createHash("sha256").update("intyga-agent-receipt-v1\0").update(content).digest("hex")}`
}

/** Verify a root-to-leaf chain of human-sealed agent scopes. Each child commits the COMPLETE
 * parent receipt. A child's substring pattern denotes a subset only when it contains one of the
 * parent's patterns; this deliberately rejects scopes whose inclusion cannot be proved. */
export function verifyAgentDelegationChain(
  chain: Array<{
    receipt: ApprovalReceipt
    expected: {
      approvers: ApproverTrustAnchor
      target: string
      agentDid: string
      requirement?: RequirementFloor
    }
  }>,
  action: { target: string; actionType: string; agentDid: string; delegatedBy: string },
  opts: VerifyReceiptOptions = {},
): { ok: boolean; reason?: string } {
  if (chain.length < 2 || !AGENT_DIGEST.test(action.delegatedBy))
    return { ok: false, reason: "delegation requires a complete root-to-leaf authority chain" }
  let parent: VerifiedAgentAuthority | null = null
  let parentHash: string | null = null
  for (let index = 0; index < chain.length; index++) {
    const link = chain[index]
    if (!link) return { ok: false, reason: "authority chain has a missing link" }
    const proof = verifyAgentAuthority(link.receipt, link.expected, opts)
    if (!proof.ok || !proof.authority)
      return { ok: false, reason: `authority link ${index + 1}: ${proof.reason}` }
    const authority = proof.authority
    if (authority.target !== action.target) return { ok: false, reason: "delegated authority changes target" }
    if (authority.parentReceiptHash !== parentHash)
      return { ok: false, reason: "delegated authority has a missing or different parent receipt" }
    if (parent) {
      if (
        parseRfc3339Ms(authority.sealedAt) < parseRfc3339Ms(parent.sealedAt) ||
        parseRfc3339Ms(authority.expiresAt) > parseRfc3339Ms(parent.expiresAt)
      )
        return { ok: false, reason: "child authority outlives or predates its parent" }
      const parentPatterns = parent.actionPatterns.map((pattern) => pattern.toLowerCase())
      if (
        authority.actionPatterns.some(
          (child) => !parentPatterns.some((scope) => scope === "*" || child.toLowerCase().includes(scope)),
        )
      )
        return { ok: false, reason: "child authority escalates the parent's action scope" }
    }
    parent = authority
    try {
      parentHash = agentReceiptDigest(link.receipt)
    } catch (err) {
      return {
        ok: false,
        reason: `authority link ${index + 1} cannot be digested: ${(err as Error).message}`,
      }
    }
  }
  if (parentHash !== action.delegatedBy || parent?.agentDid !== action.agentDid)
    return { ok: false, reason: "action does not name its delegated agent and leaf authority receipt" }
  if (
    !parent.actionPatterns.some(
      (pattern) => pattern === "*" || action.actionType.toLowerCase().includes(pattern.toLowerCase()),
    )
  )
    return { ok: false, reason: "action falls outside the delegated authority" }
  return { ok: true }
}

/** RP-side commitment to the exact model/tool/prompt configuration handed to the agent runtime.
 * This is an RP assertion, not an integrity attestation. The PEP must recalculate it immediately
 * before execution and refuse any mismatch with the signed intent. Raw prompt text is never logged. */
export function agentConfigDigest(config: {
  model: { provider: string; version: string }
  tools: Array<{ id: string; version: string; schemaDigest: string }>
  systemPrompt: string
}): string {
  if (
    !config.model.provider ||
    !config.model.version ||
    config.tools.some((tool) => !tool.id || !tool.version || !AGENT_DIGEST.test(tool.schemaDigest))
  )
    throw new Error("agent config requires immutable model and tool identities")
  const tools = [...config.tools].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
  if (tools.some((tool, index) => index > 0 && tool.id === tools.at(index - 1)?.id))
    throw new Error("duplicate agent tool identity")
  const content = stableStringify({ model: config.model, tools, systemPrompt: config.systemPrompt })
  return `sha256:${crypto.createHash("sha256").update("intyga-agent-config-v1\0").update(content).digest("hex")}`
}

/** Verify a complete ordered session bundle against a head pinned OUTSIDE the bundle. An
 * unanchored single branch cannot prove another branch was not withheld. */
export function verifyAgentSessionChain(
  entries: Array<{ receipt: ApprovalReceipt; expected: ReceiptExpectation }>,
  trustedHead: string,
  opts: VerifyReceiptOptions = {},
): { ok: boolean; reason?: string; aggregate?: { amount: string; currency: string } | null } {
  if (!AGENT_DIGEST.test(trustedHead) || entries.length === 0)
    return { ok: false, reason: "complete agent chain and independently trusted head are required" }
  let previous: string | null = null
  let sessionId: string | undefined
  let currency: string | undefined
  let sum = 0n
  let lastAggregate: { amount: string; currency: string } | null = null
  const seen = new Set<string>()
  for (let index = 0; index < entries.length; index++) {
    const entry = entries[index]
    if (!entry) return { ok: false, reason: "agent chain has a missing entry" }
    const { receipt, expected } = entry
    const context = expected.agentContext
    if (!context) return { ok: false, reason: "agent chain entry lacks independent PEP context" }
    const result = verifyApprovalReceipt(receipt, expected, { ...opts, allowAutoApproved: false })
    if (!result.ok) return { ok: false, reason: `agent chain entry ${index + 1}: ${result.reason}` }
    const { session, action } = context
    lastAggregate = session.aggregate
    if (sessionId === undefined) sessionId = session.id
    if (session.id !== sessionId) return { ok: false, reason: "agent chain changes session identity" }
    if (BigInt(session.seq) !== BigInt(index + 1))
      return { ok: false, reason: "agent chain has a gap, duplicate, or forked sequence" }
    if (session.prev !== previous)
      return { ok: false, reason: "agent chain predecessor is missing or forked" }
    let digest: string
    try {
      digest = agentReceiptDigest(receipt)
    } catch (err) {
      return {
        ok: false,
        reason: `agent chain entry ${index + 1} cannot be digested: ${(err as Error).message}`,
      }
    }
    if (seen.has(digest)) return { ok: false, reason: "agent chain repeats a receipt" }
    seen.add(digest)
    previous = digest
    if (action.amount) {
      if (currency === undefined) currency = action.amount.currency
      if (action.amount.currency !== currency || session.aggregate?.currency !== currency)
        return { ok: false, reason: "agent chain changes currency" }
      sum += decimalToNanoUnits(action.amount.amount)
      if (decimalToNanoUnits(session.aggregate.amount) !== sum)
        return { ok: false, reason: "agent aggregate does not equal the sum of signed steps" }
    } else if (session.aggregate !== null || currency !== undefined) {
      return { ok: false, reason: "agent chain mixes monetary and non-monetary steps" }
    }
  }
  if (previous !== trustedHead) return { ok: false, reason: "agent chain does not reach the trusted head" }
  return { ok: true, aggregate: lastAggregate }
}

function decimalToNanoUnits(value: string): bigint {
  const [integer, fraction = ""] = value.split(".")
  if (!integer) throw new Error("invalid decimal amount")
  return BigInt(integer) * 1_000_000_000n + BigInt(fraction.padEnd(9, "0") || "0")
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
  leafCountMismatch,
  type ProofBundle,
  type TrustedCheckpoint,
  type VerificationLevel,
  type VerificationProperties,
  verifyBundle,
  verifyEmbeddedSignature,
  type VerifyOptions,
} from "./ledger-bundle.js"
export {
  EVIDENCE_BUNDLE_KIND,
  type EvidenceAnchorSet,
  type EvidenceBundle,
  type EvidenceEntry,
  type EvidenceVerification,
  type EvidenceVerifyOptions,
  type RedactionRecord,
  verifyEvidenceBundle,
} from "./ledger-evidence.js"
export {
  ANCHOR_ALGORITHMS,
  ANCHOR_CLOCK_SKEW_SECONDS,
  type AnchorInput,
  type AnchorKeyResolver,
  type AnchorPolicy,
  type AnchorQuorumResult,
  DEFAULT_MAX_ANCHOR_LAG_SECONDS,
  type ExpectedCheckpoint,
  type ExternalAnchorKeys,
  anchorDigest,
  anchorDigestHex,
  anchorPreimage,
  isWellFormedAnchor,
  parseAnchorTimestampMs,
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

export {
  verifyRfc3161Anchor,
  verifyRfc3161Timestamp,
  verifyRfc3161TimestampAsync,
  type Rfc3161Trust,
  type Rfc3161Verification,
} from "./ledger-rfc3161.js"

export {
  verifyAuditSignature,
  type AuditSignaturePolicy,
  type AuditSignatureCheck,
} from "./ledger-signature.js"
