import crypto from "node:crypto"
import { NonCanonicalValue, stableStringify } from "./index.ts"
import { verifyEmbeddedSignature } from "./ledger-bundle.ts"
import type { AuditLeaf } from "./ledger-leaf.ts"

// DEWP §4.7 — execution evidence. A Dispatch Record says the executing party sent an approved action;
// an Evidence Record carries a statement an independent evidence source signed about whether it took
// effect. The status derived here reports what a CALLER-TRUSTED source observed, never what physically
// happened (§4.7.6), and it never changes commitment, content, signature or anchor verification.
//
// The executing party writes Dispatch Records, so nothing it writes may decide the verdict on its own:
// a statement binds to ANY Dispatch Record whose hash matches (an early record with another hash is a
// reported conflict, not a way to unbind a trusted contradiction), the evidence window is bounded by
// the caller and never by the dispatch alone, every Approval Record's nonce is reported so a silent
// approval shows as `not_reported`, and a trusted `contradicted` sampled after the deadline is its own
// alert rather than a dropped statement.

/** Signed statement `type` (DEWP §4.7.2). Distinct from every DIV payload type. */
export const DEWP_EXECUTION_EVIDENCE_TYPE = "dewp-execution-evidence"
/** DEWP §4.7.1 event types. */
export const EXECUTION_DISPATCHED = "EXECUTION_DISPATCHED"
export const EXECUTION_CONFIRMED = "EXECUTION_CONFIRMED"
export const EXECUTION_CONTRADICTED = "EXECUTION_CONTRADICTED"
export const EXECUTION_UNCONFIRMED = "EXECUTION_UNCONFIRMED"
/** DEWP §4.7.2 rule 10. */
export const MAX_EXECUTION_EVIDENCE_BYTES = 16_384
/**
 * DEWP §4.7.3 step 6: the default allowance before the dispatch time, caller-overridable. It covers
 * clock error between the source and the producer and nothing else — it also admits a measurement
 * taken just before dispatch, which for an action with no visible change confirms a no-op — so it is
 * small.
 */
export const DEFAULT_EVIDENCE_SKEW_SECONDS = 30
/**
 * DEWP §4.7.3 step 6: the default maximum evidence window, caller-overridable. The executing party
 * chooses `evidenceDeadline`; without this bound a far-out deadline keeps a nonce `pending` forever
 * and `unconfirmed` never fires.
 */
export const DEFAULT_MAX_EVIDENCE_WINDOW_SECONDS = 86_400

const DIV_INTENT_TYPE = "div-intent-verification"
const HEX64 = /^[0-9a-f]{64}$/
/** DEWP §4.7.7: arrays and objects nest at most this deep, the outermost value counting as 1. */
export const MAX_SIGNED_PAYLOAD_DEPTH = 64
/** DEWP §4.7.2 rules 8 and 12: every statement number's magnitude is at most 2^53 − 1. */
const MAX_STATEMENT_NUMBER = 9_007_199_254_740_991
const DEWP_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
const STATEMENT_KEYS = [
  "approval",
  "observation",
  "observedAt",
  "sampledAt",
  "sequence",
  "source",
  "type",
  "v",
  "verdict",
]
const VERDICT_EVENT = { confirmed: EXECUTION_CONFIRMED, contradicted: EXECUTION_CONTRADICTED } as const
const VERDICT_OUTCOME = { confirmed: "SUCCESS", contradicted: "FAILURE" } as const

export type ExecutionVerdict = "confirmed" | "contradicted"

export interface ExecutionEvidenceStatement {
  approval: { nonce: string; payloadSha256: string }
  observation: Record<string, unknown>
  /** When the source produced the statement (DEWP §4.7.2 rule 6). */
  observedAt: string
  /** When the measurement behind `observation` was taken (rule 11); the window is evaluated on it. */
  sampledAt: string
  /** The source's own gapless, per-log counter (rule 12). */
  sequence: number
  source: string
  type: typeof DEWP_EXECUTION_EVIDENCE_TYPE
  v: 1
  verdict: ExecutionVerdict
}

/**
 * One caller-trusted key for an evidence source: a bare base64 SPKI P-256 key (valid at any time), or
 * the key with a validity interval (DEWP §4.7.5), each bound a §4.3 timestamp, both inclusive, either
 * optional. A bounded key establishes trust only at the record's ANCHORED time.
 */
export type TrustedSourceKey = string | { key: string; notBefore?: string; notAfter?: string }

/** Caller-owned evidence-source trust: source identifier → keys (DEWP §4.7.5). */
export interface ExecutionEvidencePolicy {
  trustedSources: Record<string, TrustedSourceKey[]>
}

export interface ExecutionEvidenceCheck {
  status: "verified" | "invalid" | "not_checked" | "unbound" | "stale"
  reason: string
  /** True only when the statement verified under a caller-provisioned key valid for its source. */
  trusted: boolean
  nonce: string | null
  verdict: ExecutionVerdict | null
  /** The statement's `source` and `sequence` once it parsed; null before that. */
  source: string | null
  sequence: number | null
}

export type ExecutionStatus = "confirmed" | "contradicted" | "unconfirmed" | "pending" | "not_reported"

/** DEWP §4.7.3 "Source continuity": what one source's counter shows inside the bundle. */
export interface SourceContinuity {
  /** Smallest and largest `sequence` seen from this source. */
  first: number
  last: number
  /** Inclusive ranges of counter values between `first` and `last` that no record carries. */
  gaps: Array<[number, number]>
  /** Counter values carried by two or more records whose statement bytes differ. */
  divergent: number[]
}

export interface ExecutionNonceReport {
  status: ExecutionStatus
  /** The governing Dispatch Record (DEWP §4.7.3 step 5 / §4.7.4), or null. */
  dispatchSeq: string | null
  /** Its own `evidenceDeadline`, as written by the executing party. */
  evidenceDeadline: string | null
  /** The deadline the status was evaluated against: `evidenceDeadline` cut to the caller's window. */
  effectiveDeadline: string | null
  /** True when the record's own deadline lay beyond the caller's maximum window (§4.7.4). */
  windowCapped: boolean
  /** Dispatch Records for this nonce that disagree on `payloadSha256`; empty when they agree (§4.7.4). */
  dispatchConflict: string[]
  /** Trusted, bound `contradicted` statements sampled after the effective deadline (§4.7.4). */
  lateContradiction: string[]
  /**
   * Bound, in-window or late `contradicted` statements whose signature verified under a caller-provisioned
   * key that did not establish trust — its validity could not be placed in time, or the record lay
   * outside it (§4.7.4, §4.7.5). They cannot decide the status; they are never silent.
   */
  untrustedContradiction: string[]
  evidenceSeqs: string[]
}

export interface ExecutionVerification {
  /** One check per Evidence Record, in bundle order. */
  checks: Array<ExecutionEvidenceCheck & { seq: string }>
  /** DEWP §4.7.4 status per approval nonce named by an Approval, Dispatch or Evidence Record. */
  byNonce: Record<string, ExecutionNonceReport>
  confirmed: string[]
  contradicted: string[]
  unconfirmed: string[]
  pending: string[]
  notReported: string[]
  /** Nonces with a late contradiction — the alert that most needs escalation (§4.7.4). */
  lateContradicted: string[]
  /** Nonces with a contradiction under a provisioned key that established no trust (§4.7.4). */
  untrustedContradicted: string[]
  /** Nonces whose Dispatch Records disagree (§4.7.4). */
  dispatchConflicts: string[]
  /** Per-source continuity over the statements whose signature verified (§4.7.3). */
  sources: Record<string, SourceContinuity>
}

export interface ExecutionEvaluationOptions {
  policy?: ExecutionEvidencePolicy
  /** Evaluation time, epoch ms; defaults to the current time. An input, so a status is reproducible. */
  now?: number
  skewSeconds?: number
  maxWindowSeconds?: number
  /**
   * The anchored time of the record at `seq` (epoch ms): the earliest external witness time among
   * anchors that counted toward quorum for a checkpoint covering it — or null when none does (DEWP
   * §4.7.5). Only consulted for caller keys that carry a validity interval.
   */
  anchoredTime?: (seq: string) => number | null
}

/** A DEWP §4.3 timestamp that names a real instant, as epoch milliseconds; NaN otherwise. */
function parseDewpTimestamp(value: unknown): number {
  if (typeof value !== "string" || !DEWP_TIMESTAMP.test(value)) return Number.NaN
  const ms = Date.parse(value)
  // Round-trip rejects calendar overflow (30 February) that a lenient parser would roll forward.
  return Number.isFinite(ms) && new Date(ms).toISOString() === value ? ms : Number.NaN
}

/** True when `text` nests arrays/objects deeper than `limit`, scanned without parsing. */
function nestsDeeperThan(text: string, limit: number): boolean {
  let depth = 0
  let inString = false
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i)
    if (inString) {
      if (c === 0x5c)
        i++ // backslash: skip the escaped character
      else if (c === 0x22) inString = false
    } else if (c === 0x22) inString = true
    else if (c === 0x5b || c === 0x7b) {
      if (++depth > limit) return true
    } else if (c === 0x5d || c === 0x7d) depth--
  }
  return false
}

/** Every number in `value` satisfies `ok`. */
function everyNumber(value: unknown, ok: (n: number) => boolean): boolean {
  if (typeof value === "number") return ok(value)
  if (Array.isArray(value)) return value.every((v) => everyNumber(v, ok))
  if (value !== null && typeof value === "object")
    return Object.values(value as Record<string, unknown>).every((v) => everyNumber(v, ok))
  return true
}

/**
 * DEWP §4.7.7: the one way §4.7 parses a signed payload, so no two verifiers classify the same bytes
 * differently. JSON.parse already refuses trailing content and NaN/Infinity literals; the depth bound
 * and the finite-number rule are what other runtimes would otherwise disagree on.
 */
export function parseSignedPayload(text: string): { ok: true; value: unknown } | { ok: false } {
  if (nestsDeeperThan(text, MAX_SIGNED_PAYLOAD_DEPTH)) return { ok: false }
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch {
    return { ok: false }
  }
  return everyNumber(value, Number.isFinite) ? { ok: true, value } : { ok: false }
}

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v)

/**
 * Parse an Execution Evidence Statement and enforce DEWP §4.7.2 rules 1–3 and 5–12. Rule 4 (source
 * equals the leaf's signer) needs the leaf and is checked by the caller.
 */
export function parseExecutionEvidenceStatement(
  bytes: string,
): { ok: true; statement: ExecutionEvidenceStatement } | { ok: false; reason: string } {
  const fail = (reason: string) => ({ ok: false as const, reason })
  if (Buffer.byteLength(bytes, "utf8") > MAX_EXECUTION_EVIDENCE_BYTES)
    return fail(`statement exceeds ${MAX_EXECUTION_EVIDENCE_BYTES} bytes`)
  const parsed = parseSignedPayload(bytes)
  if (!parsed.ok) return fail("statement does not parse (DEWP §4.7.7)")
  const value = parsed.value
  if (!everyNumber(value, (n) => Math.abs(n) <= MAX_STATEMENT_NUMBER))
    return fail("a statement number exceeds 2^53 − 1")
  // Rules 8 and 9 together: re-serializing under RFC 8785 must reproduce the bytes exactly. This also
  // refuses duplicate member names, whitespace, non-portable numbers and unpaired surrogates, so every
  // port reads the same statement from the same bytes.
  try {
    if (stableStringify(value) !== bytes) return fail("statement is not in RFC 8785 canonical form")
  } catch (err) {
    if (err instanceof NonCanonicalValue) return fail(`statement is not canonical: ${err.message}`)
    throw err
  }
  if (!isPlainObject(value)) return fail("statement is not a JSON object")
  const keys = Object.keys(value).sort()
  if (keys.length !== STATEMENT_KEYS.length || keys.some((k, i) => k !== STATEMENT_KEYS[i]))
    return fail(`statement must have exactly the members ${STATEMENT_KEYS.join(", ")}`)
  if (value.type !== DEWP_EXECUTION_EVIDENCE_TYPE)
    return fail(`statement type is not ${DEWP_EXECUTION_EVIDENCE_TYPE}`)
  if (value.v !== 1) return fail("statement version v must be 1")
  const approval = value.approval
  if (!isPlainObject(approval)) return fail("approval must be an object")
  const approvalKeys = Object.keys(approval).sort()
  if (approvalKeys.length !== 2 || approvalKeys[0] !== "nonce" || approvalKeys[1] !== "payloadSha256")
    return fail("approval must have exactly the members nonce, payloadSha256")
  if (typeof approval.nonce !== "string" || approval.nonce.length === 0)
    return fail("approval.nonce must be a non-empty string")
  if (typeof approval.payloadSha256 !== "string" || !HEX64.test(approval.payloadSha256))
    return fail("approval.payloadSha256 must be 64 lowercase hex characters")
  if (typeof value.source !== "string" || value.source.length === 0)
    return fail("source must be a non-empty string")
  if (value.verdict !== "confirmed" && value.verdict !== "contradicted")
    return fail("verdict must be confirmed or contradicted")
  const observedMs = parseDewpTimestamp(value.observedAt)
  if (Number.isNaN(observedMs)) return fail("observedAt must be a YYYY-MM-DDTHH:mm:ss.sssZ timestamp")
  const sampledMs = parseDewpTimestamp(value.sampledAt)
  if (Number.isNaN(sampledMs)) return fail("sampledAt must be a YYYY-MM-DDTHH:mm:ss.sssZ timestamp")
  if (sampledMs > observedMs) return fail("sampledAt must not be later than observedAt")
  if (typeof value.sequence !== "number" || !Number.isInteger(value.sequence) || value.sequence < 1)
    return fail("sequence must be an integer from 1 to 2^53 − 1")
  if (!isPlainObject(value.observation)) return fail("observation must be an object")
  return { ok: true, statement: value as unknown as ExecutionEvidenceStatement }
}

/**
 * The canonical statement bytes an evidence source signs (DEWP §4.7.2). Throws on input the
 * statement rules refuse, so a source can never sign bytes a verifier will reject as malformed.
 */
export function canonicalExecutionEvidenceStatement(input: {
  nonce: string
  payloadSha256: string
  source: string
  verdict: ExecutionVerdict
  observedAt: string
  sampledAt: string
  sequence: number
  observation: Record<string, unknown>
}): string {
  const bytes = stableStringify({
    approval: { nonce: input.nonce, payloadSha256: input.payloadSha256 },
    observation: input.observation,
    observedAt: input.observedAt,
    sampledAt: input.sampledAt,
    sequence: input.sequence,
    source: input.source,
    type: DEWP_EXECUTION_EVIDENCE_TYPE,
    v: 1,
    verdict: input.verdict,
  })
  const parsed = parseExecutionEvidenceStatement(bytes)
  if (!parsed.ok) throw new NonCanonicalValue(parsed.reason)
  return bytes
}

/** Lowercase hex SHA-256 of a DIV Intent Payload's UTF-8 bytes — the statement's `payloadSha256`. */
export function executionPayloadSha256(canonicalPayload: string): string {
  return crypto.createHash("sha256").update(canonicalPayload, "utf8").digest("hex")
}

/** The parsed JSON object a signed payload carries, or null. */
function payloadObject(signedPayload: string | null): Record<string, unknown> | null {
  if (!signedPayload) return null
  const parsed = parseSignedPayload(signedPayload)
  return parsed.ok && isPlainObject(parsed.value) ? parsed.value : null
}

/** True when a leaf's signed payload is an Execution Evidence Statement (DEWP §4.7.3). */
export function isExecutionEvidencePayload(signedPayload: string | null): boolean {
  return payloadObject(signedPayload)?.type === DEWP_EXECUTION_EVIDENCE_TYPE
}

/**
 * An Evidence Record: its event type says so, or its signed payload is a statement. Either suffices,
 * so a record cannot dodge evidence-source trust by mislabelling one side (DEWP §4.7.3, §4.7.5).
 */
export function isExecutionEvidenceLeaf(leaf: Pick<AuditLeaf, "event" | "signedPayload">): boolean {
  return (
    leaf.event === EXECUTION_CONFIRMED ||
    leaf.event === EXECUTION_CONTRADICTED ||
    isExecutionEvidencePayload(leaf.signedPayload)
  )
}

interface NormalizedKey {
  key: string
  notBefore: string | undefined
  notAfter: string | undefined
  /** Why this entry can verify a signature but never establish trust (§4.7.5), or null. */
  malformed: string | null
}

const KEY_ENTRY_MEMBERS = new Set(["key", "notBefore", "notAfter"])

/**
 * The caller's keys for a source as `{key, notBefore, notAfter}`. An entry with no usable key is
 * dropped (nothing can verify under it). An entry with any other member, or a bound that is present
 * but not a string, is kept with its key and marked malformed: a misspelt `notafter` or a numeric
 * bound must fail closed, never read as "no bound".
 */
function trustedKeysFor(policy: ExecutionEvidencePolicy, source: string | null): NormalizedKey[] {
  if (!source || !Object.hasOwn(policy.trustedSources, source)) return []
  const raw = policy.trustedSources[source]
  if (!Array.isArray(raw)) return []
  const out: NormalizedKey[] = []
  for (const entry of raw) {
    if (typeof entry === "string") {
      if (entry.length > 0)
        out.push({ key: entry, notBefore: undefined, notAfter: undefined, malformed: null })
      continue
    }
    if (!isPlainObject(entry) || typeof entry.key !== "string" || entry.key.length === 0) continue
    const unknown = Object.keys(entry).filter((m) => !KEY_ENTRY_MEMBERS.has(m))
    const members = entry as Record<string, unknown>
    const badBound = ["notBefore", "notAfter"].find(
      (m) => members[m] !== undefined && typeof members[m] !== "string",
    )
    out.push({
      key: entry.key,
      notBefore: typeof entry.notBefore === "string" ? entry.notBefore : undefined,
      notAfter: typeof entry.notAfter === "string" ? entry.notAfter : undefined,
      malformed:
        unknown.length > 0
          ? `Caller key entry has unexpected member(s) ${unknown.join(", ")}; it does not establish trust.`
          : badBound
            ? `Caller key entry's ${badBound} is not a timestamp string; it does not establish trust.`
            : null,
    })
  }
  return out
}

/**
 * DEWP §4.7.5: a bounded key establishes trust only at the record's anchored time. `observedAt` and
 * `sampledAt` are the source's own claims and are never used here — a compromised key could place a
 * statement inside the period when it was still valid; a witness cannot be backdated.
 */
function keyValidAt(
  k: NormalizedKey,
  anchoredTimeMs: number | null | undefined,
): { ok: true } | { ok: false; reason: string } {
  if (k.malformed !== null) return { ok: false, reason: k.malformed }
  if (k.notBefore === undefined && k.notAfter === undefined) return { ok: true }
  const from = k.notBefore === undefined ? Number.NEGATIVE_INFINITY : parseDewpTimestamp(k.notBefore)
  const to = k.notAfter === undefined ? Number.POSITIVE_INFINITY : parseDewpTimestamp(k.notAfter)
  if (Number.isNaN(from) || Number.isNaN(to))
    return {
      ok: false,
      reason: "Caller key carries a malformed validity interval; it does not establish trust.",
    }
  if (anchoredTimeMs === null || anchoredTimeMs === undefined)
    return {
      ok: false,
      reason:
        "Caller key carries a validity interval but no counting anchor covers this record, so the key " +
        "cannot be placed in time (DEWP §4.7.5); it does not establish trust.",
    }
  if (anchoredTimeMs < from || anchoredTimeMs > to)
    return {
      ok: false,
      reason:
        "Caller key was not valid at this record's anchored time (DEWP §4.7.5); it does not establish trust.",
    }
  return { ok: true }
}

/**
 * ES256 under caller-provisioned keys for the statement's source. Evidence-source trust only: an
 * approver key never verifies a statement, and an evidence key never verifies an approval (§4.7.5).
 * A key with a validity interval verifies the signature but establishes trust only at the record's
 * anchored time (`anchoredTimeMs`, null when no counting anchor covers the record).
 */
export function verifyEvidenceSignature(
  leaf: AuditLeaf,
  policy?: ExecutionEvidencePolicy,
  anchoredTimeMs?: number | null,
): { status: "verified" | "invalid" | "not_checked"; reason: string; trusted: boolean } {
  if (!policy) {
    return verifyEmbeddedSignature(leaf)
      ? {
          status: "verified",
          reason: "Signature valid under embedded key; source identity is not established.",
          trusted: false,
        }
      : { status: "invalid", reason: "Statement signature does not verify.", trusted: false }
  }
  const keys = trustedKeysFor(policy, leaf.signerDid)
  if (keys.length === 0)
    return {
      status: "not_checked",
      reason: "No caller-trusted key for this evidence source.",
      trusted: false,
    }
  let untrustedReason: string | null = null
  for (const k of keys) {
    if (!verifyEmbeddedSignature({ ...leaf, signerPublicKey: k.key })) continue
    const validity = keyValidAt(k, anchoredTimeMs)
    if (validity.ok)
      return { status: "verified", reason: "Statement valid under caller-trusted source key.", trusted: true }
    untrustedReason ??= validity.reason
  }
  if (untrustedReason !== null) return { status: "verified", reason: untrustedReason, trusted: false }
  return {
    status: "invalid",
    reason: "Statement signature does not verify under caller trust.",
    trusted: false,
  }
}

type Decided = ExecutionEvidenceCheck

/** DEWP §4.7.3 steps 1–4: everything a single leaf can establish on its own. */
function checkLeaf(
  leaf: AuditLeaf,
  policy: ExecutionEvidencePolicy | undefined,
  anchoredTimeMs: number | null | undefined,
): { done: Decided } | { statement: ExecutionEvidenceStatement; trusted: boolean; note: string | null } {
  const done = (
    status: Decided["status"],
    reason: string,
    statement?: ExecutionEvidenceStatement,
    trusted = false,
  ) => ({
    done: {
      status,
      reason,
      trusted,
      nonce: statement?.approval.nonce ?? null,
      verdict: statement?.verdict ?? null,
      source: statement?.source ?? null,
      sequence: statement?.sequence ?? null,
    },
  })
  if (leaf.sigAlg !== "ES256" || !leaf.signature || !leaf.signerPublicKey || !leaf.signedPayload)
    return done("invalid", "Evidence Records must carry an ES256 signature, public key and statement.")
  const parsed = parseExecutionEvidenceStatement(leaf.signedPayload)
  if (!parsed.ok) return done("invalid", `Malformed statement: ${parsed.reason}.`)
  const statement = parsed.statement
  if (statement.source !== leaf.signerDid)
    return done("invalid", "Statement source does not match the record's signerDid.", statement)
  if (leaf.event !== VERDICT_EVENT[statement.verdict] || leaf.outcome !== VERDICT_OUTCOME[statement.verdict])
    return done("invalid", "Record event/outcome do not match the signed verdict.", statement)
  const signature = verifyEvidenceSignature(leaf, policy, anchoredTimeMs)
  if (signature.status !== "verified") return done(signature.status, signature.reason, statement)
  // A verified-but-untrusted signature under a policy carries the reason (a bounded key outside its
  // interval, or no anchored time); the embedded-key case needs no note, the status says it.
  return {
    statement,
    trusted: signature.trusted,
    note: policy && !signature.trusted ? signature.reason : null,
  }
}

const withNote = (reason: string, note: string | null): string => (note ? `${reason} ${note}` : reason)

/**
 * DEWP §4.7.3 for a leaf seen on its own (a single inclusion proof). Binding needs the dispatch and
 * approval records, which a single proof does not carry, so a statement is never `verified` here.
 */
export function checkExecutionEvidenceLeaf(
  leaf: AuditLeaf,
  policy?: ExecutionEvidencePolicy,
  anchoredTimeMs?: number | null,
): ExecutionEvidenceCheck {
  const r = checkLeaf(leaf, policy, anchoredTimeMs)
  if ("done" in r) return r.done
  return {
    status: "unbound",
    reason: withNote("A single proof cannot bind a statement to its dispatch and approval records.", r.note),
    trusted: r.trusted,
    nonce: r.statement.approval.nonce,
    verdict: r.statement.verdict,
    source: r.statement.source,
    sequence: r.statement.sequence,
  }
}

interface Dispatch {
  nonce: string
  seq: string
  createdAtMs: number
  deadline: string
  deadlineMs: number
  payloadSha256: string
}

/** A valid Dispatch Record's governing fields, or null when the record does not qualify. */
function dispatchOf(leaf: AuditLeaf): Dispatch | null {
  if (leaf.event !== EXECUTION_DISPATCHED) return null
  const m = isPlainObject(leaf.metadata) ? leaf.metadata : null
  if (!m || typeof m.nonce !== "string" || m.nonce.length === 0) return null
  if (typeof m.payloadSha256 !== "string" || !HEX64.test(m.payloadSha256)) return null
  const deadlineMs = parseDewpTimestamp(m.evidenceDeadline)
  const createdAtMs = parseDewpTimestamp(leaf.createdAt)
  if (Number.isNaN(deadlineMs) || Number.isNaN(createdAtMs)) return null
  return {
    nonce: m.nonce,
    seq: leaf.seq,
    createdAtMs,
    deadline: m.evidenceDeadline as string,
    deadlineMs,
    payloadSha256: m.payloadSha256,
  }
}

/** Numeric `seq` order; a non-numeric seq (which a verified entry cannot have) sorts last. */
const seqOrder = (a: string, b: string): number => {
  const num = (v: string): bigint | null => (/^\d+$/.test(v) ? BigInt(v) : null)
  const x = num(a)
  const y = num(b)
  if (x === null || y === null) return x === null ? (y === null ? 0 : 1) : -1
  return x < y ? -1 : x > y ? 1 : 0
}

/** The deadline a status is evaluated against: the record's own, cut to the caller's window. */
const effectiveDeadlineOf = (d: Dispatch, maxWindowMs: number): { ms: number; capped: boolean } => {
  const bound = d.createdAtMs + maxWindowMs
  return d.deadlineMs > bound ? { ms: bound, capped: true } : { ms: d.deadlineMs, capped: false }
}

/** DEWP §4.7.3 "Source continuity" over the records that passed step 4. */
function continuity(
  records: Map<string, Array<{ sequence: number; bytes: string }>>,
): Record<string, SourceContinuity> {
  const out = Object.create(null) as Record<string, SourceContinuity>
  for (const [source, list] of [...records.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    const bySequence = new Map<number, Set<string>>()
    for (const r of list) {
      const set = bySequence.get(r.sequence) ?? new Set<string>()
      set.add(r.bytes)
      bySequence.set(r.sequence, set)
    }
    const seen = [...bySequence.keys()].sort((a, b) => a - b)
    const first = seen[0] as number
    const last = seen[seen.length - 1] as number
    // Gaps as ranges: a source that signed 1 and 2^53 − 1 must not make the verifier enumerate the
    // numbers in between.
    const gaps: Array<[number, number]> = []
    for (let i = 1; i < seen.length; i++) {
      const prev = seen[i - 1] as number
      const next = seen[i] as number
      if (next - prev > 1) gaps.push([prev + 1, next - 1])
    }
    const divergent = seen.filter((s) => (bySequence.get(s)?.size ?? 0) > 1)
    out[source] = { first, last, gaps, divergent }
  }
  return out
}

/**
 * DEWP §4.7.3–§4.7.4 over the CONTENT-VERIFIED entries of one evidence bundle. `now` is the
 * evaluation time (epoch ms, default the current time) and is an input so a status is reproducible.
 */
export function evaluateExecutionEvidence(
  entries: Array<{ seq: string; leaf: AuditLeaf }>,
  opts: ExecutionEvaluationOptions = {},
): ExecutionVerification {
  const now = opts.now ?? Date.now()
  // A bound that is not a finite, non-negative number is no bound at all; fall back to the default
  // rather than let NaN remove the window cap or the early-sample limit.
  const seconds = (v: number | undefined, fallback: number): number =>
    typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : fallback
  const skewMs = seconds(opts.skewSeconds, DEFAULT_EVIDENCE_SKEW_SECONDS) * 1000
  const maxWindowMs = seconds(opts.maxWindowSeconds, DEFAULT_MAX_EVIDENCE_WINDOW_SECONDS) * 1000
  const anchoredTime = opts.anchoredTime ?? (() => null)
  const ordered = [...entries].sort((a, b) => seqOrder(a.seq, b.seq))
  /** Every valid Dispatch Record per nonce, in seq order. */
  const dispatches = new Map<string, Dispatch[]>()
  const approvalHashes = new Map<string, Set<string>>()
  for (const { leaf } of ordered) {
    const d = dispatchOf(leaf)
    if (d) dispatches.set(d.nonce, [...(dispatches.get(d.nonce) ?? []), d])
    const p = payloadObject(leaf.signedPayload)
    if (p?.type === DIV_INTENT_TYPE && typeof p.nonce === "string" && leaf.signedPayload) {
      const set = approvalHashes.get(p.nonce) ?? new Set<string>()
      set.add(executionPayloadSha256(leaf.signedPayload))
      approvalHashes.set(p.nonce, set)
    }
  }

  const checks: ExecutionVerification["checks"] = []
  const evidenceSeqs = new Map<string, string[]>()
  /** Per nonce: the governing Dispatch Record of its bound statements (first seen). */
  const governingByNonce = new Map<string, Dispatch>()
  const lateContradictions = new Map<string, string[]>()
  const untrustedContradictions = new Map<string, string[]>()
  const continuityRecords = new Map<string, Array<{ sequence: number; bytes: string }>>()
  for (const { seq, leaf } of entries) {
    if (!isExecutionEvidenceLeaf(leaf)) continue
    const r = checkLeaf(leaf, opts.policy, anchoredTime(seq))
    let check: ExecutionEvidenceCheck
    if ("done" in r) check = r.done
    else {
      const { statement, trusted, note } = r
      continuityRecords.set(statement.source, [
        ...(continuityRecords.get(statement.source) ?? []),
        { sequence: statement.sequence, bytes: leaf.signedPayload as string },
      ])
      const base = {
        trusted,
        nonce: statement.approval.nonce,
        verdict: statement.verdict,
        source: statement.source,
        sequence: statement.sequence,
      }
      const all = dispatches.get(statement.approval.nonce) ?? []
      const matching = all.filter((d) => d.payloadSha256 === statement.approval.payloadSha256)
      const governing = matching[0]
      if (!governing)
        check = {
          ...base,
          status: "unbound",
          reason: withNote(
            all.length === 0
              ? "No Dispatch Record for this approval nonce."
              : "No Dispatch Record for this nonce carries the statement's payload hash.",
            note,
          ),
        }
      else if (!approvalHashes.get(statement.approval.nonce)?.has(statement.approval.payloadSha256))
        check = {
          ...base,
          status: "unbound",
          reason: withNote("No Approval Record with this nonce and payload hash.", note),
        }
      else {
        if (!governingByNonce.has(statement.approval.nonce))
          governingByNonce.set(statement.approval.nonce, governing)
        const sampledMs = parseDewpTimestamp(statement.sampledAt)
        const deadline = effectiveDeadlineOf(governing, maxWindowMs)
        // A provisioned key signed this contradiction but established no trust (`note` is set only
        // then). In-window or late, it cannot decide the status and must not be silent (§4.7.4).
        if (
          sampledMs >= governing.createdAtMs - skewMs &&
          !trusted &&
          note !== null &&
          statement.verdict === "contradicted"
        )
          untrustedContradictions.set(statement.approval.nonce, [
            ...(untrustedContradictions.get(statement.approval.nonce) ?? []),
            seq,
          ])
        if (sampledMs < governing.createdAtMs - skewMs)
          check = {
            ...base,
            status: "stale",
            reason: withNote("Sampled before the dispatch evidence window (early).", note),
          }
        else if (sampledMs > deadline.ms) {
          check = {
            ...base,
            status: "stale",
            reason: withNote("Sampled after the dispatch evidence window (late).", note),
          }
          if (trusted && statement.verdict === "contradicted")
            lateContradictions.set(statement.approval.nonce, [
              ...(lateContradictions.get(statement.approval.nonce) ?? []),
              seq,
            ])
        } else {
          check = {
            ...base,
            status: "verified",
            reason: withNote("Statement verified and bound to its dispatch and approval.", note),
          }
        }
      }
    }
    checks.push({ seq, ...check })
    if (check.nonce) evidenceSeqs.set(check.nonce, [...(evidenceSeqs.get(check.nonce) ?? []), seq])
  }

  const nonces = new Set<string>([...approvalHashes.keys(), ...dispatches.keys(), ...evidenceSeqs.keys()])
  const result: ExecutionVerification = {
    checks,
    // Null prototype: a nonce named "__proto__" is an ordinary key, not the object's prototype.
    byNonce: Object.create(null) as ExecutionVerification["byNonce"],
    confirmed: [],
    contradicted: [],
    unconfirmed: [],
    pending: [],
    notReported: [],
    lateContradicted: [],
    untrustedContradicted: [],
    dispatchConflicts: [],
    sources: continuity(continuityRecords),
  }
  for (const nonce of [...nonces].sort()) {
    const counted = checks.filter((c) => c.nonce === nonce && c.status === "verified" && c.trusted)
    const all = dispatches.get(nonce) ?? []
    // The governing record: the one the nonce's bound statements bound to, else the first that names it.
    const dispatch = governingByNonce.get(nonce) ?? all[0]
    const deadline = dispatch ? effectiveDeadlineOf(dispatch, maxWindowMs) : null
    const status: ExecutionStatus = counted.some((c) => c.verdict === "contradicted")
      ? "contradicted"
      : counted.some((c) => c.verdict === "confirmed")
        ? "confirmed"
        : !dispatch || !deadline
          ? "not_reported"
          : deadline.ms < now
            ? "unconfirmed"
            : "pending"
    const conflict = new Set(all.map((d) => d.payloadSha256)).size > 1 ? all.map((d) => d.seq) : []
    const late = lateContradictions.get(nonce) ?? []
    const untrusted = untrustedContradictions.get(nonce) ?? []
    result.byNonce[nonce] = {
      status,
      dispatchSeq: dispatch?.seq ?? null,
      evidenceDeadline: dispatch?.deadline ?? null,
      effectiveDeadline: deadline ? new Date(deadline.ms).toISOString() : null,
      windowCapped: deadline?.capped ?? false,
      dispatchConflict: conflict,
      lateContradiction: late,
      untrustedContradiction: untrusted,
      evidenceSeqs: evidenceSeqs.get(nonce) ?? [],
    }
    const bucket = status === "not_reported" ? result.notReported : result[status]
    bucket.push(nonce)
    if (conflict.length > 0) result.dispatchConflicts.push(nonce)
    if (untrusted.length > 0) result.untrustedContradicted.push(nonce)
    if (late.length > 0) result.lateContradicted.push(nonce)
  }
  return result
}
