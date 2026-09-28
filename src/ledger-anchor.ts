import crypto from "node:crypto"
import { verifyRfc3161Anchor, type Rfc3161Trust } from "./ledger-rfc3161.js"
import { parseRekorEvidence, verifyRekorAnchor } from "./ledger-rekor.js"

// DEWP signed anchor objects (docs/DEWP.md §5.2/§5.3). A Daily Checkpoint Root becomes trustworthy
// only when independent external parties SIGN it. This module computes the domain-separated anchor
// digest (0x03 tag), verifies an anchor's signature, and evaluates a multi-anchor QUORUM so a single
// compromised anchor provider cannot forge non-repudiation. Zero deps beyond node:crypto.

export const ANCHOR_TAG = 0x03

/** RSA-PSS anchors (DEWP §5.2): SHA-256, MGF1-SHA-256, salt length = hash length. */
export const RSA_PSS_SALT_LENGTH = 32
/** Smallest RSA modulus an RSA-PSS anchor key may have (DEWP §5.2). */
export const RSA_MIN_MODULUS_BITS = 2048

/**
 * The signed part of an anchor (DEWP §5.2): the daily root, the checkpoint's claimed time, the issuer
 * and algorithm, AND the checkpoint's position — its global seq range and its §5.4 chain hash.
 *
 * The position fields are what make an anchor evidence about ONE checkpoint rather than about a root
 * string. Without them a witness attests only "someone showed me this 64-hex value at time T", and a
 * party able to rewrite the log could recompute a root and have it witnessed at any later time with no
 * binding to where in the log it claims to sit. With them, the chain hash commits to every earlier
 * root, so a later anchor also re-attests the history before it.
 */
export interface AnchorInput {
  dailyRoot: string // 64-char lowercase hex
  timestamp: string // ISO 8601 UTC, the checkpoint's own claimed commit time (DEWP §4.3 format)
  issuer: string // HTTPS URI or DID of the anchor provider
  algorithm: "ES256" | "Ed25519" | "RSA-PSS"
  /** First global `seq` the checkpoint commits (stringified integer). */
  seqStart: string
  /** Last global `seq` the checkpoint commits (stringified integer). */
  seqEnd: string
  /** The checkpoint's §5.4 continuity chain hash (64-char lowercase hex). */
  chainHash: string
}

/** A signed commitment to a daily checkpoint root, published to an independent public anchor. */
export interface SignedAnchor extends AnchorInput {
  keyId: string
  signature: string // base64, over the raw 32-byte anchorDigest. EMPTY for external anchors.
  /**
   * SELF | REKOR | RFC3161 | WEBHOOK. Decides WHICH verification applies; absent ⇒ treated as
   * DEWP-signed (SELF). WEBHOOK and unrecognized kinds never count toward quorum (DEWP §5.2.1) —
   * this verifier has no evidence verifier for them.
   */
  kind?: string
  /** The external log's own attestation, base64 (Rekor: entry + SET + inclusion proof). */
  evidence?: string | null
}

/**
 * The canonical anchor preimage: RFC 8785 JCS of the 7-element array
 * [dailyRoot, timestamp, issuer, algorithm, seqStart, seqEnd, chainHash]. Every element is a string,
 * so JCS is exactly `JSON.stringify` with no insignificant space.
 */
export function anchorPreimage(a: AnchorInput): string {
  return JSON.stringify([a.dailyRoot, a.timestamp, a.issuer, a.algorithm, a.seqStart, a.seqEnd, a.chainHash])
}

/** The raw 32-byte anchor digest: SHA-256(0x03 || UTF8(anchorPreimage)). This is what gets signed. */
export function anchorDigest(a: AnchorInput): Buffer {
  return crypto
    .createHash("sha256")
    .update(Buffer.from([ANCHOR_TAG]))
    .update(Buffer.from(anchorPreimage(a), "utf8"))
    .digest()
}

/** Hex form of the anchor digest (for display / vectors). */
export function anchorDigestHex(a: AnchorInput): string {
  return anchorDigest(a).toString("hex")
}

/**
 * Sign an anchor digest with a producer key. Helper for anchor providers and tests — a relying party
 * only needs `verifyAnchorSignature`. The message is the RAW 32-byte digest (never its hex string):
 * ES256/RSA-PSS then apply their own SHA-256, Ed25519 signs the bytes directly.
 */
export function signAnchor(a: AnchorInput, privateKey: crypto.KeyObject): string {
  const digest = anchorDigest(a)
  if (a.algorithm === "Ed25519") return crypto.sign(null, digest, privateKey).toString("base64")
  if (a.algorithm === "RSA-PSS") {
    // Salt length = hash length (32), the only one verifiers accept (DEWP §5.2). Node's default for
    // signing is the MAXIMUM salt, which no longer verifies.
    return crypto
      .sign("sha256", digest, {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: RSA_PSS_SALT_LENGTH,
      })
      .toString("base64")
  }
  // ES256 (P-256 + SHA-256), DER encoding.
  return crypto.sign("sha256", digest, { key: privateKey, dsaEncoding: "der" }).toString("base64")
}

/**
 * Verify an anchor's signature over its digest against a resolved public key. Pins the key type to the
 * declared algorithm so an anchor labelled ES256 can't be verified under some other scheme.
 */
export function verifyAnchorSignature(anchor: SignedAnchor, publicKey: crypto.KeyObject): boolean {
  try {
    if (!isWellFormedAnchor(anchor)) return false
    const digest = anchorDigest(anchor)
    const sig = Buffer.from(anchor.signature, "base64")
    if (anchor.algorithm === "Ed25519") {
      if (publicKey.asymmetricKeyType !== "ed25519") return false
      return crypto.verify(null, digest, publicKey, sig)
    }
    if (anchor.algorithm === "RSA-PSS") {
      if (publicKey.asymmetricKeyType !== "rsa" && publicKey.asymmetricKeyType !== "rsa-pss") return false
      if ((publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < RSA_MIN_MODULUS_BITS) return false
      // A fixed salt length, not auto-detection: RSASSA-PSS/SHA-256 with MGF1-SHA-256 and a 32-byte
      // salt is the one §5.2 profile, identical in every port.
      return crypto.verify(
        "sha256",
        digest,
        { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: RSA_PSS_SALT_LENGTH },
        sig,
      )
    }
    // ES256
    if (publicKey.asymmetricKeyType !== "ec") return false
    if (publicKey.asymmetricKeyDetails?.namedCurve !== "prime256v1") return false
    const tryEnc = (dsaEncoding: "der" | "ieee-p1363") => {
      try {
        return crypto.verify("sha256", digest, { key: publicKey, dsaEncoding }, sig)
      } catch {
        return false
      }
    }
    if (sig.length === 64 && tryEnc("ieee-p1363")) return true
    return tryEnc("der")
  } catch {
    return false
  }
}

const HEX64 = /^[0-9a-f]{64}$/
const SEQ = /^[0-9]{1,20}$/
const DEWP_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
/**
 * The §5.2 anchor signature algorithms. The label is part of the signed preimage, so an anchor naming
 * anything else (RSA-OAEP, DSA, an empty string) is not a §5.2 anchor — and must not be verified under
 * whatever scheme a fallthrough happens to pick. External anchors (Rekor, RFC 3161) carry the
 * producer's own anchor algorithm, so the same registry applies to every kind.
 */
export const ANCHOR_ALGORITHMS: readonly string[] = ["ES256", "Ed25519", "RSA-PSS"]

/**
 * An anchor whose seven signed fields have the shapes §5.2 requires. Anything else is refused before a
 * digest is computed: `JSON.stringify` would happily turn a missing position field into `null`, and a
 * digest over `[…, null, null, null]` is not the preimage any conformant producer signed.
 */
export function isWellFormedAnchor(a: AnchorInput): boolean {
  return (
    typeof a === "object" &&
    a !== null &&
    typeof a.dailyRoot === "string" &&
    HEX64.test(a.dailyRoot) &&
    typeof a.timestamp === "string" &&
    parseAnchorTimestampMs(a.timestamp) !== null &&
    typeof a.issuer === "string" &&
    typeof a.algorithm === "string" &&
    ANCHOR_ALGORITHMS.includes(a.algorithm) &&
    typeof a.seqStart === "string" &&
    SEQ.test(a.seqStart) &&
    typeof a.seqEnd === "string" &&
    SEQ.test(a.seqEnd) &&
    typeof a.chainHash === "string" &&
    HEX64.test(a.chainHash)
  )
}

/**
 * Milliseconds since the epoch for a DEWP §4.3 timestamp (`YYYY-MM-DDTHH:mm:ss.sssZ`, exactly), or null.
 * Strict on purpose: every port must read the same instant from the same bytes, and a lenient parser in
 * one of them (offsets, missing milliseconds, 30 February rolled into March) is how two verifiers come
 * to disagree about whether an anchor was on time.
 */
export function parseAnchorTimestampMs(ts: string): number | null {
  if (typeof ts !== "string" || !DEWP_TIMESTAMP.test(ts)) return null
  const ms = Date.parse(ts)
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== ts) return null
  return ms
}

/**
 * Default bound on how long after a checkpoint's claimed time an external witness may have first seen
 * its anchor (DEWP §5.3). An anchor obtained later than this proves only that the root existed when it
 * was finally witnessed — which says nothing about whether it existed at the time the checkpoint
 * claims, and is exactly what a party rewriting old history and re-anchoring it today produces.
 */
export const DEFAULT_MAX_ANCHOR_LAG_SECONDS = 86_400

/**
 * Tolerated clock disagreement in the other direction: a witness time EARLIER than the checkpoint's
 * claimed time. The producer chose that time before submitting, so a witness seeing the anchor before
 * it claims to exist means a producer clock ahead of the witness's — bounded, never unbounded.
 */
export const ANCHOR_CLOCK_SKEW_SECONDS = 300

/**
 * How an anchor of a given kind is verified. SELF/DEWP anchors carry a §5.2 signature; external ones
 * (Rekor, TSA) carry the third party's own attestation in `evidence` instead, and their `signature`
 * is empty by construction.
 */
export interface ExternalAnchorKeys {
  /** Rekor log public key (PEM or base64 SPKI), pinned by the CALLER — Sigstore publishes it via TUF. */
  rekor?: string
  /** Issuer identity assigned to the pinned log key. Required for policies with multiple issuers. */
  rekorIssuer?: string
  /**
   * The PRODUCER's Rekor submission key(s) (PEM or base64 SPKI) — normally its published anchor key.
   * When set, a Rekor entry counts only if its hashedrekord was submitted under one of these keys and
   * that key's signature over the anchor digest verifies. Unset, the log accepts a submission under
   * ANY key, so anyone who can compute the digest can have it logged.
   */
  rekorSubmitterKeys?: string[]
  /** Optional OpenSSL 3 TSA verification, keyed by caller-trusted issuer. */
  rfc3161?: Record<string, Rfc3161Trust>
}

/** The verifier's anchor-trust policy (DEWP §5.3). */
export interface AnchorPolicy {
  /** Minimum count of distinct trusted issuers that must sign the SAME root. SHOULD be ≥ 2. */
  requiredAnchors: number
  /** Allowed issuer identifiers; anchors from other issuers do not count toward quorum. */
  trustedIssuers: string[]
  /** ALL_MUST_AGREE = every present trusted anchor must sign the same root; N_OF_M = at least N. */
  quorum: "ALL_MUST_AGREE" | "N_OF_M"
  /**
   * Maximum seconds between the checkpoint's claimed time and an EXTERNAL witness's authenticated
   * time (Rekor integratedTime, TSA genTime). Absent ⇒ DEFAULT_MAX_ANCHOR_LAG_SECONDS. A witness
   * outside [-ANCHOR_CLOCK_SKEW_SECONDS, this] does not count toward quorum.
   */
  maxAnchorLagSeconds?: number
}

/** Resolve the verifying public key for an anchor (by issuer/keyId). Returns null when unknown. */
export type AnchorKeyResolver = (anchor: SignedAnchor) => crypto.KeyObject | null

/**
 * The checkpoint an anchor is being counted FOR. Every field the caller knows is compared with the
 * anchor's signed fields; an anchor that names another position, chain or time is not evidence for
 * this checkpoint, whatever root it carries.
 */
export interface ExpectedCheckpoint {
  seqStart?: string | null
  seqEnd?: string | null
  chainHash?: string | null
  /**
   * The checkpoint's own claimed time. MUST equal the anchor's signed `timestamp`.
   *
   * When an expected checkpoint is supplied WITHOUT this, an external witness (Rekor, RFC 3161) does
   * not count: the §5.3 time bound would be measured against the anchor's own `timestamp`, which the
   * producer chose, so a months-late witness could simply be re-dated to look prompt.
   */
  anchoredAt?: string | null
}

export interface AnchorQuorumResult {
  ok: boolean
  /** Distinct trusted issuers whose signature over `dailyRoot` verified. */
  verifiedIssuers: string[]
  /** True if two trusted issuers signed DIFFERENT roots for this checkpoint (fatal → not ok). */
  divergence: boolean
  reason?: string
  /** Why evidence that was present did not count (unverifiable TSA, outside the time bound, wrong position). */
  note?: string
  /**
   * Authenticated external witness time per issuer, Unix seconds — Rekor `integratedTime`, TSA
   * `genTime`, the earliest when an issuer has several. Reported for every external anchor whose
   * evidence verified, INCLUDING ones refused by the time bound, so a relying party can see when each
   * witness actually saw the checkpoint rather than only whether it counted.
   */
  witnessTimes: Record<string, number>
}

/** Where an anchor's signed fields disagree with the checkpoint it is offered for, or null. */
function positionMismatch(a: AnchorInput, expected: ExpectedCheckpoint | undefined): string | null {
  if (!expected) return null
  if (expected.seqStart != null && a.seqStart !== expected.seqStart) return "seqStart"
  if (expected.seqEnd != null && a.seqEnd !== expected.seqEnd) return "seqEnd"
  if (expected.chainHash != null && a.chainHash !== expected.chainHash) return "chainHash"
  if (expected.anchoredAt != null && a.timestamp !== expected.anchoredAt) return "timestamp"
  return null
}

/**
 * Evaluate an anchor quorum for one `dailyRoot`. `anchorVerified` in a bundle is true iff this returns
 * ok. Divergence (a trusted issuer signing a different root) is fatal, never a silent pick.
 *
 * An anchor counts only when (1) its issuer is trusted, (2) its evidence verifies under trust the
 * caller supplied, (3) its signed position matches `opts.checkpoint` where the caller knows it, and
 * (4) for an external witness, the witness time falls within the policy's time bound of the
 * checkpoint's claimed time.
 */
export function verifyAnchorQuorum(
  anchors: SignedAnchor[],
  dailyRoot: string,
  policy: AnchorPolicy,
  resolveKey: AnchorKeyResolver,
  opts: {
    /**
     * Anchors that may be used to declare DIVERGENCE. Defaults to none.
     *
     * Divergence is a fatal, tamper-shaped verdict, so what feeds it matters. An anchor from another
     * checkpoint is entirely normal — every anchor an issuer has ever published over some other day
     * looks like one — so treating any non-matching anchor as divergence would let anyone who can add
     * an anchor to a bundle attach a GENUINE, publicly available anchor from another day and force an
     * INVALID verdict with a tamper alarm. So the caller must say which anchors it fetched itself, per
     * checkpoint, from each issuer. One whose signed seq range names a different checkpoint than
     * `checkpoint` is not divergence evidence either.
     */
    divergenceAnchors?: SignedAnchor[]
    /** Pinned public keys for external logs, so their attestations can actually be checked. */
    externalKeys?: ExternalAnchorKeys
    /** The checkpoint the anchors are offered for; see ExpectedCheckpoint. */
    checkpoint?: ExpectedCheckpoint
  } = {},
): AnchorQuorumResult {
  const verifies = (a: SignedAnchor): { ok: boolean; witnessTime?: number } => {
    if (!isWellFormedAnchor(a)) return { ok: false }
    if (a.kind === "RFC3161") {
      const tsa = opts.externalKeys?.rfc3161
      const trust = tsa && Object.hasOwn(tsa, a.issuer) ? tsa[a.issuer] : undefined
      if (trust === undefined) return { ok: false }
      const r = verifyRfc3161Anchor(a, trust)
      return { ok: r.ok && typeof r.genTime === "number", witnessTime: r.genTime }
    }
    if (a.kind === "REKOR") {
      const key = opts.externalKeys?.rekor
      // The log signs arbitrary submitted digests, including producer-chosen issuer strings.
      // Its key must therefore be assigned to an issuer by the CALLER, never by the anchor.
      const scopedIssuer =
        opts.externalKeys?.rekorIssuer ??
        (new Set(policy.trustedIssuers).size === 1 ? policy.trustedIssuers[0] : undefined)
      if (a.issuer !== scopedIssuer) return { ok: false }
      const evidence = parseRekorEvidence(a.evidence)
      if (!key || !evidence) return { ok: false }
      const r = verifyRekorAnchor(evidence, a, key, { submitterKeys: opts.externalKeys?.rekorSubmitterKeys })
      return { ok: r.ok && typeof r.integratedTime === "number", witnessTime: r.integratedTime }
    }
    if (a.kind != null && a.kind !== "SELF") return { ok: false }
    const key = resolveKey(a)
    return { ok: key !== null && verifyAnchorSignature(a, key) }
  }
  const maxLagMs = (policy.maxAnchorLagSeconds ?? DEFAULT_MAX_ANCHOR_LAG_SECONDS) * 1000
  const skewMs = ANCHOR_CLOCK_SKEW_SECONDS * 1000
  /** Signed lag of an external witness behind the anchor's claimed time, in ms. */
  const witnessLagMs = (a: SignedAnchor, witnessTime: number): number =>
    witnessTime * 1000 - (parseAnchorTimestampMs(a.timestamp) ?? Number.NaN)
  /** The §5.3 lag window around the anchor's signed (claimed) checkpoint time. */
  const withinWitnessBound = (a: SignedAnchor, witnessTime: number): boolean => {
    const lagMs = witnessLagMs(a, witnessTime)
    return lagMs >= -skewMs && lagMs <= maxLagMs
  }

  const trusted = anchors.filter((a) => policy.trustedIssuers.includes(a.issuer))
  // Divergence: a trusted issuer that validly signed a DIFFERENT root for this checkpoint. Only
  // anchors the CALLER vouched for as being for this checkpoint can establish that — and not one
  // whose own signed range says it is for another checkpoint.
  const expected = opts.checkpoint
  //
  // Divergence is a fatal, tamper-shaped verdict, so a candidate is held to the same evidence rules
  // as a quorum anchor (DEWP §5.3): the seq range must be this checkpoint's, and an external witness
  // must have seen the digest within the time bound of the anchor's own signed checkpoint time. The
  // chain hash and claimed time are deliberately NOT required to match: both commit to the root, so
  // a rewritten checkpoint necessarily differs in them, and requiring equality would hide exactly
  // the rewrite divergence exists to expose.
  const divergenceCandidates = (opts.divergenceAnchors ?? []).filter(
    (a) =>
      policy.trustedIssuers.includes(a.issuer) &&
      (expected?.seqStart == null || a.seqStart === expected.seqStart) &&
      (expected?.seqEnd == null || a.seqEnd === expected.seqEnd),
  )
  for (const a of divergenceCandidates) {
    if (a.dailyRoot === dailyRoot) continue
    // Rekor logs a digest under whatever key submits it, and the digest is computed from public
    // fields — so without the producer's submission key pinned, anyone could log a different root
    // under a trusted issuer's name and raise a false alarm. Such an entry cannot establish divergence.
    if (a.kind === "REKOR" && !(opts.externalKeys?.rekorSubmitterKeys?.length ?? 0)) continue
    const r = verifies(a)
    if (r.ok && r.witnessTime !== undefined && !withinWitnessBound(a, r.witnessTime)) continue
    if (r.ok) {
      return {
        ok: false,
        verifiedIssuers: [],
        divergence: true,
        reason: `anchor divergence: issuer ${a.issuer} signed a different root for this checkpoint`,
        witnessTimes: {},
      }
    }
  }
  const verifiedIssuers = new Set<string>()
  const witnessTimes: Record<string, number> = {}
  const notes: string[] = []
  let rfc3161Present = 0
  for (const a of trusted) {
    if (a.dailyRoot !== dailyRoot) continue
    const mismatch = positionMismatch(a, expected)
    if (mismatch) {
      notes.push(`anchor from ${a.issuer} binds a different checkpoint ${mismatch}; it does not count`)
      continue
    }
    const r = verifies(a)
    if (!r.ok) {
      if (a.kind === "RFC3161") rfc3161Present++
      continue
    }
    if (r.witnessTime !== undefined) {
      const prior = witnessTimes[a.issuer]
      witnessTimes[a.issuer] = prior === undefined ? r.witnessTime : Math.min(prior, r.witnessTime)
      // The bound needs a checkpoint time the caller can vouch for. With a checkpoint named but its
      // time unknown, the only time left is the anchor's own `timestamp` — the producer's choice.
      if (expected && expected.anchoredAt == null) {
        notes.push(
          `anchor from ${a.issuer} has an external witness time but no trusted checkpoint time to hold ` +
            "it to (DEWP §5.3); it does not count",
        )
        continue
      }
      // isWellFormedAnchor has already parsed this timestamp, so it is non-null here.
      const lagMs = witnessLagMs(a, r.witnessTime)
      if (!withinWitnessBound(a, r.witnessTime)) {
        notes.push(
          `anchor from ${a.issuer} was witnessed ${Math.round(lagMs / 1000)}s from its checkpoint time ` +
            `(allowed ${-ANCHOR_CLOCK_SKEW_SECONDS}..${maxLagMs / 1000}s); it does not count`,
        )
        continue
      }
    }
    verifiedIssuers.add(a.issuer)
  }
  if (rfc3161Present > 0) {
    notes.push(
      `${rfc3161Present} RFC 3161 TSA anchor(s) over this root are present but not verifiable ` +
        "with the supplied configuration — configure RFC 3161 trust and OpenSSL 3, or inspect the evidence out of band.",
    )
  }
  const count = verifiedIssuers.size
  const trustedPresent = new Set(trusted.filter((a) => a.dailyRoot === dailyRoot).map((a) => a.issuer)).size
  const need =
    policy.quorum === "ALL_MUST_AGREE"
      ? Math.max(policy.requiredAnchors, trustedPresent)
      : policy.requiredAnchors
  return {
    ok: count >= need && count >= 1,
    verifiedIssuers: [...verifiedIssuers],
    divergence: false,
    reason: count >= need ? undefined : `anchor quorum not met (${count}/${need})`,
    ...(notes.length > 0 ? { note: notes.join("; ") } : {}),
    witnessTimes,
  }
}
