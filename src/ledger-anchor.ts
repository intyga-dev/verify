import crypto from "node:crypto"
import { parseRekorEvidence, verifyRekorAnchor } from "./ledger-rekor.js"

// DEWP signed anchor objects (docs/DEWP.md §5.2/§5.3). A Daily Checkpoint Root becomes trustworthy
// only when independent external parties SIGN it. This module computes the domain-separated anchor
// digest (0x03 tag), verifies an anchor's signature, and evaluates a multi-anchor QUORUM so a single
// compromised anchor provider cannot forge non-repudiation. Zero deps beyond node:crypto.

const ANCHOR_TAG = 0x03

/** A signed commitment to a daily checkpoint root, published to an independent public anchor. */
export interface SignedAnchor {
  dailyRoot: string // 64-char lowercase hex
  timestamp: string // ISO 8601 UTC
  issuer: string // HTTPS URI or DID of the anchor provider
  algorithm: "ES256" | "Ed25519" | "RSA-PSS"
  keyId: string
  signature: string // base64, over the raw 32-byte anchorDigest. EMPTY for external anchors.
  /** SELF | REKOR | RFC3161 | WEBHOOK. Decides WHICH verification applies; absent ⇒ treated as DEWP. */
  kind?: string
  /** The external log's own attestation, base64 (Rekor: entry + SET + inclusion proof). */
  evidence?: string | null
}

/**
 * The canonical anchor preimage: RFC 8785 JCS of the 4-element array [dailyRoot, timestamp, issuer,
 * algorithm]. For an array of strings, JCS is exactly `JSON.stringify` with no insignificant space.
 */
export function anchorPreimage(
  a: Pick<SignedAnchor, "dailyRoot" | "timestamp" | "issuer" | "algorithm">,
): string {
  return JSON.stringify([a.dailyRoot, a.timestamp, a.issuer, a.algorithm])
}

/** The raw 32-byte anchor digest: SHA-256(0x03 || UTF8(anchorPreimage)). This is what gets signed. */
export function anchorDigest(
  a: Pick<SignedAnchor, "dailyRoot" | "timestamp" | "issuer" | "algorithm">,
): Buffer {
  return crypto
    .createHash("sha256")
    .update(Buffer.from([ANCHOR_TAG]))
    .update(Buffer.from(anchorPreimage(a), "utf8"))
    .digest()
}

/** Hex form of the anchor digest (for display / vectors). */
export function anchorDigestHex(
  a: Pick<SignedAnchor, "dailyRoot" | "timestamp" | "issuer" | "algorithm">,
): string {
  return anchorDigest(a).toString("hex")
}

/**
 * Sign an anchor digest with a producer key. Helper for anchor providers and tests — a relying party
 * only needs `verifyAnchorSignature`. The message is the RAW 32-byte digest (never its hex string):
 * ES256/RSA-PSS then apply their own SHA-256, Ed25519 signs the bytes directly.
 */
export function signAnchor(
  a: Pick<SignedAnchor, "dailyRoot" | "timestamp" | "issuer" | "algorithm">,
  privateKey: crypto.KeyObject,
): string {
  const digest = anchorDigest(a)
  if (a.algorithm === "Ed25519") return crypto.sign(null, digest, privateKey).toString("base64")
  if (a.algorithm === "RSA-PSS") {
    return crypto
      .sign("sha256", digest, { key: privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING })
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
    const digest = anchorDigest(anchor)
    const sig = Buffer.from(anchor.signature, "base64")
    if (anchor.algorithm === "Ed25519") {
      if (publicKey.asymmetricKeyType !== "ed25519") return false
      return crypto.verify(null, digest, publicKey, sig)
    }
    if (anchor.algorithm === "RSA-PSS") {
      if (publicKey.asymmetricKeyType !== "rsa" && publicKey.asymmetricKeyType !== "rsa-pss") return false
      return crypto.verify(
        "sha256",
        digest,
        { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING },
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

/** The verifier's anchor-trust policy (DEWP §5.3). */
/**
 * How an anchor of a given kind is verified. SELF/DEWP anchors carry a §5.2 signature; external ones
 * (Rekor, TSA) carry the third party's own attestation in `evidence` instead, and their `signature`
 * is empty by construction.
 */
export interface ExternalAnchorKeys {
  /** Rekor log public key (PEM or base64 SPKI), pinned by the CALLER — Sigstore publishes it via TUF. */
  rekor?: string
}

export interface AnchorPolicy {
  /** Minimum count of distinct trusted issuers that must sign the SAME root. SHOULD be ≥ 2. */
  requiredAnchors: number
  /** Allowed issuer identifiers; anchors from other issuers do not count toward quorum. */
  trustedIssuers: string[]
  /** ALL_MUST_AGREE = every present trusted anchor must sign the same root; N_OF_M = at least N. */
  quorum: "ALL_MUST_AGREE" | "N_OF_M"
}

/** Resolve the verifying public key for an anchor (by issuer/keyId). Returns null when unknown. */
export type AnchorKeyResolver = (anchor: SignedAnchor) => crypto.KeyObject | null

export interface AnchorQuorumResult {
  ok: boolean
  /** Distinct trusted issuers whose signature over `dailyRoot` verified. */
  verifiedIssuers: string[]
  /** True if two trusted issuers signed DIFFERENT roots for this checkpoint (fatal → not ok). */
  divergence: boolean
  reason?: string
  /**
   * Set when trusted RFC 3161 TSA anchors over THIS root were present but could not be counted:
   * their attestation is a CMS/DER TimeStampToken that this zero-dependency verifier deliberately
   * does not parse (verify it out of band with `openssl ts -verify`). Without this note, "0
   * verified issuers" over a TSA-anchored root reads as "unanchored", which misstates the evidence
   * that actually exists — the producer's publication quorum legitimately counts TSA anchors.
   */
  note?: string
}

/**
 * Evaluate an anchor quorum for one `dailyRoot`. `anchorVerified` in a bundle is true iff this returns
 * ok. Divergence (a trusted issuer signing a different root) is fatal, never a silent pick.
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
     * Divergence is a fatal, tamper-shaped verdict, so what feeds it matters. `anchorPreimage` binds
     * [dailyRoot, timestamp, issuer, algorithm] and NOT any checkpoint identity, which means this
     * function cannot tell "issuer X signed a different root FOR THIS CHECKPOINT" (real divergence)
     * from "issuer X signed some other day's root" (entirely normal — every anchor they have ever
     * published looks like that). Treating any non-matching anchor as divergence therefore lets
     * anyone who can add an anchor to a bundle attach a GENUINE, publicly available anchor from
     * another day and force an INVALID verdict with a tamper alarm.
     *
     * So the caller must say which anchors it fetched itself, per checkpoint, from each issuer.
     */
    divergenceAnchors?: SignedAnchor[]
    /** Pinned public keys for external logs, so their attestations can actually be checked. */
    externalKeys?: ExternalAnchorKeys
  } = {},
): AnchorQuorumResult {
  const trusted = anchors.filter((a) => policy.trustedIssuers.includes(a.issuer))
  // Divergence: a trusted issuer that validly signed a DIFFERENT root for this checkpoint. Only
  // anchors the CALLER vouched for as being for this checkpoint can establish that.
  const divergenceCandidates = (opts.divergenceAnchors ?? []).filter((a) =>
    policy.trustedIssuers.includes(a.issuer),
  )
  for (const a of divergenceCandidates) {
    if (a.dailyRoot === dailyRoot) continue
    const key = resolveKey(a)
    if (key && verifyAnchorSignature(a, key)) {
      return {
        ok: false,
        verifiedIssuers: [],
        divergence: true,
        reason: `anchor divergence: issuer ${a.issuer} signed a different root for this checkpoint`,
      }
    }
  }
  const verifiedIssuers = new Set<string>()
  let rfc3161Present = 0
  for (const a of trusted) {
    if (a.dailyRoot !== dailyRoot) continue
    // External anchors (Rekor today) carry no DEWP signature — the third party's attestation IS the
    // evidence. Verifying them was previously impossible here, which meant a quorum could only ever
    // be met by anchors Intyga signed itself: the opposite of independence.
    if (a.kind === "REKOR") {
      const rekorKey = opts.externalKeys?.rekor
      if (!rekorKey) continue // no pinned log key ⇒ unverifiable ⇒ does not count
      const evidence = parseRekorEvidence(a.evidence)
      if (!evidence) continue
      if (verifyRekorAnchor(evidence, a, rekorKey).ok) verifiedIssuers.add(a.issuer)
      continue
    }
    if (a.kind === "RFC3161") {
      // A TSA anchor's attestation is a DER TimeStampToken (CMS SignedData). Checking it needs an
      // ASN.1/X.509 stack this zero-dependency verifier deliberately does not carry, so it can
      // never count toward quorum HERE — but it IS genuine third-party evidence (the producer's
      // publication quorum counts it), so its presence is reported instead of silently dropped.
      rfc3161Present++
      continue
    }
    const key = resolveKey(a)
    if (key && verifyAnchorSignature(a, key)) verifiedIssuers.add(a.issuer)
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
    ...(rfc3161Present > 0
      ? {
          note:
            `${rfc3161Present} RFC 3161 TSA anchor(s) over this root are present but not verifiable ` +
            "offline by this tool — verify the token out of band with `openssl ts -verify` and the " +
            "TSA's certificate.",
        }
      : {}),
  }
}
