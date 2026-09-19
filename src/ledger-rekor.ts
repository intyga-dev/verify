// Sigstore Rekor transparency-log anchor verification.
//
// This is what turns an external anchor from "Intyga stored a blob it says came from Rekor" into
// evidence. Before it existed, `anchorCheckpoints` recorded REKOR anchors with an EMPTY DEWP
// signature and the export dropped their evidence entirely — so a REKOR anchor could not contribute
// to a §5.3 quorum, and `AUDIT_ANCHOR_REQUIRED=2` was satisfiable only by anchors signed with
// Intyga's own key. The independence guarantee never reached the verifier.
//
// Two things must hold, and BOTH matter:
//
//   1. Rekor really signed this entry — its Signed Entry Timestamp (SET) verifies under Rekor's
//      public key, which the caller supplies from its own trust configuration.
//   2. The entry is about THIS checkpoint — the logged hashedrekord binds the payload hash to
//      SHA-256(anchorDigest) for the root being verified.
//
// Without (2) any valid Rekor entry — there are millions, all public — would "verify". That is the
// same self-referential trap as verifying a receipt against the key inside it.

import crypto from "node:crypto"
import { anchorDigest, type SignedAnchor } from "./ledger-anchor.js"

/** The parts of a Rekor log entry we need. Mirrors what packages/db persists as `evidence`. */
export interface RekorEvidence {
  uuid?: string
  /** Base64 of the canonicalized entry Rekor stored. The SET signs this — without it, nothing. */
  body?: string
  logID?: string
  logIndex?: number
  integratedTime?: number
  verification?: {
    signedEntryTimestamp?: string
    inclusionProof?: {
      logIndex?: number
      rootHash?: string
      treeSize?: number
      hashes?: string[]
      checkpoint?: string
    }
  }
}

export interface RekorVerification {
  ok: boolean
  reason?: string
  /** Rekor's log index for this entry — where a third party can retrieve it themselves. */
  logIndex?: number
  logID?: string
  integratedTime?: number
}

/**
 * RFC 8785 JCS over the SET payload.
 *
 * Rekor signs the canonicalized JSON of {body, integratedTime, logID, logIndex} — keys sorted, no
 * whitespace. Reusing the ledger's own JCS habit rather than JSON.stringify with a hand-written key
 * order, because the order IS the contract and hand-ordering is exactly how these drift.
 */
function setPayload(e: RekorEvidence): string {
  return JSON.stringify({
    body: e.body,
    integratedTime: e.integratedTime,
    logID: e.logID,
    logIndex: e.logIndex,
  })
}

/** Decode the base64 `body` into a hashedrekord and pull out the payload hash it attests to. */
function hashedRekordPayloadHash(bodyB64: string): string | null {
  try {
    const decoded = JSON.parse(Buffer.from(bodyB64, "base64").toString("utf-8")) as {
      kind?: string
      spec?: { data?: { hash?: { algorithm?: string; value?: string } } }
    }
    if (decoded.kind !== "hashedrekord") return null
    const hash = decoded.spec?.data?.hash
    if (hash?.algorithm !== "sha256" || typeof hash.value !== "string") return null
    return hash.value.toLowerCase()
  } catch {
    return null
  }
}

/**
 * The hash Rekor was asked to bind the anchor signature to.
 *
 * MUST match the producer (packages/db/src/anchors/rekor.ts): `signAnchorDigest` signs the RAW
 * 32-byte anchor digest, and the signature scheme applies SHA-256 to those bytes itself — so the
 * value Rekor holds is SHA-256 OF the anchor digest, not the digest.
 */
export function rekorPayloadHashFor(
  anchor: Pick<SignedAnchor, "dailyRoot" | "timestamp" | "issuer" | "algorithm">,
): string {
  return crypto.createHash("sha256").update(anchorDigest(anchor)).digest("hex")
}

/**
 * Verify a Rekor anchor: Rekor's signature over the entry, AND that the entry is about this root.
 *
 * `rekorPublicKey` is PEM or base64 SPKI for the log's key, supplied by the CALLER from its own
 * configuration — never from the bundle, for the same reason approver keys are not read from a
 * receipt. Sigstore publishes it via TUF; pin it at deploy time.
 */
export function verifyRekorAnchor(
  evidence: RekorEvidence,
  anchor: Pick<SignedAnchor, "dailyRoot" | "timestamp" | "issuer" | "algorithm">,
  rekorPublicKey: string,
): RekorVerification {
  if (!evidence.body) return { ok: false, reason: "rekor evidence carries no entry body" }
  const set = evidence.verification?.signedEntryTimestamp
  if (!set) return { ok: false, reason: "rekor evidence carries no signedEntryTimestamp (SET)" }
  if (typeof evidence.logIndex !== "number" || typeof evidence.integratedTime !== "number") {
    return { ok: false, reason: "rekor evidence is missing logIndex/integratedTime" }
  }

  // (2) first — cheap, and it is the check that stops an unrelated (but perfectly valid) public
  // Rekor entry from being presented as evidence for this checkpoint.
  const logged = hashedRekordPayloadHash(evidence.body)
  if (!logged) return { ok: false, reason: "rekor entry body is not a readable hashedrekord" }
  const expected = rekorPayloadHashFor(anchor)
  if (logged !== expected) {
    return {
      ok: false,
      reason: `rekor entry attests a different payload (logged ${logged.slice(0, 16)}…, expected ${expected.slice(0, 16)}…) — this entry is not about this checkpoint`,
    }
  }

  // (1) Rekor's own signature over the entry.
  try {
    const keyObject = rekorPublicKey.includes("BEGIN")
      ? crypto.createPublicKey(rekorPublicKey)
      : crypto.createPublicKey({
          key: Buffer.from(rekorPublicKey, "base64"),
          format: "der",
          type: "spki",
        })
    // Rekor's log key is ECDSA P-256; pin it rather than letting the key material choose the
    // algorithm, exactly as verifyEcdsaP256 does for approver keys.
    if (keyObject.asymmetricKeyType !== "ec" || keyObject.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
      return { ok: false, reason: "rekor public key is not an EC P-256 key" }
    }
    const verified = crypto.verify(
      "sha256",
      Buffer.from(setPayload(evidence), "utf-8"),
      { key: keyObject, dsaEncoding: "der" },
      Buffer.from(set, "base64"),
    )
    if (!verified) return { ok: false, reason: "rekor SET does not verify under the supplied log key" }
  } catch (err) {
    return { ok: false, reason: `rekor SET verification failed: ${(err as Error).message}` }
  }

  return {
    ok: true,
    logIndex: evidence.logIndex,
    logID: evidence.logID,
    integratedTime: evidence.integratedTime,
  }
}

/** Parse a stored base64 evidence blob into a RekorEvidence, or null if it is not one. */
export function parseRekorEvidence(evidenceB64: string | null | undefined): RekorEvidence | null {
  if (!evidenceB64) return null
  try {
    const parsed = JSON.parse(Buffer.from(evidenceB64, "base64").toString("utf-8")) as RekorEvidence
    return typeof parsed === "object" && parsed !== null ? parsed : null
  } catch {
    return null
  }
}
