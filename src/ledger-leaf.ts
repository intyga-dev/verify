import { hashLeaf } from "./ledger-merkle.js"

/**
 * JCS (RFC 8785) serialization of the `metadata` value — every object key sorted recursively by
 * UTF-16 code unit. DEWP §4.2 requires the metadata element to be a *canonical* string, so an equal
 * metadata object hashes identically regardless of the producer's key insertion order or language
 * (JS/Go/Rust/Python). Do NOT replace with plain JSON.stringify — that reintroduces order dependence.
 */
function jcsStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null"
  if (Array.isArray(value)) return `[${value.map(jcsStringify).join(",")}]`
  const obj = value as Record<string, unknown>
  const keys = Object.keys(obj).sort()
  return `{${keys.map((k) => `${JSON.stringify(k)}:${jcsStringify(obj[k])}`).join(",")}}`
}

// Canonical leaf encoding — the exact preimage the producer commits to for one audit event. To bind a
// proof to a human-readable event ("this leaf IS this record"), a bundle must carry every field below
// in this order; the verifier recomputes leafHash and checks it equals proof.leaf. Drop or reorder a
// field and the hash changes, so this ordering is a wire contract: never reorder, only append (with a
// format-version bump on both sides).

export interface AuditLeaf {
  seq: string // stringified bigint — matches producer's row.seq.toString()
  tenantSeq?: string | null // stringified bigint — matches producer's row.tenantSeq.toString()
  createdAt: string // ISO 8601 — matches row.createdAt.toISOString()
  event: string
  outcome: string
  detail: string | null
  metadata: unknown // arbitrary JSON; hashed as JSON.stringify(metadata ?? null)
  signerDid: string | null
  signerPublicKey: string | null
  signedPayload: string | null
  signature: string | null
  sigAlg: string | null
  isBillable: boolean
  tenantId: string | null
  actorNodeId: string | null
  subjectNodeId: string | null
  edgeId: string | null
  challengeId: string | null
}

/** The 18-field ordered array that gets JSON-stringified into the leaf preimage. Keep in lockstep
 *  with the producer's `leafHash` (packages/db/src/checkpoint.ts). */
export function canonicalPreimage(row: AuditLeaf): string {
  return JSON.stringify([
    row.seq,
    row.createdAt,
    row.event,
    row.outcome,
    row.detail,
    jcsStringify(row.metadata ?? null),
    row.signerDid,
    row.signerPublicKey,
    row.signedPayload,
    row.signature,
    row.sigAlg,
    row.isBillable,
    row.tenantId,
    row.actorNodeId,
    row.subjectNodeId,
    row.edgeId,
    row.challengeId,
    row.tenantSeq ?? null,
  ])
}

/** Domain-separated leaf digest over the full event content. */
export function leafHash(row: AuditLeaf): string {
  return hashLeaf(canonicalPreimage(row))
}
