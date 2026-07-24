import { hashLeaf } from "./ledger-merkle.js"

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
    JSON.stringify(row.metadata ?? null),
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
