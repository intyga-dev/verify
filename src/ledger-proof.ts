import { hashLeaf, type ProofStep, verifyMerkleProof } from "./ledger-merkle.js"

// The inclusion-proof shape and its two-hop verification. Mirrors the producer's `InclusionProof`
// (packages/db/src/checkpoint.ts). An event is committed under a daily root via:
//   1. event leaf  --blockProof-->        block root
//   2. block root  --checkpointProof-->   daily root   (the block root is re-wrapped with the leaf
//                                                        tag, because the daily tree's leaves ARE
//                                                        hashLeaf(blockRoot) — see merkleRoot usage)

export interface InclusionProof {
  seq: string
  leaf: string
  blockIndex: string
  blockRoot: string
  blockProof: ProofStep[] // event leaf → block root
  checkpointId: string | null
  checkpointRoot: string | null
  checkpointProof: ProofStep[] // block root → daily root
  anchorRef: string | null
  anchored: boolean
}

/**
 * Verify a two-hop inclusion proof against a KNOWN daily root (event → block → day).
 * Pass the daily root you obtained independently (from the external anchor), NOT proof.checkpointRoot —
 * trusting the root shipped inside the proof would let a forged bundle vouch for itself.
 */
export function verifyInclusionProof(proof: InclusionProof, dailyRoot: string): boolean {
  if (!verifyMerkleProof(proof.leaf, proof.blockProof, proof.blockRoot)) return false
  return verifyMerkleProof(hashLeaf(proof.blockRoot), proof.checkpointProof, dailyRoot)
}
