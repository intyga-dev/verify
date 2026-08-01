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
  /** Position of this event's leaf within its block, and how many leaves that block had. */
  leafIndex: number
  blockLeafCount: number
  checkpointId: string | null
  checkpointRoot: string | null
  checkpointProof: ProofStep[] // block root → daily root
  /** Position of the block root within the daily tree, and that tree's leaf count. */
  checkpointLeafIndex: number
  checkpointLeafCount: number
  anchorRef: string | null
  /** Producer claim: a self publication receipt exists. Commitment only — NOT independence. */
  anchored: boolean
  /**
   * Producer claim: the producer says a §5.3 external anchor quorum (distinct non-SELF issuers >=
   * its configured requirement) exists for this checkpoint. Absent on bundles exported before the
   * field shipped. Display/triage only — independence is established by THIS verifier's own anchor
   * quorum evaluation (`anchorVerified`), never by trusting the flag.
   */
  externallyAnchored?: boolean
}

/**
 * Verify a two-hop inclusion proof against a KNOWN daily root (event → block → day).
 * Pass the daily root you obtained independently (from the external anchor), NOT proof.checkpointRoot —
 * trusting the root shipped inside the proof would let a forged bundle vouch for itself.
 */
export function verifyInclusionProof(proof: InclusionProof, dailyRoot: string): boolean {
  // Position is REQUIRED, and its absence is a rejection rather than a skipped check. This tree pads
  // an unpaired trailing node against itself, so without an index and a leaf count a path to a leaf
  // that was never in the tree recomputes the real root (verified: a proof for index 3 verifies
  // against a 3-leaf root). A proof that cannot say where its leaf sits does not establish inclusion.
  if (
    !Number.isInteger(proof.leafIndex) ||
    !Number.isInteger(proof.blockLeafCount) ||
    !Number.isInteger(proof.checkpointLeafIndex) ||
    !Number.isInteger(proof.checkpointLeafCount)
  ) {
    return false
  }
  if (
    !verifyMerkleProof(proof.leaf, proof.blockProof, proof.blockRoot, {
      index: proof.leafIndex,
      leafCount: proof.blockLeafCount,
    })
  ) {
    return false
  }
  return verifyMerkleProof(hashLeaf(proof.blockRoot), proof.checkpointProof, dailyRoot, {
    index: proof.checkpointLeafIndex,
    leafCount: proof.checkpointLeafCount,
  })
}
