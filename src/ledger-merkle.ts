import crypto from "node:crypto"

// Pure Merkle primitives — zero dependencies beyond node:crypto. This file is the trust root of the
// verifier: an auditor should be able to read it end to end and be convinced. It is a byte-for-byte
// port of the tree construction used to build SÄKRA's two-tier witness anchor
// (per-event leaves → block roots → daily root). If this and the producer ever disagree, proofs fail
// closed (verification returns false), never open.

export function sha256Hex(s: string): string {
  return crypto.createHash("sha256").update(s).digest("hex")
}

// RFC 6962-style domain separation: leaves and interior nodes are hashed under DISTINCT prefixes so an
// interior-node hash can never be reinterpreted as a leaf (blocks second-preimage / proof malleability
// where a subtree root is passed off as a leaf). 0x00 = leaf, 0x01 = node. Must match the producer.
const LEAF_TAG = "\x00"
const NODE_TAG = "\x01"

/** Hash a raw leaf value into a domain-separated leaf digest. */
export function hashLeaf(data: string): string {
  return sha256Hex(LEAF_TAG + data)
}

// Checked indexed read. The loops below keep indices in range by construction; if that invariant
// ever breaks, throwing beats fabricating a hash — a wrong tree must never verify.
function at(level: string[], i: number): string {
  const v = level[i]
  if (v === undefined) throw new Error("merkle: index out of range")
  return v
}

/** Combine two child hashes into a parent (domain-separated). Order encodes position — never sort. */
export function hashPair(left: string, right: string): string {
  return sha256Hex(NODE_TAG + left + right)
}

/** Merkle root over ordered leaves (duplicate-last on odd levels). "" for empty. */
export function merkleRoot(leaves: string[]): string {
  if (leaves.length === 0) return ""
  let level = leaves
  while (level.length > 1) {
    const next: string[] = []
    for (let i = 0; i < level.length; i += 2) {
      const left = at(level, i)
      next.push(hashPair(left, level[i + 1] ?? left))
    }
    level = next
  }
  return at(level, 0)
}

/** One step on the path from a leaf to the root: the sibling hash and which side it sits on. */
export interface ProofStep {
  sibling: string
  side: "left" | "right"
}

/**
 * Inclusion proof for the leaf at `index` — the sibling hashes needed to recompute the root.
 * The producer emits these; the verifier only needs `verifyMerkleProof`. Included here so the same
 * file can generate test vectors and so auditors can reproduce a proof from raw leaves if they wish.
 */
export function merkleProof(leaves: string[], index: number): ProofStep[] {
  if (index < 0 || index >= leaves.length) throw new Error("merkleProof: index out of range")
  const proof: ProofStep[] = []
  let level = leaves
  let idx = index
  while (level.length > 1) {
    const isRightChild = idx % 2 === 1
    const siblingIdx = isRightChild ? idx - 1 : idx + 1
    // duplicate-last: an unpaired right node is hashed against itself.
    const sibling = level[siblingIdx] ?? at(level, idx)
    proof.push({ sibling, side: isRightChild ? "left" : "right" })
    const next: string[] = []
    for (let i = 0; i < level.length; i += 2) {
      const left = at(level, i)
      next.push(hashPair(left, level[i + 1] ?? left))
    }
    level = next
    idx = Math.floor(idx / 2)
  }
  return proof
}

/** Recompute the root from a leaf + its proof and compare. This is what a third party runs. */
export function verifyMerkleProof(leaf: string, proof: ProofStep[], root: string): boolean {
  let h = leaf
  for (const step of proof) {
    h = step.side === "left" ? hashPair(step.sibling, h) : hashPair(h, step.sibling)
  }
  return h === root
}
