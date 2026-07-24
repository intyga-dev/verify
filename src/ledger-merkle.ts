import crypto from "node:crypto"

// Pure Merkle primitives — zero dependencies beyond node:crypto. This file is the trust root of the
// verifier: an auditor should be able to read it end to end and be convinced. It is a byte-for-byte
// port of the tree construction used to build SÄKRA's two-tier witness anchor
// (per-event leaves → block roots → daily root). If this and the producer ever disagree, proofs fail
// closed (verification returns false), never open.

export function sha256Hex(s: string): string {
  return crypto.createHash("sha256").update(s).digest("hex")
}

// DEWP domain separation (docs/DEWP.md §4.4): leaves, interior nodes, and the empty root are hashed
// under DISTINCT one-byte prefixes so an interior-node hash can never be reinterpreted as a leaf
// (blocks second-preimage / proof malleability where a subtree root is passed off as a leaf).
// 0x00 = leaf, 0x01 = node, 0x02 = empty root. Node children are HEX-DECODED to their raw 32 bytes
// before hashing (NOT concatenated as hex text). Must stay byte-identical to the @sakra-trust/db producer.
const LEAF_TAG = 0x00
const NODE_TAG = 0x01
const EMPTY_TAG = 0x02

/** Domain-separated leaf digest: sha256(0x00 || UTF8(preimage)). */
export function hashLeaf(data: string): string {
  return crypto
    .createHash("sha256")
    .update(Buffer.from([LEAF_TAG]))
    .update(Buffer.from(data, "utf8"))
    .digest("hex")
}

// Checked indexed read. The loops below keep indices in range by construction; if that invariant
// ever breaks, throwing beats fabricating a hash — a wrong tree must never verify.
function at(level: string[], i: number): string {
  const v = level[i]
  if (v === undefined) throw new Error("merkle: index out of range")
  return v
}

/** Domain-separated node: sha256(0x01 || rawBytes(left) || rawBytes(right)). Order encodes position — never sort. */
export function hashPair(left: string, right: string): string {
  return crypto
    .createHash("sha256")
    .update(Buffer.from([NODE_TAG]))
    .update(Buffer.from(left, "hex"))
    .update(Buffer.from(right, "hex"))
    .digest("hex")
}

/** Empty-tree root (DEWP §5.1.1): sha256(0x02). */
export function emptyRoot(): string {
  return crypto
    .createHash("sha256")
    .update(Buffer.from([EMPTY_TAG]))
    .digest("hex")
}

/** Merkle root over ordered leaves (duplicate-last on odd levels). Empty tree ⇒ sha256(0x02). */
export function merkleRoot(leaves: string[]): string {
  if (leaves.length === 0) return emptyRoot()
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

/**
 * One step on the path from a leaf to the root (DEWP §5.1.6): the SIBLING's hash and the side the
 * sibling sits on relative to the running node. Ordered leaf → root.
 */
export interface ProofStep {
  siblingHash: string
  siblingPosition: "LEFT" | "RIGHT"
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
    // If the running node is the RIGHT child, its sibling sits on the LEFT, and vice versa.
    proof.push({ siblingHash: sibling, siblingPosition: isRightChild ? "LEFT" : "RIGHT" })
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
    h = step.siblingPosition === "LEFT" ? hashPair(step.siblingHash, h) : hashPair(h, step.siblingHash)
  }
  return h === root
}
