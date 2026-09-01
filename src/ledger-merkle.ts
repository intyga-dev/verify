import crypto from "node:crypto"

// Pure Merkle primitives — zero dependencies beyond node:crypto. This file is the trust root of the
// verifier: an auditor should be able to read it end to end and be convinced. It is a byte-for-byte
// port of the tree construction used to build Intyga's two-tier witness anchor
// (per-event leaves → block roots → daily root). If this and the producer ever disagree, proofs fail
// closed (verification returns false), never open.

export function sha256Hex(s: string): string {
  return crypto.createHash("sha256").update(s).digest("hex")
}

// DEWP domain separation (docs/DEWP.md §4.4): leaves, interior nodes, and the empty root are hashed
// under DISTINCT one-byte prefixes so an interior-node hash can never be reinterpreted as a leaf
// (blocks second-preimage / proof malleability where a subtree root is passed off as a leaf).
// 0x00 = leaf, 0x01 = node, 0x02 = empty root. Node children are HEX-DECODED to their raw 32 bytes
// before hashing (NOT concatenated as hex text). Must stay byte-identical to the @intyga/db producer.
export const LEAF_TAG = 0x00
export const NODE_TAG = 0x01
export const EMPTY_TAG = 0x02

/** Domain-separated leaf digest: sha256(0x00 || UTF8(preimage)). */
export function hashLeaf(data: string): string {
  return crypto
    .createHash("sha256")
    .update(Buffer.from([LEAF_TAG]))
    .update(Buffer.from(data, "utf8"))
    .digest("hex")
}

/**
 * Exactly 64 LOWERCASE hex characters (DEWP §4.4). Verification inputs must pass this before they
 * reach `hashPair`, because `Buffer.from(s, "hex")` is lenient in two ways that both break the
 * proof: it accepts uppercase, and it silently stops at the first non-hex character instead of
 * failing. So distinct proof strings collapse onto the same bytes.
 *
 * That is not cosmetic — it defeats the padding check in `verifyMerkleProof`. That check rejects a
 * step whose sibling equals the running node anywhere but the unpaired end of an odd level, which is
 * what makes a path to a never-existent index fail. The comparison is on the STRING, so uppercasing
 * a sibling makes `selfPaired` false while `hashPair` still decodes it to the identical 32 bytes:
 * the padding forgery recomputes the genuine root and verifies. Reproduced against the real 3-leaf
 * tree before this gate existed. The Go, Rust, Python and Java ports already gate on this; the
 * reference implementation did not, so it was the only port accepting the forgery.
 */
function isHash64(s: string): boolean {
  if (typeof s !== "string" || s.length !== 64) return false
  for (let i = 0; i < 64; i++) {
    const c = s.charCodeAt(i)
    const isDigit = c >= 0x30 && c <= 0x39
    const isLowerAf = c >= 0x61 && c <= 0x66
    if (!isDigit && !isLowerAf) return false
  }
  return true
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

/**
 * The audit-path length for `index` in a duplicate-last tree of `leafCount` leaves.
 * One sibling per level, and the tree has ceil(log2(n)) levels above the leaves.
 */
export function expectedPathLength(leafCount: number): number {
  return leafCount <= 1 ? 0 : Math.ceil(Math.log2(leafCount))
}

/**
 * Position of the leaf a proof is for, and how many leaves its tree had. Supplying these turns an
 * "is there SOME path from this leaf to this root" check into "is this leaf at this position".
 *
 * REQUIRED, per DEWP §3 invariant 3 ("The bounds are REQUIRED, not advisory") and §11.1. This was
 * an optional parameter, which made the unbounded check reachable by omission from outside this
 * package — the one place it must not be reachable, since external relying parties are exactly who
 * this package exists for.
 */
export interface ProofBounds {
  index: number
  leafCount: number
}

/** Recompute the root from a leaf + its proof and compare. This is what a third party runs. */
export function verifyMerkleProof(
  leaf: string,
  proof: ProofStep[],
  root: string,
  bounds: ProofBounds,
): boolean {
  // Bounds are what make this a proof of membership rather than a proof that A path exists.
  //
  // This tree pads an unpaired trailing node by hashing it against ITSELF (DEWP §5.1.1 rule 3), so
  // merkleRoot([a,b,c]) === merkleRoot([a,b,c,c]) and a path for the nonexistent index 3 recomputes
  // the 3-leaf root exactly. Without a length and index there is nothing to reject it with, which
  // falsifies DEWP §17.1's claim that forging an inclusion path needs a SHA-256 second preimage.
  // DEWP §11.1 states outright that an implementation stopping at root recomputation is
  // non-conformant, so this is a rejection, never a skipped check.
  //
  // `bounds` is required for every TS caller, but this package is the dependency-free, plain-JS-
  // callable trust anchor (see packages/verify/README.md) — nothing enforces that for a legacy
  // 3-argument call from an untyped consumer. Refusing here keeps this a boolean predicate for that
  // caller instead of a thrown TypeError.
  if (!bounds) return false
  // Canonical hex FIRST: the self-pairing check below compares sibling to node as STRINGS, so an
  // uppercased sibling slips past it while hashing to the identical bytes (see `isHash64`). Every
  // hash that reaches `hashPair` is gated here and at each step.
  if (!isHash64(leaf) || !isHash64(root)) return false
  const { index, leafCount } = bounds
  if (!Number.isInteger(index) || !Number.isInteger(leafCount)) return false
  if (leafCount < 1 || index < 0 || index >= leafCount) return false
  if (proof.length !== expectedPathLength(leafCount)) return false
  // Each sibling's side follows from the index; letting the prover choose it freely would hand
  // back the flexibility the length check just removed.
  //
  // The self-pairing check is what actually closes the padding forgery. `leafCount` comes from the
  // proof, so a prover can simply inflate it: claiming leafCount 4 on a 3-leaf tree makes index 3
  // "in range" and the path length correct, and the duplicate-last root is identical — so range
  // and length alone still accept it (verified). But padding is observable: a node hashed against
  // ITSELF only legitimately occurs at the unpaired END of an odd level. A step whose sibling
  // equals the running node anywhere else is the signature of an index pointing into padding.
  let idx = index
  let levelSize = leafCount
  let node = leaf
  for (const step of proof) {
    if (!isHash64(step.siblingHash)) return false
    const expectedSide = idx % 2 === 1 ? "LEFT" : "RIGHT"
    if (step.siblingPosition !== expectedSide) return false
    const selfPaired = step.siblingHash === node
    const legitimatelyUnpaired = idx === levelSize - 1 && levelSize % 2 === 1
    if (selfPaired && !legitimatelyUnpaired) return false
    node =
      step.siblingPosition === "LEFT" ? hashPair(step.siblingHash, node) : hashPair(node, step.siblingHash)
    idx = Math.floor(idx / 2)
    levelSize = Math.ceil(levelSize / 2)
  }
  return node === root
}
