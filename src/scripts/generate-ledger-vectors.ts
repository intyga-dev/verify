// Generates the cross-language DEWP ledger golden vectors. The Go/Rust/Python ledger verifiers MUST
// byte-match these, exactly like the DIV canonical vectors. Regenerate only on a deliberate format
// change:  pnpm --filter @intyga/verify exec tsx src/scripts/generate-ledger-vectors.ts

import crypto from "node:crypto"
import fs from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { anchorDigestHex, signAnchor } from "../ledger-anchor.js"
import { type AuditLeaf, canonicalPreimage, leafHash } from "../ledger-leaf.js"
import { hashLeaf, hashPair, merkleProof, merkleRoot, sha256Hex } from "../ledger-merkle.js"

function makeLeaf(seq: number): AuditLeaf {
  return {
    seq: String(seq),
    tenantSeq: String(seq + 1),
    createdAt: "2026-07-24T12:00:00.000Z",
    event: "ACTION_APPROVED",
    outcome: "SUCCESS",
    detail: `event ${seq}`,
    metadata: { target: "users", i: seq },
    signerDid: seq === 0 ? "did:example:human:alice" : null,
    signerPublicKey: null,
    signedPayload: null,
    signature: null,
    sigAlg: null,
    isBillable: false,
    tenantId: "tenant-1",
    actorNodeId: "node-a",
    subjectNodeId: null,
    edgeId: null,
    challengeId: null,
  }
}

// A leaf whose metadata pins UTF-16 key ordering (astral key before U+FFFD) plus nested sorting.
const metadataOrderLeaf: AuditLeaf = {
  ...makeLeaf(9),
  metadata: { "�": "replacement", "😀": "emoji", z: { b: 2, a: 1 }, i: 3 },
}

// ── Merkle primitives ────────────────────────────────────────────────────────
const H = (s: string) => sha256Hex(s)
const A = hashLeaf("A")
const B = hashLeaf("B")
const C = hashLeaf("C")

const merkleCases = [
  { name: "empty", leaves: [] as string[], expected: merkleRoot([]) },
  { name: "single", leaves: [A], expected: merkleRoot([A]) },
  { name: "pair", leaves: [A, B], expected: merkleRoot([A, B]) },
  { name: "odd-triple-duplicate-last", leaves: [A, B, C], expected: merkleRoot([A, B, C]) },
]

// ── Two-tier inclusion proof (self-consistent by construction) ───────────────
const block0 = [0, 1, 2, 3].map(makeLeaf)
const block1 = [4, 5, 6].map(makeLeaf) // odd → exercises duplicate-last
const blocks = [block0, block1]
const blockLeafArrays = blocks.map((b) => b.map(leafHash))
const blockRoots = blockLeafArrays.map(merkleRoot)
const dailyLeaves = blockRoots.map(hashLeaf)
const dailyRoot = merkleRoot(dailyLeaves)

const targetSeq = 5
const blockIndex = blocks.findIndex((b) => b.some((l) => l.seq === String(targetSeq)))
const targetBlock = blocks[blockIndex]
const targetLeafArray = blockLeafArrays[blockIndex]
const targetBlockRoot = blockRoots[blockIndex]
if (!targetBlock || !targetLeafArray || targetBlockRoot === undefined) {
  throw new Error(`target seq ${targetSeq} not found in any block`)
}
const leafIdx = targetBlock.findIndex((l) => l.seq === String(targetSeq))
const leafRow = targetBlock[leafIdx]
const leaf = targetLeafArray[leafIdx]
if (!leafRow || leaf === undefined) throw new Error(`target leaf ${targetSeq} not found`)

// The four position fields are REQUIRED by DEWP §3 invariant 3 and by the normative
// inclusion-proof JSON Schema. They were absent here, so this vector asserted
// that a positionless proof verifies — which is what the Go and Rust ports implemented, while the
// TypeScript reference rejected the very same vector. The vectors are the parity mechanism; without
// these fields they certified agreement on the one input where the ports disagreed with the spec.
const inclusion = {
  leafRow,
  leaf,
  blockIndex: String(blockIndex),
  blockRoot: targetBlockRoot,
  blockProof: merkleProof(targetLeafArray, leafIdx),
  leafIndex: leafIdx,
  blockLeafCount: targetLeafArray.length,
  checkpointProof: merkleProof(dailyLeaves, blockIndex),
  checkpointLeafIndex: blockIndex,
  checkpointLeafCount: dailyLeaves.length,
  dailyRoot,
}

// ── Negative: duplicate-last padding forgery (DEWP §11.1 check 3) ────────────
// merkleRoot([A,B,C]) === merkleRoot([A,B,C,C]), so a path built for the nonexistent index 3
// recomputes the 3-leaf root exactly. Range and length alone still accept it once the prover
// inflates leafCount to 4 — only the self-pairing rule rejects it. Every port MUST answer false.
const paddingTree = [A, B, C]
const paddingRoot = merkleRoot(paddingTree)
// The padded 4-leaf tree has the SAME root, so its index-3 path recomputes `paddingRoot` exactly.
// This IS the forgery: an honest path in a tree that never existed.
const forgedPath = merkleProof([...paddingTree, C], 3)
const inclusionNegative = [
  {
    name: "padding-forgery-index-out-of-range",
    reason: "0 <= index < leafCount (DEWP §11.1 check 1)",
    leaf: C,
    proof: forgedPath,
    root: paddingRoot,
    bounds: { index: 3, leafCount: 3 },
    expected: false,
  },
  {
    name: "padding-forgery-inflated-leaf-count",
    reason:
      "leafCount arrives inside the proof, so inflating it to 4 makes index 3 in-range AND the path " +
      "length correct. Only the self-pairing rule rejects it: a node hashed against itself away from " +
      "the unpaired end of an odd level is the signature of an index pointing into padding " +
      "(DEWP §11.1 check 3)",
    leaf: C,
    proof: forgedPath,
    root: paddingRoot,
    bounds: { index: 3, leafCount: 4 },
    expected: false,
  },
  {
    name: "honest-unpaired-tail-still-verifies",
    reason: "index 2 of 3 IS the unpaired end, so self-pairing is legitimate there",
    leaf: C,
    proof: merkleProof(paddingTree, 2),
    root: paddingRoot,
    bounds: { index: 2, leafCount: 3 },
    expected: true,
  },
]

// ── Anchor digest ────────────────────────────────────────────────────────────
const anchorInput = {
  dailyRoot,
  timestamp: "2026-07-24T23:59:00.000Z",
  issuer: "https://transparency.example.org",
  algorithm: "ES256" as const,
}

// ── Signed anchor (DEWP §5.2) ────────────────────────────────────────────────
// The digest above pins the 0x03 preimage; this pins the SIGNING rule the spec calls out as the
// interop trap: the signature covers the RAW 32-byte anchorDigest, never its 64-char hex text. An
// implementation that signs the hex will match `digestHex` above and still fail this vector. ECDSA
// is randomized, so the committed signature changes on regeneration — but it stays verifiable
// against the committed key forever. The negative case reuses the SAME valid signature over a
// different root: signature checking that ignores the root it was supposedly over must fail here.
const anchorKeyPair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
const anchorSpkiB64 = anchorKeyPair.publicKey.export({ format: "der", type: "spki" }).toString("base64")
const anchorPkcs8B64 = anchorKeyPair.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64")
const signedAnchorObject = {
  ...anchorInput,
  keyId: "vector-anchor-key-1",
  signature: signAnchor(anchorInput, anchorKeyPair.privateKey),
}
const signedAnchor = {
  signerKey: { spkiB64: anchorSpkiB64, pkcs8B64: anchorPkcs8B64 },
  cases: [
    {
      name: "es256-over-raw-digest-verifies",
      anchor: signedAnchorObject,
      digestHex: anchorDigestHex(anchorInput),
      expectOk: true,
    },
    {
      name: "same-signature-different-root-fails",
      anchor: { ...signedAnchorObject, dailyRoot: "f".repeat(64) },
      expectOk: false,
    },
  ],
}

const vectors = {
  generated: new Date().toISOString(),
  note: "Cross-language DEWP ledger vectors (docs/DEWP.md). Consumed by the Go/Rust/Python ledger verifiers. Regenerate ONLY on a deliberate format change.",
  domainTags: { leaf: "0x00", node: "0x01", empty: "0x02", anchor: "0x03" },
  hashLeaf: [
    { input: "A", expected: A },
    { input: "hello world", expected: hashLeaf("hello world") },
  ],
  hashPair: [{ left: A, right: B, expected: hashPair(A, B) }],
  sha256Hex: [{ input: "abc", expected: H("abc") }],
  emptyRoot: merkleRoot([]),
  merkleRoots: merkleCases,
  leafPreimage: [
    {
      name: "signed-leaf",
      row: makeLeaf(0),
      canonical: canonicalPreimage(makeLeaf(0)),
      leafHash: leafHash(makeLeaf(0)),
    },
    {
      name: "plain-leaf",
      row: makeLeaf(5),
      canonical: canonicalPreimage(makeLeaf(5)),
      leafHash: leafHash(makeLeaf(5)),
    },
    {
      // The metadata JCS (§4.2 index 5) sorts keys by UTF-16 code units at every level, exactly
      // like the DIV canonicalizer: the surrogate-pair emoji sorts BEFORE U+FFFD. A port sorting by
      // code point (or UTF-8 bytes) computes a different leaf for a GENUINE bundle whose metadata
      // carries a non-BMP key, and reports content-mismatch indistinguishable from tampering. No
      // earlier ledger vector contained a non-BMP key, so this exact divergence shipped unseen.
      name: "metadata-utf16-key-order",
      row: metadataOrderLeaf,
      canonical: canonicalPreimage(metadataOrderLeaf),
      leafHash: leafHash(metadataOrderLeaf),
    },
  ],
  inclusion,
  inclusionNegative,
  anchor: { input: anchorInput, digestHex: anchorDigestHex(anchorInput) },
  signedAnchor,
}

const outDir = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "mcp-schemas",
  "vectors",
)
const outFile = path.join(outDir, "ledger-vectors.json")
fs.writeFileSync(outFile, `${JSON.stringify(vectors, null, 2)}\n`)
console.log(`wrote ${outFile}`)
