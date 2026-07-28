// Generates the cross-language DEWP ledger golden vectors. The Go/Rust/Python ledger verifiers MUST
// byte-match these, exactly like the DIV canonical vectors. Regenerate only on a deliberate format
// change:  pnpm --filter @intyga/verify exec tsx src/scripts/generate-ledger-vectors.ts

import fs from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { anchorDigestHex } from "../ledger-anchor.js"
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

const inclusion = {
  leafRow,
  leaf,
  blockIndex: String(blockIndex),
  blockRoot: targetBlockRoot,
  blockProof: merkleProof(targetLeafArray, leafIdx),
  checkpointProof: merkleProof(dailyLeaves, blockIndex),
  dailyRoot,
}

// ── Anchor digest ────────────────────────────────────────────────────────────
const anchorInput = {
  dailyRoot,
  timestamp: "2026-07-24T23:59:00.000Z",
  issuer: "https://transparency.example.org",
  algorithm: "ES256" as const,
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
  ],
  inclusion,
  anchor: { input: anchorInput, digestHex: anchorDigestHex(anchorInput) },
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
