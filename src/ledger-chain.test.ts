import assert from "node:assert/strict"
import crypto from "node:crypto"
import { test } from "node:test"
import {
  chainHash,
  chainPreimage,
  GENESIS_PREV_CHAIN_HASH,
  type RootsChainEntry,
  verifyRootsChain,
} from "./ledger-chain.js"

// The reference vector. @intyga/db's chain.test.ts pins these exact values from its own independent
// implementation — if the two ever disagree, both suites fail, which is the point.
const VECTOR = {
  prevChainHash: GENESIS_PREV_CHAIN_HASH,
  root: "e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8",
  seqStart: "1",
  seqEnd: "10000",
  entryCount: 10000,
  anchoredAt: "2026-07-24T23:59:00.000Z",
} as const

test("chain preimage is a JCS array of strings — counts are stringified", () => {
  assert.equal(
    chainPreimage(VECTOR),
    `["","e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8","1","10000","10000","2026-07-24T23:59:00.000Z"]`,
  )
})

test("chain hash is sha256(0x04 || preimage)", () => {
  const expected = crypto
    .createHash("sha256")
    .update(Buffer.from([0x04]))
    .update(Buffer.from(chainPreimage(VECTOR), "utf8"))
    .digest("hex")
  assert.equal(chainHash(VECTOR), expected)
  // Domain separation: the same bytes under the anchor tag must NOT collide with the chain tag.
  const underAnchorTag = crypto
    .createHash("sha256")
    .update(Buffer.from([0x03]))
    .update(Buffer.from(chainPreimage(VECTOR), "utf8"))
    .digest("hex")
  assert.notEqual(chainHash(VECTOR), underAnchorTag)
})

/** Build a well-formed chained sequence of `n` checkpoints, 100 entries each. */
function buildChain(n: number): RootsChainEntry[] {
  const out: RootsChainEntry[] = []
  let prev = GENESIS_PREV_CHAIN_HASH
  for (let i = 0; i < n; i++) {
    const seqStart = String(i * 100 + 1)
    const seqEnd = String((i + 1) * 100)
    const root = crypto.createHash("sha256").update(`root-${i}`).digest("hex")
    const anchoredAt = new Date(Date.UTC(2026, 6, i + 1)).toISOString()
    const entryCount = 100
    const hash = chainHash({ prevChainHash: prev, root, seqStart, seqEnd, entryCount, anchoredAt })
    out.push({ seqStart, seqEnd, entryCount, root, anchoredAt, prevChainHash: prev, chainHash: hash })
    prev = hash
  }
  return out
}

test("a well-formed chain verifies", () => {
  const r = verifyRootsChain(buildChain(5))
  assert.equal(r.ok, true)
  assert.equal(r.verifiedCount, 5)
  assert.equal(r.brokenAt, -1)
  assert.equal(r.unchained, false)
})

test("an empty roots file is vacuously ok", () => {
  assert.equal(verifyRootsChain([]).ok, true)
})

test("a v1 file with no chain fields reports unchained, NOT broken", () => {
  const v1 = buildChain(3).map(({ prevChainHash: _p, chainHash: _c, ...rest }) => rest)
  const r = verifyRootsChain(v1)
  assert.equal(r.ok, false)
  // The distinction that matters: "older than the chain" must never be alerted as "tampered with".
  assert.equal(r.unchained, true)
  assert.match(r.reason ?? "", /v1 file/)
})

test("splicing chained and unchained entries is refused", () => {
  const entries = buildChain(3)
  const spliced: RootsChainEntry[] = [
    { ...entries[0]!, prevChainHash: undefined, chainHash: undefined },
    entries[1]!,
    entries[2]!,
  ]
  const r = verifyRootsChain(spliced)
  assert.equal(r.ok, false)
  assert.equal(r.unchained, false)
  assert.match(r.reason ?? "", /mixes chained and unchained/)
})

test("editing a published root breaks the chain at that entry", () => {
  const entries = buildChain(5)
  entries[2] = { ...entries[2]!, root: crypto.createHash("sha256").update("forged").digest("hex") }
  const r = verifyRootsChain(entries)
  assert.equal(r.ok, false)
  assert.equal(r.brokenAt, 2)
  assert.equal(r.verifiedCount, 2)
  assert.match(r.reason ?? "", /chain hash mismatch/)
})

test("deleting an entry from the middle breaks the link", () => {
  // This is the case a plain append-only file cannot detect on its own and the chain exists for.
  const entries = buildChain(5)
  entries.splice(2, 1)
  const r = verifyRootsChain(entries)
  assert.equal(r.ok, false)
  assert.equal(r.brokenAt, 2)
  assert.match(r.reason ?? "", /chain link broken/)
})

test("reordering entries breaks the link", () => {
  const entries = buildChain(5)
  const [a, b] = [entries[2]!, entries[3]!]
  entries[2] = b
  entries[3] = a
  const r = verifyRootsChain(entries)
  assert.equal(r.ok, false)
  assert.match(r.reason ?? "", /chain link broken/)
})

test("tampering with entryCount alone is caught", () => {
  const entries = buildChain(3)
  entries[1] = { ...entries[1]!, entryCount: 99 }
  const r = verifyRootsChain(entries)
  assert.equal(r.ok, false)
  assert.equal(r.brokenAt, 1)
})

test("overlapping seq ranges are rejected", () => {
  // Re-chain honestly so ONLY the range overlap is wrong — otherwise the hash check would fire first
  // and this would not actually be testing the range guard.
  const entries = buildChain(3)
  let prev = entries[0]!.chainHash!
  const bad = { ...entries[1]!, seqStart: "50" }
  bad.prevChainHash = prev
  bad.chainHash = chainHash({
    prevChainHash: prev,
    root: bad.root,
    seqStart: bad.seqStart,
    seqEnd: bad.seqEnd,
    entryCount: bad.entryCount,
    anchoredAt: bad.anchoredAt,
  })
  prev = bad.chainHash
  const third = { ...entries[2]!, prevChainHash: prev }
  third.chainHash = chainHash({
    prevChainHash: prev,
    root: third.root,
    seqStart: third.seqStart,
    seqEnd: third.seqEnd,
    entryCount: third.entryCount,
    anchoredAt: third.anchoredAt,
  })
  const r = verifyRootsChain([entries[0]!, bad, third])
  assert.equal(r.ok, false)
  assert.equal(r.brokenAt, 1)
  assert.match(r.reason ?? "", /overlap or regress/)
})

test("gaps in global seq between checkpoints are ACCEPTED", () => {
  // AuditLog.seq is a Postgres autoincrement sequence, and sequences are non-transactional: a
  // rolled-back audit insert burns its value forever. Global seq gaps are therefore normal in a
  // healthy log — DEWP uses the transactionally allocated tenantSeq for gapless completeness. A
  // strict seqEnd+1 check here would fire on ordinary rollbacks and train operators to ignore it.
  let prev = GENESIS_PREV_CHAIN_HASH
  const entries: RootsChainEntry[] = []
  for (const [seqStart, seqEnd] of [
    ["1", "100"],
    ["137", "260"], // 36 values burned by rollbacks
    ["261", "400"],
  ] as const) {
    const root = crypto.createHash("sha256").update(seqEnd).digest("hex")
    const anchoredAt = `2026-07-${seqEnd.padStart(2, "0").slice(0, 2)}T00:00:00.000Z`
    const entryCount = 10
    const hash = chainHash({ prevChainHash: prev, root, seqStart, seqEnd, entryCount, anchoredAt })
    entries.push({ seqStart, seqEnd, entryCount, root, anchoredAt, prevChainHash: prev, chainHash: hash })
    prev = hash
  }
  assert.equal(verifyRootsChain(entries).ok, true)
})
