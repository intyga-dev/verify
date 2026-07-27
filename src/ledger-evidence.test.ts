import assert from "node:assert/strict"
import { test } from "node:test"
import {
  EVIDENCE_BUNDLE_KIND,
  EVIDENCE_BUNDLE_KIND_ALIASES,
  type EvidenceBundle,
  verifyEvidenceBundle,
} from "./ledger-evidence.js"
import { type AuditLeaf, leafHash } from "./ledger-leaf.js"
import { hashLeaf, merkleProof, merkleRoot, emptyRoot, sha256Hex } from "./ledger-merkle.js"
import type { InclusionProof } from "./ledger-proof.js"

function makeLeaf(seq: number, tenantSeq: number = seq): AuditLeaf {
  return {
    seq: String(seq),
    tenantSeq: String(tenantSeq),
    createdAt: "2026-07-15T00:00:00.000Z",
    event: "TEST_EVENT",
    outcome: "SUCCESS",
    detail: `event ${seq}`,
    metadata: { i: seq },
    signerDid: null,
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

function buildBundle(
  opts: {
    kind?: string
    redacted?: boolean
    missingCanonical?: boolean
    tamperedCanonical?: boolean
    missingCheckpointRoot?: boolean
    unknownCheckpointRoot?: boolean
    invalidInclusionProof?: boolean
    tenantSeqGap?: boolean
  } = {},
): { bundle: EvidenceBundle; dailyRoot: string } {
  const leaf0 = makeLeaf(1, 1)
  const leaf1 = makeLeaf(2, opts.tenantSeqGap ? 4 : 2)

  const leafHash0 = leafHash(leaf0)
  const leafHash1 = leafHash(leaf1)
  const blockLeaves = [leafHash0, leafHash1]
  const blockRoot = merkleRoot(blockLeaves)

  const dailyLeaves = [hashLeaf(blockRoot)]
  const dailyRoot = merkleRoot(dailyLeaves)

  const proof0: InclusionProof = {
    seq: "1",
    leaf: opts.invalidInclusionProof ? hashLeaf("tampered") : leafHash0,
    blockIndex: "0",
    blockRoot,
    blockProof: merkleProof(blockLeaves, 0),
    checkpointId: "cp-1",
    checkpointRoot: opts.missingCheckpointRoot ? "" : opts.unknownCheckpointRoot ? "0".repeat(64) : dailyRoot,
    checkpointProof: merkleProof(dailyLeaves, 0),
    anchorRef: "anchor://test/1",
    anchored: true,
  }

  const proof1: InclusionProof = {
    seq: "2",
    leaf: leafHash1,
    blockIndex: "0",
    blockRoot,
    blockProof: merkleProof(blockLeaves, 1),
    checkpointId: "cp-1",
    checkpointRoot: dailyRoot,
    checkpointProof: merkleProof(dailyLeaves, 0),
    anchorRef: "anchor://test/1",
    anchored: true,
  }

  // A redacted entry has NO canonical preimage — its content is gone by design. The producer
  // (packages/db/src/evidence.ts) omits it, so the fixture must too, or the tests silently verify a
  // bundle shape that is never actually exported.
  const entry0Canonical =
    opts.missingCanonical || opts.redacted
      ? undefined
      : opts.tamperedCanonical
        ? { ...leaf0, detail: "tampered" }
        : leaf0

  const bundle: EvidenceBundle = {
    kind: (opts.kind ?? EVIDENCE_BUNDLE_KIND) as typeof EVIDENCE_BUNDLE_KIND,
    version: 1,
    exportedAt: "2026-07-15T00:00:00.000Z",
    tenant: { id: "tenant-1", name: "Test Tenant" },
    range: { from: "2026-07-15T00:00:00.000Z", to: "2026-07-15T23:59:59.000Z" },
    checkpoints: [
      {
        id: "cp-1",
        root: dailyRoot,
        anchorRef: "anchor://test/1",
        anchoredAt: "2026-07-15T12:00:00.000Z",
        seqStart: "1",
        seqEnd: "2",
      },
    ],
    entries: [
      {
        event: {
          seq: "1",
          createdAt: leaf0.createdAt,
          type: leaf0.event,
          outcome: leaf0.outcome,
          redacted: !!opts.redacted,
          tenantSeq: leaf0.tenantSeq,
          signerDid: null,
          sigAlg: null,
          canonical: entry0Canonical,
        },
        proof: proof0,
      },
      {
        event: {
          seq: "2",
          createdAt: leaf1.createdAt,
          type: leaf1.event,
          outcome: leaf1.outcome,
          redacted: false,
          tenantSeq: leaf1.tenantSeq,
          signerDid: null,
          sigAlg: null,
          canonical: leaf1,
        },
        proof: proof1,
      },
    ],
  }

  return { bundle, dailyRoot }
}

/**
 * Three contiguous entries (tenantSeq 1,2,3) in one block, mirroring how the producer exports them —
 * a redacted entry keeps its tenantSeq and inclusion proof but loses its canonical preimage.
 */
function buildThreeEntryBundle(
  opts: { redactMiddle?: boolean; dropMiddleTenantSeq?: boolean; duplicateTenantSeq?: boolean } = {},
): { bundle: EvidenceBundle; dailyRoot: string } {
  const leaves = [makeLeaf(1, 1), makeLeaf(2, opts.duplicateTenantSeq ? 1 : 2), makeLeaf(3, 3)]
  const leafHashes = leaves.map(leafHash)
  const blockRoot = merkleRoot(leafHashes)
  const dailyLeaves = [hashLeaf(blockRoot)]
  const dailyRoot = merkleRoot(dailyLeaves)

  const entries = leaves.map((leaf, i) => {
    const redacted = i === 1 && !!opts.redactMiddle
    return {
      event: {
        seq: leaf.seq,
        createdAt: leaf.createdAt,
        type: leaf.event,
        outcome: leaf.outcome,
        redacted,
        tenantSeq: redacted && opts.dropMiddleTenantSeq ? null : leaf.tenantSeq,
        signerDid: null,
        sigAlg: null,
        // Redacted ⇒ no preimage, exactly as packages/db/src/evidence.ts exports it.
        ...(redacted ? {} : { canonical: leaf }),
      },
      proof: {
        seq: leaf.seq,
        leaf: leafHashes[i] as string,
        blockIndex: "0",
        blockRoot,
        blockProof: merkleProof(leafHashes, i),
        checkpointId: "cp-1",
        checkpointRoot: dailyRoot,
        checkpointProof: merkleProof(dailyLeaves, 0),
        anchorRef: "anchor://test/1",
        anchored: true,
      },
    }
  })

  return {
    bundle: {
      kind: EVIDENCE_BUNDLE_KIND,
      version: 1,
      exportedAt: "2026-07-15T00:00:00.000Z",
      tenant: { id: "tenant-1", name: "Test Tenant" },
      range: { from: "2026-07-15T00:00:00.000Z", to: "2026-07-15T23:59:59.000Z" },
      checkpoints: [
        {
          id: "cp-1",
          root: dailyRoot,
          anchorRef: "anchor://test/1",
          anchoredAt: "2026-07-15T12:00:00.000Z",
          seqStart: "1",
          seqEnd: "3",
        },
      ],
      entries,
    },
    dailyRoot,
  }
}

test("verifyEvidenceBundle: valid unredacted bundle with trusted roots", () => {
  const { bundle, dailyRoot } = buildBundle()
  const res = verifyEvidenceBundle(bundle, { trustedRoots: [dailyRoot] })
  assert.equal(res.ok, true)
  assert.equal(res.total, 2)
  assert.equal(res.contentVerified, 2)
  assert.equal(res.commitmentOnly, 0)
  assert.equal(res.failed.length, 0)
  assert.equal(res.roots.length, 1)
  assert.equal(res.roots[0]?.root, dailyRoot)
})

test("verifyEvidenceBundle: accepts legacy evidence bundle alias kind", () => {
  const { bundle, dailyRoot } = buildBundle({ kind: EVIDENCE_BUNDLE_KIND_ALIASES[0] })
  const res = verifyEvidenceBundle(bundle, { trustedRoots: [dailyRoot] })
  assert.equal(res.ok, true)
  assert.equal(res.notes.length, 0)
})

test("verifyEvidenceBundle: warns on unexpected bundle kind", () => {
  const { bundle, dailyRoot } = buildBundle({ kind: "invalid.kind" })
  const res = verifyEvidenceBundle(bundle, { trustedRoots: [dailyRoot] })
  assert.equal(res.ok, true)
  assert.ok(res.notes.some((n) => n.includes('Unexpected bundle kind "invalid.kind"')))
})

test("verifyEvidenceBundle: un-trusted run adds note and returns ok=false", () => {
  const { bundle } = buildBundle()
  const res = verifyEvidenceBundle(bundle)
  assert.equal(res.ok, false)
  assert.ok(res.notes.some((n) => n.includes("No independent roots supplied")))
  assert.ok(res.notes.some((n) => n.includes("All entries internally consistent")))
})

test("verifyEvidenceBundle: entry missing checkpoint root", () => {
  const { bundle, dailyRoot } = buildBundle({ missingCheckpointRoot: true })
  const res = verifyEvidenceBundle(bundle, { trustedRoots: [dailyRoot] })
  assert.equal(res.ok, false)
  assert.ok(res.failed.some((f) => f.reason.includes("no checkpoint root")))
})

test("verifyEvidenceBundle: checkpoint root not in bundle checkpoint list", () => {
  const { bundle, dailyRoot } = buildBundle({ unknownCheckpointRoot: true })
  const res = verifyEvidenceBundle(bundle, { trustedRoots: [dailyRoot] })
  assert.equal(res.ok, false)
  assert.ok(res.failed.some((f) => f.reason.includes("not in the bundle's checkpoint list")))
})

test("verifyEvidenceBundle: checkpoint root not in supplied trusted roots", () => {
  const { bundle } = buildBundle()
  const res = verifyEvidenceBundle(bundle, { trustedRoots: ["0".repeat(64)] })
  assert.equal(res.ok, false)
  assert.ok(res.failed.some((f) => f.reason.includes("not among the supplied trusted roots")))
})

test("verifyEvidenceBundle: inclusion proof fails verification", () => {
  const { bundle, dailyRoot } = buildBundle({ invalidInclusionProof: true })
  const res = verifyEvidenceBundle(bundle, { trustedRoots: [dailyRoot] })
  assert.equal(res.ok, false)
  assert.ok(res.failed.some((f) => f.reason.includes("does not recompute")))
})

test("verifyEvidenceBundle: redacted entry counts as commitmentOnly", () => {
  const { bundle, dailyRoot } = buildBundle({ redacted: true })
  const res = verifyEvidenceBundle(bundle, { trustedRoots: [dailyRoot] })
  assert.equal(res.ok, true)
  assert.equal(res.commitmentOnly, 1)
  assert.equal(res.contentVerified, 1)
})

test("verifyEvidenceBundle: leaf hash mismatch on canonical preimage", () => {
  const { bundle, dailyRoot } = buildBundle({ tamperedCanonical: true })
  const res = verifyEvidenceBundle(bundle, { trustedRoots: [dailyRoot] })
  assert.equal(res.ok, false)
  assert.ok(res.failed.some((f) => f.reason.includes("leaf binding failed")))
})

test("verifyEvidenceBundle: unredacted entry missing canonical preimage", () => {
  const { bundle, dailyRoot } = buildBundle({ missingCanonical: true })
  const res = verifyEvidenceBundle(bundle, { trustedRoots: [dailyRoot] })
  assert.equal(res.ok, false)
  assert.ok(res.failed.some((f) => f.reason.includes("missing its canonical preimage")))
})

// A redacted entry carries no canonical preimage, so keying the gapless check off the preimage made
// it invisible: the entry after it compared tenantSeq N+2 against N and the whole bundle failed with
// "per-tenant omission detected". Lawful retention redaction must not read as tampering.
test("verifyEvidenceBundle: a redacted entry BETWEEN two intact ones does not report a phantom gap", () => {
  const { bundle, dailyRoot } = buildThreeEntryBundle({ redactMiddle: true })
  const res = verifyEvidenceBundle(bundle, { trustedRoots: [dailyRoot] })
  assert.deepEqual(res.failed, [])
  assert.equal(res.ok, true)
  assert.equal(res.commitmentOnly, 1)
  assert.equal(res.contentVerified, 2)
})

// The redacted entry must not become a blind spot either: a genuinely missing event around it still
// has to surface.
test("verifyEvidenceBundle: a real omission next to a redacted entry is still detected", () => {
  const { bundle, dailyRoot } = buildThreeEntryBundle({ redactMiddle: true, dropMiddleTenantSeq: true })
  const res = verifyEvidenceBundle(bundle, { trustedRoots: [dailyRoot] })
  assert.equal(res.ok, false)
  assert.ok(res.notes.some((n) => n.includes("no tenantSeq")))
})

test("verifyEvidenceBundle: a repeated tenantSeq is rejected as not strictly increasing", () => {
  const { bundle, dailyRoot } = buildThreeEntryBundle({ duplicateTenantSeq: true })
  const res = verifyEvidenceBundle(bundle, { trustedRoots: [dailyRoot] })
  assert.equal(res.ok, false)
  assert.ok(res.failed.some((f) => f.reason.includes("not strictly increasing")))
})

test("verifyEvidenceBundle: sequence gap between tenantSeq detects omission", () => {
  const { bundle, dailyRoot } = buildBundle({ tenantSeqGap: true })
  const res = verifyEvidenceBundle(bundle, { trustedRoots: [dailyRoot] })
  assert.equal(res.ok, false)
  assert.ok(res.failed.some((f) => f.reason.includes("per-tenant omission detected")))
})

test("merkle primitives: sha256Hex and emptyRoot", () => {
  assert.equal(sha256Hex("hello"), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
  assert.equal(emptyRoot().length, 64)
})
