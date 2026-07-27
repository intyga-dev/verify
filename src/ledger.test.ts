import assert from "node:assert/strict"
import crypto from "node:crypto"
import { test } from "node:test"
import { type ProofBundle, verifyBundle } from "./ledger-bundle.js"
import { type AuditLeaf, leafHash } from "./ledger-leaf.js"
import { hashLeaf, merkleProof, merkleRoot, verifyMerkleProof } from "./ledger-merkle.js"
import { type InclusionProof, verifyInclusionProof } from "./ledger-proof.js"

// Build a synthetic two-tier tree (events → blocks → day) the same way the producer does, so these
// vectors are self-consistent by construction and lock the hashing contract in place.

function makeLeaf(seq: number): AuditLeaf {
  return {
    seq: String(seq),
    tenantSeq: String(seq + 1),
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

/** Assemble a full inclusion proof for `targetSeq` across two blocks folded into one daily root. */
function buildProof(targetSeq: number): {
  proof: InclusionProof
  dailyRoot: string
} {
  const block0 = [0, 1, 2, 3].map(makeLeaf)
  const block1 = [4, 5, 6].map(makeLeaf) // odd length exercises duplicate-last
  const blocks = [block0, block1]

  const blockLeafArrays = blocks.map((b) => b.map(leafHash))
  const blockRoots = blockLeafArrays.map(merkleRoot)
  const dailyLeaves = blockRoots.map(hashLeaf) // daily tree leaves are hashLeaf(blockRoot)
  const dailyRoot = merkleRoot(dailyLeaves)

  const blockIndex = blocks.findIndex((b) => b.some((l) => l.seq === String(targetSeq)))
  const leafIdx = blocks[blockIndex]!.findIndex((l) => l.seq === String(targetSeq))
  const leaf = blockLeafArrays[blockIndex]![leafIdx]!

  const proof: InclusionProof = {
    seq: String(targetSeq),
    leaf,
    blockIndex: String(blockIndex),
    blockRoot: blockRoots[blockIndex]!,
    blockProof: merkleProof(blockLeafArrays[blockIndex]!, leafIdx),
    checkpointId: "cp-1",
    checkpointRoot: dailyRoot,
    checkpointProof: merkleProof(dailyLeaves, blockIndex),
    anchorRef: "anchor://test/1",
    anchored: true,
  }
  return { proof, dailyRoot }
}

test("inclusion proof verifies against the correct daily root", () => {
  for (const seq of [0, 3, 4, 6]) {
    const { proof, dailyRoot } = buildProof(seq)
    assert.equal(verifyInclusionProof(proof, dailyRoot), true, `seq ${seq}`)
  }
})

test("inclusion proof fails against a wrong root", () => {
  const { proof } = buildProof(2)
  assert.equal(verifyInclusionProof(proof, "0".repeat(64)), false)
})

test("tampering with the leaf breaks verification", () => {
  const { proof, dailyRoot } = buildProof(2)
  const tampered = { ...proof, leaf: hashLeaf("forged") }
  assert.equal(verifyInclusionProof(tampered, dailyRoot), false)
})

test("verifyBundle: independent root + canonical leaf => ok", () => {
  const target = 5
  const { proof, dailyRoot } = buildProof(target)
  const bundle: ProofBundle = {
    kind: "sakra.audit.inclusion-proof",
    version: 2,
    exportedAt: "2026-07-15T00:00:00.000Z",
    event: {
      seq: String(target),
      createdAt: "2026-07-15T00:00:00.000Z",
      type: "TEST_EVENT",
      outcome: "SUCCESS",
      detail: `event ${target}`,
      actorDid: null,
      subjectDid: null,
      signerDid: null,
      signature: null,
      sigAlg: null,
      canonical: makeLeaf(target),
    },
    proof,
    anchorRef: proof.anchorRef,
    anchored: true,
  }

  const good = verifyBundle(bundle, { trustedRoot: dailyRoot })
  assert.equal(good.ok, true)
  assert.equal(good.checks.leafBinding.pass, true)
  // DEWP §7.1 property model: an UNSIGNED, content-verified, independently-anchored event is
  // FULLY_VERIFIED (there is no signature to require).
  assert.deepEqual(good.properties, {
    commitmentVerified: true,
    contentVerified: true,
    signatureVerified: false,
    anchorVerified: true,
  })
  assert.equal(good.verificationLevel, "FULLY_VERIFIED")

  // Same bundle without an independent root: internally consistent but NOT a trustworthy verdict.
  const weak = verifyBundle(bundle)
  assert.equal(weak.ok, false)
  assert.equal(weak.rootSource, "self-asserted")
  assert.equal(weak.checks.inclusion.pass, true)
  // Without an independent anchor, anchorVerified is false → at most CONTENT_VERIFIED.
  assert.equal(weak.properties.anchorVerified, false)
  assert.equal(weak.verificationLevel, "CONTENT_VERIFIED")
})

test("verifyBundle: a signed event verifies its embedded ES256 signature => SIGNATURE/FULLY_VERIFIED", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const spki = publicKey.export({ format: "der", type: "spki" }).toString("base64")
  const signedPayload = '{"actionType":"db:dropTable","type":"div-intent-verification","v":1}'
  const signature = crypto
    .sign("sha256", Buffer.from(signedPayload, "utf8"), { key: privateKey, dsaEncoding: "ieee-p1363" })
    .toString("base64")
  const leafRow: AuditLeaf = {
    ...makeLeaf(1),
    signerDid: "did:sakra:alice",
    signerPublicKey: spki,
    signedPayload,
    signature,
    sigAlg: "ES256",
  }
  // Single-leaf block folded into a single-block day: roots collapse to the leaf/hashLeaf(root).
  const leaf = leafHash(leafRow)
  const blockRoot = merkleRoot([leaf])
  const dailyRoot = merkleRoot([hashLeaf(blockRoot)])
  const proof: InclusionProof = {
    seq: "1",
    leaf,
    blockIndex: "0",
    blockRoot,
    blockProof: merkleProof([leaf], 0),
    checkpointId: "cp-1",
    checkpointRoot: dailyRoot,
    checkpointProof: merkleProof([hashLeaf(blockRoot)], 0),
    anchorRef: "anchor://test/signed",
    anchored: true,
  }
  const bundle: ProofBundle = {
    kind: "dewp.audit.inclusion-proof",
    version: 2,
    exportedAt: "2026-07-15T00:00:00.000Z",
    event: {
      seq: "1",
      createdAt: leafRow.createdAt,
      type: leafRow.event,
      outcome: leafRow.outcome,
      detail: leafRow.detail,
      actorDid: null,
      subjectDid: null,
      signerDid: leafRow.signerDid,
      signature: leafRow.signature,
      sigAlg: leafRow.sigAlg,
      canonical: leafRow,
    },
    proof,
    anchorRef: proof.anchorRef,
    anchored: true,
  }

  const res = verifyBundle(bundle, { trustedRoot: dailyRoot })
  assert.deepEqual(res.properties, {
    commitmentVerified: true,
    contentVerified: true,
    signatureVerified: true,
    anchorVerified: true,
  })
  assert.equal(res.verificationLevel, "FULLY_VERIFIED")

  // Tampering with the signed payload (but keeping a valid tree position) drops signatureVerified.
  const tampered: ProofBundle = {
    ...bundle,
    event: {
      ...bundle.event,
      canonical: { ...leafRow, signedPayload: '{"actionType":"db:dropTable","evil":true}' },
    },
  }
  const t = verifyBundle(tampered, { trustedRoot: dailyRoot })
  // The altered canonical no longer hashes to the committed leaf, so content fails first.
  assert.equal(t.properties.contentVerified, false)
  assert.equal(t.properties.signatureVerified, false)
})

test("verifyBundle: canonical that doesn't match the leaf fails leaf binding", () => {
  const { proof, dailyRoot } = buildProof(1)
  const bundle: ProofBundle = {
    kind: "sakra.audit.inclusion-proof",
    version: 2,
    exportedAt: "2026-07-15T00:00:00.000Z",
    event: {
      seq: "1",
      createdAt: "2026-07-15T00:00:00.000Z",
      type: "TEST_EVENT",
      outcome: "SUCCESS",
      detail: "event 1",
      actorDid: null,
      subjectDid: null,
      signerDid: null,
      signature: null,
      sigAlg: null,
      canonical: makeLeaf(999), // wrong content
    },
    proof,
    anchorRef: proof.anchorRef,
    anchored: true,
  }
  const res = verifyBundle(bundle, { trustedRoot: dailyRoot })
  assert.equal(res.checks.leafBinding.pass, false)
  assert.equal(res.ok, false)
})

// Bundles exported before DEWP §6.2 carried the root and publication status under the name `anchor`,
// which the spec reserves for a SIGNED anchor object. Those bundles must keep verifying.
test("verifyBundle: a legacy pre-§6.2 `anchor` block still supplies the self-asserted root", () => {
  const target = 3
  const { proof, dailyRoot } = buildProof(target)
  const bundle: ProofBundle = {
    kind: "sakra.audit.inclusion-proof",
    version: 1,
    exportedAt: "2026-07-15T00:00:00.000Z",
    event: {
      seq: String(target),
      createdAt: "2026-07-15T00:00:00.000Z",
      type: "TEST_EVENT",
      outcome: "SUCCESS",
      detail: `event ${target}`,
      actorDid: null,
      subjectDid: null,
      signerDid: null,
      signature: null,
      sigAlg: null,
      canonical: makeLeaf(target),
    },
    proof,
    legacyAnchor: { dailyRoot, anchorRef: proof.anchorRef, anchored: true },
  }
  const res = verifyBundle(bundle)
  assert.equal(res.rootSource, "self-asserted")
  assert.equal(res.dailyRoot, dailyRoot)
  assert.equal(res.properties.commitmentVerified, true)
})

// An unfamiliar Application Profile means an unfamiliar canonical array layout. Hashing it under this
// profile's field order would report a leaf mismatch that is indistinguishable from tampering, so the
// verifier must decline to bind content rather than guess — while still verifying the commitment.
test("verifyBundle: an unknown canonical profile suspends leaf binding but not commitment", () => {
  const target = 2
  const { proof, dailyRoot } = buildProof(target)
  const bundle: ProofBundle = {
    kind: "dewp.audit.inclusion-proof",
    version: "1.0",
    profile: "com.someone-else.audit.v9",
    exportedAt: "2026-07-15T00:00:00.000Z",
    event: {
      seq: String(target),
      createdAt: "2026-07-15T00:00:00.000Z",
      type: "TEST_EVENT",
      outcome: "SUCCESS",
      detail: `event ${target}`,
      actorDid: null,
      subjectDid: null,
      signerDid: null,
      signature: null,
      sigAlg: null,
      canonical: makeLeaf(target),
    },
    proof,
    anchorRef: proof.anchorRef,
    anchored: true,
  }
  const res = verifyBundle(bundle, { trustedRoot: dailyRoot })
  assert.equal(res.properties.commitmentVerified, true)
  assert.equal(res.checks.leafBinding.pass, null)
  assert.equal(res.properties.contentVerified, false)
  assert.equal(res.verificationLevel, "COMMITMENT_VERIFIED")
  assert.ok(res.notes.some((n) => n.includes("com.someone-else.audit.v9")))
})

test("verifyMerkleProof is order-sensitive (position matters)", () => {
  const leaves = ["a", "b", "c", "d"].map(hashLeaf)
  const root = merkleRoot(leaves)
  const p = merkleProof(leaves, 1)
  assert.equal(verifyMerkleProof(leaves[1]!, p, root), true)
  // using the proof for index 1 against index 2's leaf must fail
  assert.equal(verifyMerkleProof(leaves[2]!, p, root), false)
})
