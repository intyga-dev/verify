import assert from "node:assert/strict"
import crypto from "node:crypto"
import fs from "node:fs"
import { test } from "node:test"
import { ANCHOR_TAG, type AnchorPolicy, type SignedAnchor, signAnchor } from "./ledger-anchor.js"
import { CHAIN_TAG } from "./ledger-chain.js"
import { type ProofBundle, verifyBundle } from "./ledger-bundle.js"
import { type AuditLeaf, canonicalPreimage, leafHash } from "./ledger-leaf.js"
import {
  EMPTY_TAG,
  emptyRoot,
  hashLeaf,
  hashPair,
  LEAF_TAG,
  merkleProof,
  merkleRoot,
  NODE_TAG,
  type ProofStep,
  sha256Hex,
  verifyMerkleProof,
} from "./ledger-merkle.js"
import { type InclusionProof, verifyInclusionProof } from "./ledger-proof.js"

// Build a synthetic two-tier tree (events → blocks → day) the same way the producer does, so these
// vectors are self-consistent by construction and lock the hashing contract in place.

// DEWP §3 Invariant 7 makes `anchorVerified` an if-and-only-if on the anchor quorum, so a test that
// wants FULLY_VERIFIED has to supply a real one: a signed anchor over the same daily root plus the
// policy and key resolver the caller would configure.
const ANCHOR_ISSUER = "https://anchors.example"
function quorumFor(dailyRoot: string): {
  anchors: SignedAnchor[]
  anchorPolicy: AnchorPolicy
  resolveAnchorKey: () => crypto.KeyObject
} {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const unsigned = {
    dailyRoot,
    timestamp: "2026-07-15T23:59:00.000Z",
    issuer: ANCHOR_ISSUER,
    algorithm: "ES256" as const,
  }
  return {
    anchors: [{ ...unsigned, keyId: "k1", signature: signAnchor(unsigned, privateKey) }],
    anchorPolicy: { requiredAnchors: 1, trustedIssuers: [ANCHOR_ISSUER], quorum: "N_OF_M" },
    resolveAnchorKey: () => publicKey,
  }
}

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
    leafIndex: leafIdx,
    blockLeafCount: blockLeafArrays[blockIndex]!.length,
    checkpointId: "cp-1",
    checkpointRoot: dailyRoot,
    checkpointProof: merkleProof(dailyLeaves, blockIndex),
    checkpointLeafIndex: blockIndex,
    checkpointLeafCount: dailyLeaves.length,
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
    kind: "dewp.audit.inclusion-proof",
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

  const good = verifyBundle(bundle, { trustedRoot: dailyRoot, ...quorumFor(dailyRoot) })
  assert.equal(good.ok, true)
  assert.equal(good.checks.leafBinding.pass, true)
  // DEWP §7.1 property model: an UNSIGNED, content-verified, quorum-anchored event is
  // FULLY_VERIFIED (there is no signature to require).
  assert.deepEqual(good.properties, {
    commitmentVerified: true,
    contentVerified: true,
    signatureVerified: false,
    anchorVerified: true,
  })
  assert.equal(good.verificationLevel, "FULLY_VERIFIED")

  // §3 Invariant 7 is an if-and-only-if: handing the verifier a root out of band is provenance, not
  // an anchor check. It still verifies the commitment, but must not claim anchorVerified.
  const rootOnly = verifyBundle(bundle, { trustedRoot: dailyRoot })
  assert.equal(rootOnly.ok, true)
  assert.equal(rootOnly.rootSource, "independent")
  assert.equal(rootOnly.properties.anchorVerified, false, "no quorum was evaluated")
  assert.notEqual(rootOnly.verificationLevel, "FULLY_VERIFIED")
  assert.ok(
    rootOnly.notes.some((n) => /no anchor policy was given/.test(n)),
    `expected the weaker-signal note, got: ${rootOnly.notes.join("; ")}`,
  )

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
    signerDid: "did:intyga:alice",
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
    leafIndex: 0,
    blockLeafCount: 1,
    checkpointId: "cp-1",
    checkpointRoot: dailyRoot,
    checkpointProof: merkleProof([hashLeaf(blockRoot)], 0),
    checkpointLeafIndex: 0,
    checkpointLeafCount: 1,
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

  const res = verifyBundle(bundle, { trustedRoot: dailyRoot, ...quorumFor(dailyRoot) })
  assert.deepEqual(res.properties, {
    commitmentVerified: true,
    contentVerified: true,
    signatureVerified: true,
    anchorVerified: true,
  })
  assert.equal(res.verificationLevel, "FULLY_VERIFIED")

  // Without an evaluated quorum the signature still verifies, but the summary stops one level short.
  const noQuorum = verifyBundle(bundle, { trustedRoot: dailyRoot })
  assert.equal(noQuorum.properties.signatureVerified, true)
  assert.equal(noQuorum.properties.anchorVerified, false)
  assert.equal(noQuorum.verificationLevel, "SIGNATURE_VERIFIED")

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
    kind: "dewp.audit.inclusion-proof",
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
    kind: "dewp.audit.inclusion-proof",
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
  assert.equal(verifyMerkleProof(leaves[1]!, p, root, { index: 1, leafCount: 4 }), true)
  // using the proof for index 1 against index 2's leaf must fail
  assert.equal(verifyMerkleProof(leaves[2]!, p, root, { index: 2, leafCount: 4 }), false)
})

test("verifyMerkleProof refuses instead of throwing when bounds are missing", () => {
  // `bounds` is required for every TS caller, but this package is the dependency-free trust anchor a
  // plain-JS consumer calls from outside the type system — a legacy 3-argument call reaches this as
  // `undefined`. It must return false, the same answer as any other malformed bounds, not throw.
  const leaves = ["a", "b", "c", "d"].map(hashLeaf)
  const root = merkleRoot(leaves)
  const p = merkleProof(leaves, 1)
  // @ts-expect-error — exercising the untyped-caller path deliberately.
  assert.equal(verifyMerkleProof(leaves[1]!, p, root, undefined), false)
})

// ─── Duplicate-last padding forgery (July 2026 review) ───────────────────────
// merkleRoot pads an unpaired trailing node by hashing it against ITSELF (DEWP §5.1.1 rule 3), so
// merkleRoot([a,b,c]) === merkleRoot([a,b,c,c]). Verification used to walk whatever path it was
// handed with no index and no leaf count, which meant a path to a leaf slot that never existed
// recomputed the real root — falsifying DEWP §17.1's claim that forging an inclusion path requires
// a SHA-256 second preimage.

test("duplicate-last padding: a path to a nonexistent leaf slot is refused", () => {
  const leaves = ["a", "b", "c"].map((x) => hashLeaf(x))
  const root = merkleRoot(leaves)
  // The padded 4-leaf tree has the SAME root, so its index-3 path recomputes `root` exactly.
  const forged = merkleProof([...leaves, leaves[2]!], 3)

  assert.equal(
    verifyMerkleProof(leaves[2]!, forged, root, { index: 3, leafCount: 3 }),
    false,
    "an index outside the tree must be refused",
  )
  // leafCount comes from the prover, so inflating it is the obvious next move: it makes index 3
  // in-range AND the path length correct. Padding is still observable — a node hashed against itself
  // anywhere but the unpaired end of an odd level.
  assert.equal(
    verifyMerkleProof(leaves[2]!, forged, root, { index: 3, leafCount: 4 }),
    false,
    "inflating leafCount must not rescue the forgery",
  )
})

test("legitimate duplicate-last padding still verifies (odd tree, last leaf)", () => {
  // The honest counterpart: index 2 of 3 IS the unpaired end, so self-pairing is correct there and
  // must not be mistaken for the forgery above.
  const leaves = ["a", "b", "c"].map((x) => hashLeaf(x))
  const root = merkleRoot(leaves)
  assert.equal(verifyMerkleProof(leaves[2]!, merkleProof(leaves, 2), root, { index: 2, leafCount: 3 }), true)
  for (const i of [0, 1, 2]) {
    assert.equal(
      verifyMerkleProof(leaves[i]!, merkleProof(leaves, i), root, { index: i, leafCount: 3 }),
      true,
      `honest index ${i}`,
    )
  }
})

test("verifyInclusionProof refuses a proof that cannot say where its leaf sits", () => {
  const { proof, dailyRoot } = buildProof(0)
  assert.equal(verifyInclusionProof(proof, dailyRoot), true)
  // A proof missing its position fields establishes only that SOME path exists.
  const positionless = { ...proof, leafIndex: undefined as unknown as number }
  assert.equal(verifyInclusionProof(positionless, dailyRoot), false)
})

// ─── The verdict flag must reflect the checks that ran (July 2026 audit) ─────
// `verifyBundle` computed `headerBinding` and then left it out of `ok`, so a bundle displaying
// something other than what was committed returned ok:true with headerBinding.pass:false. The SDK
// CLI branches on `.ok`, so that printed a green VERIFIED. These pin the flag to its contract.

/** A well-formed, independently-anchored, content-verified bundle — the baseline these mutate. */
function goodBundle(target = 5): { bundle: ProofBundle; dailyRoot: string } {
  const { proof, dailyRoot } = buildProof(target)
  const leaf = makeLeaf(target)
  return {
    bundle: {
      kind: "dewp.audit.inclusion-proof",
      version: 2,
      exportedAt: "2026-07-15T00:00:00.000Z",
      event: {
        seq: String(target),
        createdAt: leaf.createdAt,
        type: leaf.event,
        outcome: leaf.outcome,
        detail: leaf.detail,
        actorDid: null,
        subjectDid: null,
        signerDid: null,
        signature: null,
        sigAlg: null,
        canonical: leaf,
      },
      proof,
      anchorRef: proof.anchorRef,
      anchored: true,
    },
    dailyRoot,
  }
}

test("verifyBundle: ok is false when the displayed header contradicts the commitment", () => {
  const { bundle, dailyRoot } = goodBundle()
  assert.equal(verifyBundle(bundle, { trustedRoot: dailyRoot }).ok, true)

  // Leave `canonical` and `proof` untouched, so leaf binding still passes, and rewrite only the
  // unsigned sibling display fields an auditor actually reads.
  const lying: ProofBundle = {
    ...bundle,
    event: { ...bundle.event, type: "NOTHING_HAPPENED", outcome: "SUCCESS", detail: "routine" },
  }
  const r = verifyBundle(lying, { trustedRoot: dailyRoot })
  assert.equal(r.checks.leafBinding.pass, true, "leaf binding is untouched — that is the point")
  assert.equal(r.checks.headerBinding.pass, false)
  assert.equal(r.ok, false, "a bundle that displays something other than what it committed is not ok")
  assert.equal(r.properties.contentVerified, false)
})

test("verifyBundle: refuses a bundle of the wrong kind (DEWP §6.5)", () => {
  const { bundle, dailyRoot } = goodBundle()
  for (const kind of ["dewp.audit.evidence-bundle", "vendor.audit.proof", ""]) {
    const r = verifyBundle({ ...bundle, kind }, { trustedRoot: dailyRoot })
    assert.equal(r.ok, false, `kind ${JSON.stringify(kind)} must be refused, not noted`)
    assert.equal(r.verificationLevel, "INVALID")
  }
})

test("verifyBundle: an unknown profile cannot switch off leaf binding and stay ok", () => {
  const { bundle, dailyRoot } = goodBundle()
  // `profile` is attacker-supplied. Under an unknown one the verifier correctly declines to
  // recompute the leaf (DEWP §4.5) — but a check the prover can disable must not leave ok true.
  const forged: ProofBundle = {
    ...bundle,
    profile: "com.attacker.v1",
    event: { ...bundle.event, canonical: { ...makeLeaf(5), detail: "fabricated content" } },
  }
  const r = verifyBundle(forged, { trustedRoot: dailyRoot })
  assert.equal(r.checks.leafBinding.pass, null, "not attempted, per DEWP §4.5")
  assert.equal(r.properties.contentVerified, false)
  assert.equal(r.ok, false, "unverifiable content is not ok content")
  assert.equal(r.verificationLevel, "COMMITMENT_VERIFIED")
})

test("verifyBundle: a genuinely redacted entry stays ok at COMMITMENT_VERIFIED", () => {
  // The legitimate counterpart to the test above: leafBinding is null because there is no canonical
  // preimage to bind (retention purged it), not because a profile string disabled the check.
  const { bundle, dailyRoot } = goodBundle()
  const redacted: ProofBundle = {
    ...bundle,
    event: { ...bundle.event, canonical: undefined },
  }
  const r = verifyBundle(redacted, { trustedRoot: dailyRoot })
  assert.equal(r.checks.leafBinding.pass, null)
  assert.equal(r.ok, true, "commitment-only is a valid DEWP outcome for a redacted entry")
  assert.equal(r.verificationLevel, "COMMITMENT_VERIFIED")
})

// ─── The shared golden vectors, checked against the REFERENCE implementation ──
// These vectors are the cross-language parity mechanism: the Go, Rust and Python ledger verifiers
// all pin to them. Nothing in TypeScript consumed them, so when the ports and the reference
// disagreed the vectors sided with the ports — `inclusion` shipped without its four position fields,
// which made a positionless proof "correct" for three languages while this implementation rejected
// it. Reading them here closes the loop: one file, four languages, one answer.

const LEDGER_VECTORS = JSON.parse(
  fs.readFileSync(new URL("../vectors/ledger-vectors.json", import.meta.url), "utf8"),
) as {
  domainTags: Record<string, string>
  sha256Hex: { input: string; expected: string }[]
  hashLeaf: { input: string; expected: string }[]
  hashPair: { left: string; right: string; expected: string }[]
  emptyRoot: string
  merkleRoots: { name: string; leaves: string[]; expected: string }[]
  leafPreimage: { name: string; row: AuditLeaf; canonical: string; leafHash: string }[]
  inclusion: InclusionProof & { dailyRoot: string }
  inclusionNegative: {
    name: string
    leaf: string
    proof: ProofStep[]
    root: string
    bounds: { index: number; leafCount: number }
    expected: boolean
  }[]
}

// `leafPreimage` is the section with the widest blast radius and was the last one no TypeScript
// test read. The vectors are GENERATED from this very builder (scripts/generate-ledger-vectors.ts
// imports canonicalPreimage/leafHash from ledger-leaf.ts), so an edit here plus the documented
// regeneration turns Go, Rust and Python green again against the new bytes — while every leafHash
// already committed to the ledger becomes unreproducible. Asserting the committed bytes here is
// what makes that edit fail instead of pass.
test("golden vectors: the leaf preimage and hash match the committed bytes", () => {
  for (const c of LEDGER_VECTORS.leafPreimage) {
    assert.equal(canonicalPreimage(c.row), c.canonical, `${c.name}: canonical preimage drifted`)
    assert.equal(leafHash(c.row), c.leafHash, `${c.name}: leaf hash drifted`)
  }
})

test("golden vectors: the primitive hashes and domain tags match", () => {
  // Asserted against the implementation's own constants, not a literal copy in this test — so a
  // tag edit in the implementation fails here directly instead of only through derived hashes.
  const hex = (tag: number) => `0x${tag.toString(16).padStart(2, "0")}`
  assert.deepEqual(
    LEDGER_VECTORS.domainTags,
    {
      leaf: hex(LEAF_TAG),
      node: hex(NODE_TAG),
      empty: hex(EMPTY_TAG),
      anchor: hex(ANCHOR_TAG),
      chain: hex(CHAIN_TAG),
    },
    "all five DEWP §2 domain separation bytes",
  )
  for (const c of LEDGER_VECTORS.sha256Hex) assert.equal(sha256Hex(c.input), c.expected, c.input)
  for (const c of LEDGER_VECTORS.hashLeaf) assert.equal(hashLeaf(c.input), c.expected, c.input)
  for (const c of LEDGER_VECTORS.hashPair) {
    assert.equal(hashPair(c.left, c.right), c.expected, `${c.left.slice(0, 8)}+${c.right.slice(0, 8)}`)
  }
  assert.equal(emptyRoot(), LEDGER_VECTORS.emptyRoot)
  for (const c of LEDGER_VECTORS.merkleRoots) {
    assert.equal(merkleRoot(c.leaves), c.expected, c.name)
  }
})

test("golden vectors: the shared inclusion proof verifies, positions and all", () => {
  const v = LEDGER_VECTORS.inclusion
  // The position fields must be present — their absence is what the ports were pinned to.
  for (const k of ["leafIndex", "blockLeafCount", "checkpointLeafIndex", "checkpointLeafCount"] as const) {
    assert.equal(typeof v[k], "number", `ledger-vectors.json inclusion is missing ${k}`)
  }
  assert.equal(verifyInclusionProof({ ...v, checkpointRoot: v.dailyRoot }, v.dailyRoot), true)
})

test("golden vectors: every negative inclusion case is refused", () => {
  for (const c of LEDGER_VECTORS.inclusionNegative) {
    assert.equal(
      verifyMerkleProof(c.leaf, c.proof, c.root, c.bounds),
      c.expected,
      `${c.name} should be ${c.expected}`,
    )
  }
})

// A caller that configured an anchor quorum must get a quorum verdict even when the bundle ships
// with its anchors stripped. Falling back to the weaker "an independent root was handed to me"
// signal there was a check the prover could switch off — the CLI printed `anchor:yes` under a
// policy nobody evaluated.
test("verifyBundle: a supplied anchor policy is evaluated even when the bundle carries no anchors", () => {
  const { bundle, dailyRoot } = goodBundle()
  const r = verifyBundle(bundle, {
    trustedRoot: dailyRoot,
    anchorPolicy: {
      requiredAnchors: 1,
      trustedIssuers: ["https://anchors.example"],
      quorum: "ALL_MUST_AGREE",
    },
    resolveAnchorKey: () => null,
  })
  assert.equal(r.properties.anchorVerified, false, "no anchors can never satisfy a supplied quorum")
  assert.ok(
    r.notes.some((n) => /anchor quorum not met \(0\/1\)/.test(n)),
    `expected the 0/N verdict to be stated, got: ${r.notes.join("; ")}`,
  )
  // And with no policy at all there is no quorum verdict to report either way: a root handed over
  // out of band is provenance (`rootSource`), never the §5.3 check.
  const weak = verifyBundle(bundle, { trustedRoot: dailyRoot })
  assert.equal(weak.properties.anchorVerified, false)
  assert.equal(weak.rootSource, "independent")
})
