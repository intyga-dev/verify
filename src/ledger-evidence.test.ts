import assert from "node:assert/strict"
import crypto from "node:crypto"
import { test } from "node:test"
import { type SignedAnchor, signAnchor } from "./ledger-anchor.js"
import { EVIDENCE_BUNDLE_KIND, type EvidenceBundle, verifyEvidenceBundle } from "./ledger-evidence.js"
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
    leafIndex: 0,
    blockLeafCount: blockLeaves.length,
    checkpointId: "cp-1",
    checkpointRoot: opts.missingCheckpointRoot ? "" : opts.unknownCheckpointRoot ? "0".repeat(64) : dailyRoot,
    checkpointProof: merkleProof(dailyLeaves, 0),
    checkpointLeafIndex: 0,
    checkpointLeafCount: dailyLeaves.length,
    anchorRef: "anchor://test/1",
    anchored: true,
  }

  const proof1: InclusionProof = {
    seq: "2",
    leaf: leafHash1,
    blockIndex: "0",
    blockRoot,
    blockProof: merkleProof(blockLeaves, 1),
    leafIndex: 1,
    blockLeafCount: blockLeaves.length,
    checkpointId: "cp-1",
    checkpointRoot: dailyRoot,
    checkpointProof: merkleProof(dailyLeaves, 0),
    checkpointLeafIndex: 0,
    checkpointLeafCount: dailyLeaves.length,
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
        leafIndex: i,
        blockLeafCount: leafHashes.length,
        checkpointId: "cp-1",
        checkpointRoot: dailyRoot,
        checkpointProof: merkleProof(dailyLeaves, 0),
        checkpointLeafIndex: 0,
        checkpointLeafCount: dailyLeaves.length,
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

test("verifyEvidenceBundle: REFUSES an unexpected bundle kind (DEWP §6.5)", () => {
  // Previously a note, so a container of one type fed to the verifier for another still came back
  // ok — a passing verdict produced under semantics the artifact was never built for. §6.5 says a
  // compliant verifier MUST reject.
  const { bundle, dailyRoot } = buildBundle({ kind: "invalid.kind" })
  const res = verifyEvidenceBundle(bundle, { trustedRoots: [dailyRoot] })
  assert.equal(res.ok, false)
  assert.ok(res.failed.some((f) => f.reason.includes('refusing bundle kind "invalid.kind"')))
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

// ─── Display-vs-commitment binding (July 2026 review) ────────────────────────
// The leaf commits to `canonical`. Everything alongside it on an entry — seq, outcome, tenantSeq,
// tenantId — is an unsigned display copy, and the bundle is what a human, a console or a SIEM
// actually reads. These pin that the two must agree.

test("evidence: a renumbered tenantSeq cannot paper over an omission", () => {
  // THE attack: drop the incriminating events, keep the honest entries with their genuine proofs,
  // and renumber the DISPLAY counters so the contiguity check sees no gap. It used to work, because
  // the check read entry.tenantSeq — a field covered by nothing.
  const { bundle, dailyRoot } = buildBundle()
  const entries = bundle.entries
  assert.ok(entries.length >= 2, "fixture needs two entries")
  // Leave `canonical.tenantSeq` alone (it is committed) and rewrite only the display copy, to
  // values that close a hypothetical gap.
  for (const [i, e] of entries.entries()) {
    e.event.tenantSeq = String(100 + i)
  }
  const res = verifyEvidenceBundle(bundle, { trustedRoots: [dailyRoot] })
  assert.equal(res.ok, false, "a display counter that contradicts the commitment must be refused")
  assert.ok(
    res.failed.some((f) => f.reason.includes("tenantSeq")),
    `expected a tenantSeq mismatch, got ${JSON.stringify(res.failed)}`,
  )
})

test("evidence: a displayed outcome that contradicts the commitment is refused", () => {
  const { bundle, dailyRoot } = buildBundle()
  const first = bundle.entries[0]
  assert.ok(first?.event.canonical)
  first.event.outcome = first.event.canonical.outcome === "SUCCESS" ? "FAILURE" : "SUCCESS"
  const res = verifyEvidenceBundle(bundle, { trustedRoots: [dailyRoot] })
  assert.equal(res.ok, false)
  assert.ok(res.failed.some((f) => f.reason.includes("displayed outcome")))
})

test("evidence: an entry belonging to another tenant is not counted as this tenant's", () => {
  // A genuine proof, under a root the auditor trusts, for an event that is simply somebody else's.
  const { bundle, dailyRoot } = buildBundle()
  const first = bundle.entries[0]
  assert.ok(first?.event.canonical)
  first.event.canonical.tenantId = "tenant-SOMEONE-ELSE"
  const res = verifyEvidenceBundle(bundle, { trustedRoots: [dailyRoot] })
  assert.equal(res.ok, false)
  // Editing the committed preimage also breaks leaf binding, which fires first — either rejection is
  // correct, and both are the point: a foreign entry cannot be counted as this tenant's.
  assert.ok(
    res.failed.some(
      (f) => f.reason.includes("belongs to tenant") || f.reason.includes("leaf hash does not match"),
    ),
    `expected a rejection, got ${JSON.stringify(res.failed)}`,
  )
})

// ─── In-bundle anchor quorum (§6.3 checkpoints[].anchors) ────────────────────
//
// The evidence bundle carries the §5.2 signed anchors per checkpoint — the set the §5.3 quorum rule
// is defined over — yet the verifier used to ignore them entirely: without caller-fetched anchors,
// `anchorVerified` was unreachable. These pin the fallback: bundle anchors count toward quorum
// (they still verify only under keys the CALLER trusts) but can never force the fatal DIVERGENCE
// verdict, which stays reserved for anchors the caller fetched per checkpoint itself.

function makeAnchorIssuer(issuer: string) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" })
  const anchorFor = (dailyRoot: string): SignedAnchor => {
    const base = { dailyRoot, timestamp: "2026-07-15T23:59:00.000Z", issuer, algorithm: "ES256" as const }
    return { ...base, keyId: `${issuer}#key-1`, signature: signAnchor(base, privateKey) }
  }
  const resolveKey = (a: SignedAnchor) => (a.issuer === issuer ? publicKey : null)
  return { issuer, anchorFor, resolveKey }
}

test("evidence: bundle-carried checkpoint anchors reach quorum under the caller's policy and keys", () => {
  const { bundle, dailyRoot } = buildBundle()
  const iss = makeAnchorIssuer("https://anchors.example")
  const cp = bundle.checkpoints[0]
  assert.ok(cp)
  cp.anchors = [iss.anchorFor(dailyRoot)]

  const res = verifyEvidenceBundle(bundle, {
    trustedRoots: [dailyRoot],
    anchorPolicy: { requiredAnchors: 1, trustedIssuers: [iss.issuer], quorum: "ALL_MUST_AGREE" },
    resolveAnchorKey: iss.resolveKey,
  })
  assert.equal(res.ok, true, res.notes.concat(res.failed.map((f) => f.reason)).join("; "))
  assert.deepEqual(
    res.roots.map((r) => r.anchorVerified),
    [true],
  )
  assert.deepEqual(res.roots[0]?.verifiedIssuers, [iss.issuer])
  // The verdict says where the anchors came from, so an auditor knows divergence was not assessable.
  assert.ok(res.notes.some((n) => /carried in the bundle/.test(n)))
})

test("evidence: without a policy, bundle-carried anchors change nothing (nobody checked)", () => {
  const { bundle, dailyRoot } = buildBundle()
  const iss = makeAnchorIssuer("https://anchors.example")
  const cp = bundle.checkpoints[0]
  assert.ok(cp)
  cp.anchors = [iss.anchorFor(dailyRoot)]

  const res = verifyEvidenceBundle(bundle, { trustedRoots: [dailyRoot] })
  assert.equal(res.roots[0]?.anchorVerified, null)
  assert.ok(res.notes.some((n) => /No anchor policy supplied/.test(n)))
})

test("evidence: a bundle anchor over a DIFFERENT root neither counts nor forces divergence", () => {
  // The attack the divergence carve-out exists for: append a GENUINE, publicly available anchor from
  // another day to a valid bundle. It must not satisfy quorum for this root (it did not sign it) and
  // it must not flip the verdict to divergence (only caller-fetched anchors can establish that).
  const { bundle, dailyRoot } = buildBundle()
  const iss = makeAnchorIssuer("https://anchors.example")
  const cp = bundle.checkpoints[0]
  assert.ok(cp)
  cp.anchors = [iss.anchorFor(dailyRoot), iss.anchorFor("f".repeat(64))]

  const res = verifyEvidenceBundle(bundle, {
    trustedRoots: [dailyRoot],
    anchorPolicy: { requiredAnchors: 1, trustedIssuers: [iss.issuer], quorum: "N_OF_M" },
    resolveAnchorKey: iss.resolveKey,
  })
  assert.equal(res.roots[0]?.anchorVerified, true)
  assert.equal(res.ok, true)
  assert.ok(
    !res.failed.some((f) => f.reason.includes("DIVERGENCE")),
    `bundle anchors must not be able to fabricate divergence: ${JSON.stringify(res.failed)}`,
  )
})

test("evidence: bundle anchors from an untrusted issuer never reach quorum, and ok fails with them", () => {
  const { bundle, dailyRoot } = buildBundle()
  const iss = makeAnchorIssuer("https://anchors.example")
  const cp = bundle.checkpoints[0]
  assert.ok(cp)
  cp.anchors = [iss.anchorFor(dailyRoot)]

  const res = verifyEvidenceBundle(bundle, {
    trustedRoots: [dailyRoot],
    anchorPolicy: {
      requiredAnchors: 1,
      trustedIssuers: ["https://someone-else.example"],
      quorum: "ALL_MUST_AGREE",
    },
    resolveAnchorKey: iss.resolveKey,
  })
  assert.equal(res.roots[0]?.anchorVerified, false)
  assert.equal(res.ok, false, "a policy was supplied and no root reached quorum — ok must fail")
})

test("evidence: a producer stripping checkpoint anchors cannot bypass a supplied quorum policy", () => {
  // The fail-open shape: caller supplies policy + resolver, bundle carries no anchors at all. The
  // check must evaluate to "quorum not met (0/N)" and fail ok — never silently skip because there
  // was nothing to check, which is a check the prover switches off by deleting a field.
  const { bundle, dailyRoot } = buildBundle()
  const iss = makeAnchorIssuer("https://anchors.example")
  const res = verifyEvidenceBundle(bundle, {
    trustedRoots: [dailyRoot],
    anchorPolicy: { requiredAnchors: 1, trustedIssuers: [iss.issuer], quorum: "ALL_MUST_AGREE" },
    resolveAnchorKey: iss.resolveKey,
  })
  assert.equal(res.roots[0]?.anchorVerified, false, "stripped anchors must read as quorum NOT met")
  assert.equal(res.ok, false)
  assert.ok(
    res.notes.some((n) => /anchor quorum not met \(0\/1\)/.test(n)),
    `expected the 0/N verdict to be stated, got: ${res.notes.join("; ")}`,
  )
})

test("evidence: an explicitly supplied anchor policy without a resolver fails the overall verdict", () => {
  const { bundle, dailyRoot } = buildBundle()
  const iss = makeAnchorIssuer("https://anchors.example")
  bundle.checkpoints[0]!.anchors = [iss.anchorFor(dailyRoot)]
  const res = verifyEvidenceBundle(bundle, {
    trustedRoots: [dailyRoot],
    anchorPolicy: { requiredAnchors: 1, trustedIssuers: [iss.issuer], quorum: "N_OF_M" },
  })
  assert.equal(res.ok, false)
  assert.deepEqual(
    res.roots.map((root) => root.anchorVerified),
    [null],
  )
  assert.ok(
    res.notes.some((note) => /policy incomplete|resolveAnchorKey/i.test(note)),
    res.notes.join("; "),
  )
})

// ─── Caller anchors are attributed to a checkpoint before feeding divergence ──
//
// A date-range export routinely spans several daily checkpoints. Passing the caller's whole flat
// anchor list to EVERY root read a genuine anchor for checkpoint A as fatal ANCHOR DIVERGENCE while
// evaluating checkpoint B — the exact misbinding verifyAnchorQuorum's `divergenceAnchors` doc warns
// about, destroying the availability of sound evidence rather than its soundness.

/** Two single-entry daily checkpoints, as a two-day export produces them. */
function buildTwoCheckpointBundle(): { bundle: EvidenceBundle; rootA: string; rootB: string } {
  const day = (seq: number, cpId: string) => {
    const leaf = makeLeaf(seq)
    const lh = leafHash(leaf)
    const blockRoot = merkleRoot([lh])
    const dailyLeaves = [hashLeaf(blockRoot)]
    const root = merkleRoot(dailyLeaves)
    return {
      root,
      checkpoint: {
        id: cpId,
        root,
        anchorRef: `anchor://test/${cpId}`,
        anchoredAt: "2026-07-15T12:00:00.000Z",
        seqStart: String(seq),
        seqEnd: String(seq),
      },
      entry: {
        event: {
          seq: String(seq),
          createdAt: leaf.createdAt,
          type: leaf.event,
          outcome: leaf.outcome,
          tenantSeq: leaf.tenantSeq,
          signerDid: null,
          sigAlg: null,
          canonical: leaf,
        },
        proof: {
          seq: String(seq),
          leaf: lh,
          blockIndex: "0",
          blockRoot,
          blockProof: merkleProof([lh], 0),
          leafIndex: 0,
          blockLeafCount: 1,
          checkpointId: cpId,
          checkpointRoot: root,
          checkpointProof: merkleProof(dailyLeaves, 0),
          checkpointLeafIndex: 0,
          checkpointLeafCount: 1,
          anchorRef: `anchor://test/${cpId}`,
          anchored: true,
        },
      },
    }
  }
  const a = day(1, "cp-1")
  const b = day(2, "cp-2")
  return {
    rootA: a.root,
    rootB: b.root,
    bundle: {
      kind: EVIDENCE_BUNDLE_KIND,
      version: 1,
      exportedAt: "2026-07-16T00:00:00.000Z",
      tenant: { id: "tenant-1", name: "Test Tenant" },
      range: { from: "2026-07-15T00:00:00.000Z", to: "2026-07-16T23:59:59.000Z" },
      checkpoints: [a.checkpoint, b.checkpoint],
      entries: [a.entry, b.entry],
    },
  }
}

test("evidence: a genuine caller anchor per checkpoint verifies a multi-day bundle (flat list)", () => {
  const { bundle, rootA, rootB } = buildTwoCheckpointBundle()
  const iss = makeAnchorIssuer("https://anchors.example")
  const res = verifyEvidenceBundle(bundle, {
    trustedRoots: [rootA, rootB],
    anchors: [iss.anchorFor(rootA), iss.anchorFor(rootB)],
    anchorPolicy: { requiredAnchors: 1, trustedIssuers: [iss.issuer], quorum: "N_OF_M" },
    resolveAnchorKey: iss.resolveKey,
  })
  assert.deepEqual(
    res.failed.filter((f) => f.reason.includes("DIVERGENCE")),
    [],
    "an anchor for the OTHER checkpoint in the same bundle is not divergence evidence",
  )
  assert.deepEqual(
    res.roots.map((r) => r.anchorVerified),
    [true, true],
  )
  assert.equal(res.ok, true, res.notes.concat(res.failed.map((f) => f.reason)).join("; "))
  // The flat list cannot say which checkpoint each anchor was fetched for; the verdict says so.
  assert.ok(res.notes.some((n) => /flat list/.test(n)))
})

test("evidence: caller anchors keyed by checkpoint verify a multi-day bundle with no note", () => {
  const { bundle, rootA, rootB } = buildTwoCheckpointBundle()
  const iss = makeAnchorIssuer("https://anchors.example")
  const res = verifyEvidenceBundle(bundle, {
    trustedRoots: [rootA, rootB],
    anchors: { "cp-1": [iss.anchorFor(rootA)], [rootB]: [iss.anchorFor(rootB)] },
    anchorPolicy: { requiredAnchors: 1, trustedIssuers: [iss.issuer], quorum: "N_OF_M" },
    resolveAnchorKey: iss.resolveKey,
  })
  assert.equal(res.ok, true, res.notes.concat(res.failed.map((f) => f.reason)).join("; "))
  assert.deepEqual(
    res.roots.map((r) => r.anchorVerified),
    [true, true],
  )
  // Either key works: checkpoint id for the first, the checkpoint's root for the second.
  assert.ok(!res.notes.some((n) => /flat list|does not contain/.test(n)), res.notes.join("; "))
})

test("evidence: a keyed anchor naming a different root for ITS checkpoint is still fatal", () => {
  // The tamper signal the mechanism exists for: the issuer's anchor for cp-1 says some other root.
  // It must fail cp-1 specifically, while cp-2's genuine anchor still reaches quorum.
  const { bundle, rootA, rootB } = buildTwoCheckpointBundle()
  const iss = makeAnchorIssuer("https://anchors.example")
  const res = verifyEvidenceBundle(bundle, {
    trustedRoots: [rootA, rootB],
    anchors: { "cp-1": [iss.anchorFor("a".repeat(64))], "cp-2": [iss.anchorFor(rootB)] },
    anchorPolicy: { requiredAnchors: 1, trustedIssuers: [iss.issuer], quorum: "N_OF_M" },
    resolveAnchorKey: iss.resolveKey,
  })
  assert.equal(res.ok, false)
  const divergent = res.failed.filter((f) => f.reason.includes("DIVERGENCE"))
  assert.equal(divergent.length, 1, `expected cp-1 alone to diverge, got ${JSON.stringify(res.failed)}`)
  assert.ok(divergent[0]?.reason.includes(rootA.slice(0, 16)))
  assert.equal(res.roots.find((r) => r.root === rootB)?.anchorVerified, true)
})

test("evidence: on a single-checkpoint bundle a caller anchor over a foreign root still diverges", () => {
  // Unchanged behaviour: with one checkpoint there is nothing else the anchor could belong to.
  const { bundle, dailyRoot } = buildBundle()
  const iss = makeAnchorIssuer("https://anchors.example")
  const res = verifyEvidenceBundle(bundle, {
    trustedRoots: [dailyRoot],
    anchors: [iss.anchorFor("b".repeat(64))],
    anchorPolicy: { requiredAnchors: 1, trustedIssuers: [iss.issuer], quorum: "N_OF_M" },
    resolveAnchorKey: iss.resolveKey,
  })
  assert.equal(res.ok, false)
  assert.ok(
    res.failed.some((f) => f.reason.includes("DIVERGENCE")),
    `expected divergence, got ${JSON.stringify(res.failed)}`,
  )
})

test("evidence: anchors keyed to a checkpoint the bundle does not contain are flagged", () => {
  const { bundle, rootA, rootB } = buildTwoCheckpointBundle()
  const iss = makeAnchorIssuer("https://anchors.example")
  const res = verifyEvidenceBundle(bundle, {
    trustedRoots: [rootA, rootB],
    anchors: { "cp-1": [iss.anchorFor(rootA)], "cp-RENAMED": [iss.anchorFor(rootB)] },
    anchorPolicy: { requiredAnchors: 1, trustedIssuers: [iss.issuer], quorum: "N_OF_M" },
    resolveAnchorKey: iss.resolveKey,
  })
  // It still counts toward the quorum of the root it actually signs — the key only governs whether
  // it may be read as divergence — but the mismatch is reported rather than silently absorbed.
  assert.equal(res.ok, true, res.notes.concat(res.failed.map((f) => f.reason)).join("; "))
  assert.ok(
    res.notes.some((n) => /does not contain/.test(n)),
    `expected the unattributed-key note, got: ${res.notes.join("; ")}`,
  )
})

// DEWP §9.2 Extended Profile requires offline DIV signature verification alongside evidence-bundle
// verification. This path checked commitment, content, display and anchors but never looked at the
// signature material the entries carry, so an auditor running a date-range export learned nothing
// about the very proofs the product sells.

/** Build a one-entry bundle whose leaf carries real (or deliberately broken) ES256 material. */
function signedEntryBundle(opts: { breakSignature?: boolean } = {}): {
  bundle: EvidenceBundle
  dailyRoot: string
} {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" })
  const signedPayload = JSON.stringify({ type: "div-intent-verification", v: 1 })
  const signature = crypto.sign("sha256", Buffer.from(signedPayload, "utf8"), privateKey)
  // Flip one byte of the DER signature: still committed in the leaf, no longer a valid signature.
  if (opts.breakSignature) signature[signature.length - 1] ^= 0xff

  const leaf: AuditLeaf = {
    ...makeLeaf(1, 1),
    signerDid: "did:example:human:alice",
    signerPublicKey: publicKey.export({ format: "der", type: "spki" }).toString("base64"),
    signedPayload,
    signature: signature.toString("base64"),
    sigAlg: "ES256",
  }
  const lh = leafHash(leaf)
  const blockRoot = merkleRoot([lh])
  const dailyLeaves = [hashLeaf(blockRoot)]
  const dailyRoot = merkleRoot(dailyLeaves)

  return {
    dailyRoot,
    bundle: {
      kind: EVIDENCE_BUNDLE_KIND,
      version: 1,
      exportedAt: "2026-07-15T00:00:00.000Z",
      tenant: { id: "tenant-1", name: "Test Tenant" },
      range: { from: "2026-07-15T00:00:00.000Z", to: "2026-07-15T23:59:59.000Z" },
      checkpoints: [{ id: "cp-1", root: dailyRoot, anchorRef: "anchor://test/1" }],
      entries: [
        {
          event: {
            seq: "1",
            createdAt: leaf.createdAt,
            type: leaf.event,
            outcome: leaf.outcome,
            tenantSeq: "1",
            canonical: leaf,
          },
          proof: {
            seq: "1",
            leaf: lh,
            blockIndex: "0",
            blockRoot,
            blockProof: merkleProof([lh], 0),
            leafIndex: 0,
            blockLeafCount: 1,
            checkpointId: "cp-1",
            checkpointRoot: dailyRoot,
            checkpointProof: merkleProof(dailyLeaves, 0),
            checkpointLeafIndex: 0,
            checkpointLeafCount: 1,
            anchorRef: "anchor://test/1",
            anchored: true,
          },
        },
      ],
    } as EvidenceBundle,
  }
}

test("evidence: a valid embedded ES256 signature is verified, not merely carried", () => {
  const { bundle, dailyRoot } = signedEntryBundle()
  const res = verifyEvidenceBundle(bundle, { trustedRoots: [dailyRoot] })
  assert.equal(res.signatures.verified, 1)
  assert.equal(res.signatures.invalid.length, 0)
  assert.equal(res.signatures.notCheckable, 0)
  assert.equal(res.ok, true)
})

test("evidence: committed proof material that does not verify is reported, not ignored", () => {
  const { bundle, dailyRoot } = signedEntryBundle({ breakSignature: true })
  const res = verifyEvidenceBundle(bundle, { trustedRoots: [dailyRoot] })
  assert.equal(res.signatures.verified, 0)
  assert.deepEqual(
    res.signatures.invalid.map((s) => s.seq),
    ["1"],
  )
  // The signature bytes are themselves committed, so leaf binding still passes and the entry is
  // still content-verified: this is the producer having anchored a bad signature, not tampering.
  assert.equal(res.contentVerified, 1)
  assert.equal(res.failed.length, 0)
  assert.ok(
    res.notes.some((n) => /does NOT verify/.test(n)),
    `expected the invalid-signature note, got: ${res.notes.join("; ")}`,
  )
})

test("evidence: unsigned entries count as not offline-checkable, never as failures", () => {
  const { bundle, dailyRoot } = buildBundle()
  const res = verifyEvidenceBundle(bundle, { trustedRoots: [dailyRoot] })
  assert.equal(res.signatures.verified, 0)
  assert.equal(res.signatures.invalid.length, 0)
  assert.equal(res.signatures.notCheckable, res.contentVerified)
  assert.equal(res.ok, true)
})
