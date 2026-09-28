// External anchors are bound to TIME and POSITION (DEWP §5.2/§5.3).
//
// The regression these pin (review 2026-09-26, T1-6): a party able to write the ledger database could
// rewrite a committed event, recompute the block/checkpoint roots, anchor the new root to Rekor under a
// throwaway key months later, and every export then verified `anchorVerified: true` — nothing compared
// the witness's own time with the checkpoint's claimed time, the anchored preimage named no position,
// and the Rekor check ignored who submitted the entry.
import assert from "node:assert/strict"
import crypto from "node:crypto"
import { readFileSync } from "node:fs"
import { test } from "node:test"
import { fileURLToPath } from "node:url"
import { canonicalOfflineIntentPayload, verificationCode, verifyApprovalReceipt } from "./index.js"
import {
  type AnchorInput,
  anchorDigest,
  DEFAULT_MAX_ANCHOR_LAG_SECONDS,
  type SignedAnchor,
  signAnchor,
  verifyAnchorQuorum,
} from "./ledger-anchor.js"
import { verifyBundle } from "./ledger-bundle.js"
import { chainHash } from "./ledger-chain.js"
import { EVIDENCE_BUNDLE_KIND, type EvidenceBundle, verifyEvidenceBundle } from "./ledger-evidence.js"
import { type AuditLeaf, leafHash } from "./ledger-leaf.js"
import { hashLeaf, merkleProof, merkleRoot } from "./ledger-merkle.js"
import { rekorPayloadHashFor } from "./ledger-rekor.js"
import type { Rfc3161Trust } from "./ledger-rfc3161.js"

const rekorKey = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }) // stands in for Sigstore's pinned key
const REKOR = "https://rekor.sigstore.dev"
const rekorSpki = rekorKey.publicKey.export({ format: "der", type: "spki" }).toString("base64")
const producer = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
const producerSpki = producer.publicKey.export({ format: "der", type: "spki" }).toString("base64")
const CLAIMED = "2026-06-01T23:59:00.000Z" // the checkpoint's own commit time
const CLAIMED_S = Date.parse(CLAIMED) / 1000

function leaf(outcome: string): AuditLeaf {
  return {
    seq: "1",
    tenantSeq: "1",
    createdAt: "2026-06-01T10:00:00.000Z",
    event: "AUTHZ_DENIED",
    outcome,
    detail: "wire 5,000,000 EUR",
    metadata: null,
    signerDid: null,
    signerPublicKey: null,
    signedPayload: null,
    signature: null,
    sigAlg: null,
    isBillable: false,
    tenantId: "tenant-1",
    actorNodeId: "agent",
    subjectNodeId: "owner",
    edgeId: null,
    challengeId: null,
  }
}

/** A hashedrekord Rekor would log, with its SET. `submitter` signs the anchor digest (Rekor checks it). */
function rekorEvidence(
  anchor: AnchorInput,
  integratedTime: number,
  submitter?: crypto.KeyPairKeyObjectResult,
): string {
  const signature = submitter
    ? {
        content: crypto
          .sign("sha256", anchorDigest(anchor), { key: submitter.privateKey, dsaEncoding: "der" })
          .toString("base64"),
        publicKey: {
          content: Buffer.from(
            submitter.publicKey.export({ format: "pem", type: "spki" }).toString(),
          ).toString("base64"),
        },
      }
    : { content: "c2ln", publicKey: { content: "cGs=" } }
  const body = Buffer.from(
    JSON.stringify({
      apiVersion: "0.0.1",
      kind: "hashedrekord",
      spec: { data: { hash: { algorithm: "sha256", value: rekorPayloadHashFor(anchor) } }, signature },
    }),
  ).toString("base64")
  const logID = "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
  const logIndex = 999_999
  const set = crypto
    .sign("sha256", Buffer.from(JSON.stringify({ body, integratedTime, logID, logIndex })), {
      key: rekorKey.privateKey,
      dsaEncoding: "der",
    })
    .toString("base64")
  return Buffer.from(
    JSON.stringify({ body, logID, logIndex, integratedTime, verification: { signedEntryTimestamp: set } }),
  ).toString("base64")
}

/** The rewritten ledger: a genuine-looking one-entry checkpoint with its chain fields. */
function rewrittenExport(witnessedAt: number, submitter?: crypto.KeyPairKeyObjectResult) {
  const rewritten = leaf("SUCCESS") // the committed row said FAILURE
  const lh = leafHash(rewritten)
  const blockRoot = merkleRoot([lh])
  const dailyRoot = merkleRoot([hashLeaf(blockRoot)])
  const cpChainHash = chainHash({
    prevChainHash: "",
    root: dailyRoot,
    seqStart: "1",
    seqEnd: "1",
    entryCount: 1,
    anchoredAt: CLAIMED,
  })
  const input: AnchorInput = {
    dailyRoot,
    timestamp: CLAIMED,
    issuer: REKOR,
    algorithm: "ES256",
    seqStart: "1",
    seqEnd: "1",
    chainHash: cpChainHash,
  }
  const anchor: SignedAnchor = {
    ...input,
    keyId: "rekor",
    signature: "",
    kind: "REKOR",
    evidence: rekorEvidence(input, witnessedAt, submitter),
  }
  const bundle: EvidenceBundle = {
    kind: EVIDENCE_BUNDLE_KIND,
    version: "1.0",
    protocol: "DEWP",
    exportedAt: "2026-09-26T12:05:00.000Z",
    tenant: { id: "tenant-1", name: "T" },
    range: { from: "2026-06-01T00:00:00.000Z", to: "2026-06-02T00:00:00.000Z" },
    checkpoints: [
      {
        id: "cp-1",
        root: dailyRoot,
        anchorRef: "self:k:x",
        anchoredAt: CLAIMED,
        seqStart: "1",
        seqEnd: "1",
        entryCount: 1,
        prevChainHash: "",
        chainHash: cpChainHash,
        anchors: [anchor],
      },
    ],
    entries: [
      {
        event: {
          seq: "1",
          createdAt: rewritten.createdAt,
          type: rewritten.event,
          outcome: rewritten.outcome,
          tenantSeq: "1",
          signerDid: null,
          sigAlg: null,
          canonical: rewritten,
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
          checkpointProof: merkleProof([hashLeaf(blockRoot)], 0),
          checkpointLeafIndex: 0,
          checkpointLeafCount: 1,
          anchorRef: "self:k:x",
          anchored: true,
        },
      },
    ],
  }
  return { bundle, dailyRoot, anchor, input }
}

const policy = { requiredAnchors: 1, trustedIssuers: [REKOR], quorum: "N_OF_M" as const }
const pinnedLog = { rekor: rekorSpki, rekorIssuer: REKOR }

test("a root re-anchored 117 days after its claimed commit no longer reaches quorum (review repro)", () => {
  const witnessedAt = Date.parse("2026-09-26T12:00:00Z") / 1000
  const { bundle, dailyRoot } = rewrittenExport(witnessedAt)
  const v = verifyEvidenceBundle(bundle, {
    anchorPolicy: policy,
    externalKeys: pinnedLog,
    // The relying party even pins the root it read from the export: still refused.
    trustedRoots: [dailyRoot],
  })
  assert.equal(v.ok, false)
  assert.equal(v.roots[0]?.anchorVerified, false)
  // The witness time is surfaced — the reader can see WHEN Rekor actually saw this root.
  assert.deepEqual(v.roots[0]?.witnessTimes, { [REKOR]: witnessedAt })
  assert.ok(
    v.notes.some((n) => /witnessed \d+s from its checkpoint time/.test(n)),
    `the verdict must say why: ${v.notes.join("; ")}`,
  )
})

test("control: the same anchor witnessed minutes after the checkpoint counts", () => {
  const { bundle, dailyRoot } = rewrittenExport(CLAIMED_S + 180)
  const v = verifyEvidenceBundle(bundle, {
    anchorPolicy: policy,
    externalKeys: pinnedLog,
    trustedRoots: [dailyRoot],
  })
  assert.equal(v.ok, true, v.notes.concat(v.failed.map((f) => f.reason)).join("; "))
  assert.deepEqual(v.roots[0]?.witnessTimes, { [REKOR]: CLAIMED_S + 180 })
})

test("the lag bound is caller policy: a longer window admits a late witness, the default is a day", () => {
  assert.equal(DEFAULT_MAX_ANCHOR_LAG_SECONDS, 86_400)
  const late = CLAIMED_S + 2 * 86_400
  const { bundle, dailyRoot } = rewrittenExport(late)
  const strict = verifyEvidenceBundle(bundle, {
    anchorPolicy: policy,
    externalKeys: pinnedLog,
    trustedRoots: [dailyRoot],
  })
  assert.equal(strict.ok, false)
  const relaxed = verifyEvidenceBundle(bundle, {
    anchorPolicy: { ...policy, maxAnchorLagSeconds: 3 * 86_400 },
    externalKeys: pinnedLog,
    trustedRoots: [dailyRoot],
  })
  assert.equal(relaxed.ok, true, relaxed.notes.join("; "))
})

test("a witness time well BEFORE the checkpoint's claimed time does not count either", () => {
  const { bundle, dailyRoot } = rewrittenExport(CLAIMED_S - 3600)
  const v = verifyEvidenceBundle(bundle, {
    anchorPolicy: policy,
    externalKeys: pinnedLog,
    trustedRoots: [dailyRoot],
  })
  assert.equal(v.ok, false)
  // Within the clock-skew tolerance is fine.
  const skewed = rewrittenExport(CLAIMED_S - 60)
  const w = verifyEvidenceBundle(skewed.bundle, {
    anchorPolicy: policy,
    externalKeys: pinnedLog,
    trustedRoots: [skewed.dailyRoot],
  })
  assert.equal(w.ok, true, w.notes.join("; "))
})

test("re-dating the checkpoint breaks its chain hash, and an anchor must match the checkpoint's time", () => {
  const { bundle, dailyRoot } = rewrittenExport(Date.parse("2026-09-26T12:00:00Z") / 1000)
  const cp = bundle.checkpoints[0]
  assert.ok(cp)
  // The obvious dodge: move the checkpoint's claimed time next to the late witness. The chain hash
  // commits to anchoredAt, and the anchor's signed timestamp no longer matches the checkpoint.
  cp.anchoredAt = "2026-09-26T11:59:00.000Z"
  const v = verifyEvidenceBundle(bundle, {
    anchorPolicy: policy,
    externalKeys: pinnedLog,
    trustedRoots: [dailyRoot],
  })
  assert.equal(v.ok, false)
  assert.ok(
    v.failed.some((f) => /chainHash does not recompute/.test(f.reason)),
    JSON.stringify(v.failed),
  )
  assert.equal(v.roots[0]?.anchorVerified, false)
})

test("an anchor signed for another seq range does not count for this checkpoint", () => {
  const { bundle, dailyRoot, input } = rewrittenExport(CLAIMED_S + 60)
  const cp = bundle.checkpoints[0]
  assert.ok(cp)
  const otherRange = { ...input, seqEnd: "2" }
  cp.anchors = [
    {
      ...otherRange,
      keyId: "rekor",
      signature: "",
      kind: "REKOR",
      evidence: rekorEvidence(otherRange, CLAIMED_S + 60),
    },
  ]
  const v = verifyEvidenceBundle(bundle, {
    anchorPolicy: policy,
    externalKeys: pinnedLog,
    trustedRoots: [dailyRoot],
  })
  assert.equal(v.ok, false)
  assert.ok(
    v.notes.some((n) => /binds a different checkpoint seqEnd/.test(n)),
    v.notes.join("; "),
  )
})

test("a pinned producer submission key refuses a Rekor entry logged under a throwaway key", () => {
  const throwaway = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const pinned = { ...pinnedLog, rekorSubmitterKeys: [producerSpki] }
  const byThrowaway = rewrittenExport(CLAIMED_S + 60, throwaway)
  const refused = verifyEvidenceBundle(byThrowaway.bundle, {
    anchorPolicy: policy,
    externalKeys: pinned,
    trustedRoots: [byThrowaway.dailyRoot],
  })
  assert.equal(refused.ok, false)

  const byProducer = rewrittenExport(CLAIMED_S + 60, producer)
  const accepted = verifyEvidenceBundle(byProducer.bundle, {
    anchorPolicy: policy,
    externalKeys: pinned,
    trustedRoots: [byProducer.dailyRoot],
  })
  assert.equal(accepted.ok, true, accepted.notes.join("; "))

  // Unpinned (the default), the log's own SET is all that is checked — which is why pinning exists.
  const unpinned = verifyEvidenceBundle(byThrowaway.bundle, {
    anchorPolicy: policy,
    externalKeys: pinnedLog,
    trustedRoots: [byThrowaway.dailyRoot],
  })
  assert.equal(unpinned.ok, true)
})

test("a single proof bundle reports witness times and applies the same bound", () => {
  const { bundle, dailyRoot, anchor } = rewrittenExport(CLAIMED_S + 60 + 200 * 86_400)
  const entry = bundle.entries[0]
  assert.ok(entry?.event.canonical)
  const proofBundle = {
    kind: "dewp.audit.inclusion-proof" as const,
    version: "1.0",
    protocol: "DEWP",
    exportedAt: bundle.exportedAt,
    event: {
      seq: "1",
      createdAt: entry.event.createdAt,
      type: entry.event.type,
      outcome: entry.event.outcome,
      detail: entry.event.canonical.detail,
      actorDid: null,
      subjectDid: null,
      signerDid: null,
      signature: null,
      sigAlg: null,
      canonical: entry.event.canonical,
    },
    proof: entry.proof,
    anchors: [anchor],
  }
  const v = verifyBundle(proofBundle, {
    trustedRoot: dailyRoot,
    anchorPolicy: policy,
    externalKeys: pinnedLog,
  })
  assert.equal(v.properties.anchorVerified, false)
  assert.equal(v.ok, false)
  assert.equal(v.witnessTimes[REKOR], CLAIMED_S + 60 + 200 * 86_400)
  assert.equal(v.rootSource, "caller-supplied")
})

test("an RFC 3161 genTime is held to the same bound as a Rekor integratedTime", () => {
  const fixtures = JSON.parse(
    readFileSync(
      fileURLToPath(new URL("../vectors/rfc3161-vectors.json", import.meta.url)),
      "utf8",
    ),
  ) as { cases: { name: string; anchor: SignedAnchor; trust: Rfc3161Trust | null; expected: boolean }[] }
  const valid = fixtures.cases.find((c) => c.name === "valid-unchecked")
  assert.ok(valid?.trust)
  const tsaPolicy = { requiredAnchors: 1, trustedIssuers: [valid.anchor.issuer], quorum: "N_OF_M" as const }
  const externalKeys = { rfc3161: { [valid.anchor.issuer]: valid.trust } }
  const inTime = verifyAnchorQuorum([valid.anchor], valid.anchor.dailyRoot, tsaPolicy, () => null, {
    externalKeys,
  })
  assert.equal(inTime.ok, true, inTime.note)
  const genTime = inTime.witnessTimes[valid.anchor.issuer]
  assert.equal(typeof genTime, "number")
  // A bound the genuine token cannot meet: proves genTime, not the producer's timestamp, is compared.
  const tooStrict = verifyAnchorQuorum(
    [valid.anchor],
    valid.anchor.dailyRoot,
    { ...tsaPolicy, maxAnchorLagSeconds: -600 },
    () => null,
    { externalKeys },
  )
  assert.equal(tooStrict.ok, false)
  assert.deepEqual(tooStrict.witnessTimes, inTime.witnessTimes)
})

test("SELF anchors carry no witness time and are not lag-checked, but must match the checkpoint", () => {
  const { dailyRoot, input } = rewrittenExport(CLAIMED_S)
  const self = { ...input, issuer: "https://intyga.example", keyId: "k1", signature: "" }
  self.signature = signAnchor(self, producer.privateKey)
  const selfPolicy = { requiredAnchors: 1, trustedIssuers: [self.issuer], quorum: "N_OF_M" as const }
  const ok = verifyAnchorQuorum([self], dailyRoot, selfPolicy, () => producer.publicKey, {
    checkpoint: { seqStart: "1", seqEnd: "1", chainHash: input.chainHash, anchoredAt: CLAIMED },
  })
  assert.equal(ok.ok, true)
  assert.deepEqual(ok.witnessTimes, {})
  const wrongChain = verifyAnchorQuorum([self], dailyRoot, selfPolicy, () => producer.publicKey, {
    checkpoint: { chainHash: "d".repeat(64) },
  })
  assert.equal(wrongChain.ok, false)
})

// ─── allowedAaguids offline (review 2026-09-26, T2-16 / PK-4) ────────────────
// The offline path refused `requireHardwareKey` but a non-empty model allowlist with
// requireHardwareKey=false was satisfied by a bare software key: a key with no model at all.
function offlineProof(requirement: Record<string, unknown>) {
  const key = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const spki = key.publicKey.export({ format: "der", type: "spki" }).toString("base64")
  const now = new Date()
  const nonce = `off_${crypto.randomUUID()}`
  const requester = { did: "did:intyga:service:oncall", attestation: null }
  const canonical = canonicalOfflineIntentPayload({
    target: "payroll",
    actionType: "payroll.release",
    display: "Release payroll",
    params: { batch: "2026-09" },
    requester,
    requirement: requirement as never,
    nonce,
    challengedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 10 * 60_000).toISOString(),
  })
  const sig = crypto
    .sign("sha256", Buffer.from(canonical, "utf8"), { key: key.privateKey, dsaEncoding: "ieee-p1363" })
    .toString("base64")
  return verifyApprovalReceipt(
    {
      canonicalPayload: canonical,
      target: "payroll",
      actionType: "payroll.release",
      actionDescription: "Release payroll",
      params: { batch: "2026-09" },
      signatures: [{ signerDid: "did:intyga:alice", signerPublicKey: spki, signature: sig, sigAlg: "ES256" }],
      requester,
      verificationCode: verificationCode(canonical),
    },
    {
      target: "payroll",
      actionType: "payroll.release",
      params: { batch: "2026-09" },
      nonce,
      approvers: {
        dids: ["did:intyga:alice"],
        resolveKey: (d: string) => (d === "did:intyga:alice" ? [spki] : null),
      },
    },
    { allowOffline: true },
  )
}
const base = { requiredApprovals: 1, requesterCannotApprove: false, signerClass: "human" }

test("offline: a model allowlist is refused exactly like requireHardwareKey", () => {
  const allowlisted = offlineProof({
    ...base,
    requireHardwareKey: false,
    allowedAaguids: ["cb69481e-8ff7-4039-93ec-0a2729a154a8"],
  })
  assert.equal(allowlisted.ok, false, "a model allowlist was satisfied by a key with no model at all")
  assert.match(allowlisted.reason ?? "", /cannot be produced offline/)
  assert.equal(offlineProof({ ...base, requireHardwareKey: true, allowedAaguids: [] }).ok, false)
  // Control: no hardware policy at all, and the same bare key verifies.
  const plain = offlineProof({ ...base, requireHardwareKey: false, allowedAaguids: [] })
  assert.equal(plain.ok, true, plain.reason)
})
