// The `dewpEvidenceHardening` section of verifier-parity-vectors.json: cross-language cases for the
// Sep 2026 DEWP evidence-verifier review (counter source, tenant binding, unknown profiles, witness-time
// binding to caller-trusted checkpoint records, duplicate entries, leaf-count binding, and the anchor
// algorithm registry). Its keys are its own, so the section can be regenerated or merged independently
// of the rest of the file. Every port's parity test runs it with the same harness as `bundles` and
// `evidence`, plus two options: `trustedCheckpoints` (evidence) / `trustedCheckpoint` (single proof).
import crypto from "node:crypto"
import { anchorDigest, type AnchorInput, type SignedAnchor } from "../ledger-anchor.js"
import { BUNDLE_KIND, type ProofBundle, type TrustedCheckpoint } from "../ledger-bundle.js"
import { chainHash } from "../ledger-chain.js"
import { EVIDENCE_BUNDLE_KIND, type EvidenceBundle, type EvidenceEntry } from "../ledger-evidence.js"
import { type AuditLeaf, leafHash } from "../ledger-leaf.js"
import { hashLeaf, hashPair, merkleProof, merkleRoot } from "../ledger-merkle.js"
import type { InclusionProof } from "../ledger-proof.js"
import { rekorPayloadHashFor } from "../ledger-rekor.js"

type Pair = { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject }
const spki = (p: Pair): string => p.publicKey.export({ format: "der", type: "spki" }).toString("base64")
const need = <T>(v: T | undefined, what: string): T => {
  if (v === undefined) throw new Error(`missing ${what}`)
  return v
}

export function buildDewpEvidenceHardening() {
  const anchorKey = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const rekorLog = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const SELF_ISSUER = "https://anchor-h.example"
  const REKOR_ISSUER = "https://rekor.sigstore.dev"
  const keys = [
    { id: "h-anchor-es256", issuer: SELF_ISSUER, spkiB64: spki(anchorKey) },
    { id: "h-rekor", issuer: REKOR_ISSUER, spkiB64: spki(rekorLog) },
  ]

  const A = "tenant-a"
  const B = "tenant-b"
  const T0 = "2026-09-01T00:00:00.000Z"
  const T0_SECONDS = Date.parse(T0) / 1000
  const LATE = new Date(Date.parse(T0) + 200 * 86_400_000).toISOString()
  const LATE_SECONDS = Date.parse(LATE) / 1000

  const leaf = (
    seq: number,
    tenantId: string | null,
    tenantSeq: number | null,
    event: string,
  ): AuditLeaf => ({
    seq: String(seq),
    tenantSeq: tenantSeq === null ? null : String(tenantSeq),
    createdAt: "2026-08-31T12:00:00.000Z",
    event,
    outcome: "SUCCESS",
    detail: `event ${seq}`,
    metadata: { i: seq },
    signerDid: null,
    signerPublicKey: null,
    signedPayload: null,
    signature: null,
    sigAlg: null,
    isBillable: false,
    tenantId,
    actorNodeId: null,
    subjectNodeId: null,
    edgeId: null,
    challengeId: null,
  })

  // One genuine block: tenant A tenantSeq 1..6 (seq 1..6), tenant B 1..6 (seq 7..12), and one
  // tenantless system event (seq 13, tenantId and tenantSeq null — what audit() writes with no tenant).
  // Every attack below uses genuine leaves under a genuine root; no hash is forged.
  const rows: AuditLeaf[] = [
    ...[1, 2, 3, 4, 5, 6].map((i) => leaf(i, A, i, "ACTION_APPROVED")),
    ...[1, 2, 3, 4, 5, 6].map((i) => leaf(6 + i, B, i, "LOGIN_OK")),
    leaf(13, null, null, "SYSTEM_EVENT"),
  ]
  const leaves = rows.map(leafHash)
  const blockRoot = merkleRoot(leaves)
  const daily = [hashLeaf(blockRoot)]
  const root = merkleRoot(daily)
  const cpFields = {
    root,
    seqStart: "1",
    seqEnd: "13",
    entryCount: 13,
    anchoredAt: T0,
    prevChainHash: "",
  }
  const cpChain = chainHash(cpFields)
  const checkpoint = { id: "cp-h", anchorRef: "self://h", ...cpFields, chainHash: cpChain }
  const record: TrustedCheckpoint = {
    root,
    seqStart: "1",
    seqEnd: "13",
    entryCount: 13,
    anchoredAt: T0,
    chainHash: cpChain,
  }

  const proofFor = (i: number): InclusionProof => ({
    seq: need(rows[i], "row").seq,
    leaf: need(leaves[i], "leaf"),
    blockIndex: "0",
    blockRoot,
    blockProof: merkleProof(leaves, i),
    leafIndex: i,
    blockLeafCount: leaves.length,
    checkpointId: "cp-h",
    checkpointRoot: root,
    checkpointProof: merkleProof(daily, 0),
    checkpointLeafIndex: 0,
    checkpointLeafCount: 1,
    anchorRef: "self://h",
    anchored: true,
  })
  const entry = (i: number, extra: Record<string, unknown> = {}): EvidenceEntry => {
    const r = need(rows[i], "row")
    return {
      event: {
        seq: r.seq,
        createdAt: r.createdAt,
        type: r.event,
        outcome: r.outcome,
        signerDid: null,
        sigAlg: null,
        canonical: r,
        ...extra,
      } as EvidenceEntry["event"],
      proof: proofFor(i),
    }
  }
  const redactedEntry = (i: number): EvidenceEntry => {
    const r = need(rows[i], "row")
    return {
      event: {
        seq: r.seq,
        createdAt: r.createdAt,
        type: r.event,
        outcome: r.outcome,
        tenantSeq: r.tenantSeq,
        signerDid: null,
        sigAlg: null,
        redaction: {
          mode: "COMMITMENT_ONLY",
          removedFields: ["detail", "metadata", "signedPayload", "signature", "signerPublicKey"],
          redactedAt: "2026-09-02T00:00:00.000Z",
          reason: "retention",
          commitment: { leaf: need(leaves[i], "leaf"), tenantSeq: r.tenantSeq },
        },
      },
      proof: proofFor(i),
    }
  }
  const evidenceBundle = (entries: EvidenceEntry[], over: Record<string, unknown> = {}): EvidenceBundle =>
    ({
      protocol: "DEWP",
      kind: EVIDENCE_BUNDLE_KIND,
      version: "1.0",
      profile: "trust.intyga.audit.v1",
      exportedAt: "2026-09-03T00:00:00.000Z",
      tenant: { id: A, name: "Tenant A" },
      range: { from: "2026-08-31T00:00:00.000Z", to: "2026-09-01T00:00:00.000Z" },
      tenantSequenceCommitment: { tenantId: A, firstTenantSeq: "1", lastTenantSeq: "6" },
      entries,
      checkpoints: [checkpoint],
      ...over,
    }) as EvidenceBundle
  const honestA = [0, 1, 2, 3, 4, 5].map((i) => entry(i))
  const S = 12 // the tenantless system leaf

  // ── Anchors ──────────────────────────────────────────────────────────────────────────────────
  const selfAnchor = (over: Partial<AnchorInput> = {}): SignedAnchor => {
    const base: AnchorInput = {
      dailyRoot: root,
      timestamp: T0,
      issuer: SELF_ISSUER,
      algorithm: "ES256",
      seqStart: "1",
      seqEnd: "13",
      chainHash: cpChain,
      ...over,
    }
    // Signed as ES256 whatever the label says: the registry check, not the key, must refuse a label.
    const signature = crypto
      .sign("sha256", anchorDigest(base), { key: anchorKey.privateKey, dsaEncoding: "der" })
      .toString("base64")
    return { ...base, keyId: "h-anchor-es256", signature }
  }
  const rekorAnchor = (over: Partial<AnchorInput>, integratedTime: number): SignedAnchor => {
    const base: AnchorInput = {
      dailyRoot: root,
      timestamp: T0,
      issuer: REKOR_ISSUER,
      algorithm: "ES256",
      seqStart: "1",
      seqEnd: "13",
      chainHash: cpChain,
      ...over,
    }
    const body = Buffer.from(
      JSON.stringify({
        apiVersion: "0.0.1",
        kind: "hashedrekord",
        spec: {
          data: { hash: { algorithm: "sha256", value: rekorPayloadHashFor(base) } },
          signature: { content: "c2ln", publicKey: { content: "cGs=" } },
        },
      }),
    ).toString("base64")
    const bare = {
      body,
      integratedTime,
      logID: "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
      logIndex: 7,
    }
    const set = crypto
      .sign("sha256", Buffer.from(JSON.stringify(bare)), { key: rekorLog.privateKey, dsaEncoding: "der" })
      .toString("base64")
    const evidence = Buffer.from(
      JSON.stringify({ uuid: "h", ...bare, verification: { signedEntryTimestamp: set } }),
    ).toString("base64")
    return { ...base, keyId: "h-rekor", signature: "", kind: "REKOR", evidence }
  }
  const promptRekor = rekorAnchor({}, T0_SECONDS + 120)
  const honestLateRekor = rekorAnchor({}, LATE_SECONDS)
  // The producer had the root witnessed 200 days late and signed the anchor with the late time.
  const redatedRekor = (chain: string) => rekorAnchor({ timestamp: LATE, chainHash: chain }, LATE_SECONDS)
  const rekorPolicy = { requiredAnchors: 1, trustedIssuers: [REKOR_ISSUER], quorum: "N_OF_M" }
  const selfPolicy = { requiredAnchors: 1, trustedIssuers: [SELF_ISSUER], quorum: "N_OF_M" }
  const withAnchors = (anchors: SignedAnchor[], cp: Record<string, unknown> = checkpoint) => ({
    checkpoints: [{ ...cp, anchors }],
  })

  // Re-dated checkpoint with a self-consistent chain over a made-up predecessor.
  const fakeCpFields = { ...cpFields, anchoredAt: LATE, prevChainHash: "cd".repeat(32) }
  const fakeChain = chainHash(fakeCpFields)
  const fakeCheckpoint = { id: "cp-h", anchorRef: "self://h", ...fakeCpFields, chainHash: fakeChain }
  const strippedCheckpoint = {
    id: "cp-h",
    anchorRef: "self://h",
    root,
    seqStart: "1",
    seqEnd: "13",
    anchoredAt: null,
  }

  // Interior node of a 4-leaf block presented as a redacted leaf of a 2-leaf block (DEWP §17.3).
  const small = rows.slice(0, 4).map(leafHash)
  const smallBlock = merkleRoot(small)
  const smallDaily = [hashLeaf(smallBlock)]
  const smallRoot = merkleRoot(smallDaily)
  const interior = hashPair(need(small[0], "l0"), need(small[1], "l1"))
  const shrunkProof: InclusionProof = {
    seq: "999",
    leaf: interior,
    blockIndex: "0",
    blockRoot: smallBlock,
    blockProof: [
      { siblingHash: hashPair(need(small[2], "l2"), need(small[3], "l3")), siblingPosition: "RIGHT" },
    ],
    leafIndex: 0,
    blockLeafCount: 2,
    checkpointId: "cp-small",
    checkpointRoot: smallRoot,
    checkpointProof: [],
    checkpointLeafIndex: 0,
    checkpointLeafCount: 1,
    anchorRef: null,
    anchored: true,
  }
  const smallFields = {
    root: smallRoot,
    seqStart: "1",
    seqEnd: "4",
    entryCount: 4,
    anchoredAt: T0,
    prevChainHash: "",
  }
  const smallCheckpoint = {
    id: "cp-small",
    anchorRef: null,
    ...smallFields,
    chainHash: chainHash(smallFields),
  }

  const evidence = [
    {
      name: "hardening-honest-control",
      bundle: evidenceBundle(honestA),
      options: { trustedRoots: [root] },
      ok: true,
      total: 6,
      contentVerified: 6,
    },
    {
      // A preimage whose committed tenantSeq is null has no counter (DEWP §7.2 rule 5).
      name: "tenantless-preimage-is-uncounted",
      bundle: evidenceBundle([entry(0), entry(1), entry(2), entry(S), entry(3), entry(4), entry(5)]),
      options: { trustedRoots: [root] },
      ok: true,
      contentVerified: 7,
    },
    {
      // M3: A's tenantSeq 4 deleted; the genuine tenantless leaf fills the hole through an unsigned
      // redaction counter on an entry that HAS a preimage.
      name: "redaction-counter-on-preimage-cannot-fill-gap",
      bundle: evidenceBundle([
        entry(0),
        entry(1),
        entry(2),
        entry(S, { redaction: { mode: "NONE", commitment: { leaf: leaves[S], tenantSeq: "4" } } }),
        entry(4),
        entry(5),
      ]),
      options: { trustedRoots: [root] },
      ok: false,
    },
    {
      // M4: A's 4 and 5 replaced by B's genuine, leaf-bound 4 and 5; the bundle names no tenant.
      name: "tenantless-bundle-cannot-splice-tenants",
      bundle: evidenceBundle([entry(0), entry(1), entry(2), entry(9), entry(10), entry(5)], {
        tenant: { id: null, name: null },
        tenantSequenceCommitment: undefined,
      }),
      options: { trustedRoots: [root] },
      ok: false,
    },
    {
      // L14a: no `tenant` at all but a sequence commitment — a verdict, never an exception.
      name: "absent-tenant-with-commitment-returns-verdict",
      bundle: evidenceBundle(honestA, { tenant: undefined }),
      options: { trustedRoots: [root] },
      ok: false,
    },
    {
      // M2: fabricated tenant-A content over B's genuine leaves, under a profile nobody implements.
      name: "unknown-profile-preimage-refused",
      bundle: evidenceBundle(
        [
          entry(0),
          entry(1),
          entry(2),
          ...[9, 10].map((i, k) => {
            const e = entry(i)
            const c = {
              ...need(rows[i], "row"),
              tenantId: A,
              tenantSeq: String(4 + k),
              event: "ACTION_APPROVED",
            }
            return { ...e, event: { ...e.event, type: c.event, canonical: c } }
          }),
          entry(5),
        ],
        { profile: "org.example.audit.v9" },
      ),
      options: { trustedRoots: [root] },
      ok: false,
    },
    {
      // Control: with no preimage there is nothing to bind, so commitment-only still verifies.
      name: "unknown-profile-commitment-only-verifies",
      bundle: evidenceBundle([redactedEntry(0), redactedEntry(1)], {
        profile: "org.example.audit.v9",
        tenantSequenceCommitment: { tenantId: A, firstTenantSeq: "1", lastTenantSeq: "2" },
      }),
      options: { trustedRoots: [root] },
      ok: true,
      commitmentOnly: 2,
    },
    {
      // L13: one genuine event may appear once.
      name: "duplicate-entry-refused",
      bundle: evidenceBundle([
        entry(0),
        entry(1),
        entry(2),
        entry(S),
        entry(S),
        entry(3),
        entry(4),
        entry(5),
      ]),
      options: { trustedRoots: [root] },
      ok: false,
    },
    {
      // L13: an interior node cannot pass as a leaf of a smaller block than its checkpoint commits.
      name: "shrunk-leaf-count-refused",
      bundle: evidenceBundle(
        [
          {
            event: {
              seq: "999",
              createdAt: T0,
              type: "USER_DELETED",
              outcome: "SUCCESS",
              tenantSeq: "1",
              signerDid: null,
              sigAlg: null,
              redaction: { mode: "COMMITMENT_ONLY", commitment: { leaf: interior, tenantSeq: "1" } },
            },
            proof: shrunkProof,
          },
        ],
        {
          checkpoints: [smallCheckpoint],
          tenantSequenceCommitment: { tenantId: A, firstTenantSeq: "1", lastTenantSeq: "1" },
        },
      ),
      options: { trustedRoots: [smallRoot] },
      ok: false,
    },
    {
      // M5 control: a late witness under honest checkpoint fields is refused by the time bound.
      name: "late-rekor-with-honest-checkpoint-refused",
      bundle: evidenceBundle(honestA, withAnchors([honestLateRekor])),
      policy: rekorPolicy,
      options: { trustedRoots: [root], rekorKeyId: "h-rekor" },
      ok: false,
    },
    {
      // M5: the producer strips anchoredAt and the chain fields and re-dates the anchor.
      name: "stripped-checkpoint-chain-not-anchored",
      bundle: evidenceBundle(honestA, withAnchors([redatedRekor("ab".repeat(32))], strippedCheckpoint)),
      policy: rekorPolicy,
      options: { trustedRoots: [root], rekorKeyId: "h-rekor" },
      ok: false,
    },
    {
      // M5: the bundle re-dates the checkpoint with a self-consistent chain; the caller's own
      // chain-verified record says otherwise.
      name: "redated-checkpoint-contradicts-trusted-record",
      bundle: evidenceBundle(honestA, withAnchors([redatedRekor(fakeChain)], fakeCheckpoint)),
      policy: rekorPolicy,
      options: { trustedRoots: [root], trustedCheckpoints: [record], rekorKeyId: "h-rekor" },
      ok: false,
    },
    {
      // Control: a prompt witness held to the caller's record verifies, and the record's root is trusted.
      name: "trusted-record-prompt-rekor-verifies",
      bundle: evidenceBundle(honestA, withAnchors([promptRekor])),
      policy: rekorPolicy,
      options: { trustedCheckpoints: [record], rekorKeyId: "h-rekor" },
      ok: true,
      contentVerified: 6,
    },
    {
      // Control: the caller's record supplies what the bundle's checkpoint omits.
      name: "trusted-record-fills-stripped-checkpoint",
      bundle: evidenceBundle(honestA, withAnchors([promptRekor], strippedCheckpoint)),
      policy: rekorPolicy,
      options: { trustedCheckpoints: [record], rekorKeyId: "h-rekor" },
      ok: true,
    },
    {
      // L14b: a label outside the §5.2 registry never verifies, even under the right key.
      name: "unregistered-anchor-algorithm-refused",
      bundle: evidenceBundle(honestA, withAnchors([selfAnchor({ algorithm: "RSA-OAEP" as never })])),
      policy: selfPolicy,
      options: { trustedRoots: [root] },
      ok: false,
    },
    {
      name: "unregistered-rekor-anchor-algorithm-refused",
      bundle: evidenceBundle(
        honestA,
        withAnchors([rekorAnchor({ algorithm: "RSA-OAEP" as never }, T0_SECONDS + 120)]),
      ),
      policy: rekorPolicy,
      options: { trustedRoots: [root], trustedCheckpoints: [record], rekorKeyId: "h-rekor" },
      ok: false,
    },
    {
      name: "registered-self-anchor-verifies",
      bundle: evidenceBundle(honestA, withAnchors([selfAnchor()])),
      policy: selfPolicy,
      options: { trustedRoots: [root] },
      ok: true,
    },
  ]

  // ── Single inclusion proofs ─────────────────────────────────────────────────────────────────
  const r0 = need(rows[0], "row 0")
  const proofBundle = (anchors: SignedAnchor[]): ProofBundle => ({
    protocol: "DEWP",
    kind: BUNDLE_KIND,
    version: "1.0",
    profile: "trust.intyga.audit.v1",
    exportedAt: "2026-09-03T00:00:00.000Z",
    event: {
      seq: r0.seq,
      createdAt: r0.createdAt,
      type: r0.event,
      outcome: r0.outcome,
      detail: r0.detail,
      actorDid: null,
      subjectDid: null,
      signerDid: null,
      signature: null,
      sigAlg: null,
      canonical: r0,
    },
    proof: proofFor(0),
    anchors,
  })
  const bundles = [
    {
      // M5: no checkpoint record ⇒ the witness can only be compared with the anchor's own
      // (producer-chosen) timestamp, which here was re-dated to the late witness time.
      name: "single-proof-rekor-without-trusted-checkpoint-refused",
      bundle: proofBundle([redatedRekor(cpChain)]),
      policy: rekorPolicy,
      options: { trustedRoot: root, rekorKeyId: "h-rekor" },
      ok: false,
      properties: { anchorVerified: false },
      witnessTimes: { [REKOR_ISSUER]: LATE_SECONDS },
    },
    {
      name: "single-proof-rekor-with-trusted-checkpoint-verifies",
      bundle: proofBundle([promptRekor]),
      policy: rekorPolicy,
      options: { trustedCheckpoint: record, rekorKeyId: "h-rekor" },
      ok: true,
      verificationLevel: "FULLY_VERIFIED",
      properties: { anchorVerified: true },
      witnessTimes: { [REKOR_ISSUER]: T0_SECONDS + 120 },
    },
    {
      name: "single-proof-redated-rekor-vs-trusted-checkpoint-refused",
      bundle: proofBundle([redatedRekor(cpChain)]),
      policy: rekorPolicy,
      options: { trustedRoot: root, trustedCheckpoint: record, rekorKeyId: "h-rekor" },
      ok: false,
      properties: { anchorVerified: false },
    },
    {
      name: "single-proof-trusted-checkpoint-root-conflict-refused",
      bundle: proofBundle([promptRekor]),
      policy: rekorPolicy,
      options: { trustedRoot: smallRoot, trustedCheckpoint: record, rekorKeyId: "h-rekor" },
      ok: false,
    },
    {
      // SELF anchors carry no independent time (§5.3), so no record is needed for them.
      name: "single-proof-self-anchor-needs-no-record",
      bundle: proofBundle([selfAnchor()]),
      policy: selfPolicy,
      options: { trustedRoot: root },
      ok: true,
      properties: { anchorVerified: true },
    },
    {
      name: "single-proof-unregistered-anchor-algorithm-refused",
      bundle: proofBundle([selfAnchor({ algorithm: "RSA-OAEP" as never })]),
      policy: selfPolicy,
      options: { trustedRoot: root },
      ok: false,
      properties: { anchorVerified: false },
    },
    {
      // L13: the record's entry count exposes the shrunk leaf count.
      name: "single-proof-shrunk-leaf-count-refused",
      bundle: {
        protocol: "DEWP",
        kind: BUNDLE_KIND,
        version: "1.0",
        profile: "trust.intyga.audit.v1",
        exportedAt: "2026-09-03T00:00:00.000Z",
        event: {
          seq: "999",
          createdAt: T0,
          type: "USER_DELETED",
          outcome: "SUCCESS",
          detail: null,
          actorDid: null,
          subjectDid: null,
          signerDid: null,
          signature: null,
          sigAlg: null,
        },
        proof: shrunkProof,
      } satisfies ProofBundle,
      options: {
        trustedRoot: smallRoot,
        trustedCheckpoint: {
          root: smallRoot,
          seqStart: "1",
          seqEnd: "4",
          entryCount: 4,
          anchoredAt: T0,
          chainHash: smallCheckpoint.chainHash,
        },
      },
      ok: false,
      properties: { commitmentVerified: false },
    },
  ]

  return {
    note:
      "DEWP evidence-verifier hardening (Sep 2026 review). Keys are this section's own. Harness as for " +
      "`bundles`/`evidence`, except: a case's `policy` applies only when present; evidence options may carry " +
      "`trustedCheckpoints` (caller-trusted checkpoint records) and `rekorKeyId`; single-proof options may " +
      "carry `trustedCheckpoint`.",
    keys,
    bundles: { cases: bundles },
    evidence: { cases: evidence },
  }
}
