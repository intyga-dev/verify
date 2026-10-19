// The `executionEvidence` section of verifier-parity-vectors.json: cross-language cases for DEWP §4.7
// (execution evidence, version 1.1). Self-contained — its keys are embedded as SPKI in each case's
// policies, and the anchored-time cases carry their Rekor-witnessed anchor in the bundle's checkpoint
// with the log key inline (`options.rekorSpki`) — so it regenerates and merges independently of every
// other section (`generate-execution-evidence-vectors.ts`). Every port runs `cases` through its
// evidence-bundle verifier, `proofs` through its single-proof verifier, and `statements` / `builder`
// through its statement parser and builder.
import crypto from "node:crypto"
import type { AnchorInput, SignedAnchor } from "../ledger-anchor.js"
import { BUNDLE_KIND, type ProofBundle } from "../ledger-bundle.js"
import { chainHash } from "../ledger-chain.js"
import { EVIDENCE_BUNDLE_KIND, type EvidenceBundle, type EvidenceEntry } from "../ledger-evidence.js"
import {
  canonicalExecutionEvidenceStatement,
  executionPayloadSha256,
  type SourceContinuity,
} from "../ledger-execution.js"
import { type AuditLeaf, leafHash } from "../ledger-leaf.js"
import { hashLeaf, merkleProof, merkleRoot } from "../ledger-merkle.js"
import type { InclusionProof } from "../ledger-proof.js"
import { rekorPayloadHashFor } from "../ledger-rekor.js"
import { stableStringify } from "../index.js"

type Pair = { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject }
const newKey = (): Pair => crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
const spki = (p: Pair): string => p.publicKey.export({ format: "der", type: "spki" }).toString("base64")
const sign = (p: Pair, bytes: string): string =>
  crypto
    .sign("sha256", Buffer.from(bytes, "utf8"), { key: p.privateKey, dsaEncoding: "ieee-p1363" })
    .toString("base64")

const TENANT = "tenant-x"
const APPROVER = "did:example:human:approver"
const S1 = "did:example:relay-7"
const S2 = "did:example:meter-3"
const N1 = "4f6c1c9e-1b8a-4e2f-9d3a-7c2b5e8f0a1d"
const N2 = "8a1e2d3c-4b5a-4f6e-9d8c-7b6a5f4e3d2c"
const T_APPROVED = "2026-10-05T13:59:00.000Z"
const T_DISPATCH = "2026-10-05T14:00:00.000Z"
const T_DEADLINE = "2026-10-05T14:10:00.000Z"
const T_SAMPLED = "2026-10-05T14:02:09.500Z"
const T_OBSERVED = "2026-10-05T14:02:11.000Z"
const NOW_BEFORE = "2026-10-05T14:05:00.000Z"
const NOW_AFTER = "2026-10-05T14:30:00.000Z"
/** The checkpoint's claimed time, and the witness that places it: two minutes later (DEWP §5.3). */
const CP_ANCHORED_AT = "2026-10-05T23:59:00.000Z"
const WITNESSED_AT = "2026-10-06T00:01:00.000Z"
const REKOR_ISSUER = "https://rekor.sigstore.dev"

/** The §4.7.4 findings a case pins when present; the parity runners assert each key that is given. */
export interface Findings {
  lateContradicted?: string[]
  untrustedContradicted?: string[]
  dispatchConflicts?: string[]
  windowCapped?: Record<string, boolean>
  sources?: Record<string, SourceContinuity>
}

export function buildExecutionEvidenceVectors() {
  const approverKey = newKey()
  const s1Key = newKey()
  const s2Key = newKey()
  const strangerKey = newKey()
  const rekorLog = newKey()

  const approvalPayload = (nonce: string): string =>
    stableStringify({
      actionType: "breaker:open",
      display: "Open breaker Q7 at substation North",
      evidence: null,
      nonce,
      params: { breaker: "Q7" },
      target: "substation-north",
      type: "div-intent-verification",
      v: 1,
    })
  const payloadHash = (nonce: string) => executionPayloadSha256(approvalPayload(nonce))

  // Leaves get seq/tenantSeq by position when a case's bundle is assembled.
  type Row = Omit<AuditLeaf, "seq" | "tenantSeq">
  const base = (event: string, outcome: string, createdAt: string): Row => ({
    createdAt,
    event,
    outcome,
    detail: null,
    metadata: null,
    signerDid: null,
    signerPublicKey: null,
    signedPayload: null,
    signature: null,
    sigAlg: null,
    isBillable: false,
    tenantId: TENANT,
    actorNodeId: null,
    subjectNodeId: null,
    edgeId: null,
    challengeId: "challenge-1",
  })
  const approval = (nonce = N1): Row => {
    const payload = approvalPayload(nonce)
    return {
      ...base("AUTHZ_APPROVED", "SUCCESS", T_APPROVED),
      signerDid: APPROVER,
      signerPublicKey: spki(approverKey),
      signedPayload: payload,
      signature: sign(approverKey, payload),
      sigAlg: "ES256",
    }
  }
  /** An approval leaf over an arbitrary payload string (for parse-boundary cases). */
  const approvalOver = (payload: string): Row => ({
    ...base("AUTHZ_APPROVED", "SUCCESS", T_APPROVED),
    signerDid: APPROVER,
    signerPublicKey: spki(approverKey),
    signedPayload: payload,
    signature: sign(approverKey, payload),
    sigAlg: "ES256",
  })
  const dispatch = (
    over: { nonce?: string; deadline?: string; hash?: string; createdAt?: string; metadata?: unknown } = {},
  ): Row => ({
    ...base("EXECUTION_DISPATCHED", "PENDING", over.createdAt ?? T_DISPATCH),
    metadata:
      over.metadata !== undefined
        ? over.metadata
        : {
            evidenceDeadline: over.deadline ?? T_DEADLINE,
            nonce: over.nonce ?? N1,
            payloadSha256: over.hash ?? payloadHash(over.nonce ?? N1),
          },
  })
  interface EvidenceOver {
    nonce?: string
    hash?: string
    source?: string
    signerDid?: string
    key?: Pair
    publicKey?: Pair
    verdict?: "confirmed" | "contradicted"
    /** When the statement was produced. A given `observedAt` is also the sample time unless `sampledAt` says otherwise. */
    observedAt?: string
    sampledAt?: string
    sequence?: number
    observation?: Record<string, unknown>
    event?: string
    outcome?: string
    bytes?: string
    sigAlg?: string
    signOver?: string
  }
  const evidence = (o: EvidenceOver = {}): Row => {
    const verdict = o.verdict ?? "confirmed"
    const source = o.source ?? S1
    const key = o.key ?? s1Key
    const observedAt = o.observedAt ?? T_OBSERVED
    const bytes =
      o.bytes ??
      canonicalExecutionEvidenceStatement({
        nonce: o.nonce ?? N1,
        payloadSha256: o.hash ?? payloadHash(o.nonce ?? N1),
        source,
        verdict,
        observedAt,
        sampledAt: o.sampledAt ?? (o.observedAt ? observedAt : T_SAMPLED),
        sequence: o.sequence ?? 1,
        observation: o.observation ?? { breaker: "open", currentA: 0, previousCurrentA: 412 },
      })
    return {
      ...base(
        o.event ?? (verdict === "confirmed" ? "EXECUTION_CONFIRMED" : "EXECUTION_CONTRADICTED"),
        o.outcome ?? (verdict === "confirmed" ? "SUCCESS" : "FAILURE"),
        "2026-10-05T14:03:00.000Z",
      ),
      signerDid: o.signerDid ?? source,
      signerPublicKey: spki(o.publicKey ?? key),
      signedPayload: bytes,
      signature: sign(key, o.signOver ?? bytes),
      sigAlg: o.sigAlg ?? "ES256",
    }
  }
  const consumed = (): Row => ({
    ...base("ACTION_CONSUMED", "SUCCESS", "2026-10-05T13:59:30.000Z"),
    metadata: { nonce: N1 },
  })

  /**
   * A Rekor hashedrekord entry over the checkpoint's anchor digest, witnessed at `integratedTime`, as
   * the hardening vectors build it. The log key is pinned per case (`options.rekorSpki`).
   */
  const rekorAnchor = (cp: AnchorInput, integratedTime: number): SignedAnchor => {
    const body = Buffer.from(
      JSON.stringify({
        apiVersion: "0.0.1",
        kind: "hashedrekord",
        spec: {
          data: { hash: { algorithm: "sha256", value: rekorPayloadHashFor(cp) } },
          signature: { content: "c2ln", publicKey: { content: "cGs=" } },
        },
      }),
    ).toString("base64")
    const bare = {
      body,
      integratedTime,
      logID: "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
      logIndex: 11,
    }
    const set = crypto
      .sign("sha256", Buffer.from(JSON.stringify(bare)), { key: rekorLog.privateKey, dsaEncoding: "der" })
      .toString("base64")
    const evidence = Buffer.from(
      JSON.stringify({ uuid: "e", ...bare, verification: { signedEntryTimestamp: set } }),
    ).toString("base64")
    return { ...cp, keyId: "rekor", signature: "", kind: "REKOR", evidence }
  }

  /**
   * A one-block, one-checkpoint evidence bundle over `rows`; `redact` lists positions to purge.
   * `witnessedAt` attaches a Rekor anchor over the checkpoint, witnessed at that instant (§4.7.5).
   */
  const bundleOf = (
    rows: Row[],
    redact: number[] = [],
    witnessedAt?: string,
    duplicateCheckpoint = false,
  ) => {
    const leaves: AuditLeaf[] = rows.map((r, i) => ({ ...r, seq: String(100 + i), tenantSeq: String(i + 1) }))
    const hashes = leaves.map(leafHash)
    const blockRoot = merkleRoot(hashes)
    const daily = [hashLeaf(blockRoot)]
    const root = merkleRoot(daily)
    const cpFields = {
      root,
      seqStart: "100",
      seqEnd: String(99 + leaves.length),
      entryCount: leaves.length,
      anchoredAt: CP_ANCHORED_AT,
      prevChainHash: "",
    }
    const cpChain = chainHash(cpFields)
    const anchors = witnessedAt
      ? [
          rekorAnchor(
            {
              dailyRoot: root,
              timestamp: CP_ANCHORED_AT,
              issuer: REKOR_ISSUER,
              algorithm: "ES256",
              seqStart: cpFields.seqStart,
              seqEnd: cpFields.seqEnd,
              chainHash: cpChain,
            },
            Date.parse(witnessedAt) / 1000,
          ),
        ]
      : undefined
    const proof = (i: number): InclusionProof => ({
      seq: String(100 + i),
      leaf: hashes[i] as string,
      blockIndex: "0",
      blockRoot,
      blockProof: merkleProof(hashes, i),
      leafIndex: i,
      blockLeafCount: hashes.length,
      checkpointId: "cp-x",
      checkpointRoot: root,
      checkpointProof: merkleProof(daily, 0),
      checkpointLeafIndex: 0,
      checkpointLeafCount: 1,
      anchorRef: "self://x",
      anchored: true,
    })
    const entries: EvidenceEntry[] = leaves.map((leaf, i) =>
      redact.includes(i)
        ? {
            event: {
              seq: leaf.seq,
              createdAt: leaf.createdAt,
              type: leaf.event,
              outcome: leaf.outcome,
              tenantSeq: leaf.tenantSeq,
              signerDid: null,
              sigAlg: null,
              redaction: {
                mode: "COMMITMENT_ONLY",
                removedFields: ["detail", "metadata", "signedPayload", "signature", "signerPublicKey"],
                redactedAt: "2026-10-06T00:00:00.000Z",
                reason: "retention",
                commitment: { leaf: hashes[i] as string, tenantSeq: leaf.tenantSeq },
              },
            },
            proof: proof(i),
          }
        : {
            event: {
              seq: leaf.seq,
              createdAt: leaf.createdAt,
              type: leaf.event,
              outcome: leaf.outcome,
              signerDid: leaf.signerDid,
              sigAlg: leaf.sigAlg,
              canonical: leaf,
            } as EvidenceEntry["event"],
            proof: proof(i),
          },
    )
    const bundle = {
      protocol: "DEWP",
      kind: EVIDENCE_BUNDLE_KIND,
      version: "1.0",
      profile: "trust.intyga.audit.v1",
      exportedAt: "2026-10-06T00:00:00.000Z",
      tenant: { id: TENANT, name: "Tenant X" },
      range: { from: "2026-10-05T00:00:00.000Z", to: "2026-10-06T00:00:00.000Z" },
      tenantSequenceCommitment: {
        tenantId: TENANT,
        firstTenantSeq: "1",
        lastTenantSeq: String(leaves.length),
      },
      entries,
      checkpoints: [
        {
          id: "cp-x",
          anchorRef: "self://x",
          ...cpFields,
          chainHash: cpChain,
          ...(anchors ? { anchors } : {}),
        },
      ],
    } as unknown as EvidenceBundle
    // A second entry for the same root, claiming a wider range and carrying no chain fields or
    // anchors: what a bearer would add to make the first checkpoint's witness time cover more.
    if (duplicateCheckpoint)
      (bundle as unknown as { checkpoints: unknown[] }).checkpoints.push({
        id: "cp-x-copy",
        anchorRef: "self://x",
        root,
        seqStart: "100",
        seqEnd: "999999999",
        anchoredAt: CP_ANCHORED_AT,
      })
    return { bundle, root, leaves, proof }
  }

  type TrustEntry = string | { key: string; notBefore?: string; notAfter?: string }
  const trust = (map: Record<string, Pair[]>) =>
    Object.fromEntries(Object.entries(map).map(([did, keys]) => [did, keys.map(spki)]))
  const policyS1 = { trustedSources: trust({ [S1]: [s1Key] }) }
  const policyBoth = { trustedSources: trust({ [S1]: [s1Key], [S2]: [s2Key] }) }
  const boundedS1 = (interval: { notBefore?: string; notAfter?: string }) => ({
    trustedSources: { [S1]: [{ key: spki(s1Key), ...interval }] as TrustEntry[] },
  })
  const rekorPolicy = { requiredAnchors: 1, trustedIssuers: [REKOR_ISSUER], quorum: "N_OF_M" }

  interface CaseInput {
    name: string
    rows: Row[]
    redact?: number[]
    /** A Rekor witness over the checkpoint at this instant; implies the Rekor anchor policy. */
    witnessedAt?: string
    /** List the checkpoint's root a second time with a wider range (§4.7.5: refused). */
    duplicateCheckpoint?: boolean
    evidencePolicy?: { trustedSources: Record<string, TrustEntry[]> } | null
    signaturePolicy?: { trustedSigners: Record<string, string[]> }
    now: string
    skewSeconds?: number
    maxWindowSeconds?: number
    requireExecutionConfirmed?: boolean
    ok?: boolean
    byNonce: Record<string, string>
    checks: Array<{ index: number; status: string; trusted: boolean }>
    signatures?: Array<{ index: number; status: string; trusted: boolean }>
    findings?: Findings
  }
  const make = (c: CaseInput) => {
    const { bundle, root } = bundleOf(c.rows, c.redact, c.witnessedAt, c.duplicateCheckpoint ?? false)
    const seqOf = (i: number) => String(100 + i)
    return {
      name: c.name,
      bundle,
      ...(c.witnessedAt ? { policy: rekorPolicy } : {}),
      options: {
        trustedRoots: [root],
        ...(c.evidencePolicy === null ? {} : { evidencePolicy: c.evidencePolicy ?? policyS1 }),
        ...(c.signaturePolicy ? { signaturePolicy: c.signaturePolicy } : {}),
        now: c.now,
        ...(c.skewSeconds !== undefined ? { skewSeconds: c.skewSeconds } : {}),
        ...(c.maxWindowSeconds !== undefined ? { maxWindowSeconds: c.maxWindowSeconds } : {}),
        ...(c.requireExecutionConfirmed ? { requireExecutionConfirmed: true } : {}),
        ...(c.witnessedAt ? { rekorSpki: spki(rekorLog) } : {}),
      },
      ok: c.ok ?? true,
      execution: {
        byNonce: c.byNonce,
        checks: c.checks.map((k) => ({ seq: seqOf(k.index), status: k.status, trusted: k.trusted })),
        ...(c.findings ? { findings: c.findings } : {}),
      },
      ...(c.signatures
        ? {
            signatures: c.signatures.map((k) => ({
              seq: seqOf(k.index),
              status: k.status,
              trusted: k.trusted,
            })),
          }
        : {}),
    }
  }
  const happy = () => [approval(), consumed(), dispatch(), evidence()]
  const big = "x".repeat(16_400)
  const noGaps = (first: number, last: number): SourceContinuity => ({ first, last, gaps: [], divergent: [] })

  const cases: Array<ReturnType<typeof make>> = [
    make({
      name: "confirmed",
      rows: happy(),
      now: NOW_AFTER,
      byNonce: { [N1]: "confirmed" },
      checks: [{ index: 3, status: "verified", trusted: true }],
      findings: {
        lateContradicted: [],
        dispatchConflicts: [],
        windowCapped: { [N1]: false },
        sources: { [S1]: noGaps(1, 1) },
      },
    }),
    make({
      name: "confirmed-required",
      rows: happy(),
      now: NOW_AFTER,
      requireExecutionConfirmed: true,
      byNonce: { [N1]: "confirmed" },
      checks: [{ index: 3, status: "verified", trusted: true }],
    }),
    make({
      name: "no-policy-embedded-key-is-not-trust",
      rows: happy(),
      evidencePolicy: null,
      now: NOW_BEFORE,
      byNonce: { [N1]: "pending" },
      checks: [{ index: 3, status: "verified", trusted: false }],
    }),
    make({
      name: "no-policy-deadline-passed",
      rows: happy(),
      evidencePolicy: null,
      now: NOW_AFTER,
      requireExecutionConfirmed: true,
      ok: false,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 3, status: "verified", trusted: false }],
    }),
    make({
      name: "contradicted-beats-confirmed",
      rows: [...happy(), evidence({ source: S2, key: s2Key, verdict: "contradicted" })],
      evidencePolicy: policyBoth,
      now: NOW_AFTER,
      byNonce: { [N1]: "contradicted" },
      checks: [
        { index: 3, status: "verified", trusted: true },
        { index: 4, status: "verified", trusted: true },
      ],
      findings: { sources: { [S2]: noGaps(1, 1), [S1]: noGaps(1, 1) } },
    }),
    make({
      name: "untrusted-contradiction-does-not-count",
      rows: [...happy(), evidence({ source: S2, key: s2Key, verdict: "contradicted" })],
      now: NOW_AFTER,
      byNonce: { [N1]: "confirmed" },
      checks: [
        { index: 3, status: "verified", trusted: true },
        { index: 4, status: "not_checked", trusted: false },
      ],
      // A source with no provisioned key is not attributed a counter either.
      findings: { sources: { [S1]: noGaps(1, 1) } },
    }),
    make({
      name: "contradicted-required-fails",
      rows: [approval(), dispatch(), evidence({ verdict: "contradicted" })],
      now: NOW_AFTER,
      requireExecutionConfirmed: true,
      ok: false,
      byNonce: { [N1]: "contradicted" },
      checks: [{ index: 2, status: "verified", trusted: true }],
    }),
    make({
      name: "late-observation-is-stale",
      rows: [approval(), dispatch(), evidence({ observedAt: "2026-10-05T14:20:00.000Z" })],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "stale", trusted: true }],
      // A late CONFIRMED is stale and nothing more; only a late contradiction is an alert.
      findings: { lateContradicted: [] },
    }),
    make({
      name: "observation-before-dispatch-is-stale",
      rows: [approval(), dispatch(), evidence({ observedAt: "2026-10-05T13:50:00.000Z" })],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "stale", trusted: true }],
    }),
    make({
      name: "within-default-skew",
      rows: [approval(), dispatch(), evidence({ observedAt: "2026-10-05T13:59:30.000Z" })],
      now: NOW_AFTER,
      byNonce: { [N1]: "confirmed" },
      checks: [{ index: 2, status: "verified", trusted: true }],
    }),
    make({
      name: "beyond-default-skew",
      rows: [approval(), dispatch(), evidence({ observedAt: "2026-10-05T13:59:29.999Z" })],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "stale", trusted: true }],
    }),
    make({
      name: "caller-skew-narrows-window",
      rows: [approval(), dispatch(), evidence({ observedAt: "2026-10-05T13:59:45.000Z" })],
      now: NOW_AFTER,
      skewSeconds: 10,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "stale", trusted: true }],
    }),
    make({
      name: "caller-skew-widens-window",
      rows: [approval(), dispatch(), evidence({ observedAt: "2026-10-05T13:56:00.000Z" })],
      now: NOW_AFTER,
      skewSeconds: 300,
      byNonce: { [N1]: "confirmed" },
      checks: [{ index: 2, status: "verified", trusted: true }],
    }),
    make({
      name: "observed-at-deadline-counts",
      rows: [approval(), dispatch(), evidence({ observedAt: T_DEADLINE })],
      now: NOW_AFTER,
      byNonce: { [N1]: "confirmed" },
      checks: [{ index: 2, status: "verified", trusted: true }],
    }),
    make({
      name: "window-is-evaluated-on-sampled-at",
      // Reported inside the window, over a measurement taken long before dispatch.
      rows: [
        approval(),
        dispatch(),
        evidence({ observedAt: T_OBSERVED, sampledAt: "2026-10-05T13:30:00.000Z" }),
      ],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "stale", trusted: true }],
    }),
    make({
      name: "sample-after-report-is-malformed",
      rows: [
        approval(),
        dispatch(),
        evidence({
          // Built without the builder: it refuses this shape, which is the point (rule 11).
          bytes: `{"approval":{"nonce":"${N1}","payloadSha256":"${payloadHash(N1)}"},"observation":{},"observedAt":"${T_OBSERVED}","sampledAt":"2026-10-05T14:02:11.001Z","sequence":1,"source":"${S1}","type":"dewp-execution-evidence","v":1,"verdict":"confirmed"}`,
        }),
      ],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "invalid", trusted: false }],
    }),
    make({
      name: "dispatch-only-pending",
      rows: [approval(), dispatch()],
      now: NOW_BEFORE,
      byNonce: { [N1]: "pending" },
      checks: [],
    }),
    make({
      name: "dispatch-only-at-deadline-still-pending",
      rows: [approval(), dispatch()],
      now: T_DEADLINE,
      byNonce: { [N1]: "pending" },
      checks: [],
    }),
    make({
      name: "dispatch-only-unconfirmed",
      rows: [approval(), dispatch()],
      now: NOW_AFTER,
      requireExecutionConfirmed: true,
      ok: false,
      byNonce: { [N1]: "unconfirmed" },
      checks: [],
    }),
    make({
      // §4.7.4: a silent approval is reported, so a require-all policy cannot pass over it.
      name: "silent-approval-required-fails",
      rows: [approval(), consumed()],
      now: NOW_AFTER,
      requireExecutionConfirmed: true,
      ok: false,
      byNonce: { [N1]: "not_reported" },
      checks: [],
    }),
    make({
      name: "silent-approval-not-reported",
      rows: [approval(), consumed()],
      now: NOW_AFTER,
      byNonce: { [N1]: "not_reported" },
      checks: [],
    }),
    make({
      name: "no-approval-no-nonce-required-fails",
      rows: [consumed()],
      now: NOW_AFTER,
      requireExecutionConfirmed: true,
      ok: false,
      byNonce: {},
      checks: [],
    }),
    make({
      name: "evidence-without-dispatch",
      rows: [approval(), evidence()],
      now: NOW_AFTER,
      byNonce: { [N1]: "not_reported" },
      checks: [{ index: 1, status: "unbound", trusted: true }],
    }),
    make({
      name: "statement-hash-differs-from-dispatch",
      rows: [approval(), dispatch(), evidence({ hash: "0".repeat(64) })],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "unbound", trusted: true }],
    }),
    make({
      name: "no-approval-with-that-hash",
      rows: [approval(), dispatch({ hash: "1".repeat(64) }), evidence({ hash: "1".repeat(64) })],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "unbound", trusted: true }],
    }),
    make({
      name: "approval-record-missing",
      rows: [dispatch(), evidence()],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 1, status: "unbound", trusted: true }],
    }),
    make({
      name: "approval-for-other-nonce-does-not-bind",
      rows: [approval(N2), dispatch(), evidence()],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed", [N2]: "not_reported" },
      checks: [{ index: 2, status: "unbound", trusted: true }],
    }),
    make({
      name: "source-key-mismatch",
      rows: [approval(), dispatch(), evidence({ key: strangerKey, publicKey: strangerKey })],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "invalid", trusted: false }],
      // A record whose signature does not verify is never attributed to the source's counter.
      findings: { sources: {} },
    }),
    make({
      name: "source-not-provisioned",
      rows: [approval(), dispatch(), evidence({ source: S2, key: s2Key })],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "not_checked", trusted: false }],
    }),
    make({
      name: "source-differs-from-signer",
      rows: [approval(), dispatch(), evidence({ signerDid: S2 })],
      now: NOW_AFTER,
      evidencePolicy: policyBoth,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "invalid", trusted: false }],
    }),
    make({
      name: "event-contradicts-verdict",
      rows: [
        approval(),
        dispatch(),
        evidence({ verdict: "contradicted", event: "EXECUTION_CONFIRMED", outcome: "SUCCESS" }),
      ],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "invalid", trusted: false }],
    }),
    make({
      name: "statement-under-another-event-is-still-evidence",
      rows: [approval(), dispatch(), evidence({ event: "TEST_EVENT" })],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "invalid", trusted: false }],
    }),
    make({
      name: "evidence-event-with-approval-payload-is-invalid",
      rows: [approval(), dispatch(), { ...approval(), event: "EXECUTION_CONFIRMED" }],
      now: NOW_AFTER,
      evidencePolicy: { trustedSources: trust({ [APPROVER]: [approverKey] }) },
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "invalid", trusted: false }],
    }),
    make({
      name: "non-canonical-whitespace",
      rows: [
        approval(),
        dispatch(),
        evidence({
          bytes: `{"approval": {"nonce":"${N1}","payloadSha256":"${payloadHash(N1)}"},"observation":{},"observedAt":"${T_OBSERVED}","sampledAt":"${T_SAMPLED}","sequence":1,"source":"${S1}","type":"dewp-execution-evidence","v":1,"verdict":"confirmed"}`,
        }),
      ],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "invalid", trusted: false }],
    }),
    make({
      name: "duplicate-member-names",
      rows: [
        approval(),
        dispatch(),
        evidence({
          bytes: `{"approval":{"nonce":"${N1}","payloadSha256":"${payloadHash(N1)}"},"observation":{},"observedAt":"${T_OBSERVED}","sampledAt":"${T_SAMPLED}","sequence":1,"source":"${S1}","type":"dewp-execution-evidence","v":1,"verdict":"contradicted","verdict":"confirmed"}`,
        }),
      ],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "invalid", trusted: false }],
    }),
    make({
      name: "non-portable-number",
      rows: [
        approval(),
        dispatch(),
        evidence({
          bytes: `{"approval":{"nonce":"${N1}","payloadSha256":"${payloadHash(N1)}"},"observation":{"joules":10000000000000000},"observedAt":"${T_OBSERVED}","sampledAt":"${T_SAMPLED}","sequence":1,"source":"${S1}","type":"dewp-execution-evidence","v":1,"verdict":"confirmed"}`,
        }),
      ],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "invalid", trusted: false }],
    }),
    make({
      name: "oversized-statement",
      rows: [
        approval(),
        dispatch(),
        evidence({
          bytes: stableStringify({
            approval: { nonce: N1, payloadSha256: payloadHash(N1) },
            observation: { note: big },
            observedAt: T_OBSERVED,
            sampledAt: T_SAMPLED,
            sequence: 1,
            source: S1,
            type: "dewp-execution-evidence",
            v: 1,
            verdict: "confirmed",
          }),
        }),
      ],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "invalid", trusted: false }],
    }),
    make({
      name: "impossible-calendar-date",
      rows: [
        approval(),
        dispatch(),
        evidence({
          bytes: `{"approval":{"nonce":"${N1}","payloadSha256":"${payloadHash(N1)}"},"observation":{},"observedAt":"2026-02-30T14:02:11.000Z","sampledAt":"2026-02-28T14:02:11.000Z","sequence":1,"source":"${S1}","type":"dewp-execution-evidence","v":1,"verdict":"confirmed"}`,
        }),
      ],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "invalid", trusted: false }],
    }),
    make({
      name: "unknown-verdict",
      rows: [
        approval(),
        dispatch(),
        evidence({
          event: "EXECUTION_CONFIRMED",
          bytes: `{"approval":{"nonce":"${N1}","payloadSha256":"${payloadHash(N1)}"},"observation":{},"observedAt":"${T_OBSERVED}","sampledAt":"${T_SAMPLED}","sequence":1,"source":"${S1}","type":"dewp-execution-evidence","v":1,"verdict":"unknown"}`,
        }),
      ],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "invalid", trusted: false }],
    }),
    make({
      name: "extra-member",
      rows: [
        approval(),
        dispatch(),
        evidence({
          bytes: `{"approval":{"nonce":"${N1}","payloadSha256":"${payloadHash(N1)}"},"extra":1,"observation":{},"observedAt":"${T_OBSERVED}","sampledAt":"${T_SAMPLED}","sequence":1,"source":"${S1}","type":"dewp-execution-evidence","v":1,"verdict":"confirmed"}`,
        }),
      ],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "invalid", trusted: false }],
    }),
    make({
      // The seven-member 1.1 draft shape: refused now that `sampledAt` and `sequence` are required.
      name: "draft-seven-member-statement-is-malformed",
      rows: [
        approval(),
        dispatch(),
        evidence({
          bytes: `{"approval":{"nonce":"${N1}","payloadSha256":"${payloadHash(N1)}"},"observation":{},"observedAt":"${T_OBSERVED}","source":"${S1}","type":"dewp-execution-evidence","v":1,"verdict":"confirmed"}`,
        }),
      ],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "invalid", trusted: false }],
    }),
    make({
      name: "webauthn-label-refused",
      rows: [approval(), dispatch(), evidence({ sigAlg: "WEBAUTHN" })],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "invalid", trusted: false }],
    }),
    make({
      name: "signature-over-other-bytes",
      rows: [approval(), dispatch(), evidence({ signOver: "something else" })],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "invalid", trusted: false }],
    }),
    make({
      // Two Dispatch Records that agree are a retry: the first governs, and it is no conflict.
      name: "first-agreeing-dispatch-governs",
      rows: [
        approval(),
        dispatch(),
        dispatch({ deadline: "2026-10-05T15:00:00.000Z", createdAt: "2026-10-05T14:01:00.000Z" }),
        evidence({ observedAt: "2026-10-05T14:20:00.000Z" }),
      ],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 3, status: "stale", trusted: true }],
      findings: { dispatchConflicts: [] },
    }),
    make({
      // §4.7.3 step 5: an early Dispatch Record with another hash cannot unbind the genuine statement.
      name: "early-conflicting-dispatch-cannot-unbind",
      rows: [
        approval(),
        dispatch({ hash: "0".repeat(64) }),
        dispatch({ createdAt: "2026-10-05T14:00:30.000Z" }),
        evidence({ verdict: "contradicted" }),
      ],
      now: NOW_AFTER,
      byNonce: { [N1]: "contradicted" },
      checks: [{ index: 3, status: "verified", trusted: true }],
      findings: { dispatchConflicts: [N1] },
    }),
    make({
      // The conflict is a finding on its own: it fails the strict policy even when confirmed.
      name: "dispatch-conflict-fails-required",
      rows: [
        approval(),
        dispatch({ hash: "0".repeat(64) }),
        dispatch({ createdAt: "2026-10-05T14:00:30.000Z" }),
        evidence(),
      ],
      now: NOW_AFTER,
      requireExecutionConfirmed: true,
      ok: false,
      byNonce: { [N1]: "confirmed" },
      checks: [{ index: 3, status: "verified", trusted: true }],
      findings: { dispatchConflicts: [N1] },
    }),
    make({
      // A conflicting dispatch with no bound statement still names the nonce; the first record governs.
      name: "dispatch-conflict-without-evidence",
      rows: [
        approval(),
        dispatch({ hash: "0".repeat(64) }),
        dispatch({ createdAt: "2026-10-05T14:00:30.000Z" }),
      ],
      now: NOW_BEFORE,
      byNonce: { [N1]: "pending" },
      checks: [],
      findings: { dispatchConflicts: [N1] },
    }),
    make({
      // §4.7.3 step 6: a year-long window is cut to the default 24 h …
      name: "far-deadline-cut-to-default-window-pending",
      rows: [approval(), dispatch({ deadline: "2027-10-05T14:00:00.000Z" })],
      now: "2026-10-05T17:00:00.000Z",
      byNonce: { [N1]: "pending" },
      checks: [],
      findings: { windowCapped: { [N1]: true } },
    }),
    make({
      // … so a day later the nonce is unconfirmed, whatever the record claims.
      name: "far-deadline-cut-to-default-window-unconfirmed",
      rows: [approval(), dispatch({ deadline: "2027-10-05T14:00:00.000Z" })],
      now: "2026-10-06T14:00:00.001Z",
      byNonce: { [N1]: "unconfirmed" },
      checks: [],
      findings: { windowCapped: { [N1]: true } },
    }),
    make({
      name: "deadline-at-default-window-is-not-capped",
      rows: [approval(), dispatch({ deadline: "2026-10-06T14:00:00.000Z" })],
      now: "2026-10-06T14:00:00.000Z",
      byNonce: { [N1]: "pending" },
      checks: [],
      findings: { windowCapped: { [N1]: false } },
    }),
    make({
      // A caller may tighten the window; a statement sampled past it is late.
      name: "caller-window-cap-makes-statement-late",
      rows: [approval(), dispatch(), evidence({ observedAt: "2026-10-05T14:02:00.000Z" })],
      now: NOW_AFTER,
      maxWindowSeconds: 60,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "stale", trusted: true }],
      findings: { windowCapped: { [N1]: true } },
    }),
    make({
      // §4.7.4: a trusted contradicted statement sampled after the deadline is reported as its own alert.
      name: "late-contradiction-is-an-alert",
      rows: [
        approval(),
        dispatch(),
        evidence({ verdict: "contradicted", observedAt: "2026-10-05T14:20:00.000Z" }),
      ],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "stale", trusted: true }],
      findings: { lateContradicted: [N1] },
    }),
    make({
      name: "untrusted-late-contradiction-is-not-an-alert",
      rows: [
        approval(),
        dispatch(),
        evidence({ verdict: "contradicted", observedAt: "2026-10-05T14:20:00.000Z" }),
      ],
      evidencePolicy: null,
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "stale", trusted: false }],
      findings: { lateContradicted: [] },
    }),
    make({
      name: "early-contradiction-is-not-an-alert",
      rows: [
        approval(),
        dispatch(),
        evidence({ verdict: "contradicted", observedAt: "2026-10-05T13:00:00.000Z" }),
      ],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "stale", trusted: true }],
      findings: { lateContradicted: [] },
    }),
    make({
      // Late and unbound: the alert needs a bound statement.
      name: "unbound-late-contradiction-is-not-an-alert",
      rows: [
        approval(),
        dispatch({ hash: "0".repeat(64) }),
        evidence({ verdict: "contradicted", observedAt: "2026-10-05T14:20:00.000Z" }),
      ],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "unbound", trusted: true }],
      findings: { lateContradicted: [] },
    }),
    make({
      // §4.7.3 source continuity: statements 1, 3 and 4 — 2 is missing.
      name: "source-gap-is-reported",
      rows: [
        approval(),
        dispatch(),
        evidence({ sequence: 1 }),
        evidence({ sequence: 3, observation: { a: 1 } }),
        evidence({ sequence: 4, observation: { a: 2 } }),
      ],
      now: NOW_AFTER,
      byNonce: { [N1]: "confirmed" },
      checks: [
        { index: 2, status: "verified", trusted: true },
        { index: 3, status: "verified", trusted: true },
        { index: 4, status: "verified", trusted: true },
      ],
      findings: { sources: { [S1]: { first: 1, last: 4, gaps: [[2, 2]], divergent: [] } } },
    }),
    make({
      name: "source-gap-fails-required",
      rows: [
        approval(),
        dispatch(),
        evidence({ sequence: 1 }),
        evidence({ sequence: 3, observation: { a: 1 } }),
      ],
      now: NOW_AFTER,
      requireExecutionConfirmed: true,
      ok: false,
      byNonce: { [N1]: "confirmed" },
      checks: [
        { index: 2, status: "verified", trusted: true },
        { index: 3, status: "verified", trusted: true },
      ],
      findings: { sources: { [S1]: { first: 1, last: 3, gaps: [[2, 2]], divergent: [] } } },
    }),
    make({
      // Two statements under one counter value with different bytes: a divergence.
      name: "source-divergence-is-reported",
      rows: [
        approval(),
        dispatch(),
        evidence({ sequence: 5 }),
        evidence({ sequence: 5, observation: { a: 1 } }),
      ],
      now: NOW_AFTER,
      requireExecutionConfirmed: true,
      ok: false,
      byNonce: { [N1]: "confirmed" },
      checks: [
        { index: 2, status: "verified", trusted: true },
        { index: 3, status: "verified", trusted: true },
      ],
      findings: { sources: { [S1]: { first: 5, last: 5, gaps: [], divergent: [5] } } },
    }),
    make({
      // Gaps are ranges, and a statement for another approval still advances the source's counter.
      name: "source-gap-ranges-across-approvals",
      rows: [
        approval(),
        approval(N2),
        dispatch(),
        dispatch({ nonce: N2 }),
        evidence({ sequence: 2 }),
        evidence({ nonce: N2, sequence: 6 }),
        evidence({ sequence: 9, observation: { a: 1 } }),
      ],
      now: NOW_AFTER,
      byNonce: { [N1]: "confirmed", [N2]: "confirmed" },
      checks: [
        { index: 4, status: "verified", trusted: true },
        { index: 5, status: "verified", trusted: true },
        { index: 6, status: "verified", trusted: true },
      ],
      findings: {
        sources: {
          [S1]: {
            first: 2,
            last: 9,
            gaps: [
              [3, 5],
              [7, 8],
            ],
            divergent: [],
          },
        },
      },
    }),
    make({
      // Statements whose binding failed still count toward the source's continuity (step 4 passed).
      name: "unbound-statement-still-advances-counter",
      rows: [
        approval(),
        dispatch(),
        evidence({ sequence: 1 }),
        evidence({ sequence: 2, hash: "0".repeat(64) }),
      ],
      now: NOW_AFTER,
      byNonce: { [N1]: "confirmed" },
      checks: [
        { index: 2, status: "verified", trusted: true },
        { index: 3, status: "unbound", trusted: true },
      ],
      findings: { sources: { [S1]: noGaps(1, 2) } },
    }),
    make({
      // §4.7.5: a bounded key with no counting anchor cannot be placed in time — it fails closed.
      name: "bounded-key-without-anchored-time-is-untrusted",
      rows: [approval(), dispatch(), evidence()],
      evidencePolicy: boundedS1({ notAfter: "2026-10-07T00:00:00.000Z" }),
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "verified", trusted: false }],
    }),
    make({
      // Witnessed two minutes after the checkpoint's claimed time, inside the key's interval.
      name: "bounded-key-valid-at-anchored-time",
      rows: [approval(), dispatch(), evidence()],
      witnessedAt: WITNESSED_AT,
      evidencePolicy: boundedS1({
        notBefore: "2026-10-01T00:00:00.000Z",
        notAfter: "2026-10-07T00:00:00.000Z",
      }),
      now: NOW_AFTER,
      byNonce: { [N1]: "confirmed" },
      checks: [{ index: 2, status: "verified", trusted: true }],
      // The §4.6.1 signature report uses the same anchored time, so the two agree.
      signatures: [
        { index: 0, status: "verified", trusted: false },
        { index: 1, status: "not_applicable", trusted: false },
        { index: 2, status: "verified", trusted: true },
      ],
    }),
    make({
      // The key was revoked at 18:00; the record's anchored time is 00:01 the next day. The statement's
      // own 14:02 timestamps say nothing about when it was committed and are never consulted.
      name: "bounded-key-revoked-before-anchored-time",
      rows: [approval(), dispatch(), evidence()],
      witnessedAt: WITNESSED_AT,
      evidencePolicy: boundedS1({ notAfter: "2026-10-05T18:00:00.000Z" }),
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "verified", trusted: false }],
      signatures: [
        { index: 0, status: "verified", trusted: false },
        { index: 1, status: "not_applicable", trusted: false },
        { index: 2, status: "verified", trusted: false },
      ],
    }),
    make({
      // §4.7.5: a root listed twice with different fields is refused — a copy claiming a wider range
      // would otherwise lend the first checkpoint's witness time to records it never covered.
      name: "root-listed-twice-with-different-fields-is-refused",
      rows: [approval(), dispatch(), evidence()],
      witnessedAt: WITNESSED_AT,
      duplicateCheckpoint: true,
      evidencePolicy: boundedS1({ notAfter: "2026-10-05T18:00:00.000Z" }),
      now: NOW_AFTER,
      ok: false,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "verified", trusted: false }],
    }),
    make({
      // A bound that is not a timestamp string fails closed: the key verifies, trusts nothing.
      name: "numeric-bound-is-not-trust",
      rows: [approval(), dispatch(), evidence()],
      witnessedAt: WITNESSED_AT,
      evidencePolicy: {
        trustedSources: { [S1]: [{ key: spki(s1Key), notAfter: 1754006400000 } as unknown as TrustEntry] },
      },
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "verified", trusted: false }],
    }),
    make({
      // A misspelt bound is an unknown member, never "no bound".
      name: "unknown-member-in-key-entry-is-not-trust",
      rows: [approval(), dispatch(), evidence()],
      witnessedAt: WITNESSED_AT,
      evidencePolicy: {
        trustedSources: {
          [S1]: [{ key: spki(s1Key), notafter: "2026-10-05T18:00:00.000Z" } as unknown as TrustEntry],
        },
      },
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "verified", trusted: false }],
    }),
    make({
      // §4.7.4: a late contradiction fails the require-all policy even beside an in-window confirmation.
      name: "late-contradiction-fails-required",
      rows: [
        approval(),
        dispatch(),
        evidence(),
        evidence({ verdict: "contradicted", observedAt: "2026-10-05T14:20:00.000Z", sequence: 2 }),
      ],
      now: NOW_AFTER,
      requireExecutionConfirmed: true,
      ok: false,
      byNonce: { [N1]: "confirmed" },
      checks: [
        { index: 2, status: "verified", trusted: true },
        { index: 3, status: "stale", trusted: true },
      ],
      findings: { lateContradicted: [N1] },
    }),
    make({
      // A contradiction under a bounded key the bundle cannot place in time: not counted, never silent.
      name: "untrusted-contradiction-is-a-finding",
      rows: [approval(), dispatch(), evidence({ verdict: "contradicted" })],
      evidencePolicy: boundedS1({ notAfter: "2026-10-07T00:00:00.000Z" }),
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "verified", trusted: false }],
      findings: { untrustedContradicted: [N1], lateContradicted: [] },
    }),
    make({
      name: "untrusted-contradiction-fails-required",
      rows: [
        approval(),
        dispatch(),
        evidence({ source: S2, key: s2Key }),
        evidence({ verdict: "contradicted" }),
      ],
      evidencePolicy: {
        trustedSources: {
          [S2]: [spki(s2Key)],
          [S1]: [{ key: spki(s1Key), notAfter: "2026-10-07T00:00:00.000Z" }],
        },
      },
      now: NOW_AFTER,
      requireExecutionConfirmed: true,
      ok: false,
      byNonce: { [N1]: "confirmed" },
      checks: [
        { index: 2, status: "verified", trusted: true },
        { index: 3, status: "verified", trusted: false },
      ],
      findings: { untrustedContradicted: [N1] },
    }),
    make({
      // No policy means no provisioned key: an embedded-key contradiction is not this finding.
      name: "embedded-key-contradiction-is-not-the-finding",
      rows: [approval(), dispatch(), evidence({ verdict: "contradicted" })],
      evidencePolicy: null,
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "verified", trusted: false }],
      findings: { untrustedContradicted: [] },
    }),
    ...(["unanchored", "expired", "malformed"] as const).map((trust) =>
      make({
        // Combining lateness and missing key trust must not silence a provisioned contradiction.
        name: `late-untrusted-contradiction-${trust}-fails-required`,
        rows: [
          approval(),
          dispatch(),
          evidence({ source: S2, key: s2Key }),
          evidence({ verdict: "contradicted", observedAt: "2026-10-05T14:20:00.000Z" }),
        ],
        witnessedAt: trust === "unanchored" ? undefined : WITNESSED_AT,
        evidencePolicy: {
          trustedSources: {
            [S2]: [spki(s2Key)],
            [S1]: [
              trust === "malformed"
                ? ({ key: spki(s1Key), notafter: "2026-10-07T00:00:00.000Z" } as unknown as TrustEntry)
                : {
                    key: spki(s1Key),
                    notAfter: trust === "expired" ? "2026-10-05T18:00:00.000Z" : "2026-10-07T00:00:00.000Z",
                  },
            ],
          },
        },
        now: NOW_AFTER,
        requireExecutionConfirmed: true,
        ok: false,
        byNonce: { [N1]: "confirmed" },
        checks: [
          { index: 2, status: "verified", trusted: true },
          { index: 3, status: "stale", trusted: false },
        ],
        findings: { untrustedContradicted: [N1], lateContradicted: [] },
      }),
    ),
    ...(["early", "start", "deadline", "unbound", "embedded", "unprovisioned"] as const).map((kind) =>
      make({
        name: `untrusted-contradiction-boundary-${kind}`,
        rows: [
          approval(),
          dispatch(),
          evidence({
            verdict: "contradicted",
            observedAt:
              kind === "early"
                ? "2026-10-05T13:59:29.999Z"
                : kind === "start"
                  ? "2026-10-05T13:59:30.000Z"
                  : kind === "deadline"
                    ? T_DEADLINE
                    : "2026-10-05T14:20:00.000Z",
            hash: kind === "unbound" ? "0".repeat(64) : undefined,
          }),
        ],
        evidencePolicy:
          kind === "embedded"
            ? null
            : kind === "unprovisioned"
              ? { trustedSources: { [S2]: [spki(s2Key)] } }
              : boundedS1({ notAfter: "2026-10-07T00:00:00.000Z" }),
        now: NOW_AFTER,
        byNonce: { [N1]: "unconfirmed" },
        checks: [
          {
            index: 2,
            status:
              kind === "unprovisioned"
                ? "not_checked"
                : kind === "unbound"
                  ? "unbound"
                  : kind === "start" || kind === "deadline"
                    ? "verified"
                    : "stale",
            trusted: false,
          },
        ],
        findings: {
          untrustedContradicted: kind === "start" || kind === "deadline" ? [N1] : [],
          lateContradicted: [],
        },
      }),
    ),
    make({
      name: "bounded-key-not-yet-valid-at-anchored-time",
      rows: [approval(), dispatch(), evidence()],
      witnessedAt: WITNESSED_AT,
      evidencePolicy: boundedS1({ notBefore: "2026-10-06T12:00:00.000Z" }),
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "verified", trusted: false }],
    }),
    make({
      // An unbounded key never needs an anchored time.
      name: "bare-key-with-anchor-is-trusted",
      rows: [approval(), dispatch(), evidence()],
      witnessedAt: WITNESSED_AT,
      now: NOW_AFTER,
      byNonce: { [N1]: "confirmed" },
      checks: [{ index: 2, status: "verified", trusted: true }],
    }),
    make({
      // A bounded key beside a bare one: the bare key establishes trust on its own.
      name: "bare-key-beside-bounded-key-is-trusted",
      rows: [approval(), dispatch(), evidence()],
      evidencePolicy: {
        trustedSources: { [S1]: [{ key: spki(s1Key), notAfter: "2026-10-05T18:00:00.000Z" }, spki(s1Key)] },
      },
      now: NOW_AFTER,
      byNonce: { [N1]: "confirmed" },
      checks: [{ index: 2, status: "verified", trusted: true }],
    }),
    make({
      name: "malformed-dispatch-is-not-a-dispatch",
      rows: [approval(), dispatch({ metadata: { nonce: N1, payloadSha256: payloadHash(N1) } }), evidence()],
      now: NOW_AFTER,
      byNonce: { [N1]: "not_reported" },
      checks: [{ index: 2, status: "unbound", trusted: true }],
    }),
    make({
      name: "two-approvals-independent",
      rows: [approval(), approval(N2), dispatch(), dispatch({ nonce: N2 }), evidence()],
      now: NOW_BEFORE,
      byNonce: { [N1]: "confirmed", [N2]: "pending" },
      checks: [{ index: 4, status: "verified", trusted: true }],
    }),
    make({
      name: "redacted-evidence-is-not-read",
      rows: [approval(), dispatch(), evidence()],
      redact: [2],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [],
    }),
    make({
      name: "unconfirmed-record-does-not-decide",
      rows: [
        approval(),
        dispatch(),
        { ...base("EXECUTION_UNCONFIRMED", "FAILURE", "2026-10-05T14:11:00.000Z"), metadata: { nonce: N1 } },
      ],
      now: NOW_BEFORE,
      byNonce: { [N1]: "pending" },
      checks: [],
    }),
    make({
      name: "approver-trust-never-checks-evidence",
      rows: [approval(), dispatch(), evidence()],
      evidencePolicy: null,
      signaturePolicy: { trustedSigners: trust({ [APPROVER]: [approverKey], [S1]: [s1Key] }) },
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "verified", trusted: false }],
      signatures: [
        { index: 0, status: "verified", trusted: true },
        { index: 1, status: "not_applicable", trusted: false },
        { index: 2, status: "not_checked", trusted: false },
      ],
    }),
    make({
      name: "evidence-trust-checks-evidence-only",
      rows: [approval(), dispatch(), evidence()],
      evidencePolicy: { trustedSources: trust({ [S1]: [s1Key], [APPROVER]: [approverKey] }) },
      signaturePolicy: { trustedSigners: {} },
      now: NOW_AFTER,
      byNonce: { [N1]: "confirmed" },
      checks: [{ index: 2, status: "verified", trusted: true }],
      signatures: [
        { index: 0, status: "not_checked", trusted: false },
        { index: 1, status: "not_applicable", trusted: false },
        { index: 2, status: "verified", trusted: true },
      ],
    }),
  ]
  // §4.7.7: a payload nested past 64 levels does not parse, so it is neither an Approval Record nor a
  // statement — whatever a runtime's own depth limit would have said.
  const deepApprovalPayload = `{"actionType":"breaker:open","evidence":null,"nonce":"${N2}","params":{"d":${"[".repeat(70)}${"]".repeat(70)}},"type":"div-intent-verification","v":1}`
  const deepApprovalHash = executionPayloadSha256(deepApprovalPayload)
  const PROTO = "__proto__"
  const nonEvidence = (payload: string): Row => ({
    ...base("TEST_EVENT", "SUCCESS", "2026-10-05T14:04:00.000Z"),
    signerDid: APPROVER,
    signerPublicKey: spki(approverKey),
    signedPayload: payload,
    signature: sign(approverKey, payload),
    sigAlg: "ES256",
  })
  const approverTrust = { trustedSigners: trust({ [APPROVER]: [approverKey] }) }
  cases.push(
    make({
      name: "deadline-millisecond-boundary-stale",
      rows: [
        approval(),
        dispatch({ createdAt: "2004-10-20T11:11:06.757Z", deadline: "2004-10-20T11:21:06.757Z" }),
        evidence({ observedAt: "2004-10-20T11:21:06.758Z" }),
      ],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "stale", trusted: true }],
    }),
    make({
      name: "deadline-millisecond-boundary-inclusive",
      rows: [
        approval(),
        dispatch({ createdAt: "2004-10-20T11:11:06.757Z", deadline: "2004-10-20T11:21:06.757Z" }),
        evidence({ observedAt: "2004-10-20T11:21:06.757Z" }),
      ],
      now: NOW_AFTER,
      byNonce: { [N1]: "confirmed" },
      checks: [{ index: 2, status: "verified", trusted: true }],
    }),
    make({
      name: "observed-year-0000-is-a-valid-but-stale-statement",
      rows: [approval(), dispatch(), evidence({ observedAt: "0000-01-01T00:00:00.000Z" })],
      now: NOW_AFTER,
      byNonce: { [N1]: "unconfirmed" },
      checks: [{ index: 2, status: "stale", trusted: true }],
    }),
    make({
      name: "proto-named-nonce-is-reported",
      rows: [approval(), dispatch(), evidence(), approval(PROTO), dispatch({ nonce: PROTO })],
      now: NOW_BEFORE,
      requireExecutionConfirmed: true,
      ok: false,
      byNonce: { [N1]: "confirmed", [PROTO]: "pending" },
      checks: [{ index: 2, status: "verified", trusted: true }],
    }),
    make({
      name: "proto-named-source-is-reported",
      rows: [approval(), dispatch(), evidence({ source: PROTO, key: s2Key })],
      evidencePolicy: { trustedSources: trust({ [PROTO]: [s2Key] }) },
      now: NOW_AFTER,
      byNonce: { [N1]: "confirmed" },
      checks: [{ index: 2, status: "verified", trusted: true }],
      findings: { sources: { [PROTO]: noGaps(1, 1) } },
    }),
    make({
      name: "trailing-token-payload-is-not-evidence",
      rows: [approval(), nonEvidence(`{"type":"dewp-execution-evidence"} x`)],
      evidencePolicy: null,
      signaturePolicy: approverTrust,
      now: NOW_AFTER,
      byNonce: { [N1]: "not_reported" },
      checks: [],
      signatures: [
        { index: 0, status: "verified", trusted: true },
        { index: 1, status: "verified", trusted: true },
      ],
    }),
    make({
      name: "nan-payload-is-not-evidence",
      rows: [approval(), nonEvidence(`{"type":"dewp-execution-evidence","x":NaN}`)],
      evidencePolicy: null,
      signaturePolicy: approverTrust,
      now: NOW_AFTER,
      byNonce: { [N1]: "not_reported" },
      checks: [],
      signatures: [
        { index: 0, status: "verified", trusted: true },
        { index: 1, status: "verified", trusted: true },
      ],
    }),
    make({
      name: "infinite-number-payload-is-not-evidence",
      rows: [approval(), nonEvidence(`{"type":"dewp-execution-evidence","x":1e400}`)],
      evidencePolicy: null,
      signaturePolicy: approverTrust,
      now: NOW_AFTER,
      byNonce: { [N1]: "not_reported" },
      checks: [],
      signatures: [
        { index: 0, status: "verified", trusted: true },
        { index: 1, status: "verified", trusted: true },
      ],
    }),
    make({
      name: "huge-integer-payload-is-not-evidence",
      rows: [approval(), nonEvidence(`{"type":"dewp-execution-evidence","x":1${"0".repeat(400)}}`)],
      evidencePolicy: null,
      signaturePolicy: approverTrust,
      now: NOW_AFTER,
      byNonce: { [N1]: "not_reported" },
      checks: [],
      signatures: [
        { index: 0, status: "verified", trusted: true },
        { index: 1, status: "verified", trusted: true },
      ],
    }),
    make({
      name: "deep-payload-is-not-evidence",
      rows: [
        approval(),
        nonEvidence(`{"d":${"[".repeat(200)}${"]".repeat(200)},"type":"dewp-execution-evidence"}`),
      ],
      evidencePolicy: null,
      signaturePolicy: approverTrust,
      now: NOW_AFTER,
      byNonce: { [N1]: "not_reported" },
      checks: [],
      signatures: [
        { index: 0, status: "verified", trusted: true },
        { index: 1, status: "verified", trusted: true },
      ],
    }),
    make({
      // A deep approval payload does not parse, so it is not an Approval Record either: not enumerated.
      name: "deep-approval-payload-does-not-bind",
      rows: [
        approvalOver(deepApprovalPayload),
        dispatch({ nonce: N2, hash: deepApprovalHash }),
        evidence({ nonce: N2, hash: deepApprovalHash }),
      ],
      now: NOW_AFTER,
      byNonce: { [N2]: "unconfirmed" },
      checks: [{ index: 2, status: "unbound", trusted: true }],
    }),
  )

  // Single inclusion proofs: one leaf cannot bind evidence, so a statement is at best `unbound`.
  const single = (name: string, rows: Row[], index: number, evidencePolicy: unknown, execution: unknown) => {
    const { root, leaves, proof } = bundleOf(rows)
    const leaf = leaves[index] as AuditLeaf
    const bundle: ProofBundle = {
      protocol: "DEWP",
      kind: BUNDLE_KIND,
      version: "1.0",
      profile: "trust.intyga.audit.v1",
      exportedAt: "2026-10-06T00:00:00.000Z",
      event: {
        seq: leaf.seq,
        createdAt: leaf.createdAt,
        type: leaf.event,
        outcome: leaf.outcome,
        signerDid: leaf.signerDid,
        sigAlg: leaf.sigAlg,
        canonical: leaf,
      },
      proof: proof(index),
    } as unknown as ProofBundle
    return {
      name,
      bundle,
      options: { trustedRoot: root, ...(evidencePolicy ? { evidencePolicy } : {}) },
      execution,
    }
  }
  const proofs = [
    single("trusted-statement-is-unbound-alone", happy(), 3, policyS1, { status: "unbound", trusted: true }),
    single("untrusted-statement-is-unbound-alone", happy(), 3, null, { status: "unbound", trusted: false }),
    single(
      "malformed-statement-alone",
      [approval(), dispatch(), evidence({ sigAlg: "WEBAUTHN" })],
      2,
      policyS1,
      {
        status: "invalid",
        trusted: false,
      },
    ),
    // A single proof carries no counting anchor, so a bounded key has no anchored time to be placed at.
    single(
      "bounded-key-alone-is-untrusted",
      happy(),
      3,
      boundedS1({ notAfter: "2026-10-07T00:00:00.000Z" }),
      { status: "unbound", trusted: false },
    ),
    single("approval-leaf-has-no-execution-check", happy(), 0, policyS1, null),
    single("dispatch-leaf-has-no-execution-check", happy(), 2, policyS1, null),
  ]

  const canonicalBytes = canonicalExecutionEvidenceStatement({
    nonce: N1,
    payloadSha256: payloadHash(N1),
    source: S1,
    verdict: "confirmed",
    observedAt: T_OBSERVED,
    sampledAt: T_SAMPLED,
    sequence: 418,
    observation: { breaker: "open", currentA: 0, previousCurrentA: 412, ratio: 0.5, é: "ä", "\u{1F600}": 1 },
  })
  /** The canonical statement with a different observation (keys already in canonical order). */
  const withObservation = (observation: string): string =>
    canonicalBytes.replace(/"observation":\{[^}]*\}/, `"observation":${observation}`)
  const statements = [
    { name: "canonical", bytes: canonicalBytes, ok: true },
    {
      name: "empty-observation",
      bytes: canonicalBytes.replace(/"observation":\{[^}]*\}/, '"observation":{}'),
      ok: true,
    },
    { name: "trailing-newline", bytes: `${canonicalBytes}\n`, ok: false },
    { name: "not-json", bytes: "not json", ok: false },
    { name: "array", bytes: "[]", ok: false },
    { name: "version-2", bytes: canonicalBytes.replace('"v":1', '"v":2'), ok: false },
    { name: "version-float", bytes: canonicalBytes.replace('"v":1', '"v":1.0'), ok: false },
    {
      name: "uppercase-hash",
      bytes: canonicalBytes.replace(payloadHash(N1), payloadHash(N1).toUpperCase()),
      ok: false,
    },
    { name: "empty-nonce", bytes: canonicalBytes.replace(`"nonce":"${N1}"`, '"nonce":""'), ok: false },
    { name: "empty-source", bytes: canonicalBytes.replace(`"source":"${S1}"`, '"source":""'), ok: false },
    {
      name: "timestamp-without-millis",
      bytes: canonicalBytes.replace(T_OBSERVED, "2026-10-05T14:02:11Z"),
      ok: false,
    },
    {
      name: "timestamp-with-offset",
      bytes: canonicalBytes.replace(T_OBSERVED, "2026-10-05T14:02:11.000+00:00"),
      ok: false,
    },
    {
      name: "observation-array",
      bytes: canonicalBytes.replace(/"observation":\{[^}]*\}/, '"observation":[]'),
      ok: false,
    },
    {
      name: "wrong-type",
      bytes: canonicalBytes.replace("dewp-execution-evidence", "div-intent-verification"),
      ok: false,
    },
    {
      name: "lone-surrogate",
      bytes: canonicalBytes.replace('"breaker":"open"', '"breaker":"\\ud800"'),
      ok: false,
    },
    {
      name: "escaped-solidus-not-canonical",
      bytes: canonicalBytes.replace('"breaker":"open"', '"breaker":"a\\/b"'),
      ok: false,
    },
    { name: "integer-above-2^53", bytes: withObservation('{"x":9007199254740993}'), ok: false },
    { name: "integer-at-2^53", bytes: withObservation('{"x":9007199254740992}'), ok: false },
    { name: "integer-max-safe", bytes: withObservation('{"x":9007199254740991}'), ok: true },
    { name: "negative-integer-max-safe", bytes: withObservation('{"x":-9007199254740991}'), ok: true },
    { name: "fraction-above-2^53", bytes: withObservation('{"x":9007199254740993.5}'), ok: false },
    {
      name: "nested-64-levels",
      bytes: withObservation(`{"d":${"[".repeat(62)}${"]".repeat(62)}}`),
      ok: true,
    },
    {
      name: "nested-65-levels",
      bytes: withObservation(`{"d":${"[".repeat(63)}${"]".repeat(63)}}`),
      ok: false,
    },
    {
      name: "nested-200-levels",
      bytes: withObservation(`{"d":${"[".repeat(200)}${"]".repeat(200)}}`),
      ok: false,
    },
    {
      name: "nested-brackets-inside-strings-do-not-count",
      bytes: withObservation(`{"s":"${"[".repeat(100)}\\"${"{".repeat(100)}"}`),
      ok: true,
    },
    { name: "number-1e400", bytes: withObservation('{"x":1e400}'), ok: false },
    { name: "nan-literal", bytes: withObservation('{"x":NaN}'), ok: false },
    { name: "trailing-token", bytes: `${canonicalBytes} x`, ok: false },
    {
      name: "unicode-digit-timestamp",
      bytes: canonicalBytes.replace(T_OBSERVED, "٢٠٢٦-10-05T14:02:11.000Z"),
      ok: false,
    },
    {
      name: "fullwidth-digit-timestamp",
      bytes: canonicalBytes.replace(T_OBSERVED, "２０２６-10-05T14:02:11.000Z"),
      ok: false,
    },
    {
      // Year 0000 is valid; the sample time moves with it so rule 11 holds.
      name: "year-0000-timestamp",
      bytes: canonicalBytes
        .replace(T_OBSERVED, "0000-01-01T00:00:00.000Z")
        .replace(T_SAMPLED, "0000-01-01T00:00:00.000Z"),
      ok: true,
    },
    {
      name: "approval-extra-member",
      bytes: canonicalBytes.replace(`"nonce":"${N1}",`, `"extra":0,"nonce":"${N1}",`),
      ok: false,
    },
    // Rules 11 and 12 (the pre-publication review).
    { name: "sampled-at-equals-observed-at", bytes: canonicalBytes.replace(T_SAMPLED, T_OBSERVED), ok: true },
    {
      name: "sampled-after-observed",
      bytes: canonicalBytes.replace(T_SAMPLED, "2026-10-05T14:02:11.001Z"),
      ok: false,
    },
    {
      name: "sampled-at-without-millis",
      bytes: canonicalBytes.replace(T_SAMPLED, "2026-10-05T14:02:09Z"),
      ok: false,
    },
    {
      name: "missing-sampled-at",
      bytes: canonicalBytes.replace(`"sampledAt":"${T_SAMPLED}",`, ""),
      ok: false,
    },
    { name: "missing-sequence", bytes: canonicalBytes.replace('"sequence":418,', ""), ok: false },
    { name: "sequence-one", bytes: canonicalBytes.replace('"sequence":418', '"sequence":1'), ok: true },
    {
      name: "sequence-max-safe",
      bytes: canonicalBytes.replace('"sequence":418', '"sequence":9007199254740991'),
      ok: true,
    },
    { name: "sequence-zero", bytes: canonicalBytes.replace('"sequence":418', '"sequence":0'), ok: false },
    {
      name: "sequence-negative",
      bytes: canonicalBytes.replace('"sequence":418', '"sequence":-1'),
      ok: false,
    },
    {
      name: "sequence-fraction",
      bytes: canonicalBytes.replace('"sequence":418', '"sequence":418.5'),
      ok: false,
    },
    {
      name: "sequence-float-spelling",
      bytes: canonicalBytes.replace('"sequence":418', '"sequence":418.0'),
      ok: false,
    },
    {
      name: "sequence-string",
      bytes: canonicalBytes.replace('"sequence":418', '"sequence":"418"'),
      ok: false,
    },
    {
      name: "sequence-above-2^53",
      bytes: canonicalBytes.replace('"sequence":418', '"sequence":9007199254740992'),
      ok: false,
    },
    {
      name: "draft-seven-member-shape",
      bytes: canonicalBytes.replace(`"sampledAt":"${T_SAMPLED}","sequence":418,`, ""),
      ok: false,
    },
  ]
  const builder = [
    {
      name: "builder-sorts-and-serializes",
      input: {
        nonce: N1,
        payloadSha256: payloadHash(N1),
        source: S1,
        verdict: "contradicted",
        observedAt: T_OBSERVED,
        sampledAt: T_SAMPLED,
        sequence: 418,
        observation: { z: [1, 2.5, "x"], a: { c: true, b: null } },
      },
      bytes: canonicalExecutionEvidenceStatement({
        nonce: N1,
        payloadSha256: payloadHash(N1),
        source: S1,
        verdict: "contradicted",
        observedAt: T_OBSERVED,
        sampledAt: T_SAMPLED,
        sequence: 418,
        observation: { z: [1, 2.5, "x"], a: { c: true, b: null } },
      }),
    },
  ]

  // The relying party's `intyga-evidence-sources` trust file (docs/API.md §2e), read by every SDK's
  // loader. Static and key-free on purpose: the loader validates shape, it never verifies a signature,
  // so a fixed SPKI string suffices and the cases do not change when the section is regenerated.
  const FILE_KEY =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFapJVK9jXaesH8lZ1Xk3QylMJW/8oKuLLr+3DSXgWjHI4TwJye6MhBYcWxfgh3goR2H4ESC2+3j7dPB8IhUbIw=="
  const FILE_KEY_2 = "AAAA"
  const file = (sources: unknown, over: Record<string, unknown> = {}) =>
    JSON.stringify({ type: "intyga-evidence-sources", v: 1, sources, ...over })
  const relay = (publicKeys: unknown, extra: Record<string, unknown> = {}) => ({
    did: S1,
    publicKeys,
    ...extra,
  })
  const accepted = (name: string, text: string, policy: Record<string, unknown[]>) => ({
    name,
    text,
    ok: true,
    policy,
  })
  const refused = (name: string, text: string) => ({ name, text, ok: false })
  const trustFiles = [
    accepted("bare-key", file([relay([FILE_KEY])]), { [S1]: [FILE_KEY] }),
    accepted(
      "bounded-key",
      file([
        relay([
          { key: FILE_KEY, notBefore: "2026-10-01T00:00:00.000Z", notAfter: "2026-10-05T18:00:00.000Z" },
        ]),
      ]),
      {
        [S1]: [
          { key: FILE_KEY, notBefore: "2026-10-01T00:00:00.000Z", notAfter: "2026-10-05T18:00:00.000Z" },
        ],
      },
    ),
    accepted("not-before-only", file([relay([{ key: FILE_KEY, notBefore: "2026-10-01T00:00:00.000Z" }])]), {
      [S1]: [{ key: FILE_KEY, notBefore: "2026-10-01T00:00:00.000Z" }],
    }),
    accepted("not-after-only", file([relay([{ key: FILE_KEY, notAfter: "2026-10-05T18:00:00.000Z" }])]), {
      [S1]: [{ key: FILE_KEY, notAfter: "2026-10-05T18:00:00.000Z" }],
    }),
    accepted("object-key-without-bounds", file([relay([{ key: FILE_KEY }])]), { [S1]: [{ key: FILE_KEY }] }),
    accepted(
      "bounds-equal",
      file([
        relay([
          { key: FILE_KEY, notBefore: "2026-10-05T18:00:00.000Z", notAfter: "2026-10-05T18:00:00.000Z" },
        ]),
      ]),
      {
        [S1]: [
          { key: FILE_KEY, notBefore: "2026-10-05T18:00:00.000Z", notAfter: "2026-10-05T18:00:00.000Z" },
        ],
      },
    ),
    accepted(
      "bare-beside-bounded-in-order",
      file([relay([{ key: FILE_KEY, notAfter: "2026-10-05T18:00:00.000Z" }, FILE_KEY_2])]),
      {
        [S1]: [{ key: FILE_KEY, notAfter: "2026-10-05T18:00:00.000Z" }, FILE_KEY_2],
      },
    ),
    accepted(
      "two-sources-with-labels",
      file([relay([FILE_KEY], { label: "Relay 7" }), { did: S2, publicKeys: [FILE_KEY_2], label: "" }]),
      {
        [S1]: [FILE_KEY],
        [S2]: [FILE_KEY_2],
      },
    ),
    // Members that cannot change trust are tolerated at the file and source level; only a key entry is strict.
    accepted(
      "unknown-file-and-source-members-tolerated",
      file([relay([FILE_KEY], { kind: "relay-protection" })], { exportedAt: "x" }),
      {
        [S1]: [FILE_KEY],
      },
    ),
    accepted("year-0000-bound", file([relay([{ key: FILE_KEY, notBefore: "0000-01-01T00:00:00.000Z" }])]), {
      [S1]: [{ key: FILE_KEY, notBefore: "0000-01-01T00:00:00.000Z" }],
    }),
    // Computed key: a literal `__proto__:` would set the prototype and serialize as `{}`.
    accepted("proto-named-source", file([{ did: "__proto__", publicKeys: [FILE_KEY] }]), {
      ["__proto__"]: [FILE_KEY],
    }),
    refused("not-json", "{"),
    refused("root-array", "[]"),
    refused("root-null", "null"),
    refused("approver-trust-anchor-type", file([relay([FILE_KEY])], { type: "intyga-trust-anchor" })),
    refused("missing-type", JSON.stringify({ v: 1, sources: [relay([FILE_KEY])] })),
    refused("version-2", file([relay([FILE_KEY])], { v: 2 })),
    refused("version-string", file([relay([FILE_KEY])], { v: "1" })),
    // `v` is the NUMBER 1 in any JSON spelling: JSON.parse reads `1.0` and `1e0` as 1, so every loader
    // does (as the approver trust-anchor loaders already do). A boolean is not a number.
    accepted("version-written-1.0", file([relay([FILE_KEY])]).replace('"v":1,', '"v":1.0,'), {
      [S1]: [FILE_KEY],
    }),
    accepted("version-written-1e0", file([relay([FILE_KEY])]).replace('"v":1,', '"v":1e0,'), {
      [S1]: [FILE_KEY],
    }),
    refused("version-true", file([relay([FILE_KEY])], { v: true })),
    refused("version-1.5", file([relay([FILE_KEY])], { v: 1.5 })),
    refused("sources-empty", file([])),
    refused("sources-missing", JSON.stringify({ type: "intyga-evidence-sources", v: 1 })),
    refused("sources-object", file({ [S1]: [FILE_KEY] })),
    refused("source-null", file([null])),
    refused("source-string", file([S1])),
    refused("did-empty", file([{ did: "", publicKeys: [FILE_KEY] }])),
    refused("did-missing", file([{ publicKeys: [FILE_KEY] }])),
    refused("did-number", file([{ did: 7, publicKeys: [FILE_KEY] }])),
    refused("duplicate-did", file([relay([FILE_KEY]), relay([FILE_KEY_2])])),
    refused("public-keys-empty", file([relay([])])),
    refused("public-keys-missing", file([{ did: S1 }])),
    refused("public-keys-string", file([relay(FILE_KEY)])),
    refused("key-not-base64", file([relay(["not base64!"])])),
    refused("key-empty-string", file([relay([""])])),
    refused("key-number", file([relay([42])])),
    refused("key-null", file([relay([null])])),
    refused("key-array", file([relay([[FILE_KEY]])])),
    refused("object-without-key", file([relay([{ notAfter: "2026-10-05T18:00:00.000Z" }])])),
    refused("object-key-not-base64", file([relay([{ key: "not base64!" }])])),
    refused("object-key-number", file([relay([{ key: 42 }])])),
    // A misspelt or extra member must never read as "no bound" (DEWP §4.7.5).
    refused("misspelt-not-after", file([relay([{ key: FILE_KEY, notafter: "2026-10-05T18:00:00.000Z" }])])),
    refused("revoked-at-member", file([relay([{ key: FILE_KEY, revokedAt: "2026-10-05T18:00:00.000Z" }])])),
    refused("label-inside-key-entry", file([relay([{ key: FILE_KEY, label: "x" }])])),
    refused("not-after-date-only", file([relay([{ key: FILE_KEY, notAfter: "2026-10-05" }])])),
    refused("not-after-without-millis", file([relay([{ key: FILE_KEY, notAfter: "2026-10-05T18:00:00Z" }])])),
    refused(
      "not-after-with-offset",
      file([relay([{ key: FILE_KEY, notAfter: "2026-10-05T18:00:00.000+00:00" }])]),
    ),
    refused(
      "not-after-calendar-overflow",
      file([relay([{ key: FILE_KEY, notAfter: "2026-02-30T00:00:00.000Z" }])]),
    ),
    refused("not-after-hour-24", file([relay([{ key: FILE_KEY, notAfter: "2026-10-05T24:00:00.000Z" }])])),
    refused("not-after-number", file([relay([{ key: FILE_KEY, notAfter: 1754006400000 }])])),
    refused("not-after-null", file([relay([{ key: FILE_KEY, notAfter: null }])])),
    refused(
      "not-before-fullwidth-digits",
      file([relay([{ key: FILE_KEY, notBefore: "２０２６-10-01T00:00:00.000Z" }])]),
    ),
    refused(
      "not-before-after-not-after",
      file([
        relay([
          { key: FILE_KEY, notBefore: "2026-10-05T18:00:00.001Z", notAfter: "2026-10-05T18:00:00.000Z" },
        ]),
      ]),
    ),
    refused("label-number", file([relay([FILE_KEY], { label: 1 })])),
  ]

  return {
    note:
      "DEWP §4.7 execution evidence (version 1.1, after the pre-publication review). `cases` are evidence " +
      "bundles: run each with trustedRoots, evidencePolicy (whose keys may be bare SPKI strings or " +
      "{key, notBefore?, notAfter?} — DEWP §4.7.5), signaturePolicy, now (evaluation time), skewSeconds, " +
      "maxWindowSeconds and requireExecutionConfirmed as given; a case with `policy` carries a " +
      "Rekor-witnessed anchor in its checkpoint and pins the log key in options.rekorSpki (pass it as the " +
      "anchor policy and the Rekor external key). Then assert ok, execution.byNonce statuses, the " +
      "per-statement checks (seq, status, trusted) in bundle order, each key of execution.findings that is " +
      "present (lateContradicted, dispatchConflicts, windowCapped per nonce, sources continuity) and, where " +
      "present, the per-entry signature checks. `proofs` are single inclusion proofs; `execution` is the " +
      "expected statement check or null. `statements` are statement-parser cases; `builder` pins the " +
      "canonical statement bytes. `trustFiles` are SDK cases for the `intyga-evidence-sources` trust-file " +
      "loader (docs/API.md §2e): parse `text`; an `ok` case must load and yield `policy` — source → keys " +
      "in file order, each a bare SPKI string or {key, notBefore?, notAfter?} exactly as given — and a " +
      "refused one must fail to load. Verifier ports may ignore this subsection.",
    cases,
    proofs,
    statements,
    builder,
    trustFiles,
  }
}
