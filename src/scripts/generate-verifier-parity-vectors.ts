import crypto from "node:crypto"
import { writeFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import {
  canonicalAgentAuthorityPayload,
  canonicalIntentPayload,
  canonicalOfflineIntentPayload,
  canonicalPlatformIntentPayload,
  selfCertifyingDid,
  verificationCode,
  type ApprovalReceipt,
  type PlatformReceipt,
} from "../index.js"
import { anchorDigest, signAnchor, type SignedAnchor } from "../ledger-anchor.js"
import { chainHash, type RootsChainEntry } from "../ledger-chain.js"
import { type EvidenceBundle, EVIDENCE_BUNDLE_KIND } from "../ledger-evidence.js"
import { type AuditLeaf, leafHash } from "../ledger-leaf.js"
import { BUNDLE_KIND, type ProofBundle } from "../ledger-bundle.js"
import { hashLeaf, merkleProof, merkleRoot } from "../ledger-merkle.js"
import { rekorPayloadHashFor } from "../ledger-rekor.js"
import { buildDewpEvidenceHardening } from "./dewp-evidence-hardening-vectors.js"
import { buildVerifierInputHardening } from "./verifier-input-hardening-vectors.js"

interface Pair {
  publicKey: crypto.KeyObject
  privateKey: crypto.KeyObject
}
function required<T>(value: T | null | undefined, name: string): T {
  if (value == null) throw new Error(`Missing ${name}`)
  return value
}
const ec = (): Pair => crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
const ed = (): Pair => crypto.generateKeyPairSync("ed25519")
const rsa = (): Pair => crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
const spki = (p: Pair): string => p.publicKey.export({ format: "der", type: "spki" }).toString("base64")
const sign = (p: Pair, payload: string): string =>
  crypto
    .sign("sha256", Buffer.from(payload), { key: p.privateKey, dsaEncoding: "ieee-p1363" })
    .toString("base64")

function cose(p: Pair): string {
  const jwk = p.publicKey.export({ format: "jwk" }) as { x: string; y: string }
  return Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
    Buffer.from(jwk.x, "base64url"),
    Buffer.from([0x22, 0x58, 0x20]),
    Buffer.from(jwk.y, "base64url"),
  ]).toString("base64")
}

const subject = ec(),
  alice = ec(),
  malformedAgentSigner = ec(),
  bob = ec(),
  mallory = ec()
const anchorEc = ec(),
  anchorEd = ed(),
  anchorRsa = rsa(),
  rekor = ec()
const keys = [
  { id: "subject", did: "did:intyga:subject:42", spkiB64: spki(subject), coseB64: cose(subject) },
  { id: "alice", did: "did:intyga:alice", spkiB64: spki(alice) },
  { id: "bob", did: "did:intyga:bob", spkiB64: spki(bob) },
  { id: "mallory", did: "did:intyga:mallory", spkiB64: spki(mallory) },
  { id: "anchor-es256", issuer: "https://anchor-a.example", spkiB64: spki(anchorEc) },
  { id: "anchor-ed25519", issuer: "https://anchor-b.example", spkiB64: spki(anchorEd) },
  { id: "anchor-rsa-pss", issuer: "https://anchor-c.example", spkiB64: spki(anchorRsa) },
  { id: "rekor", issuer: "https://rekor.sigstore.dev", spkiB64: spki(rekor) },
  { id: "malformed-agent-signer", did: "did:intyga:alice", spkiB64: spki(malformedAgentSigner) },
]

const AS_OF = "2026-09-01T12:00:00.000Z"
const EXPIRES = "2027-09-01T12:00:00.000Z"
const RP = "platform.example",
  ORIGIN = "https://platform.example",
  NONCE = "parity-platform-nonce"
const payloadHash = crypto.createHash("sha256").update("platform parity payload").digest("hex")

function platformReceipt(origin = ORIGIN, rp = RP): PlatformReceipt {
  const canonical = canonicalPlatformIntentPayload({
    payloadHash,
    rpId: RP,
    subjectExternalId: "cust-42",
    signedAt: AS_OF,
    expiresAt: EXPIRES,
    nonce: NONCE,
  })
  const client = Buffer.from(
    JSON.stringify({
      type: "webauthn.get",
      challenge: Buffer.from(canonical).toString("base64url"),
      origin,
      crossOrigin: false,
    }),
  )
  const tail = Buffer.alloc(5)
  tail[0] = 0x05
  const auth = Buffer.concat([crypto.createHash("sha256").update(rp).digest(), tail])
  const signature = crypto.sign(
    "sha256",
    Buffer.concat([auth, crypto.createHash("sha256").update(client).digest()]),
    { key: subject.privateKey, dsaEncoding: "der" },
  )
  return {
    canonicalPayload: canonical,
    payloadHash,
    rpId: RP,
    subject: { externalId: "cust-42" },
    nonce: NONCE,
    signerDid: "did:intyga:subject:42",
    signerPublicKey: cose(subject),
    signature: signature.toString("base64"),
    sigAlg: "WEBAUTHN",
    authenticatorData: auth.toString("base64"),
    clientDataJSON: client.toString("base64"),
    verificationCode: verificationCode(canonical),
  }
}

const platformGood = platformReceipt()
const platform = {
  expected: {
    approverKeyIds: ["subject"],
    payloadHash,
    rpId: RP,
    nonce: NONCE,
    subjectExternalId: "cust-42",
  },
  options: { expectedOrigin: ORIGIN, asOf: "2026-09-01T12:01:00.000Z" },
  cases: [
    { name: "valid-webauthn-platform-receipt", receipt: platformGood, ok: true, signers: [cose(subject)] },
    {
      name: "payload-hash-tampered",
      receipt: platformGood,
      expected: { payloadHash: "0".repeat(64) },
      ok: false,
    },
    { name: "wrong-origin", receipt: platformReceipt("https://evil.example"), ok: false },
    { name: "wrong-rp-hash", receipt: platformReceipt(ORIGIN, "evil.example"), ok: false },
    { name: "wrong-expected-rp", receipt: platformGood, expected: { rpId: "evil.example" }, ok: false },
    {
      name: "wrong-expected-subject",
      receipt: platformGood,
      expected: { subjectExternalId: "cust-evil" },
      ok: false,
    },
    { name: "wrong-expected-nonce", receipt: platformGood, expected: { nonce: "nonce-evil" }, ok: false },
    { name: "bare-key-refused", receipt: { ...platformGood, sigAlg: "ES256" }, ok: false },
  ],
}

const approvalTarget = "prod-payments"
const approvalActionType = "payments.wire"
const approvalParams = { amount: 4200, currency: "USD" }
const approvalNonce = "parity-approval-nonce"
function approvalReceipt(input: {
  requesterDid: string
  signerDid: string
  signer: Pair
  requesterCannotApprove?: boolean
}): ApprovalReceipt {
  const requirement = {
    requiredApprovals: 1,
    requireHardwareKey: false,
    allowedAaguids: [],
    requesterCannotApprove: input.requesterCannotApprove ?? false,
    signerClass: "human",
  }
  const requester = { did: input.requesterDid, attestation: null }
  const canonical = canonicalIntentPayload({
    target: approvalTarget,
    actionType: approvalActionType,
    display: "Wire USD 4,200",
    params: approvalParams,
    requester,
    requirement,
    nonce: approvalNonce,
    expiresAt: EXPIRES,
  })
  return {
    canonicalPayload: canonical,
    target: approvalTarget,
    actionType: approvalActionType,
    actionDescription: "Wire USD 4,200",
    params: approvalParams,
    requester,
    signerDid: input.signerDid,
    signerPublicKey: spki(input.signer),
    signature: sign(input.signer, canonical),
    sigAlg: "ES256",
    verificationCode: verificationCode(canonical),
  }
}

const approvalGood = approvalReceipt({
  requesterDid: "did:intyga:agent:payments",
  signerDid: "did:intyga:alice",
  signer: alice,
})
const agentContext = {
  action: { reversibility: "irreversible" as const, amount: { amount: "4200", currency: "USD" } },
  agent: { label: "Payments agent", configDigest: `sha256:${"1".repeat(64)}`, delegatedBy: null },
  session: {
    id: "sha256:7826a1ee10082e32e0fa779f569e7f7e6fda7c6fceaea96e4570ba72599c8bc1",
    seq: "1",
    prev: null,
    aggregate: { amount: "4200", currency: "USD" },
  },
  nbf: "2026-09-01T12:00:00.000Z",
}
const agentExp = "2026-09-01T12:05:00.000Z"
const agentCanonical = canonicalIntentPayload({
  target: approvalTarget,
  actionType: approvalActionType,
  display: "Wire USD 4,200",
  params: approvalParams,
  requester: { did: "did:intyga:agent:payments", attestation: null },
  requirement: {
    requiredApprovals: 1,
    requireHardwareKey: false,
    allowedAaguids: [],
    requesterCannotApprove: false,
    signerClass: "human",
  },
  nonce: approvalNonce,
  expiresAt: agentExp,
  agentContext,
})
const agentApproval: ApprovalReceipt = {
  ...approvalGood,
  canonicalPayload: agentCanonical,
  signature: sign(alice, agentCanonical),
  verificationCode: verificationCode(agentCanonical),
}
// Deliberately bypass the producer's input validation: the bytes, independently asserted context
// and signature agree, but seq=2 with prev=null violates the agent-session invariant. Every port
// must refuse the semantic shape before accepting the otherwise valid human signature.
const malformedAgentContext = {
  ...agentContext,
  session: { ...agentContext.session, seq: "2" },
}
const malformedAgentCanonical = agentCanonical.replace('"seq":"1"', '"seq":"2"')
if (malformedAgentCanonical === agentCanonical) throw new Error("agent seq fixture was not changed")
const malformedAgentApproval: ApprovalReceipt = {
  ...agentApproval,
  canonicalPayload: malformedAgentCanonical,
  signerPublicKey: spki(malformedAgentSigner),
  signature: sign(malformedAgentSigner, malformedAgentCanonical),
  verificationCode: verificationCode(malformedAgentCanonical),
}
const delegatedAgentContext = {
  ...agentContext,
  agent: { ...agentContext.agent, delegatedBy: `sha256:${"2".repeat(64)}` },
}
const delegatedAgentCanonical = canonicalIntentPayload({
  target: approvalTarget,
  actionType: approvalActionType,
  display: "Wire USD 4,200",
  params: approvalParams,
  requester: { did: "did:intyga:agent:payments", attestation: null },
  requirement: {
    requiredApprovals: 1,
    requireHardwareKey: false,
    allowedAaguids: [],
    requesterCannotApprove: false,
    signerClass: "human",
  },
  nonce: approvalNonce,
  expiresAt: agentExp,
  agentContext: delegatedAgentContext,
})
const delegatedAgentApproval: ApprovalReceipt = {
  ...approvalGood,
  canonicalPayload: delegatedAgentCanonical,
  signature: sign(alice, delegatedAgentCanonical),
  verificationCode: verificationCode(delegatedAgentCanonical),
}
const requesterKeyLabelledMallory = approvalReceipt({
  requesterDid: "did:intyga:alice",
  signerDid: "did:intyga:mallory",
  signer: alice,
  requesterCannotApprove: true,
})
// Mutate the canonical string directly and re-sign: the builder cannot emit these shapes, which is
// the point — they are what a non-conformant or future producer would send. The one exception is the
// post-signing mutation, which deliberately keeps the original signature.
const evidenceApprovalCases = (() => {
  const good = approvalGood.canonicalPayload
  const reSign = (canonical: string) => ({
    ...approvalGood,
    canonicalPayload: canonical,
    signature: sign(alice, canonical),
    verificationCode: verificationCode(canonical),
  })
  const missing = good.replace(',"evidence":null', "")
  if (missing === good) throw new Error("evidence parity vectors: the strip did not apply")
  const swap = (replacement: string) => good.replace('"evidence":null', replacement)
  const MISSING_REASON = "missing evidence"
  const UNSUPPORTED_REASON = "declares an evidence condition"
  return [
    { name: "evidence-null-verifies", receipt: approvalGood, ok: true, signers: [spki(alice)] },
    { name: "evidence-missing-refused", receipt: reSign(missing), ok: false, reasonIncludes: MISSING_REASON },
    {
      name: "evidence-empty-array-refused",
      receipt: reSign(swap('"evidence":[]')),
      ok: false,
      reasonIncludes: UNSUPPORTED_REASON,
    },
    {
      name: "evidence-empty-object-refused",
      receipt: reSign(swap('"evidence":{}')),
      ok: false,
      reasonIncludes: UNSUPPORTED_REASON,
    },
    {
      name: "evidence-arbitrary-value-refused",
      receipt: reSign(
        swap(`"evidence":[{"alg":"SHA-256","digest":"${"0".repeat(64)}","kind":"example.reserved.v1"}]`),
      ),
      ok: false,
      reasonIncludes: UNSUPPORTED_REASON,
    },
    {
      // Signature NOT regenerated — the bytes were altered after signing. The evidence gate runs
      // before Local Payload Reconstruction, so this must refuse as an unsupported payload shape,
      // NOT as a params mismatch and NOT as a bad signature.
      name: "evidence-mutated-after-signing-refused",
      receipt: { ...approvalGood, canonicalPayload: swap('"evidence":["tampered"]') },
      ok: false,
      reasonIncludes: UNSUPPORTED_REASON,
    },
  ]
})()

// DIV §4.3.2: a non-empty `allowedAaguids` model allowlist is refused offline exactly like
// `requireHardwareKey` — an offline witness is a bare key, which has no authenticator model at all.
// The control case differs ONLY in the allowlist, so the refusal cannot be for another reason.
function offlineApproval(allowedAaguids: string[]): ApprovalReceipt {
  const requester = { did: "did:intyga:agent:payments", attestation: null }
  const canonical = canonicalOfflineIntentPayload({
    target: approvalTarget,
    actionType: approvalActionType,
    display: "Wire USD 4,200",
    params: approvalParams,
    requester,
    requirement: {
      requiredApprovals: 1,
      requireHardwareKey: false,
      allowedAaguids,
      requesterCannotApprove: false,
      signerClass: "human",
    },
    nonce: approvalNonce,
    challengedAt: AS_OF,
    expiresAt: "2026-09-01T12:30:00.000Z",
  })
  return {
    canonicalPayload: canonical,
    target: approvalTarget,
    actionType: approvalActionType,
    actionDescription: "Wire USD 4,200",
    params: approvalParams,
    requester,
    signerDid: "did:intyga:alice",
    signerPublicKey: spki(alice),
    signature: sign(alice, canonical),
    sigAlg: "ES256",
    verificationCode: verificationCode(canonical),
  }
}
const offlineApprovalCases = [
  {
    name: "offline-bare-key-without-hardware-policy-verifies",
    receipt: offlineApproval([]),
    options: { asOf: "2026-09-01T12:01:00.000Z", allowOffline: true },
    ok: true,
    signers: [spki(alice)],
  },
  {
    name: "offline-aaguid-allowlist-refused",
    receipt: offlineApproval(["cb69481e-8ff7-4039-93ec-0a2729a154a8"]),
    options: { asOf: "2026-09-01T12:01:00.000Z", allowOffline: true },
    ok: false,
    reasonIncludes: "cannot be produced offline",
  },
]

const approvals = {
  expected: {
    approverKeyIds: ["alice"],
    target: approvalTarget,
    actionType: approvalActionType,
    params: approvalParams,
    nonce: approvalNonce,
  },
  options: { asOf: "2026-09-01T12:01:00.000Z" },
  cases: [
    { name: "valid-es256-approval", receipt: approvalGood, ok: true, signers: [spki(alice)] },
    {
      name: "valid-agent-approval",
      receipt: agentApproval,
      expected: { agentContext },
      ok: true,
      signers: [spki(alice)],
    },
    {
      name: "agent-sequence-without-predecessor-refused",
      receipt: malformedAgentApproval,
      expected: { agentContext: malformedAgentContext, approverKeyIds: ["malformed-agent-signer"] },
      ok: false,
      reasonIncludes: "invalid agent session predecessor",
    },
    {
      name: "delegated-agent-needs-authority-chain",
      receipt: delegatedAgentApproval,
      expected: { agentContext: delegatedAgentContext },
      ok: false,
      reasonIncludes: "trusted root-to-leaf authority chain",
    },
    {
      name: "agent-config-drift",
      receipt: agentApproval,
      expected: {
        agentContext: {
          ...agentContext,
          agent: { ...agentContext.agent, configDigest: `sha256:${"2".repeat(64)}` },
        },
      },
      ok: false,
      reasonIncludes: "do not match",
    },
    {
      name: "agent-expired",
      receipt: agentApproval,
      expected: { agentContext },
      options: { asOf: "2026-09-01T12:10:00.000Z" },
      ok: false,
      reasonIncludes: "expired",
    },
    {
      name: "valid-es256-signature-relabeled-unknown",
      receipt: { ...approvalGood, sigAlg: "UNKNOWN" },
      ok: true,
      signers: [spki(alice)],
    },
    {
      name: "requester-key-labeled-mallory-under-key-only-trust",
      receipt: requesterKeyLabelledMallory,
      ok: false,
      reasonIncludes: "requesterCannotApprove requires a DID-mode trust anchor",
    },
    // The reserved `evidence` field (DIV §4.3.4 / §5-step-3c). These live in `approvals` rather than
    // a new section on purpose: `reasonIncludes` is already asserted by every port's harness here, so
    // they pin the REASON as well as the verdict with no harness change. A refusal landing for the
    // wrong reason — a params mismatch instead of an unsupported payload shape — is exactly the
    // divergence these vectors exist to catch.
    ...evidenceApprovalCases,
    ...offlineApprovalCases,
  ],
}

const authorityTarget = "prod-payments",
  agentDid = "did:intyga:agent:payments"
function authorityReceipt(
  signers: Array<[string, Pair]>,
  overrides: { expiresAt?: string; patterns?: string[]; fourEyes?: boolean } = {},
): ApprovalReceipt {
  const requirement = {
    requiredApprovals: 2,
    requireHardwareKey: false,
    allowedAaguids: [],
    requesterCannotApprove: overrides.fourEyes ?? false,
    signerClass: "human",
  }
  const canonical = canonicalAgentAuthorityPayload({
    target: authorityTarget,
    actionPatterns: overrides.patterns ?? ["refund", "payments."],
    display: "Payments scope",
    agent: { did: agentDid },
    requester: { did: overrides.fourEyes ? "did:intyga:alice" : "did:intyga:admin", attestation: null },
    requirement,
    nonce: "authority-nonce",
    sealedAt: AS_OF,
    expiresAt: overrides.expiresAt ?? EXPIRES,
  })
  return {
    canonicalPayload: canonical,
    actionDescription: "Payments scope",
    params: {},
    requester: { did: overrides.fourEyes ? "did:intyga:alice" : "did:intyga:admin", attestation: null },
    signatures: signers.map(([did, p]) => ({
      signerDid: did,
      signerPublicKey: spki(p),
      signature: sign(p, canonical),
      sigAlg: "ES256",
    })),
    verificationCode: verificationCode(canonical),
  }
}
const authorityGood = authorityReceipt([
  ["did:intyga:alice", alice],
  ["did:intyga:bob", bob],
])
const aliceSelfDid = selfCertifyingDid(spki(alice))
const selfAuthority = authorityReceipt([
  [aliceSelfDid, alice],
  ["did:intyga:bob", bob],
])
const wrongCarriedSelfAuthority = authorityReceipt([
  [aliceSelfDid, mallory],
  ["did:intyga:bob", bob],
])
const unknownAlgAuthority = structuredClone(authorityGood)
required(unknownAlgAuthority.signatures?.[0], "authority signature").sigAlg = "UNKNOWN"
const keyOnlyFourEyes = authorityReceipt(
  [
    ["did:intyga:mallory", alice],
    ["did:intyga:bob", bob],
  ],
  { fourEyes: true },
)
const agentAuthority = {
  expected: {
    approverDids: { "did:intyga:alice": ["alice"], "did:intyga:bob": ["bob"] },
    target: authorityTarget,
    agentDid,
  },
  options: { asOf: "2026-09-01T12:01:00.000Z" },
  cases: [
    {
      name: "valid-two-person-authority",
      receipt: authorityGood,
      ok: true,
      signers: ["did:intyga:alice", "did:intyga:bob"],
      actionPatterns: ["payments.", "refund"],
    },
    { name: "unknown-witness-algorithm-es256-fallback", receipt: unknownAlgAuthority, ok: true },
    {
      name: "key-only-authority-without-four-eyes",
      receipt: authorityGood,
      expected: { approverKeyIds: ["alice", "bob"] },
      ok: false,
    },
    {
      name: "four-eyes-requires-identity-trust",
      receipt: keyOnlyFourEyes,
      expected: { approverKeyIds: ["alice", "bob"] },
      ok: false,
    },
    {
      name: "duplicate-witness-cannot-satisfy-quorum",
      receipt: authorityReceipt([
        ["did:intyga:alice", alice],
        ["did:intyga:alice", alice],
      ]),
      ok: false,
    },
    { name: "insufficient-quorum", receipt: authorityReceipt([["did:intyga:alice", alice]]), ok: false },
    {
      name: "untrusted-signer-does-not-count",
      receipt: authorityReceipt([
        ["did:intyga:alice", alice],
        ["did:intyga:mallory", mallory],
      ]),
      ok: false,
    },
    {
      name: "expected-agent-tampered",
      receipt: authorityGood,
      expected: { agentDid: "did:intyga:agent:other" },
      ok: false,
    },
    {
      name: "expired-authority",
      receipt: authorityReceipt(
        [
          ["did:intyga:alice", alice],
          ["did:intyga:bob", bob],
        ],
        { expiresAt: "2026-09-01T12:00:01.000Z" },
      ),
      options: { asOf: "2026-09-01T12:01:00.000Z", clockSkewSeconds: 0 },
      ok: false,
    },
    {
      name: "self-certifying-did-fallback",
      receipt: selfAuthority,
      expected: { approverDids: { [aliceSelfDid]: [], "did:intyga:bob": ["bob"] } },
      ok: true,
    },
    {
      name: "self-certifying-did-wrong-carried-key",
      receipt: wrongCarriedSelfAuthority,
      expected: { approverDids: { [aliceSelfDid]: [], "did:intyga:bob": ["bob"] } },
      ok: false,
    },
    {
      name: "resolver-precedes-self-certifying-fallback",
      receipt: selfAuthority,
      expected: { approverDids: { [aliceSelfDid]: ["bob"], "did:intyga:bob": ["bob"] } },
      ok: false,
    },
  ],
}

function auditLeaf(tenantSeq: string, signed = false): AuditLeaf {
  const signedPayload = signed ? "signed parity event" : null
  return {
    seq: tenantSeq,
    tenantSeq,
    createdAt: AS_OF,
    event: "ACTION_APPROVED",
    outcome: "SUCCESS",
    detail: `event ${tenantSeq}`,
    metadata: { parity: true },
    signerDid: signed ? "did:intyga:alice" : null,
    signerPublicKey: signed ? spki(alice) : null,
    signedPayload,
    signature: signedPayload !== null ? sign(alice, signedPayload) : null,
    sigAlg: signed ? "ES256" : null,
    isBillable: false,
    tenantId: "tenant-1",
    actorNodeId: "node-1",
    subjectNodeId: null,
    edgeId: null,
    challengeId: null,
  }
}
function proofBundle(leaf: AuditLeaf): { bundle: ProofBundle; root: string } {
  const lh = leafHash(leaf),
    blockRoot = merkleRoot([lh]),
    root = merkleRoot([hashLeaf(blockRoot)])
  return {
    root,
    bundle: {
      kind: BUNDLE_KIND,
      version: 1,
      profile: "trust.intyga.audit.v1",
      exportedAt: AS_OF,
      event: {
        seq: leaf.seq,
        createdAt: leaf.createdAt,
        type: leaf.event,
        outcome: leaf.outcome,
        detail: leaf.detail,
        actorDid: null,
        subjectDid: null,
        signerDid: leaf.signerDid,
        signature: leaf.signature,
        sigAlg: leaf.sigAlg,
        canonical: leaf,
      },
      proof: {
        seq: leaf.seq,
        leaf: lh,
        blockIndex: "0",
        blockRoot,
        blockProof: [],
        leafIndex: 0,
        blockLeafCount: 1,
        checkpointId: "cp-1",
        checkpointRoot: root,
        checkpointProof: [],
        checkpointLeafIndex: 0,
        checkpointLeafCount: 1,
        anchorRef: "parity",
        anchored: true,
      },
    },
  }
}
const pb = proofBundle(auditLeaf("1", true))
// The checkpoint the proof's root belongs to: genesis, one entry at seq 1. Every anchor binds this
// position (DEWP §5.2) as well as the root.
const pbChainHash = chainHash({
  prevChainHash: "",
  root: pb.root,
  seqStart: "1",
  seqEnd: "1",
  entryCount: 1,
  anchoredAt: AS_OF,
})
const pbPosition = { seqStart: "1", seqEnd: "1", chainHash: pbChainHash }
// A single proof carries no checkpoint, so an external witness's time is bounded against the
// CALLER's record of it — the roots-file line for its root (DEWP §5.3/§6.2). Rekor cases pass it.
const pbTrustedCheckpoint = { root: pb.root, ...pbPosition, entryCount: 1, anchoredAt: AS_OF }
const AS_OF_SECONDS = Date.parse(AS_OF) / 1000
const anchorPairs: Array<[string, Pair, SignedAnchor["algorithm"]]> = [
  ["anchor-es256", anchorEc, "ES256"],
  ["anchor-ed25519", anchorEd, "Ed25519"],
  ["anchor-rsa-pss", anchorRsa, "RSA-PSS"],
]
const anchors = anchorPairs.map(([id, pair, algorithm]) => {
  const k = required(
    keys.find((x) => x.id === id),
    `anchor key ${id}`,
  )
  const base = {
    dailyRoot: pb.root,
    timestamp: AS_OF,
    issuer: required(k.issuer, `issuer ${id}`),
    algorithm,
    keyId: id,
    ...pbPosition,
  }
  return { ...base, signature: signAnchor(base, pair.privateKey) }
})
const divergentBase = {
  dailyRoot: "f".repeat(64),
  timestamp: AS_OF,
  issuer: required(required(keys[4], "ES256 anchor key").issuer, "ES256 issuer"),
  algorithm: "ES256" as const,
  keyId: "anchor-es256",
  ...pbPosition,
}
const divergent = { ...divergentBase, signature: signAnchor(divergentBase, anchorEc.privateKey) }

/** PEM for a hashedrekord `publicKey.content` (which carries base64 of the PEM text). */
const pem = (p: Pair): string => p.publicKey.export({ format: "pem", type: "spki" }).toString()
function rekorEntry(
  hash: string,
  opts: {
    integratedTime?: number
    submitter?: { pair: Pair; anchor: Parameters<typeof anchorDigest>[0] }
  } = {},
) {
  // Without a submitter the entry carries placeholder key material: nothing checks it unless the
  // caller pins the producer's submission key, which is exactly what the pinned cases exercise.
  const signature = opts.submitter
    ? {
        content: crypto
          .sign("sha256", anchorDigest(opts.submitter.anchor), {
            key: opts.submitter.pair.privateKey,
            dsaEncoding: "der",
          })
          .toString("base64"),
        publicKey: { content: Buffer.from(pem(opts.submitter.pair)).toString("base64") },
      }
    : { content: "c2ln", publicKey: { content: "cGs=" } }
  const body = Buffer.from(
    JSON.stringify({
      apiVersion: "0.0.1",
      kind: "hashedrekord",
      spec: {
        data: { hash: { algorithm: "sha256", value: hash } },
        signature,
      },
    }),
  ).toString("base64")
  const bare = {
    body,
    // Two minutes after the checkpoint's claimed time unless a case says otherwise: inside the
    // default DEWP §5.3 time bound.
    integratedTime: opts.integratedTime ?? AS_OF_SECONDS + 120,
    logID: "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
    logIndex: 4215889,
  }
  return {
    uuid: "24296fb24b8ad77a",
    ...bare,
    verification: {
      signedEntryTimestamp: crypto
        .sign("sha256", Buffer.from(JSON.stringify(bare)), { key: rekor.privateKey, dsaEncoding: "der" })
        .toString("base64"),
    },
  }
}
const rekorBase = {
  dailyRoot: pb.root,
  timestamp: AS_OF,
  issuer: "https://rekor.sigstore.dev",
  algorithm: "ES256" as const,
  keyId: "rekor",
  signature: "",
  kind: "REKOR",
  ...pbPosition,
}
const rekorEvidence = (entry: ReturnType<typeof rekorEntry>): string =>
  Buffer.from(JSON.stringify(entry)).toString("base64")
// Witnessed 117 days after the checkpoint claims to exist: what re-anchoring a rewritten old root
// today produces. Everything else about it is genuine.
const LATE_SECONDS = AS_OF_SECONDS + 117 * 86_400
const rekorLateAnchor = {
  ...rekorBase,
  evidence: rekorEvidence(rekorEntry(rekorPayloadHashFor(rekorBase), { integratedTime: LATE_SECONDS })),
}
// Witnessed an hour BEFORE the checkpoint claims to exist — beyond the clock-skew tolerance.
const rekorEarlyAnchor = {
  ...rekorBase,
  evidence: rekorEvidence(
    rekorEntry(rekorPayloadHashFor(rekorBase), { integratedTime: AS_OF_SECONDS - 3600 }),
  ),
}
// Submitted under the producer's own anchor key (anchor-es256), and under an impostor's.
const rekorPinnedAnchor = {
  ...rekorBase,
  evidence: rekorEvidence(
    rekorEntry(rekorPayloadHashFor(rekorBase), { submitter: { pair: anchorEc, anchor: rekorBase } }),
  ),
}
const rekorImpostorAnchor = {
  ...rekorBase,
  evidence: rekorEvidence(
    rekorEntry(rekorPayloadHashFor(rekorBase), { submitter: { pair: mallory, anchor: rekorBase } }),
  ),
}
const rekorAnchor = {
  ...rekorBase,
  evidence: Buffer.from(JSON.stringify(rekorEntry(rekorPayloadHashFor(rekorBase)))).toString("base64"),
}
const secondRekorLabelBase = {
  ...rekorBase,
  issuer: "https://second-label.example",
}
const secondRekorLabelAnchor = {
  ...secondRekorLabelBase,
  evidence: Buffer.from(JSON.stringify(rekorEntry(rekorPayloadHashFor(secondRekorLabelBase)))).toString(
    "base64",
  ),
}
const secondLabelDivergentBase = {
  ...secondRekorLabelBase,
  dailyRoot: "d".repeat(64),
}
const secondLabelDivergentAnchor = {
  ...secondLabelDivergentBase,
  evidence: Buffer.from(JSON.stringify(rekorEntry(rekorPayloadHashFor(secondLabelDivergentBase)))).toString(
    "base64",
  ),
}
const badRekor = {
  ...rekorBase,
  evidence: Buffer.from(
    JSON.stringify(rekorEntry(crypto.createHash("sha256").update("wrong").digest("hex"))),
  ).toString("base64"),
}
// Signed over the right root by a trusted key, but for a DIFFERENT seq range: not evidence for this
// checkpoint. Only the evidence harness can hold it against a checkpoint position (see below).
const anchorPolicy = { requiredAnchors: 2, trustedIssuers: anchors.map((a) => a.issuer), quorum: "N_OF_M" }
const rekorOnly = { requiredAnchors: 1, trustedIssuers: [rekorBase.issuer], quorum: "N_OF_M" }
const bundles = {
  anchorPolicy,
  cases: [
    ...anchors.map((anchor) => ({
      name: `single-anchor-${anchor.algorithm}`,
      bundle: { ...pb.bundle, anchors: [anchor] },
      policy: { requiredAnchors: 1, trustedIssuers: [anchor.issuer], quorum: "N_OF_M" },
      options: { trustedRoot: pb.root },
      ok: true,
      properties: { anchorVerified: true },
    })),
    ...anchors.map((anchor) => ({
      name: `tampered-anchor-${anchor.algorithm}`,
      bundle: { ...pb.bundle, anchors: [{ ...anchor, timestamp: "2026-09-02T12:00:00.000Z" }] },
      policy: { requiredAnchors: 1, trustedIssuers: [anchor.issuer], quorum: "N_OF_M" },
      options: { trustedRoot: pb.root },
      ok: false,
      properties: { anchorVerified: false },
    })),
    {
      name: "redacted-single-bundle-with-quorum",
      bundle: { ...pb.bundle, event: { ...pb.bundle.event, canonical: undefined }, anchors },
      options: { trustedRoot: pb.root },
      ok: true,
      verificationLevel: "COMMITMENT_VERIFIED",
      properties: { contentVerified: false, anchorVerified: true },
    },
    {
      name: "embedded-signature-and-three-algorithm-quorum",
      bundle: { ...pb.bundle, anchors },
      options: { trustedRoot: pb.root, anchorKeyIds: anchorPairs.map(([id]) => id) },
      ok: true,
      verificationLevel: "FULLY_VERIFIED",
      properties: {
        commitmentVerified: true,
        contentVerified: true,
        signatureVerified: true,
        anchorVerified: true,
      },
    },
    {
      name: "insufficient-anchor-quorum",
      bundle: { ...pb.bundle, anchors: [anchors[0]] },
      options: { trustedRoot: pb.root, anchorKeyIds: ["anchor-es256"] },
      ok: false,
      properties: { anchorVerified: false },
    },
    {
      name: "caller-attributed-anchor-divergence",
      bundle: { ...pb.bundle, anchors },
      options: {
        trustedRoot: pb.root,
        anchorKeyIds: anchorPairs.map(([id]) => id),
        divergenceAnchors: [divergent],
      },
      ok: false,
      verificationLevel: "INVALID",
      properties: { anchorVerified: false },
    },
    {
      name: "proof-seq-tampering",
      bundle: { ...pb.bundle, proof: { ...pb.bundle.proof, seq: "999" } },
      options: { trustedRoot: pb.root },
      ok: false,
      properties: { contentVerified: false },
    },
    {
      name: "header-tampering",
      bundle: { ...pb.bundle, event: { ...pb.bundle.event, outcome: "FAILURE" } },
      options: { trustedRoot: pb.root },
      ok: false,
      properties: { contentVerified: false },
    },
    {
      name: "unknown-profile-refused",
      bundle: { ...pb.bundle, profile: "unknown.profile" },
      options: { trustedRoot: pb.root },
      ok: false,
      properties: { contentVerified: false },
    },
    {
      name: "valid-rekor-anchor",
      bundle: { ...pb.bundle, anchors: [rekorAnchor] },
      policy: { requiredAnchors: 1, trustedIssuers: [rekorBase.issuer], quorum: "N_OF_M" },
      options: { trustedRoot: pb.root, trustedCheckpoint: pbTrustedCheckpoint, rekorKeyId: "rekor" },
      ok: true,
      properties: { anchorVerified: true },
      witnessTimes: { [rekorBase.issuer]: AS_OF_SECONDS + 120 },
    },
    {
      name: "rekor-scoped-issuer-in-multi-issuer-policy",
      bundle: { ...pb.bundle, anchors: [rekorAnchor] },
      policy: {
        requiredAnchors: 1,
        trustedIssuers: [rekorBase.issuer, secondRekorLabelBase.issuer],
        quorum: "N_OF_M",
      },
      options: {
        trustedRoot: pb.root,
        trustedCheckpoint: pbTrustedCheckpoint,
        rekorKeyId: "rekor",
        rekorIssuer: rekorBase.issuer,
      },
      ok: true,
      properties: { anchorVerified: true },
    },
    {
      name: "rekor-wrong-issuer-scope-refused",
      bundle: { ...pb.bundle, anchors: [rekorAnchor] },
      policy: {
        requiredAnchors: 1,
        trustedIssuers: [rekorBase.issuer, secondRekorLabelBase.issuer],
        quorum: "N_OF_M",
      },
      options: {
        trustedRoot: pb.root,
        trustedCheckpoint: pbTrustedCheckpoint,
        rekorKeyId: "rekor",
        rekorIssuer: secondRekorLabelBase.issuer,
      },
      ok: false,
      properties: { anchorVerified: false },
    },
    {
      name: "rekor-unscoped-multi-issuer-refused",
      bundle: { ...pb.bundle, anchors: [rekorAnchor] },
      policy: {
        requiredAnchors: 1,
        trustedIssuers: [rekorBase.issuer, secondRekorLabelBase.issuer],
        quorum: "N_OF_M",
      },
      options: { trustedRoot: pb.root, trustedCheckpoint: pbTrustedCheckpoint, rekorKeyId: "rekor" },
      ok: false,
      properties: { anchorVerified: false },
    },
    {
      name: "rekor-one-key-two-labels-cannot-fill-quorum",
      bundle: { ...pb.bundle, anchors: [rekorAnchor, secondRekorLabelAnchor] },
      policy: {
        requiredAnchors: 2,
        trustedIssuers: [rekorBase.issuer, secondRekorLabelBase.issuer],
        quorum: "N_OF_M",
      },
      options: {
        trustedRoot: pb.root,
        trustedCheckpoint: pbTrustedCheckpoint,
        rekorKeyId: "rekor",
        rekorIssuer: rekorBase.issuer,
      },
      ok: false,
      properties: { anchorVerified: false },
    },
    {
      name: "rekor-wrong-label-cannot-declare-divergence",
      bundle: { ...pb.bundle, anchors: [rekorAnchor] },
      policy: {
        requiredAnchors: 1,
        trustedIssuers: [rekorBase.issuer, secondRekorLabelBase.issuer],
        quorum: "N_OF_M",
      },
      options: {
        trustedRoot: pb.root,
        trustedCheckpoint: pbTrustedCheckpoint,
        rekorKeyId: "rekor",
        rekorIssuer: rekorBase.issuer,
        divergenceAnchors: [rekorAnchor, secondLabelDivergentAnchor],
      },
      ok: true,
      properties: { anchorVerified: true },
    },
    {
      name: "rekor-anchor-witnessed-after-lag-refused",
      bundle: { ...pb.bundle, anchors: [rekorLateAnchor] },
      policy: rekorOnly,
      options: { trustedRoot: pb.root, trustedCheckpoint: pbTrustedCheckpoint, rekorKeyId: "rekor" },
      ok: false,
      properties: { anchorVerified: false },
      witnessTimes: { [rekorBase.issuer]: LATE_SECONDS },
    },
    {
      name: "rekor-anchor-lag-within-caller-policy",
      bundle: { ...pb.bundle, anchors: [rekorLateAnchor] },
      policy: { ...rekorOnly, maxAnchorLagSeconds: 200 * 86_400 },
      options: { trustedRoot: pb.root, trustedCheckpoint: pbTrustedCheckpoint, rekorKeyId: "rekor" },
      ok: true,
      properties: { anchorVerified: true },
      witnessTimes: { [rekorBase.issuer]: LATE_SECONDS },
    },
    {
      name: "rekor-anchor-witnessed-before-checkpoint-refused",
      bundle: { ...pb.bundle, anchors: [rekorEarlyAnchor] },
      policy: rekorOnly,
      options: { trustedRoot: pb.root, trustedCheckpoint: pbTrustedCheckpoint, rekorKeyId: "rekor" },
      ok: false,
      properties: { anchorVerified: false },
      witnessTimes: { [rekorBase.issuer]: AS_OF_SECONDS - 3600 },
    },
    {
      name: "rekor-pinned-submitter-key-verifies",
      bundle: { ...pb.bundle, anchors: [rekorPinnedAnchor] },
      policy: rekorOnly,
      options: {
        trustedRoot: pb.root,
        trustedCheckpoint: pbTrustedCheckpoint,
        rekorKeyId: "rekor",
        rekorSubmitterKeyIds: ["anchor-es256"],
      },
      ok: true,
      properties: { anchorVerified: true },
    },
    {
      name: "rekor-unpinned-submitter-key-refused",
      bundle: { ...pb.bundle, anchors: [rekorImpostorAnchor] },
      policy: rekorOnly,
      options: {
        trustedRoot: pb.root,
        trustedCheckpoint: pbTrustedCheckpoint,
        rekorKeyId: "rekor",
        rekorSubmitterKeyIds: ["anchor-es256"],
      },
      ok: false,
      properties: { anchorVerified: false },
    },
    {
      name: "rekor-placeholder-submitter-refused-when-pinned",
      bundle: { ...pb.bundle, anchors: [rekorAnchor] },
      policy: rekorOnly,
      options: {
        trustedRoot: pb.root,
        trustedCheckpoint: pbTrustedCheckpoint,
        rekorKeyId: "rekor",
        rekorSubmitterKeyIds: ["anchor-es256"],
      },
      ok: false,
      properties: { anchorVerified: false },
    },
    {
      name: "anchor-without-position-fields-refused",
      bundle: {
        ...pb.bundle,
        anchors: [
          (() => {
            const { chainHash: _omitted, ...rest } = required(anchors[0], "first anchor")
            return rest
          })(),
        ],
      },
      policy: {
        requiredAnchors: 1,
        trustedIssuers: [required(anchors[0], "first anchor").issuer],
        quorum: "N_OF_M",
      },
      options: { trustedRoot: pb.root },
      ok: false,
      properties: { anchorVerified: false },
    },
    {
      name: "rekor-wrong-payload-refused",
      bundle: { ...pb.bundle, anchors: [badRekor] },
      policy: { requiredAnchors: 1, trustedIssuers: [rekorBase.issuer], quorum: "N_OF_M" },
      options: { trustedRoot: pb.root, trustedCheckpoint: pbTrustedCheckpoint, rekorKeyId: "rekor" },
      ok: false,
      properties: { anchorVerified: false },
    },
    {
      name: "unknown-anchor-algorithm-refused",
      bundle: { ...pb.bundle, anchors: [{ ...anchors[0], algorithm: "DSA" }] },
      options: { trustedRoot: pb.root, anchorKeyIds: ["anchor-es256"] },
      ok: false,
      properties: { anchorVerified: false },
    },
    {
      name: "unrelated-carried-anchor-does-not-diverge",
      bundle: { ...pb.bundle, anchors: [divergent] },
      options: { trustedRoot: pb.root },
      ok: false,
      properties: { anchorVerified: false },
    },
  ],
}

function evidenceBundle(tenantSeqs: string[]): { bundle: EvidenceBundle; root: string; chainHash: string } {
  const leaves = tenantSeqs.map((n, i) => ({ ...auditLeaf(n), seq: String(i + 1), detail: `event ${i + 1}` }))
  const hashes = leaves.map(leafHash),
    blockRoot = merkleRoot(hashes),
    root = merkleRoot([hashLeaf(blockRoot)])
  const cpChainHash = chainHash({
    prevChainHash: "",
    root,
    seqStart: "1",
    seqEnd: String(leaves.length),
    entryCount: leaves.length,
    anchoredAt: AS_OF,
  })
  return {
    root,
    chainHash: cpChainHash,
    bundle: {
      kind: EVIDENCE_BUNDLE_KIND,
      version: 1,
      profile: "trust.intyga.audit.v1",
      exportedAt: AS_OF,
      tenant: { id: "tenant-1", name: "Parity" },
      range: { from: AS_OF, to: EXPIRES },
      checkpoints: [
        {
          id: "cp-1",
          root,
          anchorRef: "parity",
          anchoredAt: AS_OF,
          seqStart: "1",
          seqEnd: String(leaves.length),
          entryCount: leaves.length,
          prevChainHash: "",
          chainHash: cpChainHash,
        },
      ],
      entries: leaves.map((leaf, i) => ({
        event: {
          seq: leaf.seq,
          createdAt: leaf.createdAt,
          type: leaf.event,
          outcome: leaf.outcome,
          redacted: false,
          tenantSeq: leaf.tenantSeq,
          signerDid: null,
          sigAlg: null,
          canonical: leaf,
        },
        proof: {
          seq: leaf.seq,
          leaf: required(hashes[i], `leaf hash ${i}`),
          blockIndex: "0",
          blockRoot,
          blockProof: merkleProof(hashes, i),
          leafIndex: i,
          blockLeafCount: hashes.length,
          checkpointId: "cp-1",
          checkpointRoot: root,
          checkpointProof: [],
          checkpointLeafIndex: 0,
          checkpointLeafCount: 1,
          anchorRef: "parity",
          anchored: true,
        },
      })),
    },
  }
}
const evGood = evidenceBundle(["1", "2", "3"]),
  evGap = evidenceBundle(["1", "3"]),
  evDup = evidenceBundle(["1", "1"]),
  evMalformed = evidenceBundle(["1", "not-a-counter"])
const evAnchorBase = {
  dailyRoot: evGood.root,
  timestamp: AS_OF,
  issuer: required(anchors[0], "first anchor").issuer,
  algorithm: "ES256" as const,
  keyId: "anchor-es256",
  seqStart: "1",
  seqEnd: "3",
  chainHash: evGood.chainHash,
}
const evAnchor = { ...evAnchorBase, signature: signAnchor(evAnchorBase, anchorEc.privateKey) }
// A genuine signature over this root, but binding a different seq range: not this checkpoint's anchor.
const evWrongRangeBase = { ...evAnchorBase, seqEnd: "4" }
const evWrongRange = { ...evWrongRangeBase, signature: signAnchor(evWrongRangeBase, anchorEc.privateKey) }
// A genuine signature over a DIFFERENT root for this checkpoint's exact position: real divergence.
const evDivergentBase = { ...evAnchorBase, dailyRoot: "f".repeat(64) }
const evDivergent = { ...evDivergentBase, signature: signAnchor(evDivergentBase, anchorEc.privateKey) }
// A genuine signature over a different root AND a different seq range: another checkpoint's anchor.
const evOtherCheckpointBase = { ...evDivergentBase, seqStart: "4", seqEnd: "6" }
const evOtherCheckpoint = {
  ...evOtherCheckpointBase,
  signature: signAnchor(evOtherCheckpointBase, anchorEc.privateKey),
}
const evFirstCheckpoint = required(evGood.bundle.checkpoints[0], "first checkpoint")
const evPolicy = { requiredAnchors: 1, trustedIssuers: [evAnchor.issuer], quorum: "N_OF_M" }
const evAnchored = {
  ...evGood.bundle,
  checkpoints: [
    { ...required(evGood.bundle.checkpoints[0], "first checkpoint"), anchors: [evAnchor, divergent] },
  ],
}
const firstEvidenceEntry = required(evGood.bundle.entries[0], "first evidence entry")
const evidence = {
  cases: [
    {
      name: "evidence-bundle-anchor-quorum",
      bundle: evAnchored,
      policy: evPolicy,
      options: { trustedRoots: [evGood.root] },
      ok: true,
    },
    {
      name: "evidence-stripped-anchors-fail-policy",
      bundle: evGood.bundle,
      policy: evPolicy,
      options: { trustedRoots: [evGood.root] },
      ok: false,
    },
    {
      name: "evidence-caller-keyed-divergence",
      bundle: evAnchored,
      policy: evPolicy,
      options: { trustedRoots: [evGood.root], anchors: { "cp-1": [evDivergent] } },
      ok: false,
    },
    {
      // Keyed to cp-1 by the caller and signed over a different root, but its own signed range names
      // ANOTHER checkpoint (seq 4..6), so it is not divergence for cp-1 — a caller mis-filing a
      // genuine anchor must not produce a tamper alarm. evAnchor still meets the quorum.
      name: "evidence-caller-keyed-other-range-is-not-divergence",
      bundle: evAnchored,
      policy: evPolicy,
      options: { trustedRoots: [evGood.root], anchors: { "cp-1": [evAnchor, evOtherCheckpoint] } },
      ok: true,
    },
    {
      name: "evidence-anchor-for-other-seq-range-does-not-count",
      bundle: { ...evGood.bundle, checkpoints: [{ ...evFirstCheckpoint, anchors: [evWrongRange] }] },
      policy: evPolicy,
      options: { trustedRoots: [evGood.root] },
      ok: false,
    },
    {
      name: "evidence-checkpoint-chain-hash-tampered",
      bundle: {
        ...evGood.bundle,
        checkpoints: [{ ...evFirstCheckpoint, chainHash: "e".repeat(64), anchors: [evAnchor] }],
      },
      options: { trustedRoots: [evGood.root] },
      ok: false,
    },
    {
      // The chain hash commits to anchoredAt, so a checkpoint re-dated after the fact no longer
      // recomputes — and an anchor's time bound is measured from this committed instant.
      name: "evidence-checkpoint-anchored-at-rewritten",
      bundle: {
        ...evGood.bundle,
        checkpoints: [{ ...evFirstCheckpoint, anchoredAt: "2026-09-02T12:00:00.000Z", anchors: [evAnchor] }],
      },
      options: { trustedRoots: [evGood.root] },
      ok: false,
    },
    {
      name: "evidence-caller-keyed-quorum",
      bundle: evGood.bundle,
      policy: evPolicy,
      options: { trustedRoots: [evGood.root], anchors: { "cp-1": [evAnchor] } },
      ok: true,
    },
    {
      name: "evidence-caller-flat-quorum",
      bundle: evGood.bundle,
      policy: evPolicy,
      options: { trustedRoots: [evGood.root], anchors: [evAnchor] },
      ok: true,
    },
    {
      name: "claimed-range-truncated",
      bundle: {
        ...evGood.bundle,
        tenantSequenceCommitment: { tenantId: "tenant-1", firstTenantSeq: "1", lastTenantSeq: "4" },
      },
      options: { trustedRoots: [evGood.root] },
      ok: false,
    },
    {
      name: "redaction-marker-cannot-hide-content-tampering",
      bundle: {
        ...evGood.bundle,
        entries: [
          {
            ...firstEvidenceEntry,
            event: {
              ...firstEvidenceEntry.event,
              redaction: {
                mode: "COMMITMENT_ONLY" as const,
                removedFields: [],
                redactedAt: AS_OF,
                reason: "test",
              },
              type: "FORGED",
            },
          },
          ...evGood.bundle.entries.slice(1),
        ],
      },
      options: { trustedRoots: [evGood.root] },
      ok: false,
    },
    {
      name: "canonical-with-redaction-marker-is-bound",
      bundle: {
        ...evGood.bundle,
        entries: [
          {
            ...firstEvidenceEntry,
            event: {
              ...firstEvidenceEntry.event,
              redaction: {
                mode: "COMMITMENT_ONLY" as const,
                removedFields: [],
                redactedAt: AS_OF,
                reason: "test",
              },
            },
          },
          ...evGood.bundle.entries.slice(1),
        ],
      },
      options: { trustedRoots: [evGood.root] },
      ok: true,
      contentVerified: 3,
    },
    {
      name: "contiguous-tenant-sequence",
      bundle: evGood.bundle,
      options: { trustedRoots: [evGood.root] },
      ok: true,
      total: 3,
      contentVerified: 3,
    },
    { name: "tenant-sequence-gap", bundle: evGap.bundle, options: { trustedRoots: [evGap.root] }, ok: false },
    {
      name: "tenant-sequence-duplicate",
      bundle: evDup.bundle,
      options: { trustedRoots: [evDup.root] },
      ok: false,
    },
    {
      name: "tenant-sequence-malformed",
      bundle: evMalformed.bundle,
      options: { trustedRoots: [evMalformed.root] },
      ok: false,
    },
    {
      name: "displayed-type-tampering",
      bundle: {
        ...evGood.bundle,
        entries: [
          { ...firstEvidenceEntry, event: { ...firstEvidenceEntry.event, type: "DOC_SIGNED" } },
          ...evGood.bundle.entries.slice(1),
        ],
      },
      options: { trustedRoots: [evGood.root] },
      ok: false,
    },
    {
      name: "displayed-tenant-tampering",
      bundle: { ...evGood.bundle, tenant: { id: "other", name: "Other" } },
      options: { trustedRoots: [evGood.root] },
      ok: false,
    },
    {
      name: "redacted-anchored-commitment",
      bundle: {
        ...evGood.bundle,
        entries: [
          {
            ...firstEvidenceEntry,
            event: { ...firstEvidenceEntry.event, redacted: true, canonical: undefined },
          },
          ...evGood.bundle.entries.slice(1),
        ],
      },
      options: { trustedRoots: [evGood.root] },
      ok: true,
      commitmentOnly: 1,
    },
  ],
}

function chainEntry(prev: string, root: string, start: string, end: string): RootsChainEntry {
  const e = {
    prevChainHash: prev,
    root,
    seqStart: start,
    seqEnd: end,
    entryCount: Number(BigInt(end) - BigInt(start) + 1n),
    anchoredAt: AS_OF,
  }
  return { ...e, chainHash: chainHash(e) }
}
/** chainEntry with an explicit entryCount, so a deliberately malformed seq range can still be built
 *  (the derived count would throw on a non-integer end). The chainHash is still correct, which is
 *  the point: the file is internally consistent and only the RANGE is malformed. */
function chainEntryRaw(
  prev: string,
  root: string,
  start: string,
  end: string,
  count: number,
): RootsChainEntry {
  const e = { prevChainHash: prev, root, seqStart: start, seqEnd: end, entryCount: count, anchoredAt: AS_OF }
  return { ...e, chainHash: chainHash(e) }
}
const c1 = chainEntry("", "1".repeat(64), "1", "2"),
  c2 = chainEntry(required(c1.chainHash, "first chain hash"), "2".repeat(64), "4", "5")
const rootsChain = {
  cases: [
    {
      name: "valid-continuity-with-global-seq-gap",
      entries: [c1, c2],
      ok: true,
      verifiedCount: 2,
      brokenAt: -1,
      unchained: false,
    },
    {
      name: "checkpoint-link-tampered",
      entries: [c1, { ...c2, prevChainHash: "f".repeat(64) }],
      ok: false,
      brokenAt: 1,
      unchained: false,
    },
    {
      name: "legacy-unchained",
      entries: [{ root: c1.root, seqStart: "1", seqEnd: "2", entryCount: 2, anchoredAt: AS_OF }],
      ok: false,
      brokenAt: -1,
      unchained: true,
    },
    // A single-entry roots file is a new tenant, or the first day after a truncation — and it is
    // exactly the shape where the first entry is the ONLY entry. TS, Java and Python gated their
    // seq-range checks on having a predecessor, so this file verified clean in three ports and was
    // refused by Go and Rust. Both cases below are single-entry on purpose.
    {
      name: "single-entry-inverted-seq-range",
      entries: [chainEntryRaw("", "3".repeat(64), "10", "5", 1)],
      ok: false,
      verifiedCount: 0,
      brokenAt: 0,
      unchained: false,
    },
    {
      name: "single-entry-non-integer-seq-range",
      entries: [chainEntryRaw("", "4".repeat(64), "1", "not-a-number", 1)],
      ok: false,
      verifiedCount: 0,
      brokenAt: 0,
      unchained: false,
    },
    // brokenAt is how an operator LOCATES a splice, so it must point at the first unchained line,
    // not at 0. Go hardcoded 0 here and Java credited the entries before the splice.
    {
      name: "mixed-chained-and-unchained",
      entries: [c1, { root: c2.root, seqStart: "4", seqEnd: "5", entryCount: 2, anchoredAt: AS_OF }],
      ok: false,
      verifiedCount: 0,
      brokenAt: 1,
      unchained: false,
    },
  ],
}

// Spec-derived backstops: valid signatures must not disguise a wrong trust-anchor shape.
const quorumAlice = ec(),
  quorumBob = ec()
keys.push(
  { id: "quorum-alice", did: "did:intyga:alice", spkiB64: spki(quorumAlice) },
  { id: "quorum-bob", did: "did:intyga:bob", spkiB64: spki(quorumBob) },
)
const quorumCanonical = approvalGood.canonicalPayload.replace(
  '"requiredApprovals":1',
  '"requiredApprovals":2',
)
const quorumReceipt: ApprovalReceipt = {
  ...approvalGood,
  canonicalPayload: quorumCanonical,
  signatures: [quorumAlice, quorumBob].map((p, i) => ({
    signerDid: i === 0 ? "did:intyga:alice" : "did:intyga:bob",
    signerPublicKey: spki(p),
    signature: sign(p, quorumCanonical),
    sigAlg: "ES256",
  })),
  verificationCode: verificationCode(quorumCanonical),
}
const extraApprovalCases = [
  {
    name: "multi-person-quorum-refuses-key-only-trust",
    receipt: quorumReceipt,
    expected: { approverKeyIds: ["quorum-alice", "quorum-bob"] },
    ok: false,
    reasonIncludes: "multi-approver quorum requires a DID-mode trust anchor",
  },
  ...[undefined, null].map((sigAlg) => ({
    name: `legacy-${sigAlg === null ? "null" : "missing"}-sigalg`,
    receipt: { ...approvalGood, sigAlg },
    ok: true,
    signers: [spki(alice)],
  })),
  {
    name: "auto-approved-witness-never-falls-back",
    receipt: {
      ...approvalGood,
      signatures: [
        {
          signerDid: "did:intyga:alice",
          signerPublicKey: spki(alice),
          signature: required(approvalGood.signature, "approvalGood.signature"),
          sigAlg: "AUTO_APPROVED",
        },
      ],
    },
    ok: false,
  },
]
// PK-11 (DIV §4.4.5 rule 6): under a signed requireHardwareKey, a WEBAUTHN witness whose signed
// authenticatorData says Backup Eligible / Backup State is refused; without the requirement a synced
// passkey is an ordinary approver. These cases carry `approverKeyEncoding: "cose"`: a WEBAUTHN
// witness verifies under the credential's COSE_Key, so the harness pins `coseB64`, not `spkiB64`.
const passkeyHolder = ec()
keys.push({
  id: "passkey-holder",
  did: "did:intyga:passkey-holder",
  spkiB64: spki(passkeyHolder),
  coseB64: cose(passkeyHolder),
})
const WEBAUTHN_RP = "app.example.com"
const WEBAUTHN_ORIGIN = "https://app.example.com"
function webauthnApproval(flags: number, requireHardwareKey: boolean): ApprovalReceipt {
  const requester = { did: "did:intyga:agent:payments", attestation: null }
  const canonical = canonicalIntentPayload({
    target: approvalTarget,
    actionType: approvalActionType,
    display: "Wire USD 4,200",
    params: approvalParams,
    requester,
    requirement: {
      requiredApprovals: 1,
      requireHardwareKey,
      allowedAaguids: [],
      requesterCannotApprove: false,
      signerClass: "human",
    },
    nonce: approvalNonce,
    expiresAt: EXPIRES,
  })
  const client = Buffer.from(
    JSON.stringify({
      type: "webauthn.get",
      challenge: Buffer.from(canonical).toString("base64url"),
      origin: WEBAUTHN_ORIGIN,
      crossOrigin: false,
    }),
  )
  const auth = Buffer.concat([
    crypto.createHash("sha256").update(WEBAUTHN_RP).digest(),
    Buffer.from([flags, 0, 0, 0, 1]),
  ])
  const signature = crypto.sign(
    "sha256",
    Buffer.concat([auth, crypto.createHash("sha256").update(client).digest()]),
    { key: passkeyHolder.privateKey, dsaEncoding: "der" },
  )
  return {
    canonicalPayload: canonical,
    target: approvalTarget,
    actionType: approvalActionType,
    actionDescription: "Wire USD 4,200",
    params: approvalParams,
    requester,
    signerDid: "did:intyga:passkey-holder",
    signerPublicKey: cose(passkeyHolder),
    signature: signature.toString("base64url"),
    sigAlg: "WEBAUTHN",
    authenticatorData: auth.toString("base64url"),
    clientDataJSON: client.toString("base64url"),
    verificationCode: verificationCode(canonical),
  }
}
const UP_UV = 0x05
const webauthnHardwareCases = [
  { name: "webauthn-device-bound-under-hardware-key", flags: UP_UV, requireHardwareKey: true, ok: true },
  {
    name: "webauthn-backup-eligible-under-hardware-key-refused",
    flags: UP_UV | 0x08,
    requireHardwareKey: true,
    ok: false,
  },
  {
    name: "webauthn-backed-up-under-hardware-key-refused",
    flags: UP_UV | 0x18,
    requireHardwareKey: true,
    ok: false,
  },
  {
    name: "webauthn-backup-state-only-under-hardware-key-refused",
    flags: UP_UV | 0x10,
    requireHardwareKey: true,
    ok: false,
  },
  {
    name: "webauthn-synced-without-hardware-key-verifies",
    flags: UP_UV | 0x18,
    requireHardwareKey: false,
    ok: true,
  },
].map((c) => ({
  name: c.name,
  receipt: webauthnApproval(c.flags, c.requireHardwareKey),
  approverKeyEncoding: "cose",
  expected: { approverKeyIds: ["passkey-holder"] },
  options: { asOf: "2026-09-01T12:01:00.000Z", expectedOrigin: WEBAUTHN_ORIGIN, expectedRpId: WEBAUTHN_RP },
  ok: c.ok,
  ...(c.ok ? { signers: [cose(passkeyHolder)] } : { reasonIncludes: "backup-eligible" }),
}))
// DIV §5 step 3d: the relying party's own minimum requirement (`expected.requirement`). The signed
// requirement is authored by the signers, so without a floor a verifier proves only the quorum they
// stated. These reuse already-signed receipts: the floor is a verifier INPUT, never signed bytes.
const WEAKER = "weaker than the relying party's policy"
const floor = (requiredApprovals: number, requesterCannotApprove = false, requireHardwareKey = false) => ({
  requirement: { requiredApprovals, requesterCannotApprove, requireHardwareKey },
})
const deviceBound = required(webauthnHardwareCases[0], "device-bound WebAuthn case")
const requirementFloorCases = [
  {
    name: "requirement-floor-absent-proves-only-signed-quorum",
    receipt: approvalGood,
    ok: true,
    signers: [spki(alice)],
  },
  {
    name: "requirement-floor-quorum-downgrade-refused",
    receipt: approvalGood,
    expected: floor(2, true),
    ok: false,
    reasonIncludes: WEAKER,
  },
  {
    name: "requirement-floor-four-eyes-downgrade-refused",
    receipt: approvalGood,
    expected: floor(1, true),
    ok: false,
    reasonIncludes: WEAKER,
  },
  {
    name: "requirement-floor-hardware-downgrade-refused",
    receipt: approvalGood,
    expected: floor(1, false, true),
    ok: false,
    reasonIncludes: WEAKER,
  },
  {
    name: "requirement-floor-equal-accepted",
    receipt: approvalGood,
    expected: floor(1),
    ok: true,
    signers: [spki(alice)],
  },
  {
    name: "requirement-floor-hardware-equal-accepted",
    receipt: deviceBound.receipt,
    approverKeyEncoding: "cose",
    expected: { ...deviceBound.expected, ...floor(1, false, true) },
    options: deviceBound.options,
    ok: true,
    signers: [cose(passkeyHolder)],
  },
]
const authorityFloorCases = [
  {
    name: "authority-requirement-floor-downgrade-refused",
    receipt: authorityGood,
    expected: floor(3),
    ok: false,
    reasonIncludes: WEAKER,
  },
  {
    name: "authority-requirement-floor-equal-accepted",
    receipt: authorityGood,
    expected: floor(2),
    ok: true,
    signers: ["did:intyga:alice", "did:intyga:bob"],
  },
]
const registry = { hashAlgorithm: "SHA-256", serialization: "RFC8785-JCS", merkleVersion: 1 }
const envelopeCases = [
  { name: "empty-protocol", patch: { protocol: "", version: "1.0" }, ok: false },
  {
    name: "registry-field-case",
    patch: {
      algorithmRegistry: { HashAlgorithm: "SHA-256", serialization: "RFC8785-JCS", merkleVersion: 1 },
    },
    ok: false,
  },
  { name: "legacy-revision-two", patch: { version: 2 }, ok: true },
  { name: "null-registry", patch: { algorithmRegistry: null }, ok: false },
  {
    name: "current-envelope",
    patch: { protocol: "DEWP", version: "1.0", algorithmRegistry: registry },
    ok: true,
  },
  { name: "wrong-protocol", patch: { protocol: "OTHER", version: "1.0" }, ok: false },
  { name: "future-version", patch: { protocol: "DEWP", version: "2.0" }, ok: false },
  { name: "wrong-legacy-version", patch: { version: 3 }, ok: false },
  { name: "missing-version", patch: { version: undefined }, ok: false },
  { name: "wrong-hash", patch: { algorithmRegistry: { ...registry, hashAlgorithm: "SHA-512" } }, ok: false },
  {
    name: "wrong-serialization",
    patch: { algorithmRegistry: { ...registry, serialization: "JSON" } },
    ok: false,
  },
  {
    name: "wrong-merkle-version",
    patch: { algorithmRegistry: { ...registry, merkleVersion: 2 } },
    ok: false,
  },
  { name: "incomplete-registry", patch: { algorithmRegistry: {} }, ok: false },
]
const proofBase = required(bundles.cases[0], "bundles.cases[0]")
const evidenceBase = required(
  evidence.cases.find((c) => c.name === "contiguous-tenant-sequence"),
  "contiguous-tenant-sequence evidence case",
)

const out = {
  version: 1,
  generated: new Date().toISOString(),
  note: "Executable cross-language verifier parity cases. Private signing keys are intentionally omitted.",
  // A port that checks only `ok` proves far less than it looks: a refusal landing for the wrong
  // reason, or an acceptance crediting the wrong identities, both read as green. Every port's parity
  // test must assert EVERY optional field a case carries, not just the verdict. This is how Go came
  // to report a wrong-shaped trust anchor as a quorum shortfall while its vectors stayed green.
  mustAssert:
    "Besides `ok`, assert every optional field present on a case: signers, reasonIncludes, actionPatterns, verificationLevel, properties, witnessTimes, total, contentVerified, commitmentOnly, brokenAt, unchained, verifiedCount. Bundle options may carry rekorSubmitterKeyIds (map to the pinned Rekor submitter keys); a policy may carry maxAnchorLagSeconds.",
  keys,
  approvals: {
    ...approvals,
    cases: [...approvals.cases, ...extraApprovalCases, ...webauthnHardwareCases, ...requirementFloorCases],
  },
  platform,
  agentAuthority: { ...agentAuthority, cases: [...agentAuthority.cases, ...authorityFloorCases] },
  bundles: {
    ...bundles,
    cases: [
      ...bundles.cases,
      ...envelopeCases.map((c) => ({
        name: `envelope-${c.name}`,
        bundle: { ...proofBase.bundle, ...c.patch },
        options: proofBase.options,
        policy: proofBase.policy,
        ok: c.ok,
        ...(!c.ok ? { verificationLevel: "INVALID" } : {}),
      })),
    ],
  },
  evidence: {
    ...evidence,
    cases: [
      ...evidence.cases,
      ...envelopeCases.map((c) => ({
        name: `envelope-${c.name}`,
        bundle: { ...evidenceBase.bundle, ...c.patch },
        options: evidenceBase.options,
        ok: c.ok,
      })),
    ],
  },
  rootsChain,
  // Kept last and self-contained (own keys) so it merges and regenerates independently.
  dewpEvidenceHardening: buildDewpEvidenceHardening(),
  // Self-contained like the section above (2026-09-27 review L15-L18, I7, I8).
  verifierInputHardening: buildVerifierInputHardening(),
}
writeFileSync(
  fileURLToPath(new URL("../../vectors/verifier-parity-vectors.json", import.meta.url)),
  `${JSON.stringify(out, null, 2)}\n`,
)
writeFileSync(
  fileURLToPath(
    new URL(
      "../../../../apps/marketing/public/specs/v1.0/vectors/verifier-parity-vectors.json",
      import.meta.url,
    ),
  ),
  `${JSON.stringify(out, null, 2)}\n`,
)
