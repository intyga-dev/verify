import assert from "node:assert/strict"
import crypto from "node:crypto"
import fs from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { describe, it } from "node:test"
import {
  type ApprovalReceipt,
  type AgentIntentContext,
  type ApproverTrustAnchor,
  agentConfigDigest,
  agentReceiptDigest,
  canonicalAgentAuthorityPayload,
  canonicalDelegationPayload,
  canonicalIntentPayload,
  canonicalOfflineIntentPayload,
  canonicalPlatformIntentPayload,
  stableStringify,
  verificationCode,
  verifyApprovalReceipt,
  verifyDelegation,
} from "./index.js"

// This package is the SHIPPED relying-party verifier, and it was the one implementation not pinned
// to the committed golden vectors: Go, Rust and Python read the file directly, while @intyga/verify
// was covered only by a live parity test against @intyga/mcp-schemas — which catches TS↔TS drift
// and misses the case where generator and both TS copies drift together. This suite closes that by
// consuming the same committed artifact every other port consumes.

const vectorsPath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..", "vectors",
  "canonical-vectors.json",
)

interface PayloadInput {
  target: string
  nonce: string
  actionType: string
  actionDescription: string
  params: Record<string, unknown>
  requester: { did: string; attestation: { method: string; issuer: string; subject: string } | null }
  requirement: {
    requiredApprovals: number
    requireHardwareKey: boolean
    allowedAaguids: string[]
    requesterCannotApprove: boolean
    signerClass: string
  }
  expiresAt: string
  challengedAt?: string
  delegatedTo?: string[]
  delegatedQuorum?: number
  sealedAt?: string
  agentDid?: string
  actionPatterns?: string[]
  parentReceiptHash?: string | null
}
interface ReceiptCase {
  name: string
  receipt: ApprovalReceipt
  expectOk: boolean
}
interface ApproverEntry {
  did: string
  keys: string[]
}
const vectors = JSON.parse(fs.readFileSync(vectorsPath, "utf8")) as {
  stableStringify: { name: string; value: unknown; expected: string }[]
  intentPayloads: { input: PayloadInput; expected: string }[]
  agentIntentPayloads: { input: PayloadInput & { agentContext: AgentIntentContext }; expected: string }[]
  offlineIntentPayloads: { input: PayloadInput; expected: string }[]
  delegationPayloads: { input: PayloadInput; expected: string }[]
  agentAuthorityPayloads: { input: PayloadInput; expected: string }[]
  platformIntentPayloads: {
    note: string
    cases: {
      input: {
        payloadHash: string
        rpId: string
        subjectExternalId: string
        signedAt: string
        expiresAt: string
        nonce: string
      }
      expected: string
    }[]
  }
  digests: { canonical: string; digestHex: string; verificationCode: string }[]
  agentDigests: {
    config: { input: Parameters<typeof agentConfigDigest>[0]; expected: string }
    receipt: { input: ApprovalReceipt; expected: string }
  }
  signerKey: { spkiB64: string }
  receipts: ReceiptCase[]
  quorumReceipts: {
    approvers: ApproverEntry[]
    cases: { name: string; receipt: ApprovalReceipt; expectOk: boolean; expectSigners?: string[] }[]
  }
  offlineReceipts: {
    name: string
    receipt: ApprovalReceipt
    /** Evaluation time (DIV §5a.3 rule 3). Ignoring it makes the forward-dated case pass — the point. */
    asOf: string
    expectOkWithOptIn: boolean
    refusedWithoutOptIn?: boolean
  }[]
  delegationReceipts: {
    approvers: ApproverEntry[]
    cases: {
      name: string
      receipt: ApprovalReceipt
      asOf: string
      expectOk: boolean
      delegatedTo?: string[]
      delegatedQuorum?: number
    }[]
  }
}

/** The committed evaluation time, refused rather than defaulted: a missing one is silent drift. */
const asOfOf = (name: string, raw: string): Date => {
  const at = new Date(raw)
  assert.ok(raw && !Number.isNaN(at.getTime()), `${name}: vector carries no usable asOf`)
  return at
}

const nonceOf = (receipt: ApprovalReceipt): string =>
  (JSON.parse(receipt.canonicalPayload) as { nonce: string }).nonce

/** DID-mode trust anchor from the vector's identity → keys table (multi-key per identity). */
const didAnchor = (approvers: ApproverEntry[]): ApproverTrustAnchor => ({
  dids: approvers.map((a) => a.did),
  resolveKey: (did: string) => approvers.find((a) => a.did === did)?.keys ?? null,
})

/** The expectation a relying party would assert, rebuilt from the receipt's echoes. */
const expectationFor = (receipt: ApprovalReceipt, approvers: ApproverTrustAnchor) => ({
  approvers,
  target: receipt.target ?? "",
  actionType: receipt.actionType ?? "",
  params: receipt.params ?? {},
  nonce: nonceOf(receipt),
})

describe("shared canonical vectors (committed artifact, same file the other ports pin against)", () => {
  it("stableStringify matches every committed case", () => {
    for (const c of vectors.stableStringify) {
      assert.equal(stableStringify(c.value), c.expected, c.name)
    }
  })

  it("intent / offline / delegation payload builders reproduce the committed bytes", () => {
    for (const { input, expected } of vectors.intentPayloads) {
      assert.equal(
        canonicalIntentPayload({
          target: input.target,
          actionType: input.actionType,
          display: input.actionDescription,
          params: input.params,
          requester: input.requester,
          requirement: input.requirement,
          nonce: input.nonce,
          expiresAt: input.expiresAt,
        }),
        expected,
      )
    }
    for (const { input, expected } of vectors.offlineIntentPayloads) {
      assert.ok(input.challengedAt)
      assert.equal(
        canonicalOfflineIntentPayload({
          target: input.target,
          actionType: input.actionType,
          display: input.actionDescription,
          params: input.params,
          requester: input.requester,
          requirement: input.requirement,
          nonce: input.nonce,
          challengedAt: input.challengedAt,
          expiresAt: input.expiresAt,
        }),
        expected,
      )
    }
    for (const { input, expected } of vectors.delegationPayloads) {
      assert.ok(input.delegatedTo && input.delegatedQuorum && input.sealedAt)
      assert.equal(
        canonicalDelegationPayload({
          target: input.target,
          actionType: input.actionType,
          display: input.actionDescription,
          params: input.params,
          requester: input.requester,
          requirement: input.requirement,
          delegatedTo: input.delegatedTo,
          delegatedQuorum: input.delegatedQuorum,
          nonce: input.nonce,
          sealedAt: input.sealedAt,
          expiresAt: input.expiresAt,
        }),
        expected,
      )
    }
    for (const { input, expected } of vectors.agentAuthorityPayloads) {
      assert.ok(input.agentDid && input.actionPatterns && input.sealedAt)
      assert.equal(
        canonicalAgentAuthorityPayload({
          target: input.target,
          actionPatterns: input.actionPatterns,
          display: input.actionDescription,
          agent: { did: input.agentDid },
          parentReceiptHash: input.parentReceiptHash,
          requester: input.requester,
          requirement: input.requirement,
          nonce: input.nonce,
          sealedAt: input.sealedAt,
          expiresAt: input.expiresAt,
        }),
        expected,
      )
    }
    for (const { input, expected } of vectors.agentIntentPayloads) {
      assert.equal(
        canonicalIntentPayload({
          target: input.target,
          actionType: input.actionType,
          display: input.actionDescription,
          params: input.params,
          requester: input.requester,
          requirement: input.requirement,
          nonce: input.nonce,
          expiresAt: input.expiresAt,
          agentContext: input.agentContext,
        }),
        expected,
      )
    }
    // DIV §5c — TS-only until the ports implement it (see the section's note in the vectors file).
    for (const { input, expected } of vectors.platformIntentPayloads.cases) {
      assert.equal(canonicalPlatformIntentPayload(input), expected)
    }
  })

  it("digest fixtures match (verification code + SHA-256 of the canonical bytes)", () => {
    for (const d of vectors.digests) {
      assert.equal(verificationCode(d.canonical), d.verificationCode)
      assert.equal(crypto.createHash("sha256").update(d.canonical, "utf8").digest("hex"), d.digestHex)
    }
  })

  it("agent config and complete receipt digests match the pinned wire bytes", () => {
    const { config, receipt } = vectors.agentDigests
    assert.equal(agentConfigDigest(config.input), config.expected)
    assert.equal(agentReceiptDigest(receipt.input), receipt.expected)
    assert.equal(
      agentReceiptDigest({ ...receipt.input, signatures: [...(receipt.input.signatures ?? [])].reverse() }),
      receipt.expected,
      "witness order must not change the digest",
    )
  })

  it("golden receipts verify (or refuse) exactly as committed", () => {
    const approvers: ApproverTrustAnchor = { publicKeys: [vectors.signerKey.spkiB64] }
    for (const c of vectors.receipts) {
      const r = verifyApprovalReceipt(c.receipt, expectationFor(c.receipt, approvers))
      assert.equal(r.ok, c.expectOk, `${c.name}: ${r.reason ?? "(ok)"}`)
    }
  })

  it("a requiredApprovals of 0 is refused on the minimum, not passed vacuously", () => {
    // Pinning the REASON, not just the refusal: `0 >= 0` makes DIV §5 step 7 true with nothing
    // counted, so a verifier can refuse this receipt for the right rule or for none at all.
    const c = vectors.receipts.find((x) => x.name === "zero-required-approvals-refused")
    assert.ok(c, "the zero-quorum vector is missing")
    const approvers: ApproverTrustAnchor = { publicKeys: [vectors.signerKey.spkiB64] }
    const r = verifyApprovalReceipt(c.receipt, expectationFor(c.receipt, approvers))
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /requiredApprovals must be an integer of at least 1/)
  })

  it("quorum receipts count distinct approver IDENTITIES, never signature entries", () => {
    const anchor = didAnchor(vectors.quorumReceipts.approvers)
    for (const c of vectors.quorumReceipts.cases) {
      const r = verifyApprovalReceipt(c.receipt, expectationFor(c.receipt, anchor))
      assert.equal(r.ok, c.expectOk, `${c.name}: ${r.reason ?? "(ok)"}`)
      if (c.expectSigners) {
        assert.deepEqual([...(r.signers ?? [])].sort(), [...c.expectSigners].sort(), c.name)
      }
      if (!c.expectOk) assert.match(r.reason ?? "", /quorum not met/, c.name)
    }
  })

  it("offline receipts pin the opt-in refusal, the 60-minute cap and the forward-dating rule", () => {
    const approvers: ApproverTrustAnchor = { publicKeys: [vectors.signerKey.spkiB64] }
    for (const c of vectors.offlineReceipts) {
      const expectation = expectationFor(c.receipt, approvers)
      const asOf = asOfOf(c.name, c.asOf)
      const withOptIn = verifyApprovalReceipt(c.receipt, expectation, { allowOffline: true, asOf })
      assert.equal(withOptIn.ok, c.expectOkWithOptIn, `${c.name}: ${withOptIn.reason ?? "(ok)"}`)
      if (c.refusedWithoutOptIn) {
        assert.equal(
          verifyApprovalReceipt(c.receipt, expectation, { asOf }).ok,
          false,
          `${c.name} must be refused without the offline opt-in`,
        )
      }
    }
  })

  it("a forward-dated offline proof is refused even under the audit override", () => {
    // `allowExpired` re-examines a proof that WAS valid and has lapsed; it says nothing about one
    // dated in the future, so DIV §5a.3 rule 3 is deliberately outside its reach.
    const c = vectors.offlineReceipts.find((x) => x.name === "offline-forward-dated-refused")
    assert.ok(c, "the forward-dated offline vector is missing")
    const approvers: ApproverTrustAnchor = { publicKeys: [vectors.signerKey.spkiB64] }
    const r = verifyApprovalReceipt(c.receipt, expectationFor(c.receipt, approvers), {
      allowOffline: true,
      allowExpired: true,
      asOf: asOfOf(c.name, c.asOf),
    })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /challenged in the future/)
  })

  it("delegation receipts pin sealing quorum, the 72-hour cap and the forward-dating rule", () => {
    const anchor = didAnchor(vectors.delegationReceipts.approvers)
    for (const c of vectors.delegationReceipts.cases) {
      const r = verifyDelegation(
        c.receipt,
        {
          approvers: anchor,
          target: c.receipt.target ?? "",
          actionType: c.receipt.actionType ?? "",
          params: c.receipt.params ?? {},
        },
        { asOf: asOfOf(c.name, c.asOf) },
      )
      assert.equal(r.ok, c.expectOk, `${c.name}: ${r.reason ?? "(ok)"}`)
      if (c.expectOk) {
        assert.deepEqual(r.delegation?.delegatedTo, c.delegatedTo)
        assert.equal(r.delegation?.delegatedQuorum, c.delegatedQuorum)
      }
    }
  })
})
