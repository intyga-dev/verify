import assert from "node:assert/strict"
import crypto from "node:crypto"
import fs from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { describe, it } from "node:test"
import {
  type ApprovalReceipt,
  type ApproverTrustAnchor,
  canonicalAgentAuthorityPayload,
  canonicalDelegationPayload,
  canonicalIntentPayload,
  canonicalOfflineIntentPayload,
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
  "..",
  "vectors",
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
  offlineIntentPayloads: { input: PayloadInput; expected: string }[]
  delegationPayloads: { input: PayloadInput; expected: string }[]
  agentAuthorityPayloads: { input: PayloadInput; expected: string }[]
  digests: { canonical: string; digestHex: string; verificationCode: string }[]
  signerKey: { spkiB64: string }
  receipts: ReceiptCase[]
  quorumReceipts: {
    approvers: ApproverEntry[]
    cases: { name: string; receipt: ApprovalReceipt; expectOk: boolean; expectSigners?: string[] }[]
  }
  offlineReceipts: {
    name: string
    receipt: ApprovalReceipt
    expectOkWithOptIn: boolean
    refusedWithoutOptIn?: boolean
  }[]
  delegationReceipts: {
    approvers: ApproverEntry[]
    cases: {
      name: string
      receipt: ApprovalReceipt
      expectOk: boolean
      delegatedTo?: string[]
      delegatedQuorum?: number
    }[]
  }
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
          requester: input.requester,
          requirement: input.requirement,
          nonce: input.nonce,
          sealedAt: input.sealedAt,
          expiresAt: input.expiresAt,
        }),
        expected,
      )
    }
  })

  it("digest fixtures match (verification code + SHA-256 of the canonical bytes)", () => {
    for (const d of vectors.digests) {
      assert.equal(verificationCode(d.canonical), d.verificationCode)
      assert.equal(crypto.createHash("sha256").update(d.canonical, "utf8").digest("hex"), d.digestHex)
    }
  })

  it("golden receipts verify (or refuse) exactly as committed", () => {
    const approvers: ApproverTrustAnchor = { publicKeys: [vectors.signerKey.spkiB64] }
    for (const c of vectors.receipts) {
      const r = verifyApprovalReceipt(c.receipt, expectationFor(c.receipt, approvers))
      assert.equal(r.ok, c.expectOk, `${c.name}: ${r.reason ?? "(ok)"}`)
    }
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

  it("offline receipts pin the opt-in refusal and the 60-minute window cap", () => {
    const approvers: ApproverTrustAnchor = { publicKeys: [vectors.signerKey.spkiB64] }
    for (const c of vectors.offlineReceipts) {
      const expectation = expectationFor(c.receipt, approvers)
      const withOptIn = verifyApprovalReceipt(c.receipt, expectation, { allowOffline: true })
      assert.equal(withOptIn.ok, c.expectOkWithOptIn, `${c.name}: ${withOptIn.reason ?? "(ok)"}`)
      if (c.refusedWithoutOptIn) {
        assert.equal(
          verifyApprovalReceipt(c.receipt, expectation).ok,
          false,
          `${c.name} must be refused without the offline opt-in`,
        )
      }
    }
  })

  it("delegation receipts pin sealing quorum and the 72-hour window cap", () => {
    const anchor = didAnchor(vectors.delegationReceipts.approvers)
    for (const c of vectors.delegationReceipts.cases) {
      const r = verifyDelegation(c.receipt, {
        approvers: anchor,
        target: c.receipt.target ?? "",
        actionType: c.receipt.actionType ?? "",
        params: c.receipt.params ?? {},
      })
      assert.equal(r.ok, c.expectOk, `${c.name}: ${r.reason ?? "(ok)"}`)
      if (c.expectOk) {
        assert.deepEqual(r.delegation?.delegatedTo, c.delegatedTo)
        assert.equal(r.delegation?.delegatedQuorum, c.delegatedQuorum)
      }
    }
  })
})
