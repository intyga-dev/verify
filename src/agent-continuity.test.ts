import assert from "node:assert/strict"
import crypto from "node:crypto"
import { test } from "node:test"
import {
  agentConfigDigest,
  type AgentIntentContext,
  agentReceiptDigest,
  type ApprovalReceipt,
  canonicalIntentPayload,
  verifyAgentSessionChain,
  verifyApprovalReceipt,
} from "./index.ts"

const key = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
const publicKey = key.publicKey.export({ format: "der", type: "spki" }).toString("base64")
const nbf = "2026-09-20T11:00:00.000Z"
const exp = "2026-09-20T11:05:00.000Z"
const asOf = new Date("2026-09-20T11:02:00.000Z")
const configDigest = agentConfigDigest({
  model: { provider: "example", version: "model-2026-09-20" },
  tools: [{ id: "payments", version: "1", schemaDigest: `sha256:${"1".repeat(64)}` }],
  systemPrompt: "Approve payments only with human review.",
})

function signedStep(seq: string, prev: string | null, amount: string, aggregate: string) {
  const agentContext: AgentIntentContext = {
    action: { reversibility: "irreversible", amount: { amount, currency: "SEK" } },
    agent: { label: "Payment agent", configDigest, delegatedBy: null },
    session: {
      id: "sha256:0eb96b3fc309cc50b1d5f9c68de1db1fe2661738c5910094ede5761fd8c257aa",
      seq,
      prev,
      aggregate: { amount: aggregate, currency: "SEK" },
    },
    nbf,
  }
  const nonce = `nonce-${seq}-${amount}`
  const canonicalPayload = canonicalIntentPayload({
    target: "payments-prod",
    actionType: "payment.wire",
    display: "Pay a supplier",
    params: { supplier: "acme" },
    requester: { did: "did:intyga:payment-agent", attestation: null },
    requirement: {
      requiredApprovals: 1,
      requireHardwareKey: false,
      allowedAaguids: [],
      requesterCannotApprove: true,
      signerClass: "human",
    },
    nonce,
    expiresAt: exp,
    agentContext,
  })
  const signature = crypto
    .sign("sha256", Buffer.from(canonicalPayload), {
      key: key.privateKey,
      dsaEncoding: "ieee-p1363",
    })
    .toString("base64")
  const receipt: ApprovalReceipt = {
    canonicalPayload,
    actionDescription: "Pay a supplier",
    params: { supplier: "acme" },
    requester: { did: "did:intyga:payment-agent", attestation: null },
    signerDid: "did:intyga:owner",
    signerPublicKey: publicKey,
    signature,
    sigAlg: "ES256",
    verificationCode: "unused",
  }
  return {
    receipt,
    expected: {
      target: "payments-prod",
      actionType: "payment.wire",
      params: { supplier: "acme" },
      nonce,
      approvers: { dids: ["did:intyga:owner"], resolveKey: () => publicKey },
      agentContext,
    },
  }
}

test("complete agent chain recomputes the signed aggregate", () => {
  const first = signedStep("1", null, "10.00", "10.00")
  const second = signedStep("2", agentReceiptDigest(first.receipt), "20.00", "30.00")
  assert.equal(
    verifyAgentSessionChain([first, second], agentReceiptDigest(second.receipt), { asOf }).ok,
    true,
  )
  assert.match(
    verifyAgentSessionChain([first], agentReceiptDigest(second.receipt), { asOf }).reason ?? "",
    /trusted head/,
  )
  assert.match(
    verifyAgentSessionChain(
      [first, second],
      "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      { asOf },
    ).reason ?? "",
    /trusted head/,
  )
})

test("gaps, forks, a broken predecessor and a false aggregate fail closed", () => {
  const first = signedStep("1", null, "10.00", "10.00")
  const digest = agentReceiptDigest(first.receipt)
  const second = signedStep("2", digest, "20.00", "30.00")
  const gap = signedStep("3", digest, "20.00", "30.00")
  const fork = signedStep("2", digest, "25.00", "35.00")
  const broken = signedStep(
    "2",
    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "20.00",
    "30.00",
  )
  const falseTotal = signedStep("2", digest, "20.00", "29.00")
  assert.match(
    verifyAgentSessionChain([first, gap], agentReceiptDigest(gap.receipt), { asOf }).reason ?? "",
    /gap/,
  )
  assert.match(
    verifyAgentSessionChain([first, second, fork], agentReceiptDigest(fork.receipt), { asOf }).reason ?? "",
    /gap|fork/,
  )
  assert.match(
    verifyAgentSessionChain([first, broken], agentReceiptDigest(broken.receipt), { asOf }).reason ?? "",
    /predecessor/,
  )
  assert.match(
    verifyAgentSessionChain([first, falseTotal], agentReceiptDigest(falseTotal.receipt), { asOf }).reason ??
      "",
    /aggregate/,
  )
})

test("expired, drifting, noncanonical and duplicate-key agent claims are refused", () => {
  const first = signedStep("1", null, "10.00", "10.00")
  assert.match(
    verifyApprovalReceipt(first.receipt, first.expected, { asOf: new Date("2026-09-20T11:06:00.000Z") })
      .reason ?? "",
    /expired/,
  )
  assert.match(
    verifyApprovalReceipt(
      first.receipt,
      {
        ...first.expected,
        agentContext: {
          ...first.expected.agentContext,
          agent: {
            ...first.expected.agentContext.agent,
            configDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
          },
        },
      },
      { asOf },
    ).reason ?? "",
    /match|approved/,
  )
  assert.throws(() => signedStep("1", null, "1e3", "1000"), /monetary/)
  const payload = first.receipt.canonicalPayload.replace(
    '"actionType":"payment.wire",',
    '"actionType":"payment.wire","actionType":"payment.wire",',
  )
  const forged: ApprovalReceipt = {
    ...first.receipt,
    canonicalPayload: payload,
    signature: crypto
      .sign("sha256", Buffer.from(payload), { key: key.privateKey, dsaEncoding: "ieee-p1363" })
      .toString("base64"),
  }
  assert.equal(verifyApprovalReceipt(forged, first.expected, { asOf }).ok, false)
  assert.notEqual(
    agentConfigDigest({ model: { provider: "x", version: "1" }, tools: [], systemPrompt: "é" }),
    agentConfigDigest({ model: { provider: "x", version: "1" }, tools: [], systemPrompt: "e\u0301" }),
  )
})
