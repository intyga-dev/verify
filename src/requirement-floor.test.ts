// DIV §5 step 3d: the signed `requirement` is authored by the signers, so a relying party that holds
// its own rule must be able to refuse a weaker one. These pin the H1 downgrade (one approver who is
// also the requester self-composing a 1-of-1 receipt for a 3-of-3 four-eyes action) on every entry
// point that counts a quorum, and pin that omitting the floor leaves behaviour unchanged.
import assert from "node:assert/strict"
import crypto from "node:crypto"
import { test } from "node:test"
import {
  type ApprovalReceipt,
  type ApprovalRequirementAttestation,
  canonicalAgentAuthorityPayload,
  canonicalDelegationPayload,
  canonicalIntentPayload,
  canonicalOfflineIntentPayload,
  type RequirementFloor,
  verifyAgentAuthority,
  verifyApprovalReceipt,
  verifyDelegation,
  WEAKER_REQUIREMENT_REASON,
} from "./index.ts"

const mk = () => {
  const kp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  return { kp, spki: kp.publicKey.export({ format: "der", type: "spki" }).toString("base64") }
}
const people = { "did:ex:alice": mk(), "did:ex:bob": mk(), "did:ex:carol": mk() }
type Did = keyof typeof people
const approvers = {
  dids: Object.keys(people),
  resolveKey: (d: string) => people[d as Did]?.spki ?? null,
}
const target = "prod-payments"
const actionType = "payments.wire"
const params = { amount: 1_000_000, to: "acct-9" }
const nonce = "c_real_nonce"
const requester = { did: "did:ex:alice", attestation: null }
const THREE_OF_THREE_FOUR_EYES: RequirementFloor = { requiredApprovals: 3, requesterCannotApprove: true }

const req = (
  requiredApprovals: number,
  requesterCannotApprove: boolean,
  requireHardwareKey = false,
): ApprovalRequirementAttestation => ({
  requiredApprovals,
  requireHardwareKey,
  allowedAaguids: [],
  requesterCannotApprove,
  signerClass: "human",
})

function signed(canonicalPayload: string, signers: Did[]): ApprovalReceipt {
  return {
    canonicalPayload,
    actionDescription: "Wire $1,000,000",
    params,
    requester,
    signatures: signers.map((did) => ({
      signerDid: did,
      signerPublicKey: people[did].spki,
      sigAlg: "ES256",
      signature: crypto
        .sign("sha256", Buffer.from(canonicalPayload), people[did].kp.privateKey)
        .toString("base64"),
    })),
    verificationCode: "",
  }
}

const intent = (requirement: ApprovalRequirementAttestation) =>
  canonicalIntentPayload({
    target,
    actionType,
    display: "Wire $1,000,000",
    params,
    requester,
    requirement,
    nonce,
    expiresAt: "2999-01-01T00:00:00.000Z",
  })

const expected = { approvers, target, actionType, params, nonce }

test("H1: a self-composed 1-of-1 receipt verifies without a floor (the signers' own stated quorum)", () => {
  const forged = signed(intent(req(1, false)), ["did:ex:alice"])
  assert.deepEqual(verifyApprovalReceipt(forged, expected), { ok: true, signers: ["did:ex:alice"] })
})

test("H1: the same receipt is refused under the relying party's 3-of-3 four-eyes floor", () => {
  const forged = signed(intent(req(1, false)), ["did:ex:alice"])
  const r = verifyApprovalReceipt(forged, { ...expected, requirement: THREE_OF_THREE_FOUR_EYES })
  assert.equal(r.ok, false)
  assert.match(r.reason ?? "", new RegExp(WEAKER_REQUIREMENT_REASON))
  assert.match(r.reason ?? "", /requires 1 approval\(s\), the policy 3/)
})

test("floor: each weaker field is refused on its own", () => {
  const floor: RequirementFloor = {
    requiredApprovals: 2,
    requesterCannotApprove: true,
    requireHardwareKey: false,
  }
  const quorum = verifyApprovalReceipt(signed(intent(req(1, true)), ["did:ex:bob"]), {
    ...expected,
    requirement: floor,
  })
  assert.match(quorum.reason ?? "", /requires 1 approval/)
  const fourEyes = verifyApprovalReceipt(signed(intent(req(2, false)), ["did:ex:bob", "did:ex:carol"]), {
    ...expected,
    requirement: floor,
  })
  assert.match(fourEyes.reason ?? "", /does not forbid the requester/)
  const hardware = verifyApprovalReceipt(signed(intent(req(2, true)), ["did:ex:bob", "did:ex:carol"]), {
    ...expected,
    requirement: { ...floor, requireHardwareKey: true },
  })
  assert.match(hardware.reason ?? "", /does not require a hardware key/)
})

test("floor: an equal or stricter signed requirement passes, and the SIGNED value is then enforced", () => {
  const honest = signed(intent(req(3, true)), ["did:ex:bob", "did:ex:carol"])
  // Equal floor: passes the floor, then the signed 3-of-3 four-eyes quorum cannot be met by bob+carol.
  const short = verifyApprovalReceipt(honest, { ...expected, requirement: THREE_OF_THREE_FOUR_EYES })
  assert.equal(short.ok, false)
  assert.match(short.reason ?? "", /quorum not met|2 of 3/)
  const twoOfThree = signed(intent(req(2, true)), ["did:ex:bob", "did:ex:carol"])
  assert.deepEqual(
    verifyApprovalReceipt(twoOfThree, {
      ...expected,
      requirement: { requiredApprovals: 2, requesterCannotApprove: true },
    }),
    { ok: true, signers: ["did:ex:bob", "did:ex:carol"] },
  )
  // Stricter signed than the floor is fine.
  assert.equal(
    verifyApprovalReceipt(twoOfThree, { ...expected, requirement: { requiredApprovals: 1 } }).ok,
    true,
  )
})

test("floor: a malformed floor fails closed rather than becoming 'no floor'", () => {
  const honest = signed(intent(req(1, false)), ["did:ex:bob"])
  for (const bad of [{ requiredApprovals: 0 }, { requiredApprovals: 1.5 }, { requiredApprovals: "3" }, {}]) {
    const r = verifyApprovalReceipt(honest, { ...expected, requirement: bad as unknown as RequirementFloor })
    assert.equal(r.ok, false, JSON.stringify(bad))
    assert.match(r.reason ?? "", /expected\.requirement is malformed/)
  }
})

test("floor: offline approvals are held to it too", () => {
  const now = new Date()
  const canonical = canonicalOfflineIntentPayload({
    target,
    actionType,
    display: "Wire $1,000,000",
    params,
    requester,
    requirement: req(1, false),
    nonce,
    challengedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 10 * 60_000).toISOString(),
  })
  const receipt = signed(canonical, ["did:ex:alice"])
  assert.equal(verifyApprovalReceipt(receipt, expected, { allowOffline: true }).ok, true)
  const r = verifyApprovalReceipt(
    receipt,
    { ...expected, requirement: THREE_OF_THREE_FOUR_EYES },
    { allowOffline: true },
  )
  assert.match(r.reason ?? "", new RegExp(WEAKER_REQUIREMENT_REASON))
})

test("floor: a delegation's sealing requirement is held to the ordinary rule", () => {
  const now = new Date()
  const canonical = canonicalDelegationPayload({
    target,
    actionType,
    display: "Wire $1,000,000",
    params,
    requester,
    requirement: req(1, false),
    delegatedTo: ["did:ex:bob", "did:ex:carol"],
    delegatedQuorum: 1,
    nonce: "d_nonce",
    sealedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3_600_000).toISOString(),
  })
  const seal = signed(canonical, ["did:ex:alice"])
  const delegationExpected = { approvers, target, actionType, params }
  assert.equal(verifyDelegation(seal, delegationExpected).ok, true)
  const r = verifyDelegation(seal, { ...delegationExpected, requirement: THREE_OF_THREE_FOUR_EYES })
  assert.equal(r.ok, false)
  assert.match(r.reason ?? "", new RegExp(WEAKER_REQUIREMENT_REASON))
})

test("floor: an agent authority's sealing requirement is held to the caller's sealing policy", () => {
  const now = new Date()
  const canonical = canonicalAgentAuthorityPayload({
    target,
    actionPatterns: ["payments."],
    display: "Wire $1,000,000",
    agent: { did: "did:ex:agent" },
    requester,
    requirement: req(1, false),
    nonce: "a_nonce",
    sealedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3_600_000).toISOString(),
  })
  const seal = signed(canonical, ["did:ex:alice"])
  const authorityExpected = { approvers, target, agentDid: "did:ex:agent" }
  const base = verifyAgentAuthority(seal, authorityExpected)
  assert.equal(base.ok, true, base.reason)
  const r = verifyAgentAuthority(seal, { ...authorityExpected, requirement: { requiredApprovals: 2 } })
  assert.equal(r.ok, false)
  assert.match(r.reason ?? "", new RegExp(WEAKER_REQUIREMENT_REASON))
  assert.equal(
    verifyAgentAuthority(seal, { ...authorityExpected, requirement: { requiredApprovals: 1 } }).ok,
    true,
  )
})
