import assert from "node:assert/strict"
import { test } from "node:test"
import {
  ApprovalPolicyConflict,
  insufficientApprovalQuorum,
  selectApprovalRule,
  lostApprovalConstraints,
  validApprovalActionId,
  type PolicyRule,
} from "./approval-policy.ts"

const base: PolicyRule = {
  actionPattern: "*",
  requiredApprovals: 2,
  approverDids: ["a", "b", "c"],
  requireHardwareKey: true,
}
const wire: PolicyRule = { actionPattern: "wire", requiredApprovals: 3, approverDids: ["a", "b", "c"] }

test("an extra approver cannot buy away hardware; repairing the rule preserves the baseline", () => {
  for (const rules of [
    [base, wire],
    [wire, base],
  ]) {
    assert.throws(() => selectApprovalRule(rules, "wire", "payment"), ApprovalPolicyConflict)
    assert.equal(selectApprovalRule(rules, "wire", "payment", 1)?.requireHardwareKey, undefined)
  }
  const fixed = { ...wire, requireHardwareKey: true }
  assert.equal(selectApprovalRule([base, fixed], "wire", "payment"), fixed)
})

test("unmatched and legacy specificity behavior are explicit", () => {
  assert.equal(selectApprovalRule([], "wire", "payment"), undefined)
  assert.equal(selectApprovalRule([wire], "restart", "server"), undefined)
  assert.equal(selectApprovalRule([base, { ...wire, requiredApprovals: 1 }], "wire", "payment", 1), base)
  assert.throws(() => selectApprovalRule([{ ...base, requiredApprovals: 0 }], "x", ""), /invalidRule/)
  assert.throws(() => selectApprovalRule([{ ...base, actionPattern: " " }], "x", " "), /invalidRule/)
})

test("all safety dimensions survive even when labels add another matching rule", () => {
  for (const extra of [
    { requireAttestedRequester: true },
    { requesterCannotApprove: true },
    { allowedAaguids: ["key-a"] },
    { allowedIssuers: ["issuer-a"] },
  ]) {
    const baseline = { ...base, ...extra }
    assert.throws(
      () => selectApprovalRule([baseline, { ...wire, requireHardwareKey: true }], "wire", ""),
      ApprovalPolicyConflict,
    )
  }
})

test("allowlists may narrow, never widen or disappear; disjoint sets conflict", () => {
  for (const field of ["allowedAaguids", "allowedIssuers"] as const) {
    const r = { ...base, [field]: ["a", "b"] }
    assert.deepEqual(lostApprovalConstraints({ ...r, [field]: ["a"] }, r), [])
    for (const list of [[], ["a", "b", "c"], ["c"]])
      assert.ok(lostApprovalConstraints({ ...r, [field]: list }, r).includes(field))
  }
})

test("eligibility cannot widen, including an empty owner fallback or unresolved group", () => {
  assert.ok(lostApprovalConstraints({ ...base, approverDids: [] }, base).includes("approverDids"))
  assert.ok(lostApprovalConstraints(base, { ...base, approverDids: [] }).includes("approverDids"))
  assert.deepEqual(lostApprovalConstraints({ ...base, approverDids: ["a", "b"] }, base), [])
  assert.ok(
    lostApprovalConstraints({ ...base, approverGroupIds: ["other"] }, base).includes("approverGroups"),
  )
  assert.ok(lostApprovalConstraints({ ...base, requiredApprovals: 1 }, base).includes("requiredApprovals"))
})

test("escalation and unsigned windows cannot silently replace another rule", () => {
  for (const extra of [
    { escalateAfterSeconds: 60 },
    { escalationApproverDids: ["d"] },
    { escalationGroupIds: ["g"] },
  ]) {
    assert.ok(lostApprovalConstraints({ ...base, ...extra }, base).includes("escalation"))
  }
  const auto = { ...base, requireHardwareKey: false, autoApproveRequesterDid: "svc" }
  assert.ok(lostApprovalConstraints(auto, base).includes("autoApproval"))
  assert.deepEqual(lostApprovalConstraints(auto, { ...auto }), [])
  assert.ok(lostApprovalConstraints(auto, { ...auto, autoApproveDayOfWeek: 1 }).includes("autoApproval"))
})

test("tie order cannot bypass mutually exclusive authenticator lists", () => {
  const a = { ...base, allowedAaguids: ["a"] },
    b = { ...base, allowedAaguids: ["b"] }
  assert.throws(() => selectApprovalRule([a, b], "wire", ""), ApprovalPolicyConflict)
  assert.throws(() => selectApprovalRule([b, a], "wire", ""), ApprovalPolicyConflict)
  const c = { ...base, actionPattern: "wire" }
  assert.equal(selectApprovalRule([base, c], "wire", ""), selectApprovalRule([c, base], "wire", ""))
})

test("quorum counts distinct eligible humans and excludes the requester when required", () => {
  assert.equal(insufficientApprovalQuorum({ ...base, approverDids: ["a", "a"] }), true)
  assert.equal(insufficientApprovalQuorum({ ...base, approverDids: [] }), true)
  assert.equal(insufficientApprovalQuorum({ ...base, approverDids: [], requiredApprovals: 1 }), false)
  assert.equal(
    insufficientApprovalQuorum({ ...base, approverDids: ["a", "b"], requesterCannotApprove: true }, "a"),
    true,
  )
  assert.equal(insufficientApprovalQuorum(base), false)
})

test("exact action policy ignores display text and requires an explicit unknown-action choice", () => {
  const baseline = { ...base, requiredApprovals: 1, requireHardwareKey: false }
  const exception = { ...baseline, actionPattern: "payment.execute", requireHardwareKey: true }
  assert.equal(selectApprovalRule([baseline, exception], "payment.execute", "anything", 3), exception)
  assert.equal(selectApprovalRule([baseline, exception], "billing.refund", "payment.execute", 3), undefined)
  assert.equal(selectApprovalRule([baseline, exception], "billing.refund", "", 3, "BASELINE"), baseline)
  assert.throws(
    () => selectApprovalRule([baseline, exception], "Payment.Execute", "", 3, "BASELINE"),
    /actionIdCaseMismatch/,
  )
  assert.throws(
    () =>
      selectApprovalRule(
        [baseline, exception, { ...exception, actionPattern: "Payment.Execute" }],
        "payment.execute",
        "",
        3,
      ),
    /invalidOrDuplicateActionId/,
  )
  assert.equal(validApprovalActionId("payment.execute"), true)
  assert.equal(validApprovalActionId("payment execute"), false)
  assert.throws(
    () => selectApprovalRule([baseline, exception, exception], "payment.execute", "", 3),
    /invalidOrDuplicateActionId/,
  )
  assert.throws(() => selectApprovalRule([exception], "payment.execute", "", 3), /missingBaseline/)
  assert.throws(
    () =>
      selectApprovalRule(
        [
          { ...baseline, requireHardwareKey: true },
          { ...exception, requireHardwareKey: false },
        ],
        "payment.execute",
        "",
        3,
      ),
    ApprovalPolicyConflict,
  )
})
