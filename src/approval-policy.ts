/** Pure policy resolution. No crypto, database, or network dependency. */
export interface PolicyRule {
  actionPattern: string
  requiredApprovals: number
  approverDids: string[]
  requireHardwareKey?: boolean
  allowedAaguids?: string[]
  requesterCannotApprove?: boolean
  requireAttestedRequester?: boolean
  allowedIssuers?: string[]
  approverGroupIds?: string[]
  escalationApproverDids?: string[]
  escalationGroupIds?: string[]
  escalateAfterSeconds?: number | null
  autoApproveRequesterDid?: string | null
  autoApproveDayOfWeek?: number | null
  autoApproveWindowStart?: string | null
  autoApproveWindowEnd?: string | null
}

export type UnmatchedActionPolicy = "DENY" | "OWNER_APPROVAL" | "BASELINE"
const ACTION_ID = /^[A-Za-z][A-Za-z0-9]*(?:[._:/-][A-Za-z0-9]+)*$/

/** Version 3 uses stable action IDs; display text is never an authorization input. */
export function validApprovalActionId(value: string): boolean {
  return value.length <= 200 && ACTION_ID.test(value)
}

/** Validate the whole v3 policy so a corrupt/duplicate rule cannot be hidden by another action. */
export function validateExactApprovalPolicy(rules: PolicyRule[]): void {
  const seen = new Set<string>()
  for (const rule of rules) {
    if (
      (rule.actionPattern !== "*" && !validApprovalActionId(rule.actionPattern)) ||
      !Number.isSafeInteger(rule.requiredApprovals) ||
      rule.requiredApprovals < 1 ||
      seen.has(rule.actionPattern.toLowerCase())
    )
      throw new ApprovalPolicyConflict(["invalidOrDuplicateActionId"])
    seen.add(rule.actionPattern.toLowerCase())
  }
  if (rules.length && !seen.has("*")) throw new ApprovalPolicyConflict(["missingBaseline"])
  const baseline = rules.find((r) => r.actionPattern === "*")
  if (!baseline) return
  for (const rule of rules) {
    const fields = lostApprovalConstraints(rule, baseline)
    if (fields.length) throw new ApprovalPolicyConflict(fields)
  }
}

export class ApprovalPolicyConflict extends Error {
  readonly fields: string[]
  constructor(fields: string[]) {
    super(`Conflicting approval requirements: ${fields.join(", ")}`)
    this.name = "ApprovalPolicyConflict"
    this.fields = fields
  }
}

export function ruleStrictness(r: PolicyRule): number {
  return (
    Math.max(1, r.requiredApprovals) * 32 +
    (r.requireHardwareKey ? 16 : 0) +
    (r.requireAttestedRequester ? 8 : 0) +
    (r.requesterCannotApprove ? 4 : 0) +
    (r.allowedAaguids?.length ? 2 : 0) +
    (r.allowedIssuers?.length ? 1 : 0)
  )
}

export function ruleSelectionKey(r: PolicyRule): string {
  return JSON.stringify([
    r.actionPattern,
    [...(r.allowedAaguids ?? [])].sort(),
    [...(r.allowedIssuers ?? [])].sort(),
    [...r.approverDids].sort(),
  ])
}

export function matchingApprovalRules<T extends PolicyRule>(
  rules: T[],
  actionType: string | undefined,
  display: string,
  version: 1 | 2 | 3 = 2,
): T[] {
  if (version === 3) {
    if (!actionType || !validApprovalActionId(actionType)) return []
    return rules.filter((r) => r.actionPattern === "*" || r.actionPattern === actionType)
  }
  const labels = `${actionType ?? ""}\n${display}`.toLowerCase()
  return rules.filter((r) => r.actionPattern === "*" || labels.includes(r.actionPattern.toLowerCase()))
}

function subset(a: string[], b: string[]): boolean {
  return a.every((value) => b.includes(value))
}
function sameSet(a: string[], b: string[]): boolean {
  return subset(a, b) && subset(b, a)
}
function windowKey(r: PolicyRule): string {
  return JSON.stringify([
    r.autoApproveRequesterDid ?? null,
    r.autoApproveDayOfWeek ?? null,
    r.autoApproveWindowStart ?? null,
    r.autoApproveWindowEnd ?? null,
  ])
}

/** Empty eligible lists denote the same owner fallback, NOT unrestricted eligibility. */
export function lostApprovalConstraints(selected: PolicyRule, other: PolicyRule): string[] {
  const lost: string[] = []
  if (selected.requiredApprovals < other.requiredApprovals) lost.push("requiredApprovals")
  for (const field of ["requireHardwareKey", "requesterCannotApprove", "requireAttestedRequester"] as const) {
    if (other[field] && !selected[field]) lost.push(field)
  }
  for (const field of ["allowedAaguids", "allowedIssuers"] as const) {
    const a = selected[field] ?? [],
      b = other[field] ?? []
    if (b.length && (!a.length || !subset(a, b))) lost.push(field)
  }
  // Different unresolved groups cannot be compared safely. DB callers expand them first.
  if (!sameSet(selected.approverGroupIds ?? [], other.approverGroupIds ?? [])) lost.push("approverGroups")
  const a = selected.approverDids,
    b = other.approverDids
  if ((a.length === 0) !== (b.length === 0) || !subset(a, b)) lost.push("approverDids")
  // Escalation widens eligibility with time. Conservatively require the same schedule and added set.
  if (
    (selected.escalateAfterSeconds ?? null) !== (other.escalateAfterSeconds ?? null) ||
    !sameSet(selected.escalationApproverDids ?? [], other.escalationApproverDids ?? []) ||
    !sameSet(selected.escalationGroupIds ?? [], other.escalationGroupIds ?? [])
  )
    lost.push("escalation")
  if (selected.autoApproveRequesterDid || other.autoApproveRequesterDid) {
    if (
      windowKey(selected) !== windowKey(other) ||
      selected.requiredApprovals !== other.requiredApprovals ||
      selected.requireHardwareKey !== other.requireHardwareKey ||
      selected.requesterCannotApprove !== other.requesterCannotApprove ||
      selected.requireAttestedRequester !== other.requireAttestedRequester ||
      !sameSet(a, b) ||
      !sameSet(selected.allowedAaguids ?? [], other.allowedAaguids ?? []) ||
      !sameSet(selected.allowedIssuers ?? [], other.allowedIssuers ?? [])
    )
      lost.push("autoApproval")
  }
  return lost
}

/** Legacy ranking is accepted ONLY when the caller explicitly requests version 1. */
export function selectApprovalRule<T extends PolicyRule>(
  rules: T[],
  actionType: string | undefined,
  display: string,
  version: 1 | 2 | 3 = 2,
  unmatched: UnmatchedActionPolicy = "DENY",
): T | undefined {
  if (version === 3) {
    validateExactApprovalPolicy(rules)
    if (unmatched === "OWNER_APPROVAL") throw new ApprovalPolicyConflict(["invalidFallback"])
    if (!actionType || !validApprovalActionId(actionType)) return undefined
    // IDs remain case-sensitive on the wire, but a differently cased spelling of a protected ID
    // must not drop to a weaker baseline. Require the caller to use the configured spelling.
    if (
      rules.some(
        (r) =>
          r.actionPattern !== "*" &&
          r.actionPattern !== actionType &&
          r.actionPattern.toLowerCase() === actionType.toLowerCase(),
      )
    )
      throw new ApprovalPolicyConflict(["actionIdCaseMismatch"])
    return (
      rules.find((r) => r.actionPattern === actionType) ??
      (unmatched === "BASELINE" ? rules.find((r) => r.actionPattern === "*") : undefined)
    )
  }
  const matches = matchingApprovalRules(rules, actionType, display, version)
  const selected = [...matches].sort(
    (a, b) =>
      ruleStrictness(b) - ruleStrictness(a) ||
      (ruleSelectionKey(a) < ruleSelectionKey(b) ? -1 : ruleSelectionKey(a) > ruleSelectionKey(b) ? 1 : 0),
  )[0]
  if (!selected || version === 1) return selected
  const invalid = matches.some(
    (r) => !r.actionPattern.trim() || !Number.isSafeInteger(r.requiredApprovals) || r.requiredApprovals < 1,
  )
  if (invalid) throw new ApprovalPolicyConflict(["invalidRule"])
  const fields = [...new Set(matches.flatMap((r) => lostApprovalConstraints(selected, r)))].sort()
  if (fields.length) throw new ApprovalPolicyConflict(fields)
  return selected
}

/** An empty list is owner-only. Distinct identities, not keys or duplicate entries, count. */
export function insufficientApprovalQuorum(rule: PolicyRule, requesterDid?: string): boolean {
  if (!rule.approverDids.length) return rule.requiredApprovals > 1
  const eligible = new Set(
    rule.approverDids.filter((did) => !rule.requesterCannotApprove || did !== requesterDid),
  )
  return eligible.size < rule.requiredApprovals
}
