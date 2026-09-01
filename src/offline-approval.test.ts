// Offline approval + delegation (docs/DIV.md §5a), verified end to end with real P-256 signatures.
//
// These tests exist to pin the properties that make the mechanism safe rather than merely functional.
// The happy paths are the least interesting cases here; what matters is that every ordinary control
// still applies, that the payload KINDS cannot be substituted for one another, and that a delegation —
// which authorizes nothing — cannot be talked into authorizing something.

import assert from "node:assert/strict"
import crypto from "node:crypto"
import { describe, it } from "node:test"
import {
  type ApprovalReceipt,
  type ApprovalWitness,
  canonicalDelegationPayload,
  canonicalIntentPayload,
  canonicalOfflineIntentPayload,
  MAX_DELEGATION_WINDOW_HOURS,
  MAX_OFFLINE_WINDOW_MINUTES,
  verificationCode,
  verifyApprovalReceipt,
  verifyDelegation,
} from "./index.js"

// ── signing helpers ─────────────────────────────────────────────────────────────
interface Signer {
  did: string
  spki: string
  sign(payload: string): string
}

function makeSigner(did: string): Signer {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  return {
    did,
    spki: publicKey.export({ format: "der", type: "spki" }).toString("base64"),
    sign: (payload: string) =>
      crypto
        .sign("sha256", Buffer.from(payload, "utf8"), { key: privateKey, dsaEncoding: "ieee-p1363" })
        .toString("base64"),
  }
}

const ALICE = makeSigner("did:intyga:alice")
const BOB = makeSigner("did:intyga:bob")
const CAROL = makeSigner("did:intyga:carol")
const MALLORY = makeSigner("did:intyga:mallory")
/** A SECOND key held by Alice — an approver legitimately has a software key plus passkeys. */
const ALICE_SECOND = makeSigner("did:intyga:alice")

const TARGET = "prod-db-cluster-01"
const ACTION_TYPE = "db.restart"
const DISPLAY = "Restart the primary database"
const PARAMS = { cluster: "primary" }
const REQUESTER = { did: "did:intyga:service:oncall", attestation: null }

function requirement(over: Partial<Record<string, unknown>> = {}) {
  return {
    requiredApprovals: 1,
    requireHardwareKey: false,
    allowedAaguids: [] as string[],
    requesterCannotApprove: false,
    signerClass: "human",
    ...over,
  } as {
    requiredApprovals: number
    requireHardwareKey: boolean
    allowedAaguids: string[]
    requesterCannotApprove: boolean
    signerClass: string
  }
}

/** A DID-mode anchor, which is what a trust bundle produces. Multiple keys may map to one DID. */
function anchor(...signers: Signer[]) {
  const byDid = new Map<string, string[]>()
  for (const s of signers) byDid.set(s.did, [...(byDid.get(s.did) ?? []), s.spki])
  return { dids: [...byDid.keys()], resolveKey: (did: string) => byDid.get(did) ?? null }
}

function witness(signer: Signer, payload: string): ApprovalWitness {
  return {
    signerDid: signer.did,
    signerPublicKey: signer.spki,
    signature: signer.sign(payload),
    sigAlg: "ES256",
  }
}

function receiptFor(
  canonical: string,
  signers: Signer[],
  over: Partial<ApprovalReceipt> = {},
): ApprovalReceipt {
  return {
    canonicalPayload: canonical,
    target: TARGET,
    actionType: ACTION_TYPE,
    actionDescription: DISPLAY,
    params: PARAMS,
    signatures: signers.map((s) => witness(s, canonical)),
    requester: REQUESTER,
    verificationCode: verificationCode(canonical),
    ...over,
  }
}

/** Build an offline proof. `windowMinutes` and `requirement` are the knobs the tests turn. */
function offlineProof(
  opts: {
    windowMinutes?: number
    req?: ReturnType<typeof requirement>
    signers?: Signer[]
    challengedAt?: Date
    requester?: { did: string; attestation: null }
    params?: Record<string, unknown>
    target?: string
    actionType?: string
  } = {},
) {
  const challengedAt = opts.challengedAt ?? new Date()
  const nonce = `off_${crypto.randomUUID()}`
  const canonical = canonicalOfflineIntentPayload({
    target: opts.target ?? TARGET,
    actionType: opts.actionType ?? ACTION_TYPE,
    display: DISPLAY,
    params: opts.params ?? PARAMS,
    requester: opts.requester ?? REQUESTER,
    requirement: opts.req ?? requirement(),
    nonce,
    challengedAt: challengedAt.toISOString(),
    expiresAt: new Date(challengedAt.getTime() + (opts.windowMinutes ?? 10) * 60_000).toISOString(),
  })
  const receipt = receiptFor(canonical, opts.signers ?? [ALICE], {
    target: opts.target ?? TARGET,
    actionType: opts.actionType ?? ACTION_TYPE,
    params: opts.params ?? PARAMS,
    requester: opts.requester ?? REQUESTER,
  })
  return { nonce, canonical, receipt }
}

function expectation(nonce: string, over: Record<string, unknown> = {}) {
  return {
    target: TARGET,
    actionType: ACTION_TYPE,
    params: PARAMS,
    nonce,
    approvers: anchor(ALICE, BOB, CAROL),
    ...over,
  } as Parameters<typeof verifyApprovalReceipt>[1]
}

/** Build a delegation naming `delegates`, signed by the ordinary approvers `signers`. */
function delegationProof(
  opts: {
    delegates?: string[]
    quorum?: number
    windowHours?: number
    signers?: Signer[]
    req?: ReturnType<typeof requirement>
    sealedAt?: Date
    target?: string
    actionType?: string
    params?: Record<string, unknown>
  } = {},
) {
  const sealedAt = opts.sealedAt ?? new Date()
  const nonce = `dlg_${crypto.randomUUID()}`
  const canonical = canonicalDelegationPayload({
    target: opts.target ?? TARGET,
    actionType: opts.actionType ?? ACTION_TYPE,
    display: DISPLAY,
    params: opts.params ?? PARAMS,
    requester: REQUESTER,
    requirement: opts.req ?? requirement({ requiredApprovals: 2 }),
    delegatedTo: opts.delegates ?? [CAROL.did, MALLORY.did],
    delegatedQuorum: opts.quorum ?? 1,
    nonce,
    sealedAt: sealedAt.toISOString(),
    expiresAt: new Date(sealedAt.getTime() + (opts.windowHours ?? 24) * 3_600_000).toISOString(),
  })
  const receipt = receiptFor(canonical, opts.signers ?? [ALICE, BOB], {
    target: opts.target ?? TARGET,
    actionType: opts.actionType ?? ACTION_TYPE,
    params: opts.params ?? PARAMS,
  })
  return { nonce, canonical, receipt }
}

const delegationExpectation = {
  approvers: anchor(ALICE, BOB),
  target: TARGET,
  actionType: ACTION_TYPE,
  params: PARAMS,
}

// ── offline approval ────────────────────────────────────────────────────────────
describe("offline approval", () => {
  it("is REFUSED by default — allowOffline is not implied by anything", () => {
    const { receipt, nonce } = offlineProof()
    const r = verifyApprovalReceipt(receipt, expectation(nonce))
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /allowOffline/)
    // Not rescued by the other opt-in either: they gate different things.
    assert.equal(verifyApprovalReceipt(receipt, expectation(nonce), { allowAutoApproved: true }).ok, false)
  })

  it("verifies once the call site opts in", () => {
    const { receipt, nonce } = offlineProof()
    const r = verifyApprovalReceipt(receipt, expectation(nonce), { allowOffline: true })
    assert.equal(r.ok, true, r.reason)
    assert.deepEqual(r.signers, [ALICE.did])
  })

  it("allowOffline does NOT let a normal approval through as offline, or the reverse", () => {
    // An ORDINARY payload presented where an offline one is expected: still an ordinary approval, and
    // it verifies as one — allowOffline widens, it does not narrow.
    const nonce = "normal-1"
    const normalCanonical = canonicalIntentPayload({
      target: TARGET,
      actionType: ACTION_TYPE,
      display: DISPLAY,
      params: PARAMS,
      requester: REQUESTER,
      requirement: requirement(),
      nonce,
      expiresAt: new Date(Date.now() + 600_000).toISOString(),
    })
    const normal = receiptFor(normalCanonical, [ALICE])
    assert.equal(verifyApprovalReceipt(normal, expectation(nonce), { allowOffline: true }).ok, true)

    // And the reverse direction, which is the dangerous one: an offline proof whose `type` has been
    // rewritten to look ordinary. The type is inside the SIGNED bytes, so the signature breaks.
    const off = offlineProof()
    const forged = off.canonical.replace('"div-offline-intent"', '"div-intent-verification"')
    const tampered = { ...off.receipt, canonicalPayload: forged }
    const r = verifyApprovalReceipt(tampered, expectation(off.nonce))
    assert.equal(r.ok, false)
  })

  it("refuses a window over the maximum even with a valid signature", () => {
    const over = offlineProof({ windowMinutes: MAX_OFFLINE_WINDOW_MINUTES + 1 })
    const r = verifyApprovalReceipt(over.receipt, expectation(over.nonce), { allowOffline: true })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /over the 60-minute maximum/)

    // Exactly at the cap is fine — the bound is inclusive.
    const atCap = offlineProof({ windowMinutes: MAX_OFFLINE_WINDOW_MINUTES })
    assert.equal(
      verifyApprovalReceipt(atCap.receipt, expectation(atCap.nonce), { allowOffline: true }).ok,
      true,
    )
  })

  it("refuses a proof that expires before it was challenged", () => {
    const { receipt, nonce } = offlineProof({ windowMinutes: -10 })
    const r = verifyApprovalReceipt(receipt, expectation(nonce), { allowOffline: true })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /expires before it was challenged|expired/)
  })

  it("refuses a proof CHALLENGED in the future, however compliant its window", () => {
    // The 60-minute cap bounds the window's width, not where it sits. A year-out proof with a
    // 10-minute window passes every other check and would keep verifying until that date —
    // the capability at rest DIV §5a.1 rejects and §5a.8 credits the cap with preventing.
    const nextYear = new Date(Date.now() + 365 * 24 * 3_600_000)
    const { receipt, nonce } = offlineProof({ challengedAt: nextYear, windowMinutes: 10 })
    const r = verifyApprovalReceipt(receipt, expectation(nonce), { allowOffline: true })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /challenged in the future/)
    // allowExpired covers the opposite case — valid then, lapsed now — so it must not rescue this.
    const audit = verifyApprovalReceipt(receipt, expectation(nonce), {
      allowOffline: true,
      allowExpired: true,
    })
    assert.equal(audit.ok, false)
    assert.match(audit.reason ?? "", /challenged in the future/)
    // Evaluated from inside the window, the same proof verifies: the rule is positional, not a ban
    // on distant dates.
    const inWindow = verifyApprovalReceipt(receipt, expectation(nonce), {
      allowOffline: true,
      asOf: new Date(nextYear.getTime() + 60_000),
    })
    assert.equal(inWindow.ok, true, inWindow.reason)
  })

  it("refuses a signed requiredApprovals below 1 instead of flooring it", () => {
    const { receipt, nonce } = offlineProof({ req: requirement({ requiredApprovals: 0 }) })
    const r = verifyApprovalReceipt(receipt, expectation(nonce), { allowOffline: true })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /requiredApprovals must be an integer of at least 1/)
  })

  it("refuses a proof missing challengedAt rather than treating it as unbounded", () => {
    const { receipt, nonce, canonical } = offlineProof()
    const parsed = JSON.parse(canonical) as Record<string, unknown>
    delete parsed.challengedAt
    const r = verifyApprovalReceipt(
      { ...receipt, canonicalPayload: JSON.stringify(parsed) },
      expectation(nonce),
      { allowOffline: true },
    )
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /missing challengedAt/)
  })

  it("refuses an expired proof", () => {
    const { receipt, nonce } = offlineProof({ challengedAt: new Date(Date.now() - 3_600_000) })
    const r = verifyApprovalReceipt(receipt, expectation(nonce), { allowOffline: true })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /expired/)
  })

  it("REFUSES an action whose signed policy requires a hardware key", () => {
    // DIV §5a.3 step 4. A WebAuthn assertion cannot be produced offline, so accepting a bare-key
    // signature here would silently downgrade the very policy the approver attested to.
    const { receipt, nonce } = offlineProof({ req: requirement({ requireHardwareKey: true }) })
    const r = verifyApprovalReceipt(receipt, expectation(nonce), { allowOffline: true })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /cannot be produced offline/)
  })

  it("still enforces target isolation", () => {
    const { receipt, nonce } = offlineProof()
    const r = verifyApprovalReceipt(receipt, expectation(nonce, { target: "staging-db" }), {
      allowOffline: true,
    })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /do not match what was approved/)
  })

  it("still enforces exact parameter binding", () => {
    const { receipt, nonce } = offlineProof()
    const r = verifyApprovalReceipt(receipt, expectation(nonce, { params: { cluster: "replica" } }), {
      allowOffline: true,
    })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /do not match what was approved/)
  })

  it("still refuses a signer outside the trust anchor", () => {
    const { receipt, nonce } = offlineProof({ signers: [MALLORY] })
    const r = verifyApprovalReceipt(receipt, expectation(nonce), { allowOffline: true })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /not an authorized approver|quorum not met/)
  })

  it("still enforces four-eyes", () => {
    // The requester signs their own action. `requesterCannotApprove` is in the signed bytes, so this
    // is checkable entirely offline.
    const { receipt, nonce } = offlineProof({
      req: requirement({ requesterCannotApprove: true }),
      requester: { did: ALICE.did, attestation: null },
      signers: [ALICE],
    })
    const r = verifyApprovalReceipt(receipt, expectation(nonce), { allowOffline: true })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /four-eyes/)
  })

  it("cannot be auto-approved, even with allowAutoApproved", () => {
    // An offline approval with no human signature is a contradiction: the entire premise is that
    // humans signed out of band.
    const { canonical, nonce } = offlineProof()
    const unsigned: ApprovalReceipt = {
      canonicalPayload: canonical,
      target: TARGET,
      actionType: ACTION_TYPE,
      actionDescription: DISPLAY,
      params: PARAMS,
      requester: REQUESTER,
      sigAlg: "AUTO_APPROVED",
      signerDid: "did:intyga:pre-authorized",
      signerPublicKey: "pre-authorized",
      signature: "pre-authorized",
      verificationCode: verificationCode(canonical),
    }
    const r = verifyApprovalReceipt(unsigned, expectation(nonce), {
      allowOffline: true,
      allowAutoApproved: true,
    })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /cannot be auto-approved/)
  })

  it("counts one approver holding several keys as ONE approver", () => {
    // The reason DID mode resolves to a LIST. If each key were its own identity, an approver with a
    // software key and two passkeys would satisfy a 3-of-N quorum single-handedly.
    const { receipt, nonce } = offlineProof({
      req: requirement({ requiredApprovals: 2 }),
      signers: [ALICE, ALICE_SECOND],
    })
    const r = verifyApprovalReceipt(
      receipt,
      expectation(nonce, { approvers: anchor(ALICE, ALICE_SECOND, BOB) }),
      { allowOffline: true },
    )
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /quorum not met: 1 of 2/)
  })

  it("meets a 2-of-3 quorum with two distinct approvers", () => {
    const { receipt, nonce } = offlineProof({
      req: requirement({ requiredApprovals: 2 }),
      signers: [ALICE, BOB],
    })
    const r = verifyApprovalReceipt(receipt, expectation(nonce), { allowOffline: true })
    assert.equal(r.ok, true, r.reason)
    assert.equal(r.signers?.length, 2)
  })
})

// ── delegation ──────────────────────────────────────────────────────────────────
describe("delegation", () => {
  it("authorizes NOTHING on its own — the approval verifier refuses it outright", () => {
    const { receipt, nonce } = delegationProof()
    // Not gated by an option: there is deliberately no flag that would let this through.
    for (const opts of [
      {},
      { allowOffline: true },
      { allowOffline: true, allowAutoApproved: true },
      { allowOffline: true, allowExpired: true },
    ]) {
      const r = verifyApprovalReceipt(receipt, expectation(nonce), opts)
      assert.equal(r.ok, false)
      assert.match(r.reason ?? "", /authorizes no action on its own/)
    }
  })

  it("verifies against the ORDINARY approver set", () => {
    const { receipt } = delegationProof()
    const r = verifyDelegation(receipt, delegationExpectation)
    assert.equal(r.ok, true, r.reason)
    assert.equal(r.delegation?.delegatedQuorum, 1)
    assert.deepEqual(r.delegation?.delegatedTo, [CAROL.did, MALLORY.did])
  })

  it("refuses a delegation the ordinary quorum did not sign", () => {
    // Signed by one approver where the delegation's own requirement demands two. Delegating is never
    // the cheaper path.
    const { receipt } = delegationProof({ signers: [ALICE] })
    const r = verifyDelegation(receipt, delegationExpectation)
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /delegation quorum not met/)
  })

  it("refuses a delegation signed by someone outside the ordinary approvers", () => {
    const { receipt } = delegationProof({ signers: [MALLORY, CAROL] })
    const r = verifyDelegation(receipt, delegationExpectation)
    assert.equal(r.ok, false)
  })

  it("refuses a window over the maximum", () => {
    const { receipt } = delegationProof({ windowHours: MAX_DELEGATION_WINDOW_HOURS + 1 })
    const r = verifyDelegation(receipt, delegationExpectation)
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /over the 72-hour maximum/)
  })

  it("refuses a delegation SEALED in the future, however compliant its window", () => {
    // §5a.8 names the 72-hour cap as Delegation's only mitigation; a sliding window is no bound.
    const nextYear = new Date(Date.now() + 365 * 24 * 3_600_000)
    const { receipt } = delegationProof({ sealedAt: nextYear, windowHours: 24 })
    const r = verifyDelegation(receipt, delegationExpectation)
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /sealed in the future/)
    const audit = verifyDelegation(receipt, delegationExpectation, { allowExpired: true })
    assert.equal(audit.ok, false)
    assert.match(audit.reason ?? "", /sealed in the future/)
    const inWindow = verifyDelegation(receipt, delegationExpectation, {
      asOf: new Date(nextYear.getTime() + 60_000),
    })
    assert.equal(inWindow.ok, true, inWindow.reason)
  })

  it("refuses a sealing requiredApprovals below 1 instead of flooring it", () => {
    const { receipt } = delegationProof({ req: requirement({ requiredApprovals: 0 }) })
    const r = verifyDelegation(receipt, delegationExpectation)
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /requiredApprovals must be an integer of at least 1/)
  })

  it("refuses a quorum larger than the pool it names", () => {
    const { receipt } = delegationProof({ delegates: [CAROL.did], quorum: 2 })
    const r = verifyDelegation(receipt, delegationExpectation)
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /can never be satisfied/)
  })

  it("does not let a duplicated name inflate the delegated pool", () => {
    // Three entries, one person. Without deduplication this would look like a 2-of-3 that Carol alone
    // could satisfy.
    const { receipt } = delegationProof({
      delegates: [CAROL.did, CAROL.did, CAROL.did],
      quorum: 2,
    })
    const r = verifyDelegation(receipt, delegationExpectation)
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /1 distinct operator/)
  })

  it("refuses target/actionType/params that differ from what is being executed", () => {
    const { receipt } = delegationProof()
    assert.equal(verifyDelegation(receipt, { ...delegationExpectation, target: "staging" }).ok, false)
    assert.equal(verifyDelegation(receipt, { ...delegationExpectation, actionType: "db.drop" }).ok, false)
    assert.equal(
      verifyDelegation(receipt, { ...delegationExpectation, params: { cluster: "replica" } }).ok,
      false,
    )
  })

  it("substitutes the approver set: a delegate's signature counts ONLY under the delegation", () => {
    // Carol is delegated but is NOT in the offline call's ordinary approver anchor.
    const verified = verifyDelegation(delegationProof().receipt, delegationExpectation)
    assert.equal(verified.ok, true, verified.reason)

    const { receipt, nonce } = offlineProof({ signers: [CAROL], req: requirement({ requiredApprovals: 1 }) })
    const anchorWithoutCarolInRule = { dids: [CAROL.did], resolveKey: () => CAROL.spki }

    // Without the delegation, Carol signing is just a signature from someone the RULE did not name.
    const withoutDelegation = verifyApprovalReceipt(
      receipt,
      expectation(nonce, { approvers: anchor(ALICE, BOB) }),
      { allowOffline: true },
    )
    assert.equal(withoutDelegation.ok, false)

    // With it, Carol is eligible and the quorum is the delegated one.
    const withDelegation = verifyApprovalReceipt(
      receipt,
      expectation(nonce, { approvers: anchorWithoutCarolInRule }),
      { allowOffline: true, delegation: verified.delegation },
    )
    assert.equal(withDelegation.ok, true, withDelegation.reason)
    assert.deepEqual(withDelegation.signers, [CAROL.did])
  })

  it("refuses a signer who is trusted but NOT named in the delegation", () => {
    const verified = verifyDelegation(delegationProof({ delegates: [CAROL.did] }).receipt, {
      ...delegationExpectation,
    })
    assert.equal(verified.ok, true, verified.reason)
    // Bob is a perfectly trusted approver — but this delegation did not name him.
    const { receipt, nonce } = offlineProof({ signers: [BOB] })
    const r = verifyApprovalReceipt(receipt, expectation(nonce), {
      allowOffline: true,
      delegation: verified.delegation,
    })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /not named in the delegation/)
  })

  it("requires the offline proof's signed quorum to equal the delegated quorum", () => {
    // Otherwise the operators would be signing a policy ("1 approval needed") different from the one
    // actually being enforced ("2 needed"), or vice versa.
    const verified = verifyDelegation(
      delegationProof({ delegates: [CAROL.did, MALLORY.did], quorum: 2 }).receipt,
      delegationExpectation,
    )
    assert.equal(verified.ok, true, verified.reason)
    const { receipt, nonce } = offlineProof({ req: requirement({ requiredApprovals: 1 }), signers: [CAROL] })
    const r = verifyApprovalReceipt(receipt, expectation(nonce), {
      allowOffline: true,
      delegation: verified.delegation,
    })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /delegates a quorum of 2/)
  })

  it("requires a DID-mode anchor — delegatedTo is unenforceable against an unverified signerDid", () => {
    const verified = verifyDelegation(
      delegationProof({ delegates: [CAROL.did] }).receipt,
      delegationExpectation,
    )
    assert.equal(verified.ok, true, verified.reason)
    const { receipt, nonce } = offlineProof({ signers: [CAROL] })
    const r = verifyApprovalReceipt(
      receipt,
      expectation(nonce, { approvers: { publicKeys: [CAROL.spki] } }),
      { allowOffline: true, delegation: verified.delegation },
    )
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /requires a DID-mode trust anchor/)
  })

  it("cannot substitute the approver set for an ORDINARY gateway-mediated approval", () => {
    const verified = verifyDelegation(delegationProof().receipt, delegationExpectation)
    const nonce = "normal-2"
    const canonical = canonicalIntentPayload({
      target: TARGET,
      actionType: ACTION_TYPE,
      display: DISPLAY,
      params: PARAMS,
      requester: REQUESTER,
      requirement: requirement(),
      nonce,
      expiresAt: new Date(Date.now() + 600_000).toISOString(),
    })
    const r = verifyApprovalReceipt(receiptFor(canonical, [CAROL]), expectation(nonce), {
      delegation: verified.delegation,
    })
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /only substitute the approver set for an offline approval/)
  })

  it("refuses an offline or intent payload handed to verifyDelegation", () => {
    const { receipt } = offlineProof()
    const r = verifyDelegation(receipt, delegationExpectation)
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /not a div-delegation/)
  })

  it("cannot be auto-approved", () => {
    const { canonical } = delegationProof()
    const unsigned: ApprovalReceipt = {
      canonicalPayload: canonical,
      target: TARGET,
      actionType: ACTION_TYPE,
      actionDescription: DISPLAY,
      params: PARAMS,
      requester: REQUESTER,
      sigAlg: "AUTO_APPROVED",
      signerDid: "did:intyga:pre-authorized",
      signerPublicKey: "pre-authorized",
      signature: "pre-authorized",
      verificationCode: verificationCode(canonical),
    }
    const r = verifyDelegation(unsigned, delegationExpectation)
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /cannot be auto-approved/)
  })

  // Resource bounds, mirroring the approval path (and Go/Rust/Python, which bound both paths). A
  // delegation is verified in the same process, right before the same irreversible action, so an
  // unbounded witness list is the same measured 3.6s event-loop stall one function over.
  it("refuses a delegation carrying more witnesses than the resource bound", () => {
    const { receipt } = delegationProof()
    const junk = Array.from({ length: 65 }, (_, i) => ({
      signerDid: `did:example:flood-${i}`,
      signerPublicKey: "AAAA",
      signature: "AAAA",
      sigAlg: "ES256",
    }))
    const flooded = { ...receipt, signatures: [...(receipt.signatures ?? []), ...junk] }
    const r = verifyDelegation(flooded, delegationExpectation)
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /above the 64/)
  })

  it("folds delegation failure reasons instead of concatenating all of them", () => {
    // One valid signer against a 2-signature requirement, padded with junk up to the bound: quorum
    // fails with 62 individual failure reasons, of which only 8 may reach the reason string.
    const { receipt } = delegationProof({ signers: [ALICE] })
    const junk = Array.from({ length: 62 }, (_, i) => ({
      signerDid: `did:example:flood-${i}`,
      signerPublicKey: "AAAA",
      signature: "AAAA",
      sigAlg: "ES256",
    }))
    const flooded = { ...receipt, signatures: [...(receipt.signatures ?? []), ...junk] }
    const r = verifyDelegation(flooded, delegationExpectation)
    assert.equal(r.ok, false)
    assert.match(r.reason ?? "", /delegation quorum not met/)
    assert.match(r.reason ?? "", /\+54 more/)
    assert.ok((r.reason ?? "").length < 2_000, `reason must stay bounded, got ${r.reason?.length} chars`)
  })
})

it("verifyDelegation refuses a key-set anchor at seal verification (DIV §4.4.6)", () => {
  // The sealing quorum names PEOPLE. Before the fix a publicKeys anchor was accepted here (only
  // delegatedTo enforcement at USE time refused it), so seal verification counted credentials.
  const r = verifyDelegation(
    {
      canonicalPayload: JSON.stringify({ v: 1, type: "div-delegation" }),
      actionDescription: "irrelevant",
      params: {},
    },
    { approvers: { publicKeys: ["a-listed-key"] }, target: "t", actionType: "x", params: {} },
  )
  assert.equal(r.ok, false)
  assert.match(r.reason ?? "", /§4\.4\.6/)
})
