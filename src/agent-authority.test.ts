// Agent authority (docs/DIV.md §5b), verified end to end with real P-256 signatures.
//
// Same testing posture as offline-approval.test.ts: the happy path is the least interesting case.
// What matters is that an authority can NEVER verify as an approval, that the sealing quorum and
// signer-class registry apply, and that the caller-asserted fields (target, agent DID) are bound by
// the byte comparison rather than read from the artifact.

import assert from "node:assert/strict"
import crypto from "node:crypto"
import { describe, it } from "node:test"
import {
  type ApprovalReceipt,
  canonicalAgentAuthorityPayload,
  canonicalDelegationPayload,
  canonicalOfflineIntentPayload,
  verificationCode,
  verifyAgentAuthority,
  verifyApprovalReceipt,
  verifyDelegation,
} from "./index.js"

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
const MALLORY = makeSigner("did:intyga:mallory")

const TARGET = "prod-payments"
const AGENT_DID = "did:intyga:agent:payments-bot"
const PATTERNS = ["payments.", "refund"]
const OPENER = { did: "did:intyga:admin:opener", attestation: null }
const FAR_FUTURE = "2999-01-01T00:00:00.000Z"
const SEALED_AT = "2026-07-01T00:00:00.000Z"

function requirement(over: Partial<Record<string, unknown>> = {}) {
  return {
    requiredApprovals: 2,
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

function sealedAuthority(over: {
  requirement?: ReturnType<typeof requirement>
  signers?: Signer[]
  sealedAt?: string
  expiresAt?: string
  actionPatterns?: string[]
}): ApprovalReceipt {
  const canonical = canonicalAgentAuthorityPayload({
    target: TARGET,
    actionPatterns: over.actionPatterns ?? PATTERNS,
    display: "Payments agent — refunds under review",
    agent: { did: AGENT_DID },
    requester: OPENER,
    requirement: over.requirement ?? requirement(),
    nonce: "aa_nonce-1",
    sealedAt: over.sealedAt ?? SEALED_AT,
    expiresAt: over.expiresAt ?? FAR_FUTURE,
  })
  const signers = over.signers ?? [ALICE, BOB]
  return {
    canonicalPayload: canonical,
    actionDescription: "Payments agent — refunds under review",
    params: {},
    requester: OPENER,
    signatures: signers.map((s) => ({
      signerDid: s.did,
      signerPublicKey: s.spki,
      signature: s.sign(canonical),
      sigAlg: "ES256",
    })),
    verificationCode: verificationCode(canonical),
  } as ApprovalReceipt
}

const EXPECTED = { target: TARGET, agentDid: AGENT_DID, approvers: anchor(ALICE, BOB) }

describe("verifyAgentAuthority", () => {
  it("verifies a quorum-sealed authority and reports the deduplicated sorted scope", () => {
    const r = verifyAgentAuthority(sealedAuthority({}), EXPECTED)
    assert.equal(r.ok, true, r.reason)
    assert.deepEqual(r.authority?.signers, [ALICE.did, BOB.did].sort())
    assert.deepEqual(r.authority?.actionPatterns, [...PATTERNS].sort())
    assert.equal(r.authority?.agentDid, AGENT_DID)
  })

  it("refuses an unmet sealing quorum", () => {
    const r = verifyAgentAuthority(sealedAuthority({ signers: [ALICE] }), EXPECTED)
    assert.equal(r.ok, false)
    assert.match(r.reason!, /quorum not met: 1 of 2/)
  })

  it("does not count a signer outside the trust anchor", () => {
    const r = verifyAgentAuthority(sealedAuthority({ signers: [ALICE, MALLORY] }), EXPECTED)
    assert.equal(r.ok, false)
    assert.match(r.reason!, /quorum not met/)
  })

  it("binds the agent DID: checking authority for a DIFFERENT agent fails the byte comparison", () => {
    const r = verifyAgentAuthority(sealedAuthority({}), { ...EXPECTED, agentDid: "did:intyga:agent:other" })
    assert.equal(r.ok, false)
    assert.match(r.reason!, /do not match what was sealed/)
  })

  it("binds the target the same way", () => {
    const r = verifyAgentAuthority(sealedAuthority({}), { ...EXPECTED, target: "staging" })
    assert.equal(r.ok, false)
    assert.match(r.reason!, /do not match what was sealed/)
  })

  it("refuses an expired seal unless allowExpired is passed for audit re-verification", () => {
    const expired = sealedAuthority({ expiresAt: "2026-07-02T00:00:00.000Z" })
    assert.equal(verifyAgentAuthority(expired, EXPECTED).ok, false)
    const audit = verifyAgentAuthority(expired, EXPECTED, { allowExpired: true })
    assert.equal(audit.ok, true, audit.reason)
  })

  it("refuses a seal that expires before it was sealed", () => {
    const r = verifyAgentAuthority(
      sealedAuthority({ sealedAt: FAR_FUTURE, expiresAt: SEALED_AT }),
      EXPECTED,
      { allowExpired: true },
    )
    assert.equal(r.ok, false)
    assert.match(r.reason!, /expires before it was sealed/)
  })

  it("refuses a seal dated after the evaluation time, audit override or not", () => {
    // DIV §5b.2/§5b.3: the evidence claim is that the grant was LIVE at the evaluation time, so a
    // seal that has not happened yet cannot support it. `allowExpired` covers the opposite case —
    // something that was valid and lapsed — and deliberately does not reach this.
    const future = sealedAuthority({
      sealedAt: "2999-06-01T00:00:00.000Z",
      // Ordered AFTER sealedAt, so the inverted-window rule cannot be what refuses this.
      expiresAt: "2999-07-01T00:00:00.000Z",
    })
    const r = verifyAgentAuthority(future, EXPECTED, { allowExpired: true })
    assert.equal(r.ok, false)
    assert.match(r.reason!, /sealed in the future/)
  })

  it("refuses a sealing requirement whose requiredApprovals is below 1", () => {
    // 0 satisfies "at least requiredApprovals" with nothing counted (DIV §4.3.2 / §5 step 7).
    const r = verifyAgentAuthority(
      sealedAuthority({ requirement: requirement({ requiredApprovals: 0 }) }),
      EXPECTED,
    )
    assert.equal(r.ok, false)
    assert.match(r.reason!, /requiredApprovals must be an integer of at least 1/)
  })

  it("applies the signerClass registry: an unknown class in the sealing requirement is refused", () => {
    const r = verifyAgentAuthority(
      sealedAuthority({ requirement: requirement({ signerClass: "delegated-agent" }) }),
      EXPECTED,
    )
    assert.equal(r.ok, false)
    assert.match(r.reason!, /does not recognize/)
  })

  it("enforces four-eyes on sealing when the requirement demands it", () => {
    const opener = makeSigner(OPENER.did)
    const r = verifyAgentAuthority(
      sealedAuthority({
        requirement: requirement({ requesterCannotApprove: true }),
        signers: [ALICE, opener],
      }),
      { ...EXPECTED, approvers: anchor(ALICE, opener) },
    )
    assert.equal(r.ok, false)
    assert.match(r.reason!, /quorum not met/)
  })
})

describe("an authority authorizes nothing", () => {
  it("verifyApprovalReceipt refuses the payload type outright", () => {
    const receipt = sealedAuthority({})
    const r = verifyApprovalReceipt(receipt, {
      target: TARGET,
      nonce: "aa_nonce-1",
      actionType: "payments.refund",
      params: {},
      approvers: { publicKeys: [ALICE.spki, BOB.spki] },
    })
    assert.equal(r.ok, false)
    assert.match(r.reason!, /authorizes no action on its own/)
  })

  it("verifyDelegation refuses it too — the kinds cannot be substituted", () => {
    const r = verifyDelegation(sealedAuthority({}), {
      approvers: anchor(ALICE, BOB),
      target: TARGET,
      actionType: "payments.refund",
      params: {},
    })
    assert.equal(r.ok, false)
    assert.match(r.reason!, /not a div-delegation/)
  })
})

describe("delegation expiry is checked again when a cached result is used", () => {
  it("refuses cached delegation reuse after expiry, unless explicitly auditing", () => {
    const sealedAt = new Date("2026-07-01T00:00:00.000Z")
    const expiresAt = new Date("2026-07-01T00:01:00.000Z")
    const requester = { did: OPENER.did, attestation: null }
    const requirement = {
      requiredApprovals: 1,
      requireHardwareKey: false,
      allowedAaguids: [],
      requesterCannotApprove: false,
      signerClass: "human",
    }
    const dPayload = canonicalDelegationPayload({
      target: TARGET,
      actionType: "payments.refund",
      display: "Refund",
      params: { amount: 5 },
      requester,
      requirement,
      delegatedTo: [BOB.did],
      delegatedQuorum: 1,
      nonce: "dlg-expiry",
      sealedAt: sealedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
    })
    const delegation = {
      canonicalPayload: dPayload,
      actionDescription: "Refund",
      params: { amount: 5 },
      requester,
      signatures: [
        {
          signerDid: ALICE.did,
          signerPublicKey: ALICE.spki,
          signature: ALICE.sign(dPayload),
          sigAlg: "ES256",
        },
      ],
      verificationCode: verificationCode(dPayload),
    } as ApprovalReceipt
    const expected = {
      target: TARGET,
      actionType: "payments.refund",
      params: { amount: 5 },
      approvers: anchor(ALICE),
    }
    const cached = verifyDelegation(delegation, expected, {
      asOf: new Date("2026-07-01T00:00:30Z"),
      clockSkewSeconds: 0,
    })
    assert.equal(cached.ok, true, cached.reason)
    const oPayload = canonicalOfflineIntentPayload({
      target: TARGET,
      actionType: "payments.refund",
      display: "Refund",
      params: { amount: 5 },
      requester,
      requirement,
      nonce: "off-expiry",
      challengedAt: new Date("2026-07-01T00:02:00Z").toISOString(),
      expiresAt: new Date("2026-07-01T00:03:00Z").toISOString(),
    })
    const approval = {
      canonicalPayload: oPayload,
      actionDescription: "Refund",
      params: { amount: 5 },
      requester,
      signatures: [
        { signerDid: BOB.did, signerPublicKey: BOB.spki, signature: BOB.sign(oPayload), sigAlg: "ES256" },
      ],
      verificationCode: verificationCode(oPayload),
    } as ApprovalReceipt
    const check = (allowExpired: boolean) =>
      verifyApprovalReceipt(
        approval,
        { ...expected, nonce: "off-expiry", approvers: anchor(BOB) },
        {
          allowOffline: true,
          delegation: cached.delegation,
          asOf: new Date("2026-07-01T00:02:00Z"),
          clockSkewSeconds: 0,
          allowExpired,
        },
      )
    assert.equal(check(false).ok, false)
    assert.equal(check(true).ok, true)
  })
})
