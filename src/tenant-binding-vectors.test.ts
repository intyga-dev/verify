import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { test } from "node:test"
import { fileURLToPath } from "node:url"
import {
  canonicalAgentAuthorityPayload,
  canonicalDelegationPayload,
  canonicalIntentPayload,
  canonicalOfflineIntentPayload,
  canonicalPlatformIntentPayload,
  agentReceiptDigest,
  verifyAgentAuthority,
  verifyAgentDelegationChain,
  verifyApprovalReceipt,
  verifyDelegation,
  verifyPlatformReceipt,
  type ApprovalReceipt,
  type ApproverTrustAnchor,
  type PlatformReceipt,
  type ReceiptExpectation,
  type VerifyReceiptOptions,
} from "./index.js"

type Obj = Record<string, unknown>
interface KeyFixture {
  id: string
  did: string
  spkiB64: string
  coseB64: string
}
interface VectorCase extends Obj {
  name: string
  verifier: string
  ok: boolean
  options: Obj
}
interface Fixtures {
  keys: KeyFixture[]
  cases: VectorCase[]
  agentReceiptDigestCases: Array<{ name: string; receipt: unknown; expected: string }>
  invalidBuilderTenantIds: unknown[]
}

const fixtures = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../vectors/tenant-binding-vectors.json", import.meta.url)),
    "utf8",
  ),
) as Fixtures
const keys = new Map(fixtures.keys.map((key) => [key.id, key]))

function anchor(expected: Obj, platform = false): ApproverTrustAnchor {
  if (Array.isArray(expected.approverKeyIds)) {
    return {
      publicKeys: expected.approverKeyIds.map((id) => {
        const key = keys.get(String(id))!
        return platform ? key.coseB64 : key.spkiB64
      }),
    }
  }
  const table = expected.approverDids as Record<string, string[]>
  return {
    dids: Object.keys(table),
    resolveKey: (did) => (table[did] ?? []).map((id) => keys.get(id)!.spkiB64),
  }
}

const options = (raw: Obj): VerifyReceiptOptions =>
  ({
    ...raw,
    ...(typeof raw.asOf === "string" ? { asOf: new Date(raw.asOf) } : {}),
  }) as VerifyReceiptOptions

function expectedWithTenant(raw: Obj, expectedTenantId: unknown, platform = false): Obj {
  const { approverKeyIds: _keyIds, approverDids: _dids, ...rest } = raw
  return {
    ...rest,
    approvers: anchor(raw, platform),
    ...(expectedTenantId !== null ? { tenantId: expectedTenantId } : {}),
  }
}

test("shared tenant-binding verifier vectors", () => {
  for (const vector of fixtures.cases) {
    const expected = vector.expected as Obj | undefined
    const tenantId = vector.expectedTenantId
    let result: { ok: boolean; reason?: string }
    switch (vector.verifier) {
      case "approval": {
        const chain = Array.isArray(vector.chain)
          ? (vector.chain as Obj[]).map((link) => ({
              receipt: link.receipt as unknown as ApprovalReceipt,
              expected: expectedWithTenant(link.expected as Obj, link.expectedTenantId) as never,
            }))
          : undefined
        const opts = { ...options(vector.options), ...(chain ? { agentAuthorityChain: chain } : {}) }
        result = verifyApprovalReceipt(
          vector.receipt as unknown as ApprovalReceipt,
          expectedWithTenant(expected!, tenantId) as unknown as ReceiptExpectation,
          opts,
        )
        break
      }
      case "delegation":
        result = verifyDelegation(
          vector.receipt as unknown as ApprovalReceipt,
          expectedWithTenant(expected!, tenantId) as never,
          options(vector.options),
        )
        break
      case "authority":
        result = verifyAgentAuthority(
          vector.receipt as unknown as ApprovalReceipt,
          expectedWithTenant(expected!, tenantId) as never,
          options(vector.options),
        )
        break
      case "platform":
        result = verifyPlatformReceipt(
          vector.receipt as unknown as PlatformReceipt,
          expectedWithTenant(expected!, tenantId, true) as never,
          options(vector.options),
        )
        break
      case "approval-with-delegation": {
        const delegationExpected = vector.delegationExpected as Obj
        const proof = verifyDelegation(
          vector.delegationReceipt as unknown as ApprovalReceipt,
          expectedWithTenant(delegationExpected, vector.delegationExpectedTenantId) as never,
          options(vector.options),
        )
        assert.equal(proof.ok, true, `${vector.name}: setup delegation: ${proof.reason}`)
        result = verifyApprovalReceipt(
          vector.receipt as unknown as ApprovalReceipt,
          expectedWithTenant(expected!, tenantId) as unknown as ReceiptExpectation,
          { ...options(vector.options), delegation: proof.delegation },
        )
        break
      }
      case "authority-chain": {
        const chain = (vector.chain as Obj[]).map((link) => ({
          receipt: link.receipt as unknown as ApprovalReceipt,
          expected: expectedWithTenant(link.expected as Obj, link.expectedTenantId) as never,
        }))
        result = verifyAgentDelegationChain(chain, vector.action as never, options(vector.options))
        break
      }
      default:
        throw new Error(`unknown tenant vector verifier ${vector.verifier}`)
    }
    assert.equal(result.ok, vector.ok, `${vector.name}: ${result.reason}`)
  }
})

test("shared invalid builder tenant values are refused by every canonical builder", () => {
  const common = {
    target: "prod-payments",
    actionType: "payments.wire",
    display: "Wire USD 4,200",
    params: {},
    requester: { did: "did:intyga:service:release", attestation: null },
    requirement: {
      requiredApprovals: 1,
      requireHardwareKey: false,
      allowedAaguids: [],
      requesterCannotApprove: false,
      signerClass: "human",
    },
    nonce: "tenant-builder-nonce",
    expiresAt: "2027-10-10T12:00:00.000Z",
  }
  for (const tenantId of fixtures.invalidBuilderTenantIds) {
    assert.throws(() => canonicalIntentPayload({ tenantId, ...common } as never))
    assert.throws(() =>
      canonicalOfflineIntentPayload({
        tenantId,
        ...common,
        challengedAt: "2026-10-10T12:00:00.000Z",
      } as never),
    )
    assert.throws(() =>
      canonicalDelegationPayload({
        tenantId,
        ...common,
        delegatedTo: ["did:intyga:alice"],
        delegatedQuorum: 1,
        sealedAt: "2026-10-10T12:00:00.000Z",
      } as never),
    )
    assert.throws(() =>
      canonicalAgentAuthorityPayload({
        tenantId,
        target: common.target,
        actionPatterns: ["payments."],
        display: common.display,
        agent: { did: "did:intyga:agent:payments" },
        parentReceiptHash: null,
        requester: common.requester,
        requirement: common.requirement,
        nonce: common.nonce,
        sealedAt: "2026-10-10T12:00:00.000Z",
        expiresAt: common.expiresAt,
      } as never),
    )
    assert.throws(() =>
      canonicalPlatformIntentPayload({
        tenantId,
        payloadHash: "0".repeat(64),
        rpId: "platform.example",
        subjectExternalId: "cust-42",
        signedAt: "2026-10-10T12:00:00.000Z",
        expiresAt: common.expiresAt,
        nonce: common.nonce,
      } as never),
    )
  }
})

test("shared authority receipt digest preserves legacy and explicit witness signerDid projections", () => {
  for (const vector of fixtures.agentReceiptDigestCases) {
    assert.equal(agentReceiptDigest(vector.receipt as never), vector.expected, vector.name)
  }
})
