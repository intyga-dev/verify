import crypto from "node:crypto"
import { writeFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import {
  agentReceiptDigest,
  canonicalAgentAuthorityPayload,
  canonicalDelegationPayload,
  canonicalIntentPayload,
  canonicalOfflineIntentPayload,
  canonicalPlatformIntentPayload,
  stableStringify,
  verificationCode,
  type ApprovalReceipt,
  type PlatformReceipt,
} from "../index.js"

const TENANT = "tenant-alpha"
const OTHER_TENANT = "tenant-beta"
const TARGET = "prod-payments"
const ACTION_TYPE = "payments.wire"
const PARAMS = { amount: 4200, currency: "USD" }
const DISPLAY = "Wire USD 4,200"
const NONCE = "tenant-vector-nonce"
const AS_OF = "2026-10-10T12:00:00.000Z"
const EXPIRES = "2027-10-10T12:00:00.000Z"
const OFFLINE_EXPIRES = "2026-10-10T12:10:00.000Z"
const DELEGATION_EXPIRES = "2026-10-11T12:00:00.000Z"
const REQUESTER = { did: "did:intyga:service:release", attestation: null }
const REQUIREMENT = {
  requiredApprovals: 1,
  requireHardwareKey: false,
  allowedAaguids: [] as string[],
  requesterCannotApprove: false,
  signerClass: "human",
}

// Deliberately public test material: a fixed key keeps every language on one trust anchor.
const PRIVATE_JWK = {
  kty: "EC",
  x: "Ay-nsTNlKhurC4kkgGqXFbtrTs_XjZU3lX8XSKBLmZY",
  y: "48RePSI_KeYrdJL80riaOv0v0AV_QvkdAZnn3LzzhGE",
  crv: "P-256",
  d: "B0kk8PgcjcUlMjEJW2ENT6tCmWALTdi0PgyO4WJPx7I",
} as const
const privateKey = crypto.createPrivateKey({ key: PRIVATE_JWK, format: "jwk" })
const publicKey = crypto.createPublicKey(privateKey)
const spkiB64 = publicKey.export({ format: "der", type: "spki" }).toString("base64")
const publicJwk = publicKey.export({ format: "jwk" }) as { x: string; y: string }
const coseB64 = Buffer.concat([
  Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
  Buffer.from(publicJwk.x, "base64url"),
  Buffer.from([0x22, 0x58, 0x20]),
  Buffer.from(publicJwk.y, "base64url"),
]).toString("base64")
const DID = "did:intyga:alice"
const sign = (payload: string): string =>
  crypto
    .sign("sha256", Buffer.from(payload), { key: privateKey, dsaEncoding: "ieee-p1363" })
    .toString("base64")

function approvalReceipt(canonicalPayload: string): ApprovalReceipt {
  const signed = JSON.parse(canonicalPayload) as Record<string, unknown>
  return {
    canonicalPayload,
    target: TARGET,
    actionType: ACTION_TYPE,
    actionDescription: typeof signed.display === "string" ? signed.display : DISPLAY,
    params:
      typeof signed.params === "object" && signed.params !== null
        ? (signed.params as Record<string, unknown>)
        : {},
    requester:
      typeof signed.requester === "object" && signed.requester !== null
        ? (signed.requester as typeof REQUESTER)
        : REQUESTER,
    signerDid: DID,
    signerPublicKey: spkiB64,
    signature: sign(canonicalPayload),
    sigAlg: "ES256",
    verificationCode: verificationCode(canonicalPayload),
  }
}

function mutateAndResign(receipt: ApprovalReceipt, mutate: (p: Record<string, unknown>) => void) {
  const parsed = JSON.parse(receipt.canonicalPayload) as Record<string, unknown>
  mutate(parsed)
  return approvalReceipt(stableStringify(parsed))
}

const intentInput = {
  target: TARGET,
  actionType: ACTION_TYPE,
  display: DISPLAY,
  params: PARAMS,
  requester: REQUESTER,
  requirement: REQUIREMENT,
  nonce: NONCE,
  expiresAt: EXPIRES,
}
const intentV2 = approvalReceipt(canonicalIntentPayload({ tenantId: TENANT, ...intentInput }))
const intentV1 = approvalReceipt(canonicalIntentPayload(intentInput))
const fractionalParams = { amount: 0.30000000000000004, currency: "USD" }
const fractionalV2 = approvalReceipt(
  canonicalIntentPayload({
    tenantId: TENANT,
    ...intentInput,
    params: fractionalParams,
  }),
)
const agentExpires = "2026-10-10T12:05:00.000Z"
const agentContext = {
  action: { reversibility: "irreversible" as const, amount: null },
  agent: {
    label: "Release agent",
    configDigest: `sha256:${"1".repeat(64)}`,
    delegatedBy: null,
  },
  session: {
    id: `sha256:${"2".repeat(64)}`,
    seq: "1",
    prev: null,
    aggregate: null,
  },
  nbf: AS_OF,
}
const agentV2 = approvalReceipt(
  canonicalIntentPayload({ tenantId: TENANT, ...intentInput, expiresAt: agentExpires, agentContext }),
)
const offlineV2 = approvalReceipt(
  canonicalOfflineIntentPayload({
    tenantId: TENANT,
    ...intentInput,
    challengedAt: AS_OF,
    expiresAt: OFFLINE_EXPIRES,
  }),
)
const fractionalOfflineV2 = approvalReceipt(
  canonicalOfflineIntentPayload({
    tenantId: TENANT,
    ...intentInput,
    params: fractionalParams,
    challengedAt: AS_OF,
    expiresAt: OFFLINE_EXPIRES,
  }),
)
const offlineV1 = approvalReceipt(
  canonicalOfflineIntentPayload({
    ...intentInput,
    challengedAt: AS_OF,
    expiresAt: OFFLINE_EXPIRES,
  }),
)

const delegationInput = {
  target: TARGET,
  actionType: ACTION_TYPE,
  display: DISPLAY,
  params: PARAMS,
  requester: REQUESTER,
  requirement: REQUIREMENT,
  delegatedTo: [DID],
  delegatedQuorum: 1,
  nonce: "tenant-delegation-nonce",
  sealedAt: AS_OF,
  expiresAt: DELEGATION_EXPIRES,
}
const delegationV2 = approvalReceipt(canonicalDelegationPayload({ tenantId: TENANT, ...delegationInput }))
const fractionalDelegationV2 = approvalReceipt(
  canonicalDelegationPayload({ tenantId: TENANT, ...delegationInput, params: fractionalParams }),
)
const delegationV1 = approvalReceipt(canonicalDelegationPayload(delegationInput))
const delegationOther = approvalReceipt(
  canonicalDelegationPayload({ tenantId: OTHER_TENANT, ...delegationInput }),
)

const authorityInput = {
  target: TARGET,
  actionPatterns: ["payments."],
  display: "Payments agent authority",
  agent: { did: "did:intyga:agent:payments" },
  parentReceiptHash: null as string | null,
  requester: REQUESTER,
  requirement: REQUIREMENT,
  nonce: "tenant-authority-nonce",
  sealedAt: AS_OF,
  expiresAt: EXPIRES,
}
const authorityReceipt = (tenantId: string | undefined, input = authorityInput) =>
  approvalReceipt(canonicalAgentAuthorityPayload({ tenantId, ...input }))
const authorityV2 = authorityReceipt(TENANT)
const authorityV1 = authorityReceipt(undefined)
const delegatedAgentDid = "did:intyga:agent:worker"
const authorityRoot = authorityReceipt(TENANT)
const authorityRootV1 = authorityReceipt(undefined)
const authorityChildV1 = authorityReceipt(undefined, {
  ...authorityInput,
  agent: { did: "did:intyga:agent:worker" },
  actionPatterns: ["payments.refund"],
  nonce: "tenant-authority-child-v1-nonce",
  parentReceiptHash: agentReceiptDigest(authorityRootV1),
})
const authorityChild = authorityReceipt(OTHER_TENANT, {
  ...authorityInput,
  agent: { did: "did:intyga:agent:worker" },
  actionPatterns: ["payments.refund"],
  nonce: "tenant-authority-child-nonce",
  parentReceiptHash: agentReceiptDigest(authorityRoot),
})
const authorityChildSameTenant = authorityReceipt(TENANT, {
  ...authorityInput,
  agent: { did: delegatedAgentDid },
  actionPatterns: ["payments.wire"],
  nonce: "tenant-authority-child-valid-nonce",
  parentReceiptHash: agentReceiptDigest(authorityRoot),
})

const RP_ID = "platform.example"
const ORIGIN = "https://platform.example"
const PAYLOAD_HASH = crypto.createHash("sha256").update("tenant platform payload").digest("hex")
function platformReceipt(tenantId: string | null = TENANT): PlatformReceipt {
  const canonicalPayload = canonicalPlatformIntentPayload({
    ...(tenantId !== null ? { tenantId } : {}),
    payloadHash: PAYLOAD_HASH,
    rpId: RP_ID,
    subjectExternalId: "cust-42",
    signedAt: AS_OF,
    expiresAt: EXPIRES,
    nonce: "tenant-platform-nonce",
  })
  const clientDataJSON = Buffer.from(
    JSON.stringify({
      type: "webauthn.get",
      challenge: Buffer.from(canonicalPayload).toString("base64url"),
      origin: ORIGIN,
      crossOrigin: false,
    }),
  )
  const tail = Buffer.from([0x05, 0, 0, 0, 1])
  const authenticatorData = Buffer.concat([crypto.createHash("sha256").update(RP_ID).digest(), tail])
  const signature = crypto.sign(
    "sha256",
    Buffer.concat([authenticatorData, crypto.createHash("sha256").update(clientDataJSON).digest()]),
    { key: privateKey, dsaEncoding: "der" },
  )
  return {
    canonicalPayload,
    payloadHash: PAYLOAD_HASH,
    rpId: RP_ID,
    subject: { externalId: "cust-42" },
    nonce: "tenant-platform-nonce",
    signerDid: DID,
    signerPublicKey: coseB64,
    signature: signature.toString("base64"),
    sigAlg: "WEBAUTHN",
    authenticatorData: authenticatorData.toString("base64"),
    clientDataJSON: clientDataJSON.toString("base64"),
    verificationCode: verificationCode(canonicalPayload),
  }
}
const platformV1 = platformReceipt(null)

const delegatedAgentContext = {
  ...agentContext,
  agent: { ...agentContext.agent, delegatedBy: agentReceiptDigest(authorityChildSameTenant) },
}
const delegatedAgentReceipt = approvalReceipt(
  canonicalIntentPayload({
    tenantId: TENANT,
    ...intentInput,
    requester: { did: delegatedAgentDid, attestation: null },
    expiresAt: agentExpires,
    agentContext: delegatedAgentContext,
  }),
)

const approvalExpected = {
  approverKeyIds: ["alice"],
  target: TARGET,
  actionType: ACTION_TYPE,
  params: PARAMS,
  nonce: NONCE,
}
const didExpected = {
  approverDids: { [DID]: ["alice"] },
  target: TARGET,
  actionType: ACTION_TYPE,
  params: PARAMS,
}

const legacyMissingWitnessDid = { ...authorityRoot }
delete legacyMissingWitnessDid.signerDid
const authorityWitness = {
  signerDid: authorityRoot.signerDid,
  signerPublicKey: authorityRoot.signerPublicKey,
  signature: authorityRoot.signature,
  sigAlg: authorityRoot.sigAlg,
}
const explicitMissingWitnessDid = { ...authorityRoot, signatures: [{ ...authorityWitness }] }
delete explicitMissingWitnessDid.signatures[0]!.signerDid
const explicitNullWitnessDid = { ...authorityRoot, signatures: [{ ...authorityWitness, signerDid: null }] }
const explicitEmptyWitnessDid = { ...authorityRoot, signatures: [{ ...authorityWitness, signerDid: "" }] }
// These deliberately malformed JSON fixtures model inputs from outside TypeScript's type system.
// Keep the unsafe shape at this one explicit verifier boundary instead of weakening ApprovalReceipt.
const agentReceiptDigestFixture = (receipt: unknown) => agentReceiptDigest(receipt as ApprovalReceipt)

const vectors = {
  version: 1,
  note: "DIV v2 tenant binding. expectedTenantId:null means the caller supplies no tenant expectation; it is never read from the receipt.",
  tenantId: TENANT,
  otherTenantId: OTHER_TENANT,
  keys: [{ id: "alice", did: DID, spkiB64, coseB64 }],
  agentReceiptDigestCases: [
    {
      name: "legacy-witness-missing-signer-did-normalizes-empty",
      receipt: legacyMissingWitnessDid,
      expected: agentReceiptDigestFixture(legacyMissingWitnessDid),
    },
    {
      name: "array-witness-missing-signer-did-projects-null",
      receipt: explicitMissingWitnessDid,
      expected: agentReceiptDigestFixture(explicitMissingWitnessDid),
    },
    {
      name: "array-witness-null-signer-did-projects-null",
      receipt: explicitNullWitnessDid,
      expected: agentReceiptDigestFixture(explicitNullWitnessDid),
    },
    {
      name: "array-witness-empty-signer-did-preserves-empty",
      receipt: explicitEmptyWitnessDid,
      expected: agentReceiptDigestFixture(explicitEmptyWitnessDid),
    },
  ],
  cases: [
    {
      name: "tenant-v2-intent-valid",
      verifier: "approval",
      receipt: intentV2,
      expected: approvalExpected,
      expectedTenantId: TENANT,
      options: { asOf: AS_OF },
      ok: true,
    },
    {
      name: "tenant-v2-fractional-params-valid",
      verifier: "approval",
      receipt: fractionalV2,
      expected: { ...approvalExpected, params: fractionalParams },
      expectedTenantId: TENANT,
      options: { asOf: AS_OF },
      ok: true,
    },
    {
      name: "tenant-v2-offline-fractional-params-valid",
      verifier: "approval",
      receipt: fractionalOfflineV2,
      expected: { ...approvalExpected, params: fractionalParams },
      expectedTenantId: TENANT,
      options: { asOf: AS_OF, allowOffline: true },
      ok: true,
    },
    {
      name: "tenant-v2-delegation-fractional-params-valid",
      verifier: "delegation",
      receipt: fractionalDelegationV2,
      expected: { ...didExpected, params: fractionalParams },
      expectedTenantId: TENANT,
      options: { asOf: AS_OF },
      ok: true,
    },
    {
      name: "tenant-v2-intent-wrong-expected",
      verifier: "approval",
      receipt: intentV2,
      expected: approvalExpected,
      expectedTenantId: OTHER_TENANT,
      options: { asOf: AS_OF },
      ok: false,
    },
    {
      name: "tenant-v2-intent-case-sensitive-mismatch",
      verifier: "approval",
      receipt: intentV2,
      expected: approvalExpected,
      expectedTenantId: "Tenant-Alpha",
      options: { asOf: AS_OF },
      ok: false,
    },
    {
      name: "tenant-v2-intent-whitespace-mismatch",
      verifier: "approval",
      receipt: intentV2,
      expected: approvalExpected,
      expectedTenantId: " tenant-alpha ",
      options: { asOf: AS_OF },
      ok: false,
    },
    {
      name: "tenant-v2-intent-missing-expected",
      verifier: "approval",
      receipt: intentV2,
      expected: approvalExpected,
      expectedTenantId: null,
      options: { asOf: AS_OF },
      ok: false,
    },
    {
      name: "tenant-v2-intent-empty-expected",
      verifier: "approval",
      receipt: intentV2,
      expected: approvalExpected,
      expectedTenantId: "",
      options: { asOf: AS_OF },
      ok: false,
    },
    {
      name: "tenant-v2-intent-missing-signed-tenant",
      verifier: "approval",
      receipt: mutateAndResign(intentV2, (p) => delete p.tenantId),
      expected: approvalExpected,
      expectedTenantId: TENANT,
      options: { asOf: AS_OF },
      ok: false,
    },
    {
      name: "tenant-v2-intent-empty-signed-tenant",
      verifier: "approval",
      receipt: mutateAndResign(intentV2, (p) => {
        p.tenantId = ""
      }),
      expected: approvalExpected,
      expectedTenantId: TENANT,
      options: { asOf: AS_OF },
      ok: false,
    },
    {
      name: "tenant-v2-intent-downgrade-refused",
      verifier: "approval",
      receipt: mutateAndResign(intentV2, (p) => {
        p.v = 1
        delete p.tenantId
      }),
      expected: approvalExpected,
      expectedTenantId: TENANT,
      options: { asOf: AS_OF },
      ok: false,
    },
    {
      name: "tenant-v1-intent-legacy-valid",
      verifier: "approval",
      receipt: intentV1,
      expected: approvalExpected,
      expectedTenantId: null,
      options: { asOf: AS_OF },
      ok: true,
    },
    {
      name: "tenant-v1-intent-with-tenant-refused",
      verifier: "approval",
      receipt: intentV1,
      expected: approvalExpected,
      expectedTenantId: TENANT,
      options: { asOf: AS_OF },
      ok: false,
    },
    {
      name: "tenant-v1-offline-with-tenant-refused",
      verifier: "approval",
      receipt: offlineV1,
      expected: approvalExpected,
      expectedTenantId: TENANT,
      options: { asOf: AS_OF, allowOffline: true },
      ok: false,
    },
    {
      name: "tenant-v1-delegation-with-tenant-refused",
      verifier: "delegation",
      receipt: delegationV1,
      expected: didExpected,
      expectedTenantId: TENANT,
      options: { asOf: AS_OF },
      ok: false,
    },
    {
      name: "tenant-v1-authority-with-tenant-refused",
      verifier: "authority",
      receipt: authorityV1,
      expected: {
        approverDids: didExpected.approverDids,
        target: TARGET,
        agentDid: authorityInput.agent.did,
      },
      expectedTenantId: TENANT,
      options: { asOf: AS_OF },
      ok: false,
    },
    {
      name: "tenant-v1-platform-with-tenant-refused",
      verifier: "platform",
      receipt: platformV1,
      expected: {
        approverKeyIds: ["alice"],
        payloadHash: PAYLOAD_HASH,
        rpId: RP_ID,
        nonce: "tenant-platform-nonce",
        subjectExternalId: "cust-42",
      },
      expectedTenantId: TENANT,
      options: { asOf: AS_OF, expectedOrigin: ORIGIN },
      ok: false,
    },
    {
      name: "tenant-v2-offline-valid",
      verifier: "approval",
      receipt: offlineV2,
      expected: approvalExpected,
      expectedTenantId: TENANT,
      options: { asOf: AS_OF, allowOffline: true },
      ok: true,
    },
    {
      name: "tenant-v2-agent-intent-valid",
      verifier: "approval",
      receipt: agentV2,
      expected: { ...approvalExpected, requesterDid: REQUESTER.did, agentContext },
      expectedTenantId: TENANT,
      options: { asOf: AS_OF },
      ok: true,
    },
    {
      name: "tenant-v2-delegated-agent-chain-valid",
      verifier: "approval",
      receipt: delegatedAgentReceipt,
      expected: {
        ...approvalExpected,
        requesterDid: delegatedAgentDid,
        agentContext: delegatedAgentContext,
      },
      expectedTenantId: TENANT,
      chain: [
        {
          receipt: authorityRoot,
          expected: {
            ...didExpected,
            agentDid: authorityInput.agent.did,
          },
          expectedTenantId: TENANT,
        },
        {
          receipt: authorityChildSameTenant,
          expected: {
            ...didExpected,
            agentDid: delegatedAgentDid,
          },
          expectedTenantId: TENANT,
        },
      ],
      options: { asOf: AS_OF },
      ok: true,
    },
    {
      name: "tenant-v2-delegated-agent-requester-did-mismatch",
      verifier: "approval",
      receipt: delegatedAgentReceipt,
      expected: {
        ...approvalExpected,
        requesterDid: "did:intyga:agent:another",
        agentContext: delegatedAgentContext,
      },
      expectedTenantId: TENANT,
      chain: [
        {
          receipt: authorityRoot,
          expected: { ...didExpected, agentDid: authorityInput.agent.did },
          expectedTenantId: TENANT,
        },
        {
          receipt: authorityChildSameTenant,
          expected: { ...didExpected, agentDid: delegatedAgentDid },
          expectedTenantId: TENANT,
        },
      ],
      options: { asOf: AS_OF },
      ok: false,
    },
    {
      name: "tenant-v2-agent-requester-did-mismatch",
      verifier: "approval",
      receipt: agentV2,
      expected: { ...approvalExpected, requesterDid: "did:intyga:agent:other", agentContext },
      expectedTenantId: TENANT,
      options: { asOf: AS_OF },
      ok: false,
    },
    {
      name: "tenant-v2-delegation-valid",
      verifier: "delegation",
      receipt: delegationV2,
      expected: didExpected,
      expectedTenantId: TENANT,
      options: { asOf: AS_OF },
      ok: true,
    },
    {
      name: "tenant-v2-authority-valid",
      verifier: "authority",
      receipt: authorityV2,
      expected: {
        approverDids: didExpected.approverDids,
        target: TARGET,
        agentDid: authorityInput.agent.did,
      },
      expectedTenantId: TENANT,
      options: { asOf: AS_OF },
      ok: true,
    },
    {
      name: "tenant-v2-platform-valid",
      verifier: "platform",
      receipt: platformReceipt(),
      expected: {
        approverKeyIds: ["alice"],
        payloadHash: PAYLOAD_HASH,
        rpId: RP_ID,
        nonce: "tenant-platform-nonce",
        subjectExternalId: "cust-42",
      },
      expectedTenantId: TENANT,
      options: { asOf: AS_OF, expectedOrigin: ORIGIN },
      ok: true,
    },
    {
      name: "tenant-v2-cross-tenant-delegation-refused",
      verifier: "approval-with-delegation",
      receipt: offlineV2,
      delegationReceipt: delegationOther,
      expected: approvalExpected,
      delegationExpected: didExpected,
      expectedTenantId: TENANT,
      delegationExpectedTenantId: OTHER_TENANT,
      options: { asOf: AS_OF, allowOffline: true },
      ok: false,
    },
    {
      name: "tenant-v2-cross-tenant-authority-chain-refused",
      verifier: "authority-chain",
      chain: [
        {
          receipt: authorityRoot,
          expected: {
            approverDids: didExpected.approverDids,
            target: TARGET,
            agentDid: authorityInput.agent.did,
          },
          expectedTenantId: TENANT,
        },
        {
          receipt: authorityChild,
          expected: {
            approverDids: didExpected.approverDids,
            target: TARGET,
            agentDid: "did:intyga:agent:worker",
          },
          expectedTenantId: OTHER_TENANT,
        },
      ],
      action: {
        tenantId: TENANT,
        target: TARGET,
        actionType: "payments.refund.issue",
        agentDid: "did:intyga:agent:worker",
        delegatedBy: agentReceiptDigest(authorityChild),
      },
      options: { asOf: AS_OF },
      ok: false,
    },
    {
      name: "tenant-v1-authority-chain-archival-valid-without-tenant-expectation",
      verifier: "authority-chain",
      chain: [
        { receipt: authorityRootV1, expected: { ...didExpected, agentDid: authorityInput.agent.did } },
        { receipt: authorityChildV1, expected: { ...didExpected, agentDid: "did:intyga:agent:worker" } },
      ],
      action: {
        target: TARGET,
        actionType: "payments.refund.issue",
        agentDid: "did:intyga:agent:worker",
        delegatedBy: agentReceiptDigest(authorityChildV1),
      },
      options: { asOf: AS_OF },
      ok: true,
    },
    {
      name: "tenant-v1-authority-chain-refused-when-tenant-is-expected",
      verifier: "authority-chain",
      chain: [
        {
          receipt: authorityRootV1,
          expected: { ...didExpected, agentDid: authorityInput.agent.did },
          expectedTenantId: TENANT,
        },
        {
          receipt: authorityChildV1,
          expected: { ...didExpected, agentDid: "did:intyga:agent:worker" },
          expectedTenantId: TENANT,
        },
      ],
      action: {
        tenantId: TENANT,
        target: TARGET,
        actionType: "payments.refund.issue",
        agentDid: "did:intyga:agent:worker",
        delegatedBy: agentReceiptDigest(authorityChildV1),
      },
      options: { asOf: AS_OF },
      ok: false,
    },
  ],
  invalidBuilderTenantIds: [null, ""],
}

const output = fileURLToPath(
  new URL("../../vectors/tenant-binding-vectors.json", import.meta.url),
)
writeFileSync(output, `${JSON.stringify(vectors, null, 2)}\n`)
console.log(`wrote ${output}`)
