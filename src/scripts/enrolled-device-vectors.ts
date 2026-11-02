// DIV §4.3.2 "Enrolled approver devices" and §5 steps 3d/3e/7: the `enrolledDevice` section of
// verifier-parity-vectors.json. Self-contained (its own keys), like `verifierInputHardening`, so
// generate-enrolled-device-vectors.ts can regenerate it alone without rotating any other section's
// keys or signatures.
//
// Harness contract (every port): an approval case's `expected.enrolledDeviceKeyIds` maps through this
// section's key table to SPKI strings and becomes `expected.enrolledDeviceKeys`; a literal
// `expected.enrolledDeviceKeys` is passed through verbatim (malformed-list cases). Delegation and
// agent-authority cases run the seal verifiers with a DID-mode anchor from `expected.approverDids`.
import crypto from "node:crypto"
import {
  canonicalAgentAuthorityPayload,
  canonicalDelegationPayload,
  canonicalIntentPayload,
  canonicalOfflineIntentPayload,
  ENROLLED_DEVICE_KEYS_MALFORMED_REASON,
  ENROLLED_DEVICE_KEYS_REQUIRED_REASON,
  ENROLLED_DEVICE_MALFORMED_REASON,
  ENROLLED_DEVICE_ORDINARY_ONLY_REASON,
  ENROLLED_DEVICE_WITH_HARDWARE_REASON,
  stableStringify,
  verificationCode,
  type ApprovalReceipt,
} from "../index.js"

interface Pair {
  publicKey: crypto.KeyObject
  privateKey: crypto.KeyObject
}
const ec = (): Pair => crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
const spki = (p: Pair): string => p.publicKey.export({ format: "der", type: "spki" }).toString("base64")
const sign = (p: Pair, payload: string): string =>
  crypto.sign("sha256", Buffer.from(payload), { key: p.privateKey, dsaEncoding: "der" }).toString("base64")
function cose(p: Pair): string {
  const jwk = p.publicKey.export({ format: "jwk" }) as { x: string; y: string }
  return Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
    Buffer.from(jwk.x, "base64url"),
    Buffer.from([0x22, 0x58, 0x20]),
    Buffer.from(jwk.y, "base64url"),
  ]).toString("base64")
}

const TARGET = "prod-payments"
const ACTION = "payments.wire"
const PARAMS = { amount: 4200, currency: "USD" }
const DISPLAY = "Wire USD 4,200"
const NONCE = "ed-approval-nonce"
const AS_OF = "2026-09-01T12:00:00.000Z"
const EXPIRES = "2027-09-01T12:00:00.000Z"
const REQUESTER = { did: "did:intyga:agent:payments", attestation: null }
const ALICE = "did:intyga:alice"
const RP = "app.example.com"
const ORIGIN = "https://app.example.com"
const WEAKER = "signed requirement is weaker than the relying party's policy"

type Requirement = Record<string, unknown>
const baseRequirement = (extra: Requirement = {}): Requirement => ({
  requiredApprovals: 1,
  requireHardwareKey: false,
  allowedAaguids: [],
  requesterCannotApprove: false,
  signerClass: "human",
  ...extra,
})

/**
 * Canonical bytes for a requirement the builders would refuse (`false`, `null`, a hardware
 * combination, a non-ordinary kind): build without the field, then splice it into the parsed object
 * and re-canonicalize. A verifier must refuse these before any signature check matters.
 */
function withRequirementField(canonical: string, value: unknown, extra: Requirement = {}): string {
  const parsed = JSON.parse(canonical) as { requirement: Requirement }
  parsed.requirement = { ...parsed.requirement, ...extra, requireEnrolledDevice: value }
  return stableStringify(parsed)
}

function intent(requirement: Requirement): string {
  return canonicalIntentPayload({
    target: TARGET,
    actionType: ACTION,
    display: DISPLAY,
    params: PARAMS,
    requester: REQUESTER,
    requirement: requirement as never,
    nonce: NONCE,
    expiresAt: EXPIRES,
  })
}

function es256Receipt(canonical: string, signerDid: string, signer: Pair): ApprovalReceipt {
  return {
    canonicalPayload: canonical,
    target: TARGET,
    actionType: ACTION,
    actionDescription: DISPLAY,
    params: PARAMS,
    requester: REQUESTER,
    signerDid,
    signerPublicKey: spki(signer),
    signature: sign(signer, canonical),
    sigAlg: "ES256",
    verificationCode: verificationCode(canonical),
  }
}

function webauthnReceipt(canonical: string, signerDid: string, signer: Pair): ApprovalReceipt {
  const client = Buffer.from(
    JSON.stringify({
      type: "webauthn.get",
      challenge: Buffer.from(canonical).toString("base64url"),
      origin: ORIGIN,
      crossOrigin: false,
    }),
  )
  // UP | UV, BE/BS clear: a device-bound passkey, still not an enrolled approver device.
  const auth = Buffer.concat([
    crypto.createHash("sha256").update(RP).digest(),
    Buffer.from([0x05, 0, 0, 0, 1]),
  ])
  const signature = crypto.sign(
    "sha256",
    Buffer.concat([auth, crypto.createHash("sha256").update(client).digest()]),
    { key: signer.privateKey, dsaEncoding: "der" },
  )
  return {
    canonicalPayload: canonical,
    target: TARGET,
    actionType: ACTION,
    actionDescription: DISPLAY,
    params: PARAMS,
    requester: REQUESTER,
    signerDid,
    signerPublicKey: cose(signer),
    signature: signature.toString("base64url"),
    sigAlg: "WEBAUTHN",
    authenticatorData: auth.toString("base64url"),
    clientDataJSON: client.toString("base64url"),
    verificationCode: verificationCode(canonical),
  }
}

export function buildEnrolledDeviceVectors() {
  const device = ec(),
    browserKey = ec(),
    passkey = ec(),
    other = ec(),
    bob = ec()
  const keys = [
    { id: "ed-device", did: ALICE, spkiB64: spki(device), coseB64: cose(device) },
    { id: "ed-browser-key", did: ALICE, spkiB64: spki(browserKey) },
    { id: "ed-passkey", did: ALICE, spkiB64: spki(passkey), coseB64: cose(passkey) },
    { id: "ed-other-device", did: "did:intyga:carol", spkiB64: spki(other) },
    { id: "ed-bob", did: "did:intyga:bob", spkiB64: spki(bob) },
  ]

  const deviceIntent = intent(baseRequirement({ requireEnrolledDevice: true }))
  const plainIntent = intent(baseRequirement())
  const deviceByDevice = es256Receipt(deviceIntent, ALICE, device)
  const deviceByBrowserKey = es256Receipt(deviceIntent, ALICE, browserKey)
  const plainByDevice = es256Receipt(plainIntent, ALICE, device)
  const devicePasskey = webauthnReceipt(deviceIntent, ALICE, passkey)
  const falseValued = es256Receipt(withRequirementField(plainIntent, false), ALICE, device)
  const nullValued = es256Receipt(withRequirementField(plainIntent, null), ALICE, device)
  const withHardware = es256Receipt(
    withRequirementField(plainIntent, true, { requireHardwareKey: true }),
    ALICE,
    device,
  )
  const withAaguids = es256Receipt(
    withRequirementField(plainIntent, true, { allowedAaguids: ["00112233-4455-6677-8899-aabbccddeeff"] }),
    ALICE,
    device,
  )
  const offline = es256Receipt(
    withRequirementField(
      canonicalOfflineIntentPayload({
        target: TARGET,
        actionType: ACTION,
        display: DISPLAY,
        params: PARAMS,
        requester: REQUESTER,
        requirement: baseRequirement() as never,
        nonce: NONCE,
        challengedAt: AS_OF,
        expiresAt: "2026-09-01T12:30:00.000Z",
      }),
      true,
    ),
    ALICE,
    device,
  )

  const keyMode = { approverKeyIds: ["ed-device"] }
  const enrolled = { enrolledDeviceKeyIds: ["ed-device"] }
  const approvals = {
    expected: {
      approverKeyIds: ["ed-device"],
      target: TARGET,
      actionType: ACTION,
      params: PARAMS,
      nonce: NONCE,
    },
    options: { asOf: "2026-09-01T12:01:00.000Z" },
    cases: [
      {
        name: "enrolled-device-es256-under-listed-key-accepted",
        receipt: deviceByDevice,
        expected: { ...keyMode, ...enrolled },
        ok: true,
        signers: [spki(device)],
      },
      {
        name: "enrolled-device-did-mode-accepted",
        receipt: deviceByDevice,
        expected: { approverDids: { [ALICE]: ["ed-browser-key", "ed-device"] }, ...enrolled },
        ok: true,
        signers: [ALICE],
      },
      {
        name: "enrolled-device-keys-required",
        receipt: deviceByDevice,
        expected: keyMode,
        ok: false,
        reason: ENROLLED_DEVICE_KEYS_REQUIRED_REASON,
      },
      {
        name: "enrolled-device-empty-key-list-refused",
        receipt: deviceByDevice,
        expected: { ...keyMode, enrolledDeviceKeys: [] },
        ok: false,
        reason: ENROLLED_DEVICE_KEYS_REQUIRED_REASON,
      },
      {
        name: "enrolled-device-malformed-key-list-refused",
        receipt: deviceByDevice,
        expected: { ...keyMode, enrolledDeviceKeys: [""] },
        ok: false,
        reason: ENROLLED_DEVICE_KEYS_MALFORMED_REASON,
      },
      {
        // The browser key is a TRUSTED approver key for alice, but not an enrolled device key.
        name: "enrolled-device-trusted-but-unlisted-key-not-counted",
        receipt: deviceByBrowserKey,
        expected: { approverDids: { [ALICE]: ["ed-browser-key", "ed-device"] }, ...enrolled },
        ok: false,
        reasonIncludes: "did not sign with an enrolled approver device key",
      },
      {
        // Listing a device key does not add trust: it is not one of the approver keys.
        name: "enrolled-device-listed-but-untrusted-key-refused",
        receipt: es256Receipt(deviceIntent, "did:intyga:carol", other),
        expected: { ...keyMode, enrolledDeviceKeyIds: ["ed-device", "ed-other-device"] },
        ok: false,
        reasonIncludes: "quorum not met",
      },
      {
        name: "enrolled-device-webauthn-witness-never-counts",
        receipt: devicePasskey,
        approverKeyEncoding: "cose",
        expected: { approverKeyIds: ["ed-passkey"], enrolledDeviceKeyIds: ["ed-passkey"] },
        options: { asOf: "2026-09-01T12:01:00.000Z", expectedOrigin: ORIGIN, expectedRpId: RP },
        ok: false,
        reasonIncludes: "did not sign with an enrolled approver device key",
      },
      {
        name: "enrolled-device-false-value-refused",
        receipt: falseValued,
        expected: { ...keyMode, ...enrolled },
        ok: false,
        reason: ENROLLED_DEVICE_MALFORMED_REASON,
      },
      {
        name: "enrolled-device-null-value-refused",
        receipt: nullValued,
        expected: { ...keyMode, ...enrolled },
        ok: false,
        reason: ENROLLED_DEVICE_MALFORMED_REASON,
      },
      {
        name: "enrolled-device-with-hardware-key-refused",
        receipt: withHardware,
        expected: { ...keyMode, ...enrolled },
        ok: false,
        reason: ENROLLED_DEVICE_WITH_HARDWARE_REASON,
      },
      {
        name: "enrolled-device-with-aaguid-allowlist-refused",
        receipt: withAaguids,
        expected: { ...keyMode, ...enrolled },
        ok: false,
        reason: ENROLLED_DEVICE_WITH_HARDWARE_REASON,
      },
      {
        name: "enrolled-device-offline-intent-refused",
        receipt: offline,
        expected: { ...keyMode, ...enrolled },
        options: { asOf: "2026-09-01T12:01:00.000Z", allowOffline: true },
        ok: false,
        reason: ENROLLED_DEVICE_ORDINARY_ONLY_REASON,
      },
      {
        name: "enrolled-device-floor-downgrade-refused",
        receipt: plainByDevice,
        expected: {
          ...keyMode,
          ...enrolled,
          requirement: { requiredApprovals: 1, requireEnrolledDevice: true },
        },
        ok: false,
        reason: `${WEAKER}: it does not require an enrolled approver device (DIV §5 step 3d)`,
      },
      {
        name: "enrolled-device-floor-equal-accepted",
        receipt: deviceByDevice,
        expected: {
          ...keyMode,
          ...enrolled,
          requirement: { requiredApprovals: 1, requireEnrolledDevice: true },
        },
        ok: true,
        signers: [spki(device)],
      },
      {
        name: "enrolled-device-floor-malformed-refused",
        receipt: deviceByDevice,
        expected: {
          ...keyMode,
          ...enrolled,
          requirement: { requiredApprovals: 1, requireEnrolledDevice: "yes" },
        },
        ok: false,
        reasonIncludes: "expected.requirement is malformed",
      },
      {
        // Without the signed field the list is never consulted, even when it names other keys.
        name: "enrolled-device-list-ignored-without-signed-field",
        receipt: plainByDevice,
        expected: { ...keyMode, enrolledDeviceKeyIds: ["ed-other-device"] },
        ok: true,
        signers: [spki(device)],
      },
    ],
  }

  // Seal kinds: the field is defined for ordinary intents only (DIV §4.3.2), refused before any
  // signature matters.
  const delegationCanonical = withRequirementField(
    canonicalDelegationPayload({
      tenantId: "11111111-1111-4111-8111-111111111111",
      target: TARGET,
      actionType: ACTION,
      display: DISPLAY,
      params: PARAMS,
      requester: REQUESTER,
      requirement: baseRequirement({ requiredApprovals: 2 }) as never,
      delegatedTo: [ALICE, "did:intyga:bob"],
      delegatedQuorum: 1,
      nonce: "ed-delegation-nonce",
      sealedAt: AS_OF,
      expiresAt: "2026-09-02T12:00:00.000Z",
    }),
    true,
  )
  const delegationReceipt: ApprovalReceipt = {
    canonicalPayload: delegationCanonical,
    actionDescription: DISPLAY,
    params: PARAMS,
    requester: REQUESTER,
    signatures: [
      {
        signerDid: ALICE,
        signerPublicKey: spki(device),
        signature: sign(device, delegationCanonical),
        sigAlg: "ES256",
      },
      {
        signerDid: "did:intyga:bob",
        signerPublicKey: spki(bob),
        signature: sign(bob, delegationCanonical),
        sigAlg: "ES256",
      },
    ],
    verificationCode: verificationCode(delegationCanonical),
  }
  const authorityCanonical = withRequirementField(
    canonicalAgentAuthorityPayload({
      target: TARGET,
      actionPatterns: ["payments."],
      display: "Payments scope",
      agent: { did: "did:intyga:agent:payments" },
      requester: { did: "did:intyga:admin", attestation: null },
      requirement: baseRequirement({ requiredApprovals: 2 }) as never,
      nonce: "ed-authority-nonce",
      sealedAt: AS_OF,
      expiresAt: EXPIRES,
    }),
    true,
  )
  const authorityReceipt: ApprovalReceipt = {
    canonicalPayload: authorityCanonical,
    actionDescription: "Payments scope",
    params: {},
    requester: { did: "did:intyga:admin", attestation: null },
    signatures: [
      {
        signerDid: ALICE,
        signerPublicKey: spki(device),
        signature: sign(device, authorityCanonical),
        sigAlg: "ES256",
      },
      {
        signerDid: "did:intyga:bob",
        signerPublicKey: spki(bob),
        signature: sign(bob, authorityCanonical),
        sigAlg: "ES256",
      },
    ],
    verificationCode: verificationCode(authorityCanonical),
  }
  const sealAnchor = { approverDids: { [ALICE]: ["ed-device"], "did:intyga:bob": ["ed-bob"] } }

  return {
    note: "DIV §4.3.2 enrolled approver devices. Own keys. An approval case's expected.enrolledDeviceKeyIds maps through this section's keys (spkiB64) to expected.enrolledDeviceKeys; a literal expected.enrolledDeviceKeys is passed verbatim. Delegation and agentAuthority cases use a DID-mode anchor from expected.approverDids.",
    keys,
    approvals,
    delegation: {
      expected: {
        ...sealAnchor,
        tenantId: "11111111-1111-4111-8111-111111111111",
        target: TARGET,
        actionType: ACTION,
        params: PARAMS,
      },
      options: { asOf: "2026-09-01T12:01:00.000Z" },
      cases: [
        {
          name: "enrolled-device-field-in-delegation-refused",
          receipt: delegationReceipt,
          ok: false,
          reason: ENROLLED_DEVICE_ORDINARY_ONLY_REASON,
        },
      ],
    },
    agentAuthority: {
      expected: { ...sealAnchor, target: TARGET, agentDid: "did:intyga:agent:payments" },
      options: { asOf: "2026-09-01T12:01:00.000Z" },
      cases: [
        {
          name: "enrolled-device-field-in-agent-authority-refused",
          receipt: authorityReceipt,
          ok: false,
          reason: ENROLLED_DEVICE_ORDINARY_ONLY_REASON,
        },
      ],
    },
  }
}
