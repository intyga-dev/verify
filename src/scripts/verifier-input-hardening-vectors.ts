// The `verifierInputHardening` section of verifier-parity-vectors.json: cross-language cases for the
// Low/Informational findings of the 2026-09-27 security review (docs/reviews/2026-09-27-security-review.md):
//
//   L15  signed timestamps follow one strict RFC 3339 grammar in every port
//   L16  verifyPlatformReceipt demands user verification even when the caller waives it
//   L17  a string with an unpaired UTF-16 surrogate is refused at canonicalization
//   L18  a WebAuthn assertion whose `topOrigin` differs from `origin` is refused like crossOrigin=true
//   I7   one key mapped to two DIDs counts as one approver
//   I8   RSA-PSS anchors: salt length 32 and a 2048-bit modulus floor; divergence evidence is held to
//        the quorum rules (time bound; a Rekor entry needs a pinned submitter key)
//
// Keys are the section's own, so it regenerates independently of the rest of the file. Each sub-section
// has exactly the shape of the top-level section of the same name, and every port runs it with the same
// harness (the bundle cases like `dewpEvidenceHardening`: a policy applies only when a case has one).
//
// Run directly (`node --import tsx src/scripts/verifier-input-hardening-vectors.ts`) to replace ONLY
// this section in the committed file; generate-verifier-parity-vectors.ts also includes it.
import crypto from "node:crypto"
import { readFileSync, writeFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import {
  canonicalAgentAuthorityPayload,
  canonicalIntentPayload,
  canonicalOfflineIntentPayload,
  canonicalPlatformIntentPayload,
  verificationCode,
  type ApprovalReceipt,
} from "../index.js"
import { anchorDigest, type AnchorInput, type SignedAnchor } from "../ledger-anchor.js"
import { BUNDLE_KIND, type ProofBundle } from "../ledger-bundle.js"
import { chainHash } from "../ledger-chain.js"
import { type AuditLeaf, leafHash } from "../ledger-leaf.js"
import { hashLeaf, merkleRoot } from "../ledger-merkle.js"
import { rekorPayloadHashFor } from "../ledger-rekor.js"

type Pair = { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject }
const ec = (): Pair => crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
const spki = (p: Pair): string => p.publicKey.export({ format: "der", type: "spki" }).toString("base64")
const pem = (p: Pair): string => p.publicKey.export({ format: "pem", type: "spki" }).toString()
const es256 = (p: Pair, payload: string): string =>
  crypto
    .sign("sha256", Buffer.from(payload), { key: p.privateKey, dsaEncoding: "ieee-p1363" })
    .toString("base64")
function cose(p: Pair): string {
  const jwk = p.publicKey.export({ format: "jwk" }) as { x: string; y: string }
  return Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
    Buffer.from(jwk.x, "base64url"),
    Buffer.from([0x22, 0x58, 0x20]),
    Buffer.from(jwk.y, "base64url"),
  ]).toString("base64")
}
const sha256 = (b: Buffer | string): Buffer => crypto.createHash("sha256").update(b).digest()

export function buildVerifierInputHardening() {
  const alice = ec()
  const bob = ec()
  const passkey = ec()
  const subject = ec()
  const anchorEc = ec()
  const rekorLog = ec()
  const rsa2048 = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
  const rsa1024 = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 })
  const ANCHOR_ISSUER = "https://anchor-ih.example"
  const RSA_ISSUER = "https://anchor-ih-rsa.example"
  const RSA_SMALL_ISSUER = "https://anchor-ih-rsa-1024.example"
  const REKOR_ISSUER = "https://rekor.sigstore.dev"
  const keys = [
    { id: "ih-alice", did: "did:intyga:alice", spkiB64: spki(alice) },
    { id: "ih-bob", did: "did:intyga:bob", spkiB64: spki(bob) },
    { id: "ih-passkey", did: "did:intyga:passkey-holder", spkiB64: spki(passkey), coseB64: cose(passkey) },
    { id: "ih-subject", did: "did:intyga:subject:42", spkiB64: spki(subject), coseB64: cose(subject) },
    { id: "ih-anchor-es256", issuer: ANCHOR_ISSUER, spkiB64: spki(anchorEc) },
    { id: "ih-anchor-rsa-2048", issuer: RSA_ISSUER, spkiB64: spki(rsa2048) },
    { id: "ih-anchor-rsa-1024", issuer: RSA_SMALL_ISSUER, spkiB64: spki(rsa1024) },
    { id: "ih-rekor", issuer: REKOR_ISSUER, spkiB64: spki(rekorLog) },
  ]

  const AS_OF = "2026-09-01T12:01:00.000Z"
  const TARGET = "prod-payments"
  const ACTION = "payments.wire"
  const PARAMS = { amount: 4200, currency: "USD" }
  const NONCE = "ih-approval-nonce"
  const DISPLAY = "Wire USD 4,200"
  const requirement = (requiredApprovals = 1) => ({
    requiredApprovals,
    requireHardwareKey: false,
    allowedAaguids: [],
    requesterCannotApprove: false,
    signerClass: "human",
  })
  const requester = { did: "did:intyga:agent:payments", attestation: null }

  // ── L15: one approval per timestamp spelling, validly signed over bytes carrying it ──────────
  const approvalWith = (expiresAt: string): ApprovalReceipt => {
    const canonical = canonicalIntentPayload({
      target: TARGET,
      actionType: ACTION,
      display: DISPLAY,
      params: PARAMS,
      requester,
      requirement: requirement(),
      nonce: NONCE,
      expiresAt,
    })
    return {
      canonicalPayload: canonical,
      target: TARGET,
      actionType: ACTION,
      actionDescription: DISPLAY,
      params: PARAMS,
      requester,
      signerDid: "did:intyga:alice",
      signerPublicKey: spki(alice),
      signature: es256(alice, canonical),
      sigAlg: "ES256",
      verificationCode: verificationCode(canonical),
    }
  }
  const TIMESTAMP_REASON = "RFC3339"
  const accepted = [
    ["offset-form", "2027-09-01T14:00:00+02:00"],
    ["nanosecond-fraction", "2027-09-01T12:00:00.123456789Z"],
    ["leap-day", "2028-02-29T12:00:00Z"],
    ["offset-beyond-18-hours", "2027-09-01T12:00:00-23:59"],
  ]
  const refused = [
    ["date-only", "2027-09-01"],
    ["zone-less", "2027-09-01T12:00:00"],
    ["lowercase-separators", "2027-09-01t12:00:00z"],
    ["space-separator", "2027-09-01 12:00:00Z"],
    ["february-30", "2027-02-30T12:00:00Z"],
    ["non-leap-february-29", "2027-02-29T12:00:00Z"],
    ["hour-24", "2027-09-01T24:00:00Z"],
    ["leap-second", "2027-06-30T23:59:60Z"],
    ["comma-fraction", "2027-09-01T12:00:00,5Z"],
    ["ten-digit-fraction", "2027-09-01T12:00:00.1234567891Z"],
    ["empty-fraction", "2027-09-01T12:00:00.Z"],
    ["offset-hour-24", "2027-09-01T12:00:00+24:00"],
    ["offset-minute-60", "2027-09-01T12:00:00+05:60"],
    ["offset-without-colon", "2027-09-01T12:00:00+0200"],
    ["expanded-year", "+02027-09-01T12:00:00Z"],
    ["missing-seconds", "2027-09-01T12:00Z"],
  ]
  const timestampCases = [
    ...accepted.map(([name, ts]) => ({
      name: `timestamp-${name}-accepted`,
      receipt: approvalWith(ts as string),
      ok: true,
      signers: [spki(alice)],
    })),
    ...refused.map(([name, ts]) => ({
      name: `timestamp-${name}-refused`,
      receipt: approvalWith(ts as string),
      ok: false,
      reasonIncludes: TIMESTAMP_REASON,
    })),
  ]

  // An offline approval whose challengedAt is zone-less: the window cap is computed from it.
  const offlineCanonical = canonicalOfflineIntentPayload({
    target: TARGET,
    actionType: ACTION,
    display: DISPLAY,
    params: PARAMS,
    requester,
    requirement: requirement(),
    nonce: NONCE,
    challengedAt: "2026-09-01T12:00:00",
    expiresAt: "2026-09-01T12:30:00.000Z",
  })
  const offlineZoneLess: ApprovalReceipt = {
    ...approvalWith("2027-09-01T12:00:00Z"),
    canonicalPayload: offlineCanonical,
    signature: es256(alice, offlineCanonical),
    verificationCode: verificationCode(offlineCanonical),
  }

  // ── L18: a WebAuthn approval with (and without) a WebAuthn L3 topOrigin ──────────────────────
  const WEBAUTHN_RP = "app.example.com"
  const WEBAUTHN_ORIGIN = "https://app.example.com"
  const assertion = (
    canonical: string,
    signer: Pair,
    rpId: string,
    origin: string,
    extra: Record<string, unknown>,
    flags: number,
  ) => {
    const client = Buffer.from(
      JSON.stringify({
        type: "webauthn.get",
        challenge: Buffer.from(canonical).toString("base64url"),
        origin,
        crossOrigin: false,
        ...extra,
      }),
    )
    const auth = Buffer.concat([sha256(rpId), Buffer.from([flags, 0, 0, 0, 1])])
    const signature = crypto.sign("sha256", Buffer.concat([auth, sha256(client)]), {
      key: signer.privateKey,
      dsaEncoding: "der",
    })
    return {
      signature: signature.toString("base64url"),
      authenticatorData: auth.toString("base64url"),
      clientDataJSON: client.toString("base64url"),
    }
  }
  const webauthnApproval = (extra: Record<string, unknown>): ApprovalReceipt => {
    const base = approvalWith("2027-09-01T12:00:00.000Z")
    return {
      ...base,
      signerDid: "did:intyga:passkey-holder",
      signerPublicKey: cose(passkey),
      sigAlg: "WEBAUTHN",
      ...assertion(base.canonicalPayload, passkey, WEBAUTHN_RP, WEBAUTHN_ORIGIN, extra, 0x05),
    }
  }
  const webauthnOptions = { expectedOrigin: WEBAUTHN_ORIGIN, expectedRpId: WEBAUTHN_RP }
  const webauthnCases = [
    {
      name: "webauthn-top-origin-equal-accepted",
      receipt: webauthnApproval({ topOrigin: WEBAUTHN_ORIGIN }),
      approverKeyEncoding: "cose",
      expected: { approverKeyIds: ["ih-passkey"] },
      options: webauthnOptions,
      ok: true,
      signers: [cose(passkey)],
    },
    {
      name: "webauthn-top-origin-differs-refused",
      receipt: webauthnApproval({ topOrigin: "https://embedder.example" }),
      approverKeyEncoding: "cose",
      expected: { approverKeyIds: ["ih-passkey"] },
      options: webauthnOptions,
      ok: false,
      reasonIncludes: "topOrigin",
    },
  ]

  const approvals = {
    expected: {
      approverKeyIds: ["ih-alice"],
      target: TARGET,
      actionType: ACTION,
      params: PARAMS,
      nonce: NONCE,
    },
    options: { asOf: AS_OF },
    cases: [
      ...timestampCases,
      {
        name: "offline-challenged-at-zone-less-refused",
        receipt: offlineZoneLess,
        options: { allowOffline: true },
        ok: false,
        reasonIncludes: TIMESTAMP_REASON,
      },
      ...webauthnCases,
    ],
  }

  // ── L16 (and L15/L18 on the platform plane) ────────────────────────────────────────────────
  const RP = "platform.example"
  const ORIGIN = "https://platform.example"
  const PNONCE = "ih-platform-nonce"
  const payloadHash = sha256("verifier input hardening payload").toString("hex")
  const platformReceipt = (
    opts: { flags?: number; signedAt?: string; clientExtra?: Record<string, unknown> } = {},
  ) => {
    const canonical = canonicalPlatformIntentPayload({
      payloadHash,
      rpId: RP,
      subjectExternalId: "cust-42",
      signedAt: opts.signedAt ?? "2026-09-01T12:00:00.000Z",
      expiresAt: "2027-09-01T12:00:00.000Z",
      nonce: PNONCE,
    })
    return {
      canonicalPayload: canonical,
      payloadHash,
      rpId: RP,
      subject: { externalId: "cust-42" },
      nonce: PNONCE,
      signerDid: "did:intyga:subject:42",
      signerPublicKey: cose(subject),
      sigAlg: "WEBAUTHN",
      ...assertion(canonical, subject, RP, ORIGIN, opts.clientExtra ?? {}, opts.flags ?? 0x05),
      verificationCode: verificationCode(canonical),
    }
  }
  const platform = {
    expected: {
      approverKeyIds: ["ih-subject"],
      payloadHash,
      rpId: RP,
      nonce: PNONCE,
      subjectExternalId: "cust-42",
    },
    options: { expectedOrigin: ORIGIN, asOf: AS_OF },
    cases: [
      {
        name: "platform-user-verified-control",
        receipt: platformReceipt(),
        ok: true,
        signers: [cose(subject)],
      },
      { name: "platform-user-not-verified-refused", receipt: platformReceipt({ flags: 0x01 }), ok: false },
      {
        // DIV §5c.3: UV is unconditional; the ordinary-receipt waiver must not reach this plane.
        name: "platform-user-verification-waiver-ignored",
        receipt: platformReceipt({ flags: 0x01 }),
        options: { requireUserVerification: false },
        ok: false,
      },
      {
        name: "platform-signed-at-zone-less-refused",
        receipt: platformReceipt({ signedAt: "2026-09-01T12:00:00" }),
        ok: false,
      },
      {
        name: "platform-top-origin-differs-refused",
        receipt: platformReceipt({ clientExtra: { topOrigin: "https://embedder.example" } }),
        ok: false,
      },
    ],
  }

  // ── I7, L17 and L15 on agent authority ────────────────────────────────────────────────────
  const AGENT = "did:intyga:agent:payments"
  const authorityCanonical = (patterns: string[], sealedAt = "2026-09-01T12:00:00.000Z") =>
    canonicalAgentAuthorityPayload({
      target: TARGET,
      actionPatterns: patterns,
      display: "Payments scope",
      agent: { did: AGENT },
      requester: { did: "did:intyga:admin", attestation: null },
      requirement: requirement(2),
      nonce: "ih-authority-nonce",
      sealedAt,
      expiresAt: "2027-09-01T12:00:00.000Z",
    })
  const authorityReceipt = (canonical: string, signers: Array<[string, Pair]>): ApprovalReceipt => ({
    canonicalPayload: canonical,
    actionDescription: "Payments scope",
    params: {},
    requester: { did: "did:intyga:admin", attestation: null },
    signatures: signers.map(([did, p]) => ({
      signerDid: did,
      signerPublicKey: spki(p),
      signature: es256(p, canonical),
      sigAlg: "ES256",
    })),
    verificationCode: verificationCode(canonical),
  })
  const good = authorityCanonical(["payments."])
  // An unpaired surrogate cannot be produced by a conformant canonicalizer any more, so the bytes are
  // edited as text: the pattern carries the six ASCII characters `\ud800`, exactly what the permissive
  // canonicalizer emitted. The file itself stays valid I-JSON (the backslash is escaped in it).
  const PLACEHOLDER = "payments.LONE"
  const lone = authorityCanonical([PLACEHOLDER]).replace(PLACEHOLDER, "payments.\\ud800")
  if (!lone.includes("\\ud800")) throw new Error("lone-surrogate fixture was not applied")
  const agentAuthority = {
    expected: {
      approverDids: { "did:intyga:alice": ["ih-alice"], "did:intyga:bob": ["ih-bob"] },
      target: TARGET,
      agentDid: AGENT,
    },
    options: { asOf: AS_OF },
    cases: [
      {
        name: "authority-two-people-two-keys-control",
        receipt: authorityReceipt(good, [
          ["did:intyga:alice", alice],
          ["did:intyga:bob", bob],
        ]),
        ok: true,
        signers: ["did:intyga:alice", "did:intyga:bob"],
        actionPatterns: ["payments."],
      },
      {
        // DIV §4.4.6: the anchor maps alice's key to two DIDs; one key-holder is one approver.
        name: "authority-two-dids-sharing-one-key-count-once",
        receipt: authorityReceipt(good, [
          ["did:intyga:alice", alice],
          ["did:intyga:alice-alias", alice],
        ]),
        expected: {
          approverDids: { "did:intyga:alice": ["ih-alice"], "did:intyga:alice-alias": ["ih-alice"] },
        },
        ok: false,
      },
      {
        name: "authority-lone-surrogate-pattern-refused",
        receipt: authorityReceipt(lone, [
          ["did:intyga:alice", alice],
          ["did:intyga:bob", bob],
        ]),
        ok: false,
      },
      {
        name: "authority-sealed-at-date-only-refused",
        receipt: authorityReceipt(authorityCanonical(["payments."], "2026-09-01"), [
          ["did:intyga:alice", alice],
          ["did:intyga:bob", bob],
        ]),
        ok: false,
        reasonIncludes: TIMESTAMP_REASON,
      },
    ],
  }

  // ── I8: RSA-PSS profile and divergence admission ────────────────────────────────────────────
  const T0 = "2026-09-01T12:00:00.000Z"
  const T0_SECONDS = Date.parse(T0) / 1000
  const leaf: AuditLeaf = {
    seq: "1",
    tenantSeq: "1",
    createdAt: T0,
    event: "ACTION_APPROVED",
    outcome: "SUCCESS",
    detail: "event 1",
    metadata: { i: 1 },
    signerDid: null,
    signerPublicKey: null,
    signedPayload: null,
    signature: null,
    sigAlg: null,
    isBillable: false,
    tenantId: "tenant-ih",
    actorNodeId: null,
    subjectNodeId: null,
    edgeId: null,
    challengeId: null,
  }
  const lh = leafHash(leaf)
  const blockRoot = merkleRoot([lh])
  const root = merkleRoot([hashLeaf(blockRoot)])
  const cpChain = chainHash({
    prevChainHash: "",
    root,
    seqStart: "1",
    seqEnd: "1",
    entryCount: 1,
    anchoredAt: T0,
  })
  const trustedCheckpoint = {
    root,
    seqStart: "1",
    seqEnd: "1",
    entryCount: 1,
    anchoredAt: T0,
    chainHash: cpChain,
  }
  const proofBundle = (anchors: SignedAnchor[]): ProofBundle =>
    ({
      protocol: "DEWP",
      kind: BUNDLE_KIND,
      version: "1.0",
      profile: "trust.intyga.audit.v1",
      exportedAt: "2026-09-02T00:00:00.000Z",
      event: {
        seq: leaf.seq,
        createdAt: leaf.createdAt,
        type: leaf.event,
        outcome: leaf.outcome,
        detail: leaf.detail,
        actorDid: null,
        subjectDid: null,
        signerDid: null,
        signature: null,
        sigAlg: null,
        canonical: leaf,
      },
      proof: {
        seq: leaf.seq,
        leaf: lh,
        blockIndex: "0",
        blockRoot,
        blockProof: [],
        leafIndex: 0,
        blockLeafCount: 1,
        checkpointId: "cp-ih",
        checkpointRoot: root,
        checkpointProof: [],
        checkpointLeafIndex: 0,
        checkpointLeafCount: 1,
        anchorRef: "ih",
        anchored: true,
      },
      anchors,
    }) as ProofBundle
  const position = (over: Partial<AnchorInput>): AnchorInput => ({
    dailyRoot: root,
    timestamp: T0,
    issuer: ANCHOR_ISSUER,
    algorithm: "ES256",
    seqStart: "1",
    seqEnd: "1",
    chainHash: cpChain,
    ...over,
  })
  const rsaAnchor = (pair: Pair, issuer: string, keyId: string, saltLength: number): SignedAnchor => {
    const base = position({ issuer, algorithm: "RSA-PSS" })
    const signature = crypto
      .sign("sha256", anchorDigest(base), {
        key: pair.privateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength,
      })
      .toString("base64")
    return { ...base, keyId, signature }
  }
  const selfAnchor = (over: Partial<AnchorInput> = {}): SignedAnchor => {
    const base = position(over)
    const signature = crypto
      .sign("sha256", anchorDigest(base), { key: anchorEc.privateKey, dsaEncoding: "der" })
      .toString("base64")
    return { ...base, keyId: "ih-anchor-es256", signature }
  }
  // A Rekor entry over `anchor`, logged at `integratedTime`. `submittedBy` signs the hashedrekord
  // with a real key (checked only when the caller pins submitter keys); otherwise placeholder material.
  const rekorAnchor = (
    over: Partial<AnchorInput>,
    integratedTime: number,
    submittedBy?: Pair,
  ): SignedAnchor => {
    const base = position({ issuer: REKOR_ISSUER, ...over })
    const signature = submittedBy
      ? {
          content: crypto
            .sign("sha256", anchorDigest(base), { key: submittedBy.privateKey, dsaEncoding: "der" })
            .toString("base64"),
          publicKey: { content: Buffer.from(pem(submittedBy)).toString("base64") },
        }
      : { content: "c2ln", publicKey: { content: "cGs=" } }
    const body = Buffer.from(
      JSON.stringify({
        apiVersion: "0.0.1",
        kind: "hashedrekord",
        spec: { data: { hash: { algorithm: "sha256", value: rekorPayloadHashFor(base) } }, signature },
      }),
    ).toString("base64")
    const bare = {
      body,
      integratedTime,
      logID: "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
      logIndex: 11,
    }
    const set = crypto
      .sign("sha256", Buffer.from(JSON.stringify(bare)), { key: rekorLog.privateKey, dsaEncoding: "der" })
      .toString("base64")
    const evidence = Buffer.from(
      JSON.stringify({ uuid: "ih", ...bare, verification: { signedEntryTimestamp: set } }),
    ).toString("base64")
    return { ...base, keyId: "ih-rekor", signature: "", kind: "REKOR", evidence }
  }
  const OTHER_ROOT = "e".repeat(64)
  const LATE_SECONDS = T0_SECONDS + 117 * 86_400
  const one = (issuer: string) => ({ requiredAnchors: 1, trustedIssuers: [issuer], quorum: "N_OF_M" })
  const withRekor = { requiredAnchors: 1, trustedIssuers: [ANCHOR_ISSUER, REKOR_ISSUER], quorum: "N_OF_M" }
  const rekorOptions = {
    trustedRoot: root,
    trustedCheckpoint,
    rekorKeyId: "ih-rekor",
    rekorIssuer: REKOR_ISSUER,
  }
  // Caller-supplied anchors REPLACE the bundle's for quorum as well (verifyBundle's `anchors`), so
  // every divergence case hands over the honest anchor alongside the candidate.
  const honestAnchor = selfAnchor()
  const honest = proofBundle([honestAnchor])
  const bundles = {
    cases: [
      {
        name: "rsa-pss-digest-length-salt-accepted",
        bundle: proofBundle([rsaAnchor(rsa2048, RSA_ISSUER, "ih-anchor-rsa-2048", 32)]),
        policy: one(RSA_ISSUER),
        options: { trustedRoot: root },
        ok: true,
        properties: { anchorVerified: true },
      },
      {
        // Node/OpenSSL's signing default: the maximum salt (222 bytes for a 2048-bit key).
        name: "rsa-pss-maximum-salt-refused",
        bundle: proofBundle([
          rsaAnchor(rsa2048, RSA_ISSUER, "ih-anchor-rsa-2048", crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN),
        ]),
        policy: one(RSA_ISSUER),
        options: { trustedRoot: root },
        ok: false,
        properties: { anchorVerified: false },
      },
      {
        name: "rsa-pss-zero-salt-refused",
        bundle: proofBundle([rsaAnchor(rsa2048, RSA_ISSUER, "ih-anchor-rsa-2048", 0)]),
        policy: one(RSA_ISSUER),
        options: { trustedRoot: root },
        ok: false,
        properties: { anchorVerified: false },
      },
      {
        name: "rsa-pss-1024-bit-key-refused",
        bundle: proofBundle([rsaAnchor(rsa1024, RSA_SMALL_ISSUER, "ih-anchor-rsa-1024", 32)]),
        policy: one(RSA_SMALL_ISSUER),
        options: { trustedRoot: root },
        ok: false,
        properties: { anchorVerified: false },
      },
      {
        name: "divergence-honest-control",
        bundle: honest,
        policy: withRekor,
        options: rekorOptions,
        ok: true,
        properties: { anchorVerified: true },
      },
      {
        // Anyone can have a digest logged: without the producer's submission key pinned, a Rekor
        // entry over another root is not evidence that the issuer signed it.
        name: "divergence-rekor-unpinned-submitter-ignored",
        bundle: honest,
        policy: withRekor,
        options: {
          ...rekorOptions,
          divergenceAnchors: [honestAnchor, rekorAnchor({ dailyRoot: OTHER_ROOT }, T0_SECONDS + 120)],
        },
        ok: true,
        properties: { anchorVerified: true },
      },
      {
        name: "divergence-rekor-late-witness-ignored",
        bundle: honest,
        policy: withRekor,
        options: {
          ...rekorOptions,
          rekorSubmitterKeyIds: ["ih-anchor-es256"],
          divergenceAnchors: [honestAnchor, rekorAnchor({ dailyRoot: OTHER_ROOT }, LATE_SECONDS, anchorEc)],
        },
        ok: true,
        properties: { anchorVerified: true },
      },
      {
        name: "divergence-rekor-pinned-prompt-detected",
        bundle: honest,
        policy: withRekor,
        options: {
          ...rekorOptions,
          rekorSubmitterKeyIds: ["ih-anchor-es256"],
          divergenceAnchors: [
            honestAnchor,
            rekorAnchor({ dailyRoot: OTHER_ROOT }, T0_SECONDS + 120, anchorEc),
          ],
        },
        ok: false,
        verificationLevel: "INVALID",
        properties: { anchorVerified: false },
      },
      {
        // A SELF anchor carries no witness time; the issuer's own signature over another root for
        // this seq range is equivocation, whatever chain hash and time it names.
        name: "divergence-self-anchor-other-root-detected",
        bundle: honest,
        policy: one(ANCHOR_ISSUER),
        options: {
          trustedRoot: root,
          trustedCheckpoint,
          divergenceAnchors: [
            honestAnchor,
            selfAnchor({ dailyRoot: OTHER_ROOT, chainHash: "ab".repeat(32) }),
          ],
        },
        ok: false,
        verificationLevel: "INVALID",
        properties: { anchorVerified: false },
      },
    ],
  }

  return {
    note: "Verifier input hardening (2026-09-27 review L15-L18, I7, I8). Keys are this section's own. Each sub-section has the shape of the top-level section of the same name and runs with the same harness, except that a bundle case's `policy` applies only when present (as in `dewpEvidenceHardening`). Approval/platform options may carry requireUserVerification and allowOffline.",
    keys,
    approvals,
    platform,
    agentAuthority,
    bundles,
  }
}

// Direct run: replace this one section of the committed file, leaving every other key and case as is.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const path = fileURLToPath(
    new URL("../../../mcp-schemas/vectors/verifier-parity-vectors.json", import.meta.url),
  )
  const doc = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>
  doc.verifierInputHardening = buildVerifierInputHardening()
  writeFileSync(path, `${JSON.stringify(doc, null, 2)}\n`)
}
