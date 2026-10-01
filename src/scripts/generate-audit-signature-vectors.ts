import fs from "node:fs"
import crypto from "node:crypto"
import { leafHash, type AuditLeaf } from "../ledger-leaf.js"
import { hashLeaf } from "../ledger-merkle.js"
const dir = new URL("../../vectors/", import.meta.url)
const v = JSON.parse(fs.readFileSync(new URL("webauthn-vector.json", dir), "utf8"))
const r = v.receipt
// Public test-only scalar 1. Never used by an application or production signer.
const scalar = Buffer.alloc(32)
scalar[31] = 1
const ecdh = crypto.createECDH("prime256v1")
ecdh.setPrivateKey(scalar)
const point = ecdh.getPublicKey(),
  x = point.subarray(1, 33),
  y = point.subarray(33)
const privateKey = crypto.createPrivateKey({
  format: "jwk",
  key: {
    kty: "EC",
    crv: "P-256",
    d: scalar.toString("base64url"),
    x: x.toString("base64url"),
    y: y.toString("base64url"),
  },
})
const spki = crypto.createPublicKey(privateKey).export({ format: "der", type: "spki" }).toString("base64")
const cose = Buffer.concat([
  Buffer.from([0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 0x20]),
  x,
  Buffer.from([0x22, 0x58, 0x20]),
  y,
]).toString("base64")
function resign(c: AuditLeaf, p: { trustedSigners: Record<string, string[]> }) {
  const w = c.metadata as { webauthn: { authenticatorData: string; clientDataJSON: string } }
  const bytes = Buffer.concat([
    Buffer.from(w.webauthn.authenticatorData, "base64"),
    crypto.createHash("sha256").update(Buffer.from(w.webauthn.clientDataJSON, "base64")).digest(),
  ])
  c.signature = crypto.sign("sha256", bytes, privateKey).toString("base64")
  c.signerPublicKey = cose
  p.trustedSigners[r.signerDid] = [cose]
}

const canonical: AuditLeaf = {
  seq: "1",
  tenantSeq: "1",
  createdAt: "2026-09-30T00:00:00.000Z",
  event: "AUTHZ_APPROVED",
  outcome: "SUCCESS",
  detail: null,
  metadata: { webauthn: { authenticatorData: r.authenticatorData, clientDataJSON: r.clientDataJSON } },
  signerDid: r.signerDid,
  signerPublicKey: r.signerPublicKey,
  signedPayload: r.canonicalPayload,
  signature: r.signature,
  sigAlg: "WEBAUTHN",
  isBillable: false,
  tenantId: "test-tenant",
  actorNodeId: null,
  subjectNodeId: null,
  edgeId: null,
  challengeId: null,
}
const policy = {
  trustedSigners: { [r.signerDid]: [r.signerPublicKey] },
  expectedOrigin: v.origin,
  expectedRpId: v.rpId,
}
const cases: unknown[] = []
function add(
  name: string,
  mutate: (c: AuditLeaf, p: typeof policy) => void,
  status: string,
  trusted = false,
  noPolicy = false,
) {
  const c = structuredClone(canonical),
    p = structuredClone(policy)
  mutate(c, p)
  const leaf = leafHash(c),
    root = hashLeaf(leaf)
  const proof = {
    seq: "1",
    leaf,
    blockIndex: "0",
    blockRoot: leaf,
    blockProof: [],
    leafIndex: 0,
    blockLeafCount: 1,
    checkpointId: "cp",
    checkpointRoot: root,
    checkpointProof: [],
    checkpointLeafIndex: 0,
    checkpointLeafCount: 1,
    anchorRef: null,
    anchored: false,
  }
  const event = {
    seq: c.seq,
    createdAt: c.createdAt,
    type: c.event,
    outcome: c.outcome,
    detail: c.detail,
    signerDid: c.signerDid,
    signature: c.signature,
    sigAlg: c.sigAlg,
    canonical: c,
  }
  const bundle = {
    kind: "dewp.audit.inclusion-proof",
    version: "1.0",
    protocol: "DEWP",
    profile: "trust.intyga.audit.v1",
    exportedAt: "2026-09-30T00:00:00.000Z",
    event,
    proof,
  }
  cases.push({
    name,
    bundle,
    root,
    policy: noPolicy ? null : p,
    status,
    trusted,
    strictOk: status === "verified" && trusted,
  })
}
add("valid", () => {}, "verified", true)
add(
  "key-rotation",
  (_, p) => {
    p.trustedSigners[r.signerDid] = ["AAAA", ...(p.trustedSigners[r.signerDid] ?? [])]
  },
  "verified",
  true,
)
add("no-trust", () => {}, "not_checked", false, true)
add(
  "unknown-signer",
  (c) => {
    c.signerDid = "did:intyga:unknown"
  },
  "not_checked",
)
add(
  "wrong-key",
  (_, p) => {
    p.trustedSigners[r.signerDid] = ["AAAA"]
  },
  "invalid",
)
add(
  "missing-origin",
  (_, p) => {
    p.expectedOrigin = ""
  },
  "not_checked",
)
add(
  "missing-rp",
  (_, p) => {
    p.expectedRpId = ""
  },
  "not_checked",
)
add(
  "wrong-origin",
  (_, p) => {
    p.expectedOrigin = "https://evil.example"
  },
  "invalid",
)
add(
  "wrong-rp",
  (_, p) => {
    p.expectedRpId = "evil.example"
  },
  "invalid",
)
add(
  "missing-webauthn",
  (c) => {
    c.metadata = {}
  },
  "not_checked",
)
add(
  "missing-signature",
  (c) => {
    c.signature = null
  },
  "not_checked",
)
add(
  "tampered-signature",
  (c) => {
    c.signature = "AAAA"
  },
  "invalid",
)
add(
  "tampered-payload",
  (c) => {
    c.signedPayload += " "
  },
  "invalid",
)
add(
  "ignored-embedded-key",
  (c) => {
    c.signerPublicKey = "AAAA"
  },
  "verified",
  true,
)
add(
  "unsupported-algorithm",
  (c) => {
    c.sigAlg = "UNKNOWN"
  },
  "not_checked",
)
add(
  "auto-approved",
  (c) => {
    c.sigAlg = "AUTO_APPROVED"
    c.signature = null
  },
  "not_applicable",
)
add(
  "unsigned",
  (c) => {
    c.sigAlg = null
    c.signature = null
    c.signerPublicKey = null
    c.signedPayload = null
  },
  "not_applicable",
)
add(
  "missing-alg-with-signature",
  (c) => {
    c.sigAlg = null
  },
  "not_checked",
)
for (const [name, field, value] of [
  ["cross-origin", "crossOrigin", true],
  ["wrong-top-origin", "topOrigin", "https://evil.example"],
  ["wrong-ceremony", "type", "webauthn.create"],
] as const)
  add(
    name,
    (c, p) => {
      const w = (c.metadata as { webauthn: { clientDataJSON: string } }).webauthn
      const data = JSON.parse(Buffer.from(w.clientDataJSON, "base64").toString())
      data[field] = value
      w.clientDataJSON = Buffer.from(JSON.stringify(data)).toString("base64")
      resign(c, p)
    },
    "invalid",
  )
for (const [name, mask] of [
  ["missing-up", ~1],
  ["missing-uv", ~4],
] as const)
  add(
    name,
    (c, p) => {
      const w = (c.metadata as { webauthn: { authenticatorData: string } }).webauthn
      const data = Buffer.from(w.authenticatorData, "base64")
      data[32] = (data[32] ?? 0) & mask
      w.authenticatorData = data.toString("base64")
      resign(c, p)
    },
    "invalid",
  )
add(
  "webauthn-spki-refused",
  (c, p) => {
    resign(c, p)
    p.trustedSigners[r.signerDid] = [spki]
  },
  "invalid",
)
function es(c: AuditLeaf, p: typeof policy) {
  c.sigAlg = "ES256"
  c.signerPublicKey = spki
  c.signature = crypto.sign("sha256", Buffer.from(c.signedPayload ?? ""), privateKey).toString("base64")
  p.trustedSigners[r.signerDid] = [spki]
}
add("es256-trusted", es, "verified", true)
add("es256-embedded-only", es, "verified", false, true)
add(
  "es256-invalid",
  (c, p) => {
    es(c, p)
    c.signature = "AAAA"
  },
  "invalid",
)
add(
  "es256-invalid-embedded",
  (c, p) => {
    es(c, p)
    c.signature = "AAAA"
  },
  "invalid",
  false,
  true,
)
add(
  "es256-missing-key",
  (c, p) => {
    es(c, p)
    c.signerPublicKey = null
  },
  "not_checked",
  false,
  true,
)
add(
  "empty-trust",
  (_, p) => {
    p.trustedSigners[r.signerDid] = []
  },
  "not_checked",
)
add(
  "missing-payload",
  (c) => {
    c.signedPayload = null
  },
  "not_checked",
)
add(
  "metadata-null",
  (c) => {
    c.metadata = null
  },
  "not_checked",
)
add(
  "metadata-wrong-type",
  (c) => {
    c.metadata = "invalid"
  },
  "not_checked",
)
fs.writeFileSync(
  new URL("audit-signature-vectors.json", dir),
  `${JSON.stringify(
    {
      note: "Synthetic audit assertions from webauthn-vector.json. Roots recomputed after mutations to test signature checks independently of leaf binding. No change to the DEWP preimage or DIV signed payload format.",
      cases,
    },
    null,
    2,
  )}\n`,
)
