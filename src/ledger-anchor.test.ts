import assert from "node:assert/strict"
import crypto from "node:crypto"
import { test } from "node:test"
import {
  anchorDigestHex,
  anchorPreimage,
  type SignedAnchor,
  signAnchor,
  verifyAnchorQuorum,
  verifyAnchorSignature,
} from "./ledger-anchor.js"

const DAILY_ROOT = "e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8"
const base = {
  dailyRoot: DAILY_ROOT,
  timestamp: "2026-07-24T23:59:00.000Z",
}

function es256() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  return { publicKey, privateKey }
}

function mkAnchor(issuer: string, priv: crypto.KeyObject, root = DAILY_ROOT): SignedAnchor {
  const a = { ...base, dailyRoot: root, issuer, algorithm: "ES256" as const, keyId: `${issuer}-k1` }
  return { ...a, signature: signAnchor(a, priv) }
}

test("anchor preimage is JCS of [dailyRoot, timestamp, issuer, algorithm]", () => {
  assert.equal(
    anchorPreimage({ ...base, issuer: "https://a.example", algorithm: "ES256" }),
    `["${DAILY_ROOT}","2026-07-24T23:59:00.000Z","https://a.example","ES256"]`,
  )
})

test("digest is deterministic and 32 bytes (64 hex)", () => {
  const hex = anchorDigestHex({ ...base, issuer: "https://a.example", algorithm: "ES256" })
  assert.match(hex, /^[0-9a-f]{64}$/)
})

test("a valid ES256 anchor signature verifies; a wrong key does not", () => {
  const { publicKey, privateKey } = es256()
  const anchor = mkAnchor("https://transparency.example.org", privateKey)
  assert.equal(verifyAnchorSignature(anchor, publicKey), true)
  const other = es256()
  assert.equal(verifyAnchorSignature(anchor, other.publicKey), false)
})

test("Ed25519 and RSA-PSS anchors verify", () => {
  const ed = crypto.generateKeyPairSync("ed25519")
  const edAnchor = { ...base, issuer: "did:web:ed", algorithm: "Ed25519" as const, keyId: "ed1" }
  const edSigned: SignedAnchor = { ...edAnchor, signature: signAnchor(edAnchor, ed.privateKey) }
  assert.equal(verifyAnchorSignature(edSigned, ed.publicKey), true)

  const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
  const rsaAnchor = { ...base, issuer: "https://rsa.example", algorithm: "RSA-PSS" as const, keyId: "r1" }
  const rsaSigned: SignedAnchor = { ...rsaAnchor, signature: signAnchor(rsaAnchor, rsa.privateKey) }
  assert.equal(verifyAnchorSignature(rsaSigned, rsa.publicKey), true)
})

test("quorum: needs requiredAnchors distinct trusted issuers over the SAME root", () => {
  const a = es256()
  const b = es256()
  const anchorA = mkAnchor("https://a.example", a.privateKey)
  const anchorB = mkAnchor("https://b.example", b.privateKey)
  const keys = new Map([
    ["https://a.example", a.publicKey],
    ["https://b.example", b.publicKey],
  ])
  const resolve = (an: SignedAnchor) => keys.get(an.issuer) ?? null
  const policy = {
    requiredAnchors: 2,
    trustedIssuers: ["https://a.example", "https://b.example"],
    quorum: "N_OF_M" as const,
  }

  // One anchor → not enough.
  const one = verifyAnchorQuorum([anchorA], DAILY_ROOT, policy, resolve)
  assert.equal(one.ok, false)

  // Two distinct trusted issuers → quorum met.
  const two = verifyAnchorQuorum([anchorA, anchorB], DAILY_ROOT, policy, resolve)
  assert.equal(two.ok, true)
  assert.deepEqual(two.verifiedIssuers.sort(), ["https://a.example", "https://b.example"])
})

test("quorum: an untrusted issuer does not count", () => {
  const a = es256()
  const evil = es256()
  const good = mkAnchor("https://a.example", a.privateKey)
  const rogue = mkAnchor("https://evil.example", evil.privateKey)
  const resolve = (an: SignedAnchor) =>
    ({ "https://a.example": a.publicKey, "https://evil.example": evil.publicKey })[an.issuer] ?? null
  const policy = { requiredAnchors: 2, trustedIssuers: ["https://a.example"], quorum: "N_OF_M" as const }
  const res = verifyAnchorQuorum([good, rogue], DAILY_ROOT, policy, resolve)
  assert.equal(res.ok, false) // only one trusted issuer present
})

test("quorum: divergence (a trusted issuer signs a DIFFERENT root) is fatal", () => {
  const a = es256()
  const b = es256()
  const anchorA = mkAnchor("https://a.example", a.privateKey, DAILY_ROOT)
  const forkRoot = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  const anchorBFork = mkAnchor("https://b.example", b.privateKey, forkRoot)
  const resolve = (an: SignedAnchor) =>
    ({ "https://a.example": a.publicKey, "https://b.example": b.publicKey })[an.issuer] ?? null
  const policy = {
    requiredAnchors: 1,
    trustedIssuers: ["https://a.example", "https://b.example"],
    quorum: "N_OF_M" as const,
  }
  const res = verifyAnchorQuorum([anchorA, anchorBFork], DAILY_ROOT, policy, resolve)
  assert.equal(res.divergence, true)
  assert.equal(res.ok, false)
})
