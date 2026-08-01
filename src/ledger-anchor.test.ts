import assert from "node:assert/strict"
import crypto from "node:crypto"
import { test } from "node:test"
import {
  anchorDigest,
  anchorDigestHex,
  anchorPreimage,
  type SignedAnchor,
  signAnchor,
  verifyAnchorQuorum,
  verifyAnchorSignature,
} from "./ledger-anchor.js"
import { emptyRoot, hashLeaf } from "./ledger-merkle.js"

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
  // Divergence is only established by anchors the CALLER fetched per checkpoint. The signed anchor
  // preimage carries no checkpoint identity, so a conflicting root and a perfectly ordinary anchor
  // from another day look identical — see verifyAnchorQuorum's divergenceAnchors.
  const res = verifyAnchorQuorum([anchorA, anchorBFork], DAILY_ROOT, policy, resolve, {
    divergenceAnchors: [anchorBFork],
  })
  assert.equal(res.divergence, true)
  assert.equal(res.ok, false)
})

test("quorum: an anchor the caller did NOT vouch for cannot manufacture divergence", () => {
  // The regression: appending a genuine, publicly available anchor for a DIFFERENT day used to force
  // an INVALID verdict with a tamper alarm — denial of evidence by anyone who can edit a bundle.
  const a = es256()
  const b = es256()
  const anchorA = mkAnchor("https://a.example", a.privateKey, DAILY_ROOT)
  const otherDay = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  const anchorBOtherDay = mkAnchor("https://b.example", b.privateKey, otherDay)
  const resolve = (an: SignedAnchor) =>
    ({ "https://a.example": a.publicKey, "https://b.example": b.publicKey })[an.issuer] ?? null
  const policy = {
    requiredAnchors: 1,
    trustedIssuers: ["https://a.example", "https://b.example"],
    quorum: "N_OF_M" as const,
  }
  const res = verifyAnchorQuorum([anchorA, anchorBOtherDay], DAILY_ROOT, policy, resolve)
  assert.equal(res.divergence, false, "an unvouched anchor must not be read as divergence")
  assert.equal(res.ok, true, "the genuine quorum over this root still stands")
})

// The reference vectors printed in docs/DEWP.md §10 exist so a third party can check their SHA-256
// implementation against ours without running our code. If the spec's numbers and the implementation
// ever disagree, the spec is publishing values nobody can reproduce — so pin them here.
test("DEWP §10 published reference vectors reproduce exactly", () => {
  const coreLeaf = [
    "1048576",
    "2026-07-24T12:00:00.000Z",
    "ACTION_APPROVED",
    "SUCCESS",
    "Database drop approved",
    '{"target":"users"}',
    "did:example:human:alice",
    "base64-spki",
    '{"actionType":"db:dropTable","type":"div-intent-verification","v":1}',
    "base64-sig",
    "ES256",
    "42",
  ]
  assert.equal(
    hashLeaf(JSON.stringify(coreLeaf)),
    "0d82acddaf17b6fecccffa03e13d97174d0d0aaf69893251dcd3d79ba48385fe",
  )

  const anchor = {
    dailyRoot: "e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8",
    timestamp: "2026-07-24T23:59:00.000Z",
    issuer: "https://transparency.example.org",
    algorithm: "ES256" as const,
  }
  assert.equal(
    anchorPreimage(anchor),
    '["e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8","2026-07-24T23:59:00.000Z","https://transparency.example.org","ES256"]',
  )
  assert.equal(anchorDigestHex(anchor), "005978edb1a6227bb93622874436fc662e01ee9bb53d3708d245f728e98d5120")
  // The signed message is the RAW digest, never its hex text (§5.2).
  assert.equal(anchorDigest(anchor).length, 32)

  assert.equal(emptyRoot(), "dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986")
})

// ── Shared signedAnchor golden vectors ───────────────────────────────────────
// The committed ledger vectors pinned the anchor DIGEST but carried no key or signature, so anchor
// SIGNING — the §5.2 raw-32-bytes-not-hex interop trap — was pinned by nothing shared. Every port
// consumes this same section; an implementation that signs the 64-char hex text matches the digest
// vector and fails here, which is the trap's exact signature.
test("shared signedAnchor vectors verify (raw-digest signing, cross-language)", async () => {
  const fs = await import("node:fs")
  const path = await import("node:path")
  const { fileURLToPath } = await import("node:url")
  const vectors = JSON.parse(
    fs.readFileSync(
      path.join(
        path.dirname(fileURLToPath(import.meta.url)),
        "..",
        "..",
        "mcp-schemas",
        "vectors",
        "ledger-vectors.json",
      ),
      "utf8",
    ),
  ) as {
    signedAnchor: {
      signerKey: { spkiB64: string }
      cases: { name: string; anchor: SignedAnchor; digestHex?: string; expectOk: boolean }[]
    }
  }
  const publicKey = crypto.createPublicKey({
    key: Buffer.from(vectors.signedAnchor.signerKey.spkiB64, "base64"),
    format: "der",
    type: "spki",
  })
  for (const c of vectors.signedAnchor.cases) {
    if (c.digestHex) assert.equal(anchorDigestHex(c.anchor), c.digestHex, c.name)
    assert.equal(verifyAnchorSignature(c.anchor, publicKey), c.expectOk, c.name)
    // The same anchor through the quorum path: a 1-of-1 policy naming its issuer must agree.
    const q = verifyAnchorQuorum(
      [c.anchor],
      c.anchor.dailyRoot,
      { requiredAnchors: 1, trustedIssuers: [c.anchor.issuer], quorum: "ALL_MUST_AGREE" },
      () => publicKey,
    )
    assert.equal(q.ok, c.expectOk, `${c.name} (quorum path)`)
  }
})

// ── RFC 3161 honesty ─────────────────────────────────────────────────────────
// The producer's publication quorum legitimately counts TSA anchors (they ARE third-party
// evidence, checkable with `openssl ts -verify`), but this zero-dependency verifier deliberately
// carries no CMS/X.509 stack and cannot check them. That asymmetry must be REPORTED, not silent:
// "0 verified issuers" over a TSA-anchored root would otherwise read as "unanchored".
test("RFC 3161 TSA anchors are reported present-but-unverifiable, never silently dropped", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const dewpInput = { ...base, issuer: "https://dewp.example", algorithm: "ES256" as const }
  const dewpAnchor: SignedAnchor = {
    ...dewpInput,
    keyId: "k1",
    signature: signAnchor(dewpInput, privateKey),
  }
  const tsaAnchor: SignedAnchor = {
    ...base,
    issuer: "https://tsa.example",
    algorithm: "ES256",
    keyId: "tsa-2026",
    signature: "", // a TSA anchor carries no DEWP signature — its DER token lives in `evidence`
    kind: "RFC3161",
    evidence: Buffer.from("stand-in DER TimeStampToken").toString("base64"),
  }
  const resolve = (a: SignedAnchor) => (a.issuer === "https://dewp.example" ? publicKey : null)
  const issuers = ["https://dewp.example", "https://tsa.example"]

  // Quorum met without the TSA: the note still surfaces the TSA evidence.
  const met = verifyAnchorQuorum(
    [dewpAnchor, tsaAnchor],
    DAILY_ROOT,
    {
      requiredAnchors: 1,
      trustedIssuers: issuers,
      quorum: "N_OF_M",
    },
    resolve,
  )
  assert.equal(met.ok, true)
  assert.match(met.note ?? "", /RFC 3161/)

  // Quorum NOT met because the second trusted anchor is the TSA: the verdict must carry the
  // out-of-band pointer rather than reading as "unanchored".
  const notMet = verifyAnchorQuorum(
    [dewpAnchor, tsaAnchor],
    DAILY_ROOT,
    {
      requiredAnchors: 2,
      trustedIssuers: issuers,
      quorum: "N_OF_M",
    },
    resolve,
  )
  assert.equal(notMet.ok, false)
  assert.match(notMet.reason ?? "", /anchor quorum not met \(1\/2\)/)
  assert.match(notMet.note ?? "", /openssl ts -verify/)

  // No TSA present ⇒ no note. The note must never fire vacuously, or it trains readers to skip it.
  const clean = verifyAnchorQuorum(
    [dewpAnchor],
    DAILY_ROOT,
    {
      requiredAnchors: 1,
      trustedIssuers: issuers,
      quorum: "N_OF_M",
    },
    resolve,
  )
  assert.equal(clean.note, undefined)
})
