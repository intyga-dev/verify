// Rekor anchor verification. Before this existed, external anchors were recorded with an empty DEWP
// signature and their evidence was dropped on export, so a REKOR anchor could not contribute to a
// §5.3 quorum — AUDIT_ANCHOR_REQUIRED=2 was satisfiable only by anchors Intyga signed itself.
//
// The fixtures below are built the way Rekor builds a real entry: a hashedrekord body binding
// SHA-256(anchorDigest), and a SET that is an ECDSA-P256 signature over the canonical JSON of
// {body, integratedTime, logID, logIndex}.

import assert from "node:assert/strict"
import crypto from "node:crypto"
import { test } from "node:test"
import type { AnchorInput } from "./ledger-anchor.js"
import { parseRekorEvidence, rekorPayloadHashFor, verifyRekorAnchor } from "./ledger-rekor.js"

const ANCHOR: AnchorInput = {
  dailyRoot: "e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8",
  timestamp: "2026-07-24T23:59:00.000Z",
  issuer: "https://rekor.sigstore.dev",
  algorithm: "ES256",
  seqStart: "1",
  seqEnd: "1",
  chainHash: "c".repeat(64),
}
/** Two minutes after the anchor's claimed time: inside the default DEWP §5.3 time bound. */
const WITNESSED = Date.parse(ANCHOR.timestamp) / 1000 + 120

/** Rekor's log key. In production this is pinned from Sigstore's TUF root, never from the bundle. */
const rekorKey = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })

function hashedRekordBody(payloadHashHex: string): string {
  return Buffer.from(
    JSON.stringify({
      apiVersion: "0.0.1",
      kind: "hashedrekord",
      spec: {
        data: { hash: { algorithm: "sha256", value: payloadHashHex } },
        signature: { content: "c2ln", publicKey: { content: "cGs=" } },
      },
    }),
    "utf-8",
  ).toString("base64")
}

/** Build an entry the way Rekor would, signing the SET with `key`. */
function rekorEntry(
  payloadHashHex: string,
  opts: { key?: crypto.KeyPairKeyObjectResult; logIndex?: number; integratedTime?: number } = {},
) {
  const body = hashedRekordBody(payloadHashHex)
  const logIndex = opts.logIndex ?? 4_215_889
  const integratedTime = opts.integratedTime ?? WITNESSED
  const logID = "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
  // The SET signs the canonical JSON of exactly these four fields, keys sorted.
  const setPayload = JSON.stringify({ body, integratedTime, logID, logIndex })
  const set = crypto
    .sign("sha256", Buffer.from(setPayload, "utf-8"), {
      key: (opts.key ?? rekorKey).privateKey,
      dsaEncoding: "der",
    })
    .toString("base64")
  return {
    uuid: "24296fb24b8ad77a",
    body,
    logID,
    logIndex,
    integratedTime,
    verification: { signedEntryTimestamp: set },
  }
}

const rekorPubB64 = rekorKey.publicKey.export({ format: "der", type: "spki" }).toString("base64")

test("a genuine Rekor entry for this anchor verifies", () => {
  const entry = rekorEntry(rekorPayloadHashFor(ANCHOR))
  const res = verifyRekorAnchor(entry, ANCHOR, rekorPubB64)
  assert.equal(res.ok, true, res.reason)
  assert.equal(res.logIndex, 4_215_889)
})

test("REFUSES a valid Rekor entry that attests something else", () => {
  // The trap this check exists for: Rekor's log is public and full of millions of genuine entries.
  // Without binding the logged payload hash to THIS anchor digest, any of them would "verify".
  const someoneElse = rekorEntry(crypto.createHash("sha256").update("a different artifact").digest("hex"))
  const res = verifyRekorAnchor(someoneElse, ANCHOR, rekorPubB64)
  assert.equal(res.ok, false)
  assert.match(res.reason!, /not about this checkpoint/)
})

test("REFUSES an entry whose SET was signed by a key we do not trust", () => {
  const impostor = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const entry = rekorEntry(rekorPayloadHashFor(ANCHOR), { key: impostor })
  const res = verifyRekorAnchor(entry, ANCHOR, rekorPubB64)
  assert.equal(res.ok, false)
  assert.match(res.reason!, /does not verify/)
})

test("REFUSES a tampered logIndex or integratedTime (both are covered by the SET)", () => {
  const entry = rekorEntry(rekorPayloadHashFor(ANCHOR))
  assert.equal(verifyRekorAnchor({ ...entry, logIndex: 999 }, ANCHOR, rekorPubB64).ok, false)
  assert.equal(verifyRekorAnchor({ ...entry, integratedTime: 1 }, ANCHOR, rekorPubB64).ok, false)
})

test("REFUSES evidence with no body — the SET cannot be reconstructed without it", () => {
  const entry = rekorEntry(rekorPayloadHashFor(ANCHOR))
  const res = verifyRekorAnchor({ ...entry, body: undefined }, ANCHOR, rekorPubB64)
  assert.equal(res.ok, false)
  assert.match(res.reason!, /no entry body/)
})

test("REFUSES evidence with no SET — a stored entry is not an attestation", () => {
  const entry = rekorEntry(rekorPayloadHashFor(ANCHOR))
  const res = verifyRekorAnchor({ ...entry, verification: {} }, ANCHOR, rekorPubB64)
  assert.equal(res.ok, false)
  assert.match(res.reason!, /signedEntryTimestamp/)
})

test("an anchor for a DIFFERENT root does not match the same entry", () => {
  // The payload hash is derived from the anchor preimage, so changing the root changes what must
  // have been logged. This is what stops one day's entry vouching for another day.
  const entry = rekorEntry(rekorPayloadHashFor(ANCHOR))
  const otherDay = { ...ANCHOR, dailyRoot: "f".repeat(64) }
  assert.equal(verifyRekorAnchor(entry, otherDay, rekorPubB64).ok, false)
})

test("parseRekorEvidence round-trips what the producer stores, and rejects junk", () => {
  const entry = rekorEntry(rekorPayloadHashFor(ANCHOR))
  const stored = Buffer.from(JSON.stringify(entry), "utf-8").toString("base64")
  const parsed = parseRekorEvidence(stored)
  assert.ok(parsed)
  assert.equal(verifyRekorAnchor(parsed, ANCHOR, rekorPubB64).ok, true)
  assert.equal(parseRekorEvidence(null), null)
  assert.equal(parseRekorEvidence("not-base64-json"), null)
})

// ─── Quorum ──────────────────────────────────────────────────────────────────
// The point of all of the above: a Rekor anchor must be able to SATISFY a §5.3 quorum. Previously it
// could not — external anchors were stored with an empty DEWP signature, so verifyAnchorQuorum could
// never count one, and AUDIT_ANCHOR_REQUIRED=2 was reachable only by anchors Intyga signed itself.

test("a verified Rekor anchor counts toward the quorum", async () => {
  const { verifyAnchorQuorum } = await import("./ledger-anchor.js")
  const entry = rekorEntry(rekorPayloadHashFor(ANCHOR))
  const anchor = {
    ...ANCHOR,
    keyId: "rekor",
    signature: "", // external anchors carry no DEWP signature — the evidence is the attestation
    kind: "REKOR",
    evidence: Buffer.from(JSON.stringify(entry), "utf-8").toString("base64"),
  }
  const policy = {
    requiredAnchors: 1,
    trustedIssuers: ["https://rekor.sigstore.dev"],
    quorum: "N_OF_M" as const,
  }

  const withKey = verifyAnchorQuorum([anchor], ANCHOR.dailyRoot, policy, () => null, {
    externalKeys: { rekor: rekorPubB64 },
  })
  assert.equal(withKey.ok, true, withKey.reason)
  assert.deepEqual(withKey.verifiedIssuers, ["https://rekor.sigstore.dev"])

  // No pinned log key ⇒ the attestation cannot be checked ⇒ it must NOT count. Silently counting an
  // unverifiable anchor is exactly the hollow guarantee this work removed.
  const withoutKey = verifyAnchorQuorum([anchor], ANCHOR.dailyRoot, policy, () => null)
  assert.equal(withoutKey.ok, false, "an unverifiable Rekor anchor must not satisfy quorum")
})

test("a Rekor anchor whose evidence is for another artifact does not count", async () => {
  const { verifyAnchorQuorum } = await import("./ledger-anchor.js")
  const wrong = rekorEntry(crypto.createHash("sha256").update("unrelated").digest("hex"))
  const anchor = {
    ...ANCHOR,
    keyId: "rekor",
    signature: "",
    kind: "REKOR",
    evidence: Buffer.from(JSON.stringify(wrong), "utf-8").toString("base64"),
  }
  const res = verifyAnchorQuorum(
    [anchor],
    ANCHOR.dailyRoot,
    { requiredAnchors: 1, trustedIssuers: [ANCHOR.issuer], quorum: "N_OF_M" as const },
    () => null,
    { externalKeys: { rekor: rekorPubB64 } },
  )
  assert.equal(res.ok, false)
})

test("verifyBundle threads the pinned Rekor key through to quorum", async () => {
  // A flag that silently goes nowhere is worse than no flag: the operator believes the anchor was
  // checked. This pins that --rekor-key actually reaches verifyAnchorQuorum.
  const { verifyBundle } = await import("./ledger-bundle.js")
  const { hashLeaf, merkleRoot } = await import("./ledger-merkle.js")

  const leaf = hashLeaf("evt")
  const blockRoot = merkleRoot([leaf])
  const dailyRoot = merkleRoot([hashLeaf(blockRoot)])
  const anchorForRoot = { ...ANCHOR, dailyRoot }
  const entry = rekorEntry(rekorPayloadHashFor(anchorForRoot))

  const bundle = {
    kind: "dewp.audit.inclusion-proof" as const,
    version: 1,
    event: { seq: "1", createdAt: "2026-07-15T00:00:00.000Z", type: "T", outcome: "SUCCESS" },
    proof: {
      seq: "1",
      leaf,
      blockIndex: "0",
      blockRoot,
      blockProof: [],
      leafIndex: 0,
      blockLeafCount: 1,
      checkpointId: "cp-1",
      checkpointRoot: dailyRoot,
      checkpointProof: [],
      checkpointLeafIndex: 0,
      checkpointLeafCount: 1,
      anchorRef: "rekor:24296fb24b8ad77a",
      anchored: true,
    },
    anchors: [
      {
        ...anchorForRoot,
        keyId: "rekor",
        signature: "",
        kind: "REKOR",
        evidence: Buffer.from(JSON.stringify(entry), "utf-8").toString("base64"),
      },
    ],
  } as unknown as Parameters<typeof verifyBundle>[0]

  const policy = {
    requiredAnchors: 1,
    trustedIssuers: [ANCHOR.issuer],
    quorum: "N_OF_M" as const,
  }
  // A single proof carries no checkpoint, so the witness time is held to the caller's own record.
  const trustedCheckpoint = {
    root: dailyRoot,
    seqStart: ANCHOR.seqStart,
    seqEnd: ANCHOR.seqEnd,
    chainHash: ANCHOR.chainHash,
    anchoredAt: ANCHOR.timestamp,
  }
  const withKey = verifyBundle(bundle, {
    trustedRoot: dailyRoot,
    trustedCheckpoint,
    anchorPolicy: policy,
    resolveAnchorKey: () => null,
    externalKeys: { rekor: rekorPubB64 },
  })
  assert.equal(withKey.properties.anchorVerified, true, `expected anchored: ${withKey.notes.join("; ")}`)

  // Without that record the external witness cannot be time-bounded, so it does not count (§5.3).
  const withoutRecord = verifyBundle(bundle, {
    trustedRoot: dailyRoot,
    anchorPolicy: policy,
    resolveAnchorKey: () => null,
    externalKeys: { rekor: rekorPubB64 },
  })
  assert.equal(withoutRecord.properties.anchorVerified, false)
  assert.ok(
    withoutRecord.notes.some((n) => /no trusted checkpoint time/.test(n)),
    withoutRecord.notes.join("; "),
  )
  // And a record that dates the checkpoint differently from the anchor refuses it as another position.
  const redated = verifyBundle(bundle, {
    trustedCheckpoint: { ...trustedCheckpoint, anchoredAt: "2026-01-01T00:00:00.000Z" },
    anchorPolicy: policy,
    resolveAnchorKey: () => null,
    externalKeys: { rekor: rekorPubB64 },
  })
  assert.equal(redated.properties.anchorVerified, false)
  assert.equal(redated.rootSource, "caller-supplied")

  const withoutKey = verifyBundle(bundle, {
    trustedRoot: dailyRoot,
    anchorPolicy: policy,
    resolveAnchorKey: () => null,
  })
  assert.equal(withoutKey.properties.anchorVerified, false, "unpinned Rekor key must not count")
})
