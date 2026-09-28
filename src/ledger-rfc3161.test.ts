import assert from "node:assert/strict"
import crypto from "node:crypto"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { test } from "node:test"
import type { SignedAnchor } from "./ledger-anchor.ts"
import { verifyAnchorQuorum } from "./ledger-anchor.ts"
import { verifyBundle } from "./ledger-bundle.ts"
import { hashLeaf, merkleRoot } from "./ledger-merkle.ts"
import { rekorPayloadHashFor } from "./ledger-rekor.ts"
import { type Rfc3161Trust, verifyRfc3161Anchor, verifyRfc3161TimestampAsync } from "./ledger-rfc3161.ts"

interface VectorCase {
  name: string
  anchor: SignedAnchor
  trust: Rfc3161Trust | null
  expected: boolean
}
const vectors = JSON.parse(
  fs.readFileSync(new URL("../vectors/rfc3161-vectors.json", import.meta.url), "utf8"),
) as {
  version: number
  cases: VectorCase[]
  producer: { digestHex: string; query: string; token: string; trust: Rfc3161Trust }
}
const byName = (name: string): VectorCase => {
  const value = vectors.cases.find((candidate) => candidate.name === name)
  assert.ok(value, `missing RFC 3161 vector ${name}`)
  return value
}

test("shared RFC 3161 vectors exercise real OpenSSL verification", () => {
  assert.equal(vectors.version, 1)
  for (const fixture of vectors.cases) {
    const actual = fixture.trust ? verifyRfc3161Anchor(fixture.anchor, fixture.trust) : { ok: false }
    assert.equal(actual.ok, fixture.expected, fixture.name)
    if (fixture.expected) assert.ok(actual.genTime, `${fixture.name} must authenticate genTime`)
  }
})

test("unavailable and timed-out OpenSSL processes fail closed", () => {
  const fixture = byName("valid-unchecked")
  assert.ok(fixture.trust)
  assert.equal(
    verifyRfc3161Anchor(fixture.anchor, { ...fixture.trust, opensslPath: "/definitely/missing/openssl" }).ok,
    false,
  )

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "intyga-tsa-timeout-test-"))
  const sleeper = path.join(directory, "sleeper")
  try {
    fs.writeFileSync(sleeper, "#!/usr/bin/env node\nsetTimeout(() => {}, 30_000)\n", { mode: 0o700 })
    const started = Date.now()
    assert.equal(verifyRfc3161Anchor(fixture.anchor, { ...fixture.trust, opensslPath: sleeper }).ok, false)
    assert.ok(Date.now() - started < 7_000, "subprocess timeout must stay near the five-second limit")
  } finally {
    fs.rmSync(directory, { recursive: true, force: true })
  }
})

test("async producer helper verifies the original nonce-bound request and refuses a changed nonce", async () => {
  const producer = vectors.producer
  const digest = Buffer.from(producer.digestHex, "hex")
  const request = Buffer.from(producer.query, "base64")
  const valid = await verifyRfc3161TimestampAsync(producer.token, digest, producer.trust, request)
  assert.equal(valid.ok, true, valid.reason)
  assert.ok(valid.genTime)

  // certReq is the final 01 01 ff TLV; the preceding byte is the last byte of the request nonce.
  const wrongNonce = Buffer.from(request)
  wrongNonce[wrongNonce.length - 4] ^= 1
  const refused = await verifyRfc3161TimestampAsync(producer.token, digest, producer.trust, wrongNonce)
  assert.equal(refused.ok, false)

  assert.equal((await verifyRfc3161TimestampAsync("", digest, producer.trust)).ok, false)
  assert.equal(
    (await verifyRfc3161TimestampAsync(producer.token, new Uint8Array(31), producer.trust)).ok,
    false,
  )
  assert.equal(
    (
      await verifyRfc3161TimestampAsync(producer.token, digest, {
        ...producer.trust,
        opensslPath: "/definitely/missing/openssl-async",
      })
    ).ok,
    false,
  )
})

test("async OpenSSL timeout does not block the event loop", async () => {
  const producer = vectors.producer
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "intyga-tsa-async-timeout-test-"))
  const sleeper = path.join(directory, "sleeper")
  let ticks = 0
  try {
    fs.writeFileSync(sleeper, "#!/usr/bin/env node\nsetTimeout(() => {}, 30_000)\n", { mode: 0o700 })
    const ticker = setInterval(() => ticks++, 50)
    const started = Date.now()
    const result = await verifyRfc3161TimestampAsync(producer.token, Buffer.from(producer.digestHex, "hex"), {
      ...producer.trust,
      opensslPath: sleeper,
    })
    clearInterval(ticker)
    assert.equal(result.ok, false)
    assert.ok(Date.now() - started < 7_000, "async subprocess must honor the five-second timeout")
    assert.ok(ticks >= 20, `event loop was blocked during async verification (only ${ticks} ticks)`)
  } finally {
    fs.rmSync(directory, { recursive: true, force: true })
  }
})

test("verified RFC 3161 evidence counts toward quorum and caller-attributed divergence", () => {
  const valid = byName("valid-unchecked")
  const divergent = byName("valid-different-root-for-divergence")
  assert.ok(valid.trust)
  const policy = {
    requiredAnchors: 1,
    trustedIssuers: [valid.anchor.issuer],
    quorum: "N_OF_M" as const,
  }
  const externalKeys = { rfc3161: { [valid.anchor.issuer]: valid.trust } }
  const verified = verifyAnchorQuorum([valid.anchor], valid.anchor.dailyRoot, policy, () => null, {
    externalKeys,
  })
  assert.equal(verified.ok, true, verified.reason)
  assert.deepEqual(verified.verifiedIssuers, [valid.anchor.issuer])

  const withoutTrust = verifyAnchorQuorum([valid.anchor], valid.anchor.dailyRoot, policy, () => null)
  assert.equal(withoutTrust.ok, false)
  assert.match(
    withoutTrust.note ?? "",
    /not verifiable.*configure RFC 3161 trust\/OpenSSL|not verifiable.*configure RFC 3161 trust and OpenSSL/s,
  )

  const ignoredBundleAnchor = verifyAnchorQuorum(
    [valid.anchor],
    valid.anchor.dailyRoot,
    policy,
    () => null,
    // A bundle cannot provide trust. This deliberately supplies only the independently configured map.
    { externalKeys, divergenceAnchors: [divergent.anchor] },
  )
  assert.equal(ignoredBundleAnchor.divergence, true)
  assert.equal(ignoredBundleAnchor.ok, false)

  // Genuine evidence attached to another root but omitted from caller-attributed candidates cannot
  // manufacture a tamper alarm merely by being inserted into an untrusted bundle.
  const notAttributed = verifyAnchorQuorum(
    [valid.anchor, divergent.anchor],
    valid.anchor.dailyRoot,
    policy,
    () => null,
    { externalKeys },
  )
  assert.equal(notAttributed.divergence, false)
  assert.equal(notAttributed.ok, true)
})

test("verifyBundle threads caller-owned RFC 3161 trust into anchor quorum", () => {
  const fixture = byName("valid-unchecked")
  assert.ok(fixture.trust)
  const leaf = hashLeaf("evt")
  const blockRoot = merkleRoot([leaf])
  const dailyRoot = merkleRoot([hashLeaf(blockRoot)])
  // The fixture root is deliberately the genuine one-leaf proof root, because anchorVerified is
  // available only after commitment verification succeeds.
  const bundle = {
    kind: "dewp.audit.inclusion-proof",
    version: 1,
    event: { seq: "1", createdAt: "2026-09-25T00:00:00.000Z", type: "T", outcome: "SUCCESS" },
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
      anchorRef: "tsa:vector",
      anchored: true,
    },
    anchors: [fixture.anchor],
  } as unknown as Parameters<typeof verifyBundle>[0]
  const policy = {
    requiredAnchors: 1,
    trustedIssuers: [fixture.anchor.issuer],
    quorum: "N_OF_M" as const,
  }
  const externalKeys = { rfc3161: { [fixture.anchor.issuer]: fixture.trust } }
  const result = verifyBundle(bundle, {
    trustedRoot: fixture.anchor.dailyRoot,
    // A single proof carries no checkpoint: the TSA time is bounded against the caller's record (§5.3).
    trustedCheckpoint: {
      root: fixture.anchor.dailyRoot,
      seqStart: fixture.anchor.seqStart,
      seqEnd: fixture.anchor.seqEnd,
      chainHash: fixture.anchor.chainHash,
      anchoredAt: fixture.anchor.timestamp,
    },
    anchorPolicy: policy,
    externalKeys,
  })
  assert.equal(result.properties.anchorVerified, true, result.notes.join("; "))
})

test("a release bundle needs both independently verified Rekor and RFC 3161 witnesses", () => {
  const tsa = byName("valid-unchecked")
  assert.ok(tsa.trust)
  const rekorIssuer = "https://rekor.release.example"
  const logKey = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const makeRekorAnchor = (issuer: string, dailyRoot = tsa.anchor.dailyRoot): SignedAnchor => {
    const base = {
      ...tsa.anchor,
      dailyRoot,
      issuer,
      kind: "REKOR",
      keyId: "release-log",
      signature: "",
      evidence: null,
    } satisfies SignedAnchor
    const body = Buffer.from(
      JSON.stringify({
        apiVersion: "0.0.1",
        kind: "hashedrekord",
        spec: {
          data: { hash: { algorithm: "sha256", value: rekorPayloadHashFor(base) } },
          signature: { content: "c2ln", publicKey: { content: "cGs=" } },
        },
      }),
    ).toString("base64")
    const entry = {
      body,
      // Witnessed a minute after the checkpoint time the anchor claims (DEWP §5.3 time bound).
      integratedTime: Math.floor(Date.parse(base.timestamp) / 1000) + 60,
      logID: "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
      logIndex: 42,
      verification: { signedEntryTimestamp: "" },
    }
    entry.verification.signedEntryTimestamp = crypto
      .sign(
        "sha256",
        Buffer.from(
          JSON.stringify({
            body: entry.body,
            integratedTime: entry.integratedTime,
            logID: entry.logID,
            logIndex: entry.logIndex,
          }),
        ),
        { key: logKey.privateKey, dsaEncoding: "der" },
      )
      .toString("base64")
    return { ...base, evidence: Buffer.from(JSON.stringify(entry)).toString("base64") }
  }
  const rekorAnchor = makeRekorAnchor(rekorIssuer)

  const leaf = hashLeaf("evt")
  const blockRoot = merkleRoot([leaf])
  const dailyRoot = merkleRoot([hashLeaf(blockRoot)])
  assert.equal(dailyRoot, tsa.anchor.dailyRoot, "fixture stopped matching the release proof")
  const makeBundle = (anchors: SignedAnchor[]) =>
    ({
      kind: "dewp.audit.inclusion-proof",
      version: 1,
      event: { seq: "1", createdAt: "2026-09-25T00:00:00.000Z", type: "T", outcome: "SUCCESS" },
      proof: {
        seq: "1",
        leaf,
        blockIndex: "0",
        blockRoot,
        blockProof: [],
        leafIndex: 0,
        blockLeafCount: 1,
        checkpointId: "cp-release",
        checkpointRoot: dailyRoot,
        checkpointProof: [],
        checkpointLeafIndex: 0,
        checkpointLeafCount: 1,
        anchorRef: "release:two-witness",
        anchored: true,
      },
      anchors,
    }) as unknown as Parameters<typeof verifyBundle>[0]
  const anchorPolicy = {
    requiredAnchors: 2,
    trustedIssuers: [rekorIssuer, tsa.anchor.issuer],
    quorum: "N_OF_M" as const,
  }
  const logSpki = logKey.publicKey.export({ format: "der", type: "spki" }).toString("base64")
  const externalKeys = {
    rekor: logSpki,
    rekorIssuer,
    rfc3161: { [tsa.anchor.issuer]: tsa.trust },
  }
  const unresolvedSelf: SignedAnchor = {
    ...tsa.anchor,
    issuer: rekorIssuer,
    kind: "SELF",
    keyId: "unresolved-self",
    signature: "not-a-signature",
    evidence: null,
  }
  const verify = (anchors: SignedAnchor[], keys: typeof externalKeys = externalKeys) =>
    verifyBundle(makeBundle([unresolvedSelf, ...anchors]), {
      trustedRoot: dailyRoot,
      trustedCheckpoint: {
        root: dailyRoot,
        seqStart: tsa.anchor.seqStart,
        seqEnd: tsa.anchor.seqEnd,
        chainHash: tsa.anchor.chainHash,
        anchoredAt: tsa.anchor.timestamp,
      },
      anchorPolicy,
      externalKeys: keys,
    })

  const valid = verify([rekorAnchor, tsa.anchor])
  assert.equal(valid.properties.anchorVerified, true, valid.notes.join("; "))
  assert.equal(valid.ok, true, valid.notes.join("; "))

  const rekorEntry = JSON.parse(Buffer.from(rekorAnchor.evidence!, "base64").toString("utf8")) as {
    body: string
    integratedTime: number
    logID: string
    logIndex: number
    verification: { signedEntryTimestamp: string }
  }
  const tamperedSet = Buffer.from(rekorEntry.verification.signedEntryTimestamp, "base64")
  tamperedSet[tamperedSet.length - 1] ^= 1
  const badRekor: SignedAnchor = {
    ...rekorAnchor,
    evidence: Buffer.from(
      JSON.stringify({
        ...rekorEntry,
        verification: { signedEntryTimestamp: tamperedSet.toString("base64") },
      }),
    ).toString("base64"),
  }
  assert.equal(verify([badRekor, tsa.anchor]).properties.anchorVerified, false)

  const badTsa = byName("tampered-token").anchor
  assert.equal(verify([rekorAnchor, badTsa]).properties.anchorVerified, false)
  assert.equal(
    verify([rekorAnchor, tsa.anchor], { rekor: logSpki, rekorIssuer, rfc3161: {} }).properties.anchorVerified,
    false,
  )

  // A Rekor log signs submitted digests, not issuer identities it independently controls. The same
  // genuine log key must not be reusable to mint a second quorum identity under the TSA's name.
  const forgedSecondIssuer = makeRekorAnchor(tsa.anchor.issuer)
  const attack = verifyAnchorQuorum([rekorAnchor, forgedSecondIssuer], dailyRoot, anchorPolicy, () => null, {
    externalKeys,
  })
  assert.equal(attack.ok, false)
  assert.deepEqual(attack.verifiedIssuers, [rekorIssuer])

  // Omitting the issuer scope is fail-closed for any multi-issuer policy, including valid evidence.
  const unscoped = verifyAnchorQuorum([rekorAnchor, tsa.anchor], dailyRoot, anchorPolicy, () => null, {
    externalKeys: { rekor: logSpki, rfc3161: { [tsa.anchor.issuer]: tsa.trust } },
  })
  assert.equal(unscoped.ok, false)
  assert.deepEqual(unscoped.verifiedIssuers, [tsa.anchor.issuer])

  const wrongIssuerDivergence = verifyAnchorQuorum([tsa.anchor], dailyRoot, anchorPolicy, () => null, {
    externalKeys,
    divergenceAnchors: [makeRekorAnchor(tsa.anchor.issuer, "b".repeat(64))],
  })
  assert.equal(wrongIssuerDivergence.divergence, false)
})
