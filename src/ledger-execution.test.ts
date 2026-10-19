import assert from "node:assert/strict"
import crypto from "node:crypto"
import { test } from "node:test"
import { type ApprovalReceipt, NonCanonicalValue, verifyApprovalReceipt } from "./index.js"
import {
  canonicalExecutionEvidenceStatement,
  checkExecutionEvidenceLeaf,
  evaluateExecutionEvidence,
  executionPayloadSha256,
  isExecutionEvidenceLeaf,
  isExecutionEvidencePayload,
  parseExecutionEvidenceStatement,
  verifyEvidenceSignature,
} from "./ledger-execution.js"
import type { AuditLeaf } from "./ledger-leaf.js"
import { verifyAuditSignature } from "./ledger-signature.js"

const NONCE = "4f6c1c9e-1b8a-4e2f-9d3a-7c2b5e8f0a1d"
const HASH = "a".repeat(64)
const input = {
  nonce: NONCE,
  payloadSha256: HASH,
  source: "did:example:relay-7",
  verdict: "confirmed" as const,
  observedAt: "2026-10-05T14:02:11.000Z",
  sampledAt: "2026-10-05T14:02:09.500Z",
  sequence: 7,
  observation: { breaker: "open", currentA: 0, ratio: 0.25, nested: { list: [1, "two", null] } },
}

// Byte parity with @intyga/mcp-schemas lives in canonical-parity.test.ts, which the public tree
// drops: this file must run from the published package alone (the public-trees CI job runs it).
test("the statement builder produces bytes its own parser accepts", () => {
  for (const verdict of ["confirmed", "contradicted"] as const) {
    const ours = canonicalExecutionEvidenceStatement({ ...input, verdict })
    assert.equal(parseExecutionEvidenceStatement(ours).ok, true)
  }
  assert.equal(
    executionPayloadSha256('{"a":"é"}'),
    crypto.createHash("sha256").update('{"a":"é"}', "utf8").digest("hex"),
  )
})

test("the builders refuse input a verifier would reject", () => {
  const refused = [
    { ...input, payloadSha256: "A".repeat(64) },
    { ...input, nonce: "" },
    { ...input, source: "" },
    { ...input, observedAt: "2026-10-05T14:02:11Z" },
    { ...input, observation: { big: 1e16 } },
    { ...input, observation: { note: "x".repeat(16_400) } },
    // Rule 11: the sample cannot postdate the statement. Rule 12: a whole, positive counter.
    { ...input, sampledAt: "2026-10-05T14:02:11.001Z" },
    { ...input, sampledAt: "2026-10-05T14:02:09Z" },
    { ...input, sequence: 0 },
    { ...input, sequence: 1.5 },
    { ...input, sequence: 9_007_199_254_740_992 },
  ]
  for (const bad of refused) {
    assert.throws(() => canonicalExecutionEvidenceStatement(bad), NonCanonicalValue)
  }
})

test("the parser refuses malformed statements", () => {
  const good = canonicalExecutionEvidenceStatement(input)
  for (const bytes of [
    good.replace('"v":1', '"v":2'),
    good.replace('"approval":{', '"approval":{"extra":0,'),
    good.replace("dewp-execution-evidence", "div-intent-verification"),
    good.replace('"verdict":"confirmed"', '"verdict":"maybe"'),
    good.replace(/"observation":\{.*?\},"observedAt"/, '"observation":"text","observedAt"'),
    "[1]",
    "{",
    // Canonicalizer refusals must surface as a malformed statement, never a throw.
    good.replace('"ratio":0.25', '"ratio":-0'),
    good.replace('"ratio":0.25', '"ratio":1e-7'),
    good.replace('"ratio":0.25', '"ratio":10000000000000000'),
    `{"approval":1,"observation":{},"observedAt":"x","source":"s","type":"dewp-execution-evidence","v":1,"verdict":"confirmed"}`,
  ]) {
    assert.equal(parseExecutionEvidenceStatement(bytes).ok, false, bytes.slice(0, 60))
  }
})

test("an ordinary approval verifier refuses a statement with its own reason", () => {
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const canonical = canonicalExecutionEvidenceStatement(input)
  const receipt = {
    canonicalPayload: canonical,
    target: "t",
    actionType: "a",
    actionDescription: "d",
    params: {},
    requester: { did: "did:example:r", attestation: null },
    signerDid: "did:example:relay-7",
    signerPublicKey: pair.publicKey.export({ format: "der", type: "spki" }).toString("base64"),
    signature: crypto.sign("sha256", Buffer.from(canonical), pair.privateKey).toString("base64"),
    sigAlg: "ES256",
  } as unknown as ApprovalReceipt
  const result = verifyApprovalReceipt(receipt, {
    target: "t",
    actionType: "a",
    params: {},
  } as never)
  assert.equal(result.ok, false)
  assert.match(result.reason ?? "", /execution-evidence statement/)
})

const leaf = (over: Partial<AuditLeaf> = {}): AuditLeaf => ({
  seq: "1",
  tenantSeq: "1",
  createdAt: "2026-10-05T14:03:00.000Z",
  event: "EXECUTION_CONFIRMED",
  outcome: "SUCCESS",
  detail: null,
  metadata: null,
  signerDid: "did:example:relay-7",
  signerPublicKey: null,
  signedPayload: null,
  signature: null,
  sigAlg: null,
  isBillable: false,
  tenantId: null,
  actorNodeId: null,
  subjectNodeId: null,
  edgeId: null,
  challengeId: null,
  ...over,
})

test("evidence detection, edge statuses and trust separation", () => {
  assert.equal(isExecutionEvidencePayload(null), false)
  assert.equal(isExecutionEvidencePayload("not json"), false)
  assert.equal(isExecutionEvidenceLeaf(leaf({ event: "EXECUTION_DISPATCHED" })), false)
  assert.equal(isExecutionEvidenceLeaf(leaf()), true)

  // An Evidence Record without its signature material is invalid, and a single proof never binds.
  assert.equal(checkExecutionEvidenceLeaf(leaf()).status, "invalid")

  // Empty or malformed caller key lists provision nothing.
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const bytes = canonicalExecutionEvidenceStatement(input)
  const signed = leaf({
    signerPublicKey: pair.publicKey.export({ format: "der", type: "spki" }).toString("base64"),
    signedPayload: bytes,
    signature: crypto.sign("sha256", Buffer.from(bytes), pair.privateKey).toString("base64"),
    sigAlg: "ES256",
  })
  assert.equal(
    verifyEvidenceSignature(signed, { trustedSources: { [input.source]: [] } }).status,
    "not_checked",
  )
  assert.equal(
    verifyEvidenceSignature(signed, { trustedSources: { [input.source]: [""] } }).status,
    "not_checked",
  )
  assert.equal(checkExecutionEvidenceLeaf(signed).status, "unbound")

  // With any trust supplied, an Evidence Record is checked against evidence-source trust only.
  const approverOnly = { trustedSigners: { [input.source]: [signed.signerPublicKey as string] } }
  assert.equal(verifyAuditSignature(signed, approverOnly).status, "not_checked")
  assert.equal(verifyAuditSignature({ ...signed, sigAlg: "WEBAUTHN" }, approverOnly).status, "not_checked")
  assert.equal(
    verifyAuditSignature(signed, undefined, { trustedSources: approverOnly.trustedSigners }).trusted,
    true,
  )
  // No trust at all keeps the §4.6.1 embedded-key behaviour.
  assert.deepEqual(
    { status: verifyAuditSignature(signed).status, trusted: verifyAuditSignature(signed).trusted },
    { status: "verified", trusted: false },
  )
})

test("evaluation tolerates entries out of seq order and non-numeric seqs", () => {
  const dispatch = (seq: string, deadline: string) =>
    leaf({
      seq,
      event: "EXECUTION_DISPATCHED",
      outcome: "PENDING",
      signerDid: null,
      createdAt: "2026-10-05T14:00:00.000Z",
      metadata: { nonce: NONCE, payloadSha256: HASH, evidenceDeadline: deadline },
    })
  const result = evaluateExecutionEvidence(
    [
      { seq: "x", leaf: dispatch("x", "2026-10-05T16:00:00.000Z") },
      { seq: "20", leaf: dispatch("20", "2026-10-05T15:00:00.000Z") },
      { seq: "3", leaf: dispatch("3", "2026-10-05T14:10:00.000Z") },
      { seq: "y", leaf: dispatch("y", "2026-10-05T17:00:00.000Z") },
    ],
    { now: Date.parse("2026-10-05T14:30:00.000Z") },
  )
  assert.equal(result.byNonce[NONCE]?.dispatchSeq, "3")
  assert.deepEqual(result.unconfirmed, [NONCE])
  // The default evaluation time is the current clock.
  assert.deepEqual(
    evaluateExecutionEvidence([{ seq: "3", leaf: dispatch("3", "2026-10-05T14:10:00.000Z") }]).unconfirmed,
    [NONCE],
  )
})

// ── The pre-publication review (DEWP §4.7, Oct 2026): nothing the executing party writes decides ──

const T_DISPATCH = "2026-10-05T14:00:00.000Z"
const T_DEADLINE = "2026-10-05T14:10:00.000Z"
const approvalPayload = `{"actionType":"breaker:open","evidence":null,"nonce":"${NONCE}","params":{},"target":"t","type":"div-intent-verification","v":1}`
const approvalHash = executionPayloadSha256(approvalPayload)
const approver = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
const source = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
const spkiOf = (k: crypto.KeyPairKeyObjectResult) =>
  k.publicKey.export({ format: "der", type: "spki" }).toString("base64")
const signWith = (k: crypto.KeyPairKeyObjectResult, bytes: string) =>
  crypto
    .sign("sha256", Buffer.from(bytes), { key: k.privateKey, dsaEncoding: "ieee-p1363" })
    .toString("base64")
const approvalLeaf = (seq: string): AuditLeaf =>
  leaf({
    seq,
    event: "AUTHZ_APPROVED",
    createdAt: "2026-10-05T13:59:00.000Z",
    signerDid: "did:example:approver",
    signerPublicKey: spkiOf(approver),
    signedPayload: approvalPayload,
    signature: signWith(approver, approvalPayload),
    sigAlg: "ES256",
  })
const dispatchLeaf = (
  seq: string,
  over: { hash?: string; deadline?: string; createdAt?: string } = {},
): AuditLeaf =>
  leaf({
    seq,
    event: "EXECUTION_DISPATCHED",
    outcome: "PENDING",
    signerDid: null,
    createdAt: over.createdAt ?? T_DISPATCH,
    metadata: {
      nonce: NONCE,
      payloadSha256: over.hash ?? approvalHash,
      evidenceDeadline: over.deadline ?? T_DEADLINE,
    },
  })
const evidenceLeaf = (
  seq: string,
  over: {
    verdict?: "confirmed" | "contradicted"
    sampledAt?: string
    sequence?: number
    observation?: Record<string, unknown>
  } = {},
): AuditLeaf => {
  const verdict = over.verdict ?? "confirmed"
  const sampledAt = over.sampledAt ?? "2026-10-05T14:02:09.500Z"
  const bytes = canonicalExecutionEvidenceStatement({
    nonce: NONCE,
    payloadSha256: approvalHash,
    source: input.source,
    verdict,
    // Reported no earlier than sampled (rule 11): a late sample is reported at the same instant.
    observedAt: sampledAt > "2026-10-05T14:02:11.000Z" ? sampledAt : "2026-10-05T14:02:11.000Z",
    sampledAt,
    sequence: over.sequence ?? 1,
    observation: over.observation ?? {},
  })
  return leaf({
    seq,
    event: verdict === "confirmed" ? "EXECUTION_CONFIRMED" : "EXECUTION_CONTRADICTED",
    outcome: verdict === "confirmed" ? "SUCCESS" : "FAILURE",
    signerPublicKey: spkiOf(source),
    signedPayload: bytes,
    signature: signWith(source, bytes),
    sigAlg: "ES256",
  })
}
const entriesOf = (...leaves: AuditLeaf[]) => leaves.map((l) => ({ seq: l.seq, leaf: l }))
const policy = { trustedSources: { [input.source]: [spkiOf(source)] } }
const NOW_AFTER = Date.parse("2026-10-05T14:30:00.000Z")

test("binding is against any Dispatch Record whose hash matches; a conflicting earlier one is a finding", () => {
  // The executing party commits an early record with a wrong hash, then the genuine one.
  const r = evaluateExecutionEvidence(
    entriesOf(
      approvalLeaf("1"),
      dispatchLeaf("2", { hash: "0".repeat(64) }),
      dispatchLeaf("3", { createdAt: "2026-10-05T14:00:30.000Z" }),
      evidenceLeaf("4", { verdict: "contradicted", sampledAt: "2026-10-05T14:01:00.000Z" }),
    ),
    { policy, now: NOW_AFTER },
  )
  assert.equal(r.checks[0]?.status, "verified")
  assert.deepEqual(r.contradicted, [NONCE])
  assert.equal(r.byNonce[NONCE]?.dispatchSeq, "3")
  assert.deepEqual(r.byNonce[NONCE]?.dispatchConflict, ["2", "3"])
  assert.deepEqual(r.dispatchConflicts, [NONCE])
  // Two records that agree are a retry, not a conflict, and the first of them governs.
  const agree = evaluateExecutionEvidence(
    entriesOf(
      approvalLeaf("1"),
      dispatchLeaf("2"),
      dispatchLeaf("3", { createdAt: "2026-10-05T14:05:00.000Z" }),
      evidenceLeaf("4"),
    ),
    { policy, now: NOW_AFTER },
  )
  assert.deepEqual(agree.byNonce[NONCE]?.dispatchConflict, [])
  assert.equal(agree.byNonce[NONCE]?.dispatchSeq, "2")
  assert.deepEqual(agree.confirmed, [NONCE])
})

test("the evidence window is bounded by the verifier, not the dispatch", () => {
  const farOut = dispatchLeaf("2", { deadline: "2027-10-05T14:00:00.000Z" })
  const r = evaluateExecutionEvidence(entriesOf(approvalLeaf("1"), farOut), { policy, now: NOW_AFTER })
  // A year-long window is cut to the default 24 h, so three hours later it is still pending …
  assert.deepEqual(r.pending, [NONCE])
  assert.equal(r.byNonce[NONCE]?.windowCapped, true)
  assert.equal(r.byNonce[NONCE]?.effectiveDeadline, "2026-10-06T14:00:00.000Z")
  // … and after the bound it is unconfirmed, whatever the record claims.
  const later = evaluateExecutionEvidence(entriesOf(approvalLeaf("1"), farOut), {
    policy,
    now: Date.parse("2026-10-06T14:00:00.001Z"),
  })
  assert.deepEqual(later.unconfirmed, [NONCE])
  // A caller may tighten the bound; a statement sampled past it is late.
  const tight = evaluateExecutionEvidence(
    entriesOf(approvalLeaf("1"), farOut, evidenceLeaf("3", { sampledAt: "2026-10-05T14:02:00.000Z" })),
    { policy, now: NOW_AFTER, maxWindowSeconds: 60 },
  )
  assert.equal(tight.checks[0]?.status, "stale")
  assert.match(tight.checks[0]?.reason ?? "", /late/)
  assert.equal(tight.byNonce[NONCE]?.windowCapped, true)
})

test("an approval with no dispatch and no evidence is reported, not passed over", () => {
  const r = evaluateExecutionEvidence(entriesOf(approvalLeaf("1")), { policy, now: NOW_AFTER })
  assert.deepEqual(r.notReported, [NONCE])
  assert.equal(r.byNonce[NONCE]?.status, "not_reported")
  assert.equal(r.byNonce[NONCE]?.dispatchSeq, null)
})

test("a trusted contradicted statement sampled after the deadline is a late-contradiction alert", () => {
  const r = evaluateExecutionEvidence(
    entriesOf(
      approvalLeaf("1"),
      dispatchLeaf("2"),
      evidenceLeaf("3", { verdict: "contradicted", sampledAt: "2026-10-05T14:20:00.000Z" }),
    ),
    { policy, now: NOW_AFTER },
  )
  assert.equal(r.checks[0]?.status, "stale")
  assert.deepEqual(r.unconfirmed, [NONCE])
  assert.deepEqual(r.byNonce[NONCE]?.lateContradiction, ["3"])
  assert.deepEqual(r.lateContradicted, [NONCE])
  // A late CONFIRMED, an early contradicted, or an untrusted late contradicted are not the alert.
  const notAlerts = [
    evidenceLeaf("3", { verdict: "confirmed", sampledAt: "2026-10-05T14:20:00.000Z" }),
    evidenceLeaf("3", { verdict: "contradicted", sampledAt: "2026-10-05T13:00:00.000Z" }),
  ]
  for (const e of notAlerts) {
    const x = evaluateExecutionEvidence(entriesOf(approvalLeaf("1"), dispatchLeaf("2"), e), {
      policy,
      now: NOW_AFTER,
    })
    assert.deepEqual(x.lateContradicted, [], e.event)
  }
  const untrusted = evaluateExecutionEvidence(
    entriesOf(
      approvalLeaf("1"),
      dispatchLeaf("2"),
      evidenceLeaf("3", { verdict: "contradicted", sampledAt: "2026-10-05T14:20:00.000Z" }),
    ),
    { now: NOW_AFTER },
  )
  assert.deepEqual(untrusted.lateContradicted, [])
})

test("the window is evaluated on sampledAt with a 30 s clock allowance", () => {
  const at = (sampledAt: string) =>
    evaluateExecutionEvidence(
      entriesOf(approvalLeaf("1"), dispatchLeaf("2"), evidenceLeaf("3", { sampledAt })),
      {
        policy,
        now: NOW_AFTER,
      },
    ).checks[0]?.status
  assert.equal(at("2026-10-05T13:59:30.000Z"), "verified")
  assert.equal(at("2026-10-05T13:59:29.999Z"), "stale")
  assert.equal(at(T_DEADLINE), "verified")
  assert.equal(at("2026-10-05T14:10:00.001Z"), "stale")
})

test("source continuity reports gaps and divergence without touching a status", () => {
  const r = evaluateExecutionEvidence(
    entriesOf(
      approvalLeaf("1"),
      dispatchLeaf("2"),
      evidenceLeaf("3", { sequence: 4 }),
      evidenceLeaf("4", { sequence: 7 }),
      evidenceLeaf("5", { sequence: 7, observation: { other: true } }),
      evidenceLeaf("6", { sequence: 9 }),
    ),
    { policy, now: NOW_AFTER },
  )
  assert.deepEqual(r.sources[input.source], {
    first: 4,
    last: 9,
    gaps: [
      [5, 6],
      [8, 8],
    ],
    divergent: [7],
  })
  assert.deepEqual(r.confirmed, [NONCE])
  // The same bytes relayed twice are one statement, not a divergence; a record whose signature does
  // not verify is not attributed to the source at all.
  const dup = evidenceLeaf("4", { sequence: 7 })
  const forged = { ...evidenceLeaf("5", { sequence: 8 }), signature: signWith(approver, "x") }
  const r2 = evaluateExecutionEvidence(
    entriesOf(approvalLeaf("1"), dispatchLeaf("2"), evidenceLeaf("3", { sequence: 7 }), dup, forged),
    {
      policy,
      now: NOW_AFTER,
    },
  )
  assert.deepEqual(r2.sources[input.source], { first: 7, last: 7, gaps: [], divergent: [] })
  assert.equal(r2.checks[2]?.status, "invalid")
})

test("a caller key with a validity interval is placed in time by the anchored time only", () => {
  const bounded = (interval: { notBefore?: string; notAfter?: string }) => ({
    trustedSources: { [input.source]: [{ key: spkiOf(source), ...interval }] },
  })
  const run = (p: typeof policy | ReturnType<typeof bounded>, anchoredAt: string | null) =>
    evaluateExecutionEvidence(entriesOf(approvalLeaf("1"), dispatchLeaf("2"), evidenceLeaf("3")), {
      policy: p,
      now: NOW_AFTER,
      anchoredTime: () => (anchoredAt === null ? null : Date.parse(anchoredAt)),
    })
  const revokedLater = bounded({ notAfter: "2026-10-05T18:00:00.000Z" })
  // Witnessed before the revocation: trusted. Witnessed after it: verified, but establishes nothing.
  assert.deepEqual(
    [
      run(revokedLater, "2026-10-05T15:00:00.000Z").confirmed,
      run(revokedLater, "2026-10-05T19:00:00.000Z").confirmed,
    ],
    [[NONCE], []],
  )
  const late = run(revokedLater, "2026-10-05T19:00:00.000Z").checks[0]
  assert.equal(late?.status, "verified")
  assert.equal(late?.trusted, false)
  assert.match(late?.reason ?? "", /anchored time/)
  // No counting anchor: a bounded key cannot be placed in time, so it fails closed; a bare key is unaffected.
  const none = run(revokedLater, null).checks[0]
  assert.equal(none?.trusted, false)
  assert.match(none?.reason ?? "", /no counting anchor/)
  assert.deepEqual(run(policy, null).confirmed, [NONCE])
  // notBefore after the witness: the key was not yet trusted when the record provably existed.
  assert.deepEqual(
    run(bounded({ notBefore: "2026-10-05T16:00:00.000Z" }), "2026-10-05T15:00:00.000Z").confirmed,
    [],
  )
  // A malformed interval never establishes trust.
  assert.equal(run(bounded({ notAfter: "yesterday" }), "2026-10-05T15:00:00.000Z").checks[0]?.trusted, false)
  // The statement's own timestamps are never the anchored time: a sample inside the interval does not help.
  assert.deepEqual(
    run(bounded({ notAfter: "2026-10-05T14:05:00.000Z" }), "2026-10-05T15:00:00.000Z").confirmed,
    [],
  )
})

test("key entries fail closed, a contradiction so refused is a finding, and options are sanitised", () => {
  const run = (entry: unknown) =>
    evaluateExecutionEvidence(
      entriesOf(approvalLeaf("1"), dispatchLeaf("2"), evidenceLeaf("3", { verdict: "contradicted" })),
      {
        policy: { trustedSources: { [input.source]: [entry as string] } },
        now: NOW_AFTER,
        anchoredTime: () => Date.parse("2026-10-05T15:00:00.000Z"),
      },
    )
  for (const entry of [
    { key: spkiOf(source), notafter: "2026-10-05T18:00:00.000Z" },
    { key: spkiOf(source), notAfter: 1754006400000 },
    { key: spkiOf(source), notAfter: "2026-10-07T00:00:00.000Z", revokedAt: null },
  ]) {
    const r = run(entry)
    assert.equal(r.checks[0]?.status, "verified", JSON.stringify(entry))
    assert.equal(r.checks[0]?.trusted, false, JSON.stringify(entry))
    assert.deepEqual(r.contradicted, [])
    // … and a contradiction a provisioned key signed is reported even when it cannot count.
    assert.deepEqual(r.untrustedContradicted, [NONCE])
    assert.deepEqual(r.byNonce[NONCE]?.untrustedContradiction, ["3"])
  }
  // A well-formed bound inside its interval trusts, and is not the finding.
  const ok = run({ key: spkiOf(source), notAfter: "2026-10-07T00:00:00.000Z" })
  assert.deepEqual([ok.contradicted, ok.untrustedContradicted], [[NONCE], []])
  // An entry without a usable key verifies nothing: not provisioned.
  assert.equal(run({ notAfter: "2026-10-07T00:00:00.000Z" }).checks[0]?.status, "not_checked")
  // Non-finite or negative bounds fall back to the defaults instead of removing the limit.
  const nan = evaluateExecutionEvidence(
    entriesOf(approvalLeaf("1"), dispatchLeaf("2", { deadline: "2027-10-05T14:00:00.000Z" })),
    { policy, now: Date.parse("2026-10-06T14:00:00.001Z"), maxWindowSeconds: Number.NaN, skewSeconds: -1 },
  )
  assert.deepEqual(nan.unconfirmed, [NONCE])
  assert.equal(nan.byNonce[NONCE]?.windowCapped, true)
})

test("a late contradiction under a provisioned key without established trust remains a finding", () => {
  const r = evaluateExecutionEvidence(
    entriesOf(
      approvalLeaf("1"),
      dispatchLeaf("2"),
      evidenceLeaf("3", { verdict: "contradicted", sampledAt: "2026-10-05T14:20:00.000Z" }),
    ),
    {
      policy: {
        trustedSources: { [input.source]: [{ key: spkiOf(source), notAfter: "2026-10-07T00:00:00.000Z" }] },
      },
      now: NOW_AFTER,
    },
  )
  assert.equal(r.checks[0]?.status, "stale")
  assert.equal(r.checks[0]?.trusted, false)
  assert.deepEqual(r.unconfirmed, [NONCE])
  assert.deepEqual(r.untrustedContradicted, [NONCE])
  assert.deepEqual(r.byNonce[NONCE]?.untrustedContradiction, ["3"])
  assert.deepEqual(r.lateContradicted, [])
})
