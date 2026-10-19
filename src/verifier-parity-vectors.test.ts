import assert from "node:assert/strict"
import crypto from "node:crypto"
import { readFileSync } from "node:fs"
import { test } from "node:test"
import { fileURLToPath } from "node:url"
import {
  verifyAgentAuthority,
  verifyApprovalReceipt,
  verifyPlatformReceipt,
  type ApprovalReceipt,
  type PlatformReceipt,
} from "./index.js"
import { verifyBundle, type ProofBundle, type TrustedCheckpoint } from "./ledger-bundle.js"
import { verifyEvidenceBundle, type EvidenceBundle, type EvidenceVerifyOptions } from "./ledger-evidence.js"
import { verifyRootsChain, type RootsChainEntry } from "./ledger-chain.js"
import {
  canonicalExecutionEvidenceStatement,
  type ExecutionEvidencePolicy,
  type ExecutionVerdict,
  parseExecutionEvidenceStatement,
} from "./ledger-execution.js"
import type { AuditSignaturePolicy } from "./ledger-signature.js"
import type { AnchorPolicy, SignedAnchor } from "./ledger-anchor.js"

type Obj = Record<string, unknown>
interface KeyFixture {
  id: string
  did?: string
  spkiB64: string
  coseB64?: string
}
interface Case {
  name: string
  receipt?: Obj
  bundle?: Obj
  entries?: Obj[]
  expected?: Obj
  options?: Obj
  policy?: Obj
  ok: boolean
  [key: string]: unknown
}
interface Fixtures {
  keys: KeyFixture[]
  approvals: { expected: Obj; options: Obj; cases: Case[] }
  platform: { expected: Obj; options: Obj; cases: Case[] }
  agentAuthority: { expected: Obj; options: Obj; cases: Case[] }
  bundles: { anchorPolicy: Obj; cases: Case[] }
  evidence: { cases: Case[] }
  rootsChain: { cases: Case[] }
  dewpEvidenceHardening: { keys: KeyFixture[]; bundles: { cases: Case[] }; evidence: { cases: Case[] } }
  executionEvidence: {
    cases: Case[]
    proofs: Case[]
    statements: Array<{ name: string; bytes: string; ok: boolean }>
    builder: Array<{ name: string; input: Obj; bytes: string }>
  }
  verifierInputHardening: {
    keys: KeyFixture[]
    approvals: Section
    platform: Section
    agentAuthority: Section
    bundles: { cases: Case[] }
  }
}
interface Section {
  expected: Obj
  options: Obj
  cases: Case[]
}

const fixtures = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../vectors/verifier-parity-vectors.json", import.meta.url)),
    "utf8",
  ),
) as Fixtures
const keyById = new Map(fixtures.keys.map((k) => [k.id, k]))
const opts = (o: Obj): Obj => ({ ...o, ...(typeof o.asOf === "string" ? { asOf: new Date(o.asOf) } : {}) })

type KeyTable = Map<string, KeyFixture>

function runApprovalCases(section: Section, keys: KeyTable) {
  for (const c of section.cases) {
    const raw = { ...section.expected, ...c.expected }
    const ids = (raw.approverKeyIds as string[] | undefined) ?? []
    // A WEBAUTHN witness verifies under the credential's COSE_Key; such cases say so explicitly.
    const encoding = c.approverKeyEncoding === "cose" ? "coseB64" : "spkiB64"
    const table = raw.approverDids as Record<string, string[]> | undefined
    const coseDids = new Set((raw.approverCoseDids as string[] | undefined) ?? [])
    const approvers = table
      ? {
          dids: Object.keys(table),
          resolveKey: (did: string) =>
            (table[did] ?? []).map((id) => keys.get(id)![coseDids.has(did) ? "coseB64" : "spkiB64"]!),
        }
      : { publicKeys: ids.map((id) => keys.get(id)![encoding]!) }
    const expected = { ...raw, approvers }
    const result = verifyApprovalReceipt(
      c.receipt as unknown as ApprovalReceipt,
      expected as never,
      opts({ ...section.options, ...c.options }) as never,
    )
    assert.equal(result.ok, c.ok, `${c.name}: ${result.reason}`)
    if (c.signers) assert.deepEqual(result.signers, c.signers, c.name)
    if (c.reasonIncludes) assert.match(result.reason ?? "", new RegExp(String(c.reasonIncludes)), c.name)
  }
}

function runPlatformCases(section: Section, keys: KeyTable) {
  for (const c of section.cases) {
    const raw = { ...section.expected, ...c.expected }
    const ids = raw.approverKeyIds as string[]
    const expected = { ...raw, approvers: { publicKeys: ids.map((id) => keys.get(id)!.coseB64!) } }
    const result = verifyPlatformReceipt(
      c.receipt as unknown as PlatformReceipt,
      expected as never,
      opts({ ...section.options, ...c.options }) as never,
    )
    assert.equal(result.ok, c.ok, `${c.name}: ${result.reason}`)
    if (c.signers) assert.deepEqual(result.signers, c.signers, c.name)
    if (c.reasonIncludes) assert.match(result.reason ?? "", new RegExp(String(c.reasonIncludes)), c.name)
  }
}

function runAuthorityCases(section: Section, keys: KeyTable) {
  for (const c of section.cases) {
    const raw = { ...section.expected, ...c.expected }
    const table = raw.approverDids as Record<string, string[]>
    const approvers = Array.isArray(raw.approverKeyIds)
      ? { publicKeys: (raw.approverKeyIds as string[]).map((id) => keys.get(id)!.spkiB64) }
      : {
          dids: Object.keys(table),
          resolveKey: (did: string) => (table[did] ?? []).map((id) => keys.get(id)!.spkiB64),
        }
    const result = verifyAgentAuthority(
      c.receipt as unknown as ApprovalReceipt,
      {
        approvers,
        target: raw.target as string,
        agentDid: raw.agentDid as string,
        ...(raw.requirement ? { requirement: raw.requirement as never } : {}),
      },
      opts({ ...section.options, ...c.options }) as never,
    )
    assert.equal(result.ok, c.ok, `${c.name}: ${result.reason}`)
    if (c.signers) assert.deepEqual(result.authority?.signers, c.signers, c.name)
    if (c.actionPatterns) assert.deepEqual(result.authority?.actionPatterns, c.actionPatterns, c.name)
    if (c.reasonIncludes) assert.match(result.reason ?? "", new RegExp(String(c.reasonIncludes)), c.name)
  }
}

test("shared approval signature-algorithm and four-eyes vectors", () => {
  runApprovalCases(fixtures.approvals, keyById)
})

test("shared platform receipt parity vectors", () => {
  runPlatformCases(fixtures.platform, keyById)
})

test("shared agent-authority and self-certifying DID vectors", () => {
  runAuthorityCases(fixtures.agentAuthority, keyById)
})

const keyObject = (keys: KeyTable, id: string): crypto.KeyObject =>
  crypto.createPublicKey({ key: Buffer.from(keys.get(id)!.spkiB64, "base64"), format: "der", type: "spki" })
const externalKeysFor = (keys: KeyTable, o: Obj) =>
  o.rekorKeyId
    ? {
        rekor: keys.get(o.rekorKeyId as string)!.spkiB64,
        rekorIssuer: o.rekorIssuer as string | undefined,
        rekorSubmitterKeys: (o.rekorSubmitterKeyIds as string[] | undefined)?.map(
          (id) => keys.get(id)!.spkiB64,
        ),
      }
    : undefined

/** `defaultPolicy` is the `bundles` section's; the hardening section applies a policy only when a case has one. */
function runBundleCases(cases: Case[], keys: KeyTable, defaultPolicy: Obj | undefined) {
  for (const c of cases) {
    const o = c.options ?? {}
    const policy = (c.policy ?? defaultPolicy) as unknown as AnchorPolicy | undefined
    const result = verifyBundle(c.bundle as unknown as ProofBundle, {
      trustedRoot: o.trustedRoot as string | undefined,
      trustedCheckpoint: o.trustedCheckpoint as TrustedCheckpoint | undefined,
      anchorPolicy: policy,
      resolveAnchorKey: (a) => (keys.has(a.keyId) ? keyObject(keys, a.keyId) : null),
      anchors: o.divergenceAnchors as SignedAnchor[] | undefined,
      externalKeys: externalKeysFor(keys, o),
    })
    assert.equal(result.ok, c.ok, `${c.name}: ${result.notes.join("; ")}`)
    if (c.verificationLevel) assert.equal(result.verificationLevel, c.verificationLevel, c.name)
    if (c.witnessTimes) assert.deepEqual(result.witnessTimes, c.witnessTimes, `${c.name}: witnessTimes`)
    for (const [k, v] of Object.entries((c.properties ?? {}) as Obj))
      assert.equal(result.properties[k as keyof typeof result.properties], v, `${c.name}:${k}`)
  }
}

function runEvidenceCases(cases: Case[], keys: KeyTable) {
  for (const c of cases) {
    const o = c.options ?? {}
    const result = verifyEvidenceBundle(c.bundle as unknown as EvidenceBundle, {
      trustedRoots: o.trustedRoots as string[] | undefined,
      trustedCheckpoints: o.trustedCheckpoints as TrustedCheckpoint[] | undefined,
      anchors: o.anchors as EvidenceVerifyOptions["anchors"],
      anchorPolicy: c.policy as unknown as AnchorPolicy | undefined,
      resolveAnchorKey: c.policy
        ? (a: SignedAnchor) => (keys.has(a.keyId) ? keyObject(keys, a.keyId) : null)
        : undefined,
      externalKeys: externalKeysFor(keys, o),
    })
    assert.equal(result.ok, c.ok, `${c.name}: ${result.failed.map((f) => f.reason).join("; ")}`)
    if (c.total !== undefined) assert.equal(result.total, c.total, c.name)
    if (c.contentVerified !== undefined) assert.equal(result.contentVerified, c.contentVerified, c.name)
    if (c.commitmentOnly !== undefined) assert.equal(result.commitmentOnly, c.commitmentOnly, c.name)
  }
}

test("shared single-bundle, anchor-algorithm, divergence, and Rekor vectors", () => {
  runBundleCases(fixtures.bundles.cases, keyById, fixtures.bundles.anchorPolicy)
})

test("shared evidence completeness vectors", () => {
  runEvidenceCases(fixtures.evidence.cases, keyById)
})

test("shared DEWP evidence-hardening vectors (own keys)", () => {
  const section = fixtures.dewpEvidenceHardening
  const keys: KeyTable = new Map(section.keys.map((k) => [k.id, k]))
  assert.ok(section.bundles.cases.length > 0 && section.evidence.cases.length > 0)
  runBundleCases(section.bundles.cases, keys, undefined)
  runEvidenceCases(section.evidence.cases, keys)
})

test("shared verifier input-hardening vectors (own keys)", () => {
  const section = fixtures.verifierInputHardening
  const keys: KeyTable = new Map(section.keys.map((k) => [k.id, k]))
  for (const part of [section.approvals, section.platform, section.agentAuthority, section.bundles])
    assert.ok(part.cases.length > 0)
  runApprovalCases(section.approvals, keys)
  runPlatformCases(section.platform, keys)
  runAuthorityCases(section.agentAuthority, keys)
  runBundleCases(section.bundles.cases, keys, undefined)
})

test("shared checkpoint continuity vectors", () => {
  for (const c of fixtures.rootsChain.cases) {
    const result = verifyRootsChain(c.entries as unknown as RootsChainEntry[])
    assert.equal(result.ok, c.ok, c.name)
    assert.equal(result.brokenAt, c.brokenAt, c.name)
    assert.equal(result.unchained, c.unchained, c.name)
    if (c.verifiedCount !== undefined) assert.equal(result.verifiedCount, c.verifiedCount, c.name)
  }
})

test("shared DEWP §4.7 execution-evidence vectors (own keys)", () => {
  const section = fixtures.executionEvidence
  assert.ok(section.cases.length > 0 && section.proofs.length > 0)
  for (const c of section.cases) {
    const o = c.options ?? {}
    const result = verifyEvidenceBundle(c.bundle as unknown as EvidenceBundle, {
      trustedRoots: o.trustedRoots as string[],
      evidencePolicy: o.evidencePolicy as ExecutionEvidencePolicy | undefined,
      signaturePolicy: o.signaturePolicy as AuditSignaturePolicy | undefined,
      executionNow: Date.parse(o.now as string),
      evidenceSkewSeconds: o.skewSeconds as number | undefined,
      maxEvidenceWindowSeconds: o.maxWindowSeconds as number | undefined,
      requireExecutionConfirmed: o.requireExecutionConfirmed === true,
      // The anchored-time cases (DEWP §4.7.5) carry a Rekor-witnessed anchor in the bundle's checkpoint
      // and pin the log key inline: the section stays self-contained.
      anchorPolicy: c.policy as unknown as AnchorPolicy | undefined,
      externalKeys: typeof o.rekorSpki === "string" ? { rekor: o.rekorSpki } : undefined,
    })
    assert.equal(result.ok, c.ok, `${c.name}: ${result.failed.map((f) => f.reason).join("; ")}`)
    const expected = c.execution as {
      byNonce: Record<string, string>
      checks: Obj[]
      findings?: {
        lateContradicted?: string[]
        untrustedContradicted?: string[]
        dispatchConflicts?: string[]
        windowCapped?: Record<string, boolean>
        sources?: Record<string, unknown>
      }
    }
    assert.deepEqual(
      Object.fromEntries(Object.entries(result.execution.byNonce).map(([n, v]) => [n, v.status])),
      expected.byNonce,
      `${c.name}: byNonce`,
    )
    assert.deepEqual(
      result.execution.checks.map(({ seq, status, trusted }) => ({ seq, status, trusted })),
      expected.checks,
      `${c.name}: checks ${result.execution.checks.map((k) => k.reason).join("; ")}`,
    )
    const f = expected.findings
    if (f?.lateContradicted)
      assert.deepEqual(result.execution.lateContradicted, f.lateContradicted, `${c.name}: late`)
    if (f?.untrustedContradicted)
      assert.deepEqual(
        result.execution.untrustedContradicted,
        f.untrustedContradicted,
        `${c.name}: untrusted`,
      )
    if (f?.dispatchConflicts)
      assert.deepEqual(result.execution.dispatchConflicts, f.dispatchConflicts, `${c.name}: conflicts`)
    if (f?.sources) assert.deepEqual({ ...result.execution.sources }, f.sources, `${c.name}: sources`)
    if (f?.windowCapped)
      assert.deepEqual(
        Object.fromEntries(Object.entries(result.execution.byNonce).map(([n, v]) => [n, v.windowCapped])),
        f.windowCapped,
        `${c.name}: windowCapped`,
      )
    if (c.signatures)
      assert.deepEqual(
        (result.signatures.checks ?? []).map(({ seq, status, trusted }) => ({ seq, status, trusted })),
        c.signatures,
        `${c.name}: signatures`,
      )
  }
  for (const c of section.proofs) {
    const o = c.options ?? {}
    const result = verifyBundle(c.bundle as unknown as ProofBundle, {
      trustedRoot: o.trustedRoot as string,
      evidencePolicy: o.evidencePolicy as ExecutionEvidencePolicy | undefined,
    })
    assert.equal(result.properties.contentVerified, true, c.name)
    const got = result.execution
      ? { status: result.execution.status, trusted: result.execution.trusted }
      : null
    assert.deepEqual(got, c.execution, c.name)
  }
  for (const c of section.statements) assert.equal(parseExecutionEvidenceStatement(c.bytes).ok, c.ok, c.name)
  for (const c of section.builder) {
    const i = c.input as {
      nonce: string
      payloadSha256: string
      source: string
      verdict: ExecutionVerdict
      observedAt: string
      sampledAt: string
      sequence: number
      observation: Record<string, unknown>
    }
    assert.equal(canonicalExecutionEvidenceStatement(i), c.bytes, c.name)
  }
})
