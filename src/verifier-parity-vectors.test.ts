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
import { verifyBundle, type ProofBundle } from "./ledger-bundle.js"
import { verifyEvidenceBundle, type EvidenceBundle } from "./ledger-evidence.js"
import { verifyRootsChain, type RootsChainEntry } from "./ledger-chain.js"
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
}

const fixtures = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../vectors/verifier-parity-vectors.json", import.meta.url)),
    "utf8",
  ),
) as Fixtures
const keyById = new Map(fixtures.keys.map((k) => [k.id, k]))
const publicKey = (id: string): crypto.KeyObject =>
  crypto.createPublicKey({
    key: Buffer.from(keyById.get(id)!.spkiB64, "base64"),
    format: "der",
    type: "spki",
  })
const opts = (o: Obj): Obj => ({ ...o, ...(typeof o.asOf === "string" ? { asOf: new Date(o.asOf) } : {}) })

test("shared approval signature-algorithm and four-eyes vectors", () => {
  for (const c of fixtures.approvals.cases) {
    const raw = { ...fixtures.approvals.expected, ...c.expected }
    const ids = raw.approverKeyIds as string[]
    const expected = { ...raw, approvers: { publicKeys: ids.map((id) => keyById.get(id)!.spkiB64) } }
    const result = verifyApprovalReceipt(
      c.receipt as unknown as ApprovalReceipt,
      expected as never,
      opts({ ...fixtures.approvals.options, ...c.options }) as never,
    )
    assert.equal(result.ok, c.ok, `${c.name}: ${result.reason}`)
    if (c.signers) assert.deepEqual(result.signers, c.signers, c.name)
    if (c.reasonIncludes) assert.match(result.reason ?? "", new RegExp(String(c.reasonIncludes)), c.name)
  }
})

test("shared platform receipt parity vectors", () => {
  for (const c of fixtures.platform.cases) {
    const raw = { ...fixtures.platform.expected, ...c.expected }
    const ids = raw.approverKeyIds as string[]
    const expected = { ...raw, approvers: { publicKeys: ids.map((id) => keyById.get(id)!.coseB64!) } }
    const result = verifyPlatformReceipt(
      c.receipt as unknown as PlatformReceipt,
      expected as never,
      opts({ ...fixtures.platform.options, ...c.options }) as never,
    )
    assert.equal(result.ok, c.ok, `${c.name}: ${result.reason}`)
    if (c.signers) assert.deepEqual(result.signers, c.signers, c.name)
  }
})

test("shared agent-authority and self-certifying DID vectors", () => {
  for (const c of fixtures.agentAuthority.cases) {
    const raw = { ...fixtures.agentAuthority.expected, ...c.expected }
    const table = raw.approverDids as Record<string, string[]>
    const approvers = Array.isArray(raw.approverKeyIds)
      ? { publicKeys: (raw.approverKeyIds as string[]).map((id) => keyById.get(id)!.spkiB64) }
      : {
          dids: Object.keys(table),
          resolveKey: (did: string) => (table[did] ?? []).map((id) => keyById.get(id)!.spkiB64),
        }
    const result = verifyAgentAuthority(
      c.receipt as unknown as ApprovalReceipt,
      { approvers, target: raw.target as string, agentDid: raw.agentDid as string },
      opts({ ...fixtures.agentAuthority.options, ...c.options }) as never,
    )
    assert.equal(result.ok, c.ok, `${c.name}: ${result.reason}`)
    if (c.signers) assert.deepEqual(result.authority?.signers, c.signers, c.name)
    if (c.actionPatterns) assert.deepEqual(result.authority?.actionPatterns, c.actionPatterns, c.name)
  }
})

test("shared single-bundle, anchor-algorithm, divergence, and Rekor vectors", () => {
  for (const c of fixtures.bundles.cases) {
    const o = c.options ?? {}
    const policy = (c.policy ?? fixtures.bundles.anchorPolicy) as unknown as AnchorPolicy
    const result = verifyBundle(c.bundle as unknown as ProofBundle, {
      trustedRoot: o.trustedRoot as string | undefined,
      anchorPolicy: policy,
      resolveAnchorKey: (a) => {
        const k = keyById.get(a.keyId)
        return k ? publicKey(k.id) : null
      },
      anchors: o.divergenceAnchors as SignedAnchor[] | undefined,
      externalKeys: o.rekorKeyId ? { rekor: keyById.get(o.rekorKeyId as string)!.spkiB64 } : undefined,
    })
    assert.equal(result.ok, c.ok, `${c.name}: ${result.notes.join("; ")}`)
    if (c.verificationLevel) assert.equal(result.verificationLevel, c.verificationLevel, c.name)
    for (const [k, v] of Object.entries((c.properties ?? {}) as Obj))
      assert.equal(result.properties[k as keyof typeof result.properties], v, `${c.name}:${k}`)
  }
})

test("shared evidence completeness vectors", () => {
  for (const c of fixtures.evidence.cases) {
    const result = verifyEvidenceBundle(c.bundle as unknown as EvidenceBundle, {
      ...c.options,
      anchorPolicy: c.policy as unknown as AnchorPolicy | undefined,
      resolveAnchorKey: c.policy
        ? (a: SignedAnchor) => {
            const key = keyById.get(a.keyId)
            return key ? publicKey(key.id) : null
          }
        : undefined,
    })
    assert.equal(result.ok, c.ok, `${c.name}: ${result.failed.map((f) => f.reason).join("; ")}`)
    if (c.total !== undefined) assert.equal(result.total, c.total, c.name)
    if (c.contentVerified !== undefined) assert.equal(result.contentVerified, c.contentVerified, c.name)
    if (c.commitmentOnly !== undefined) assert.equal(result.commitmentOnly, c.commitmentOnly, c.name)
  }
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
