import assert from "node:assert/strict"
import fs from "node:fs"
import { test } from "node:test"
import { verifyBundle } from "./ledger-bundle.js"
import { verifyEvidenceBundle } from "./ledger-evidence.js"
const vectors = JSON.parse(
  fs.readFileSync(new URL("../vectors/audit-signature-vectors.json", import.meta.url), "utf8"),
)
for (const v of vectors.cases)
  test(`audit WebAuthn parity: ${v.name}`, () => {
    const opts = { trustedRoot: v.root, signaturePolicy: v.policy ?? undefined }
    const result = verifyBundle(v.bundle, opts)
    assert.equal(result.ok, true)
    assert.equal(result.properties.contentVerified, true)
    assert.equal(result.signature.status, v.status)
    assert.equal(result.signature.trusted, v.trusted)
    assert.equal(result.properties.signatureVerified, v.status === "verified")
    assert.equal(verifyBundle(v.bundle, { ...opts, requireSignatures: true }).ok, v.strictOk)
    const evidence = {
      kind: "dewp.audit.evidence-bundle" as const,
      version: "1.0",
      tenant: { id: "test-tenant", name: null },
      exportedAt: "",
      range: { from: "2026-09-30T00:00:00Z", to: "2026-10-01T00:00:00Z" },
      entries: [{ event: v.bundle.event, proof: v.bundle.proof }],
      checkpoints: [
        { id: "cp", root: v.root, seqStart: "1", seqEnd: "1", anchorRef: null, anchoredAt: null },
      ],
    }
    const bulk = verifyEvidenceBundle(evidence, {
      trustedRoots: [v.root],
      signaturePolicy: opts.signaturePolicy,
    })
    assert.equal(bulk.ok, true, JSON.stringify(bulk.failed))
    assert.equal(bulk.signatures.checks?.[0]?.status, v.status)
    assert.equal(
      verifyEvidenceBundle(evidence, {
        trustedRoots: [v.root],
        signaturePolicy: opts.signaturePolicy,
        requireSignatures: true,
      }).ok,
      v.strictOk,
    )
    const tampered = structuredClone(v.bundle)
    tampered.event.canonical.detail = "edited after sealing"
    const refused = verifyBundle(tampered, { ...opts, requireSignatures: true })
    assert.equal(refused.ok, false)
    assert.equal(refused.signature.status, "not_checked")
  })
