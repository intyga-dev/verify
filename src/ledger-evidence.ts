import { type AuditLeaf, leafHash } from "./ledger-leaf.js"
import { type InclusionProof, verifyInclusionProof } from "./ledger-proof.js"

// Multi-entry auditor evidence bundle (date-range export from the console's Audit page). Each entry
// carries its own two-hop inclusion proof. REDACTED entries (content removed by the retention
// ladder) carry only the leaf digest: they verify as COMMITMENT-ONLY — "an event with this digest
// existed at this position under this anchored root" — while unredacted entries additionally bind
// the displayed content to the leaf (CONTENT-VERIFIED).

// DEWP canonical kind (docs/DEWP.md §6.3). The legacy `sakra.audit.*` form is accepted as an alias
// on read (§6.5) so previously-exported bundles still verify.
export const EVIDENCE_BUNDLE_KIND = "dewp.audit.evidence-bundle"
export const EVIDENCE_BUNDLE_KIND_ALIASES = ["sakra.audit.evidence-bundle"] as const

export interface EvidenceEntry {
  event: {
    seq: string
    createdAt: string
    type: string
    outcome: string
    redacted: boolean
    signerDid: string | null
    sigAlg: string | null
    /** Full canonical preimage — present only for unredacted entries. */
    canonical?: AuditLeaf
  }
  proof: InclusionProof
}

export interface EvidenceBundle {
  kind: typeof EVIDENCE_BUNDLE_KIND | (typeof EVIDENCE_BUNDLE_KIND_ALIASES)[number]
  version: number
  exportedAt: string
  tenant: { id: string; name: string | null }
  range: { from: string; to: string }
  entries: EvidenceEntry[]
  checkpoints: {
    id: string
    root: string
    anchorRef: string | null
    anchoredAt: string | null
    seqStart: string
    seqEnd: string
  }[]
}

export interface EvidenceVerification {
  ok: boolean
  total: number
  contentVerified: number
  commitmentOnly: number
  failed: { seq: string; reason: string }[]
  /** Distinct daily roots the entries chain up to — confirm each against its external anchor. */
  roots: { root: string; anchorRef: string | null }[]
  notes: string[]
}

export interface EvidenceVerifyOptions {
  /** Daily roots obtained from the external anchor (root hex strings). When supplied, every entry
   * must chain to one of them for a trustworthy verdict. */
  trustedRoots?: string[]
}

export function verifyEvidenceBundle(
  bundle: EvidenceBundle,
  opts: EvidenceVerifyOptions = {},
): EvidenceVerification {
  const notes: string[] = []
  const failed: { seq: string; reason: string }[] = []
  let contentVerified = 0
  let commitmentOnly = 0

  if (bundle.kind !== EVIDENCE_BUNDLE_KIND && !EVIDENCE_BUNDLE_KIND_ALIASES.includes(bundle.kind as never)) {
    notes.push(`Unexpected bundle kind "${bundle.kind}" (expected "${EVIDENCE_BUNDLE_KIND}").`)
  }

  const trusted = opts.trustedRoots ? new Set(opts.trustedRoots) : null
  if (!trusted) {
    notes.push(
      "No independent roots supplied — verifying against the roots inside the bundle. This proves " +
        "internal consistency, NOT that the bundle matches SÄKRA's anchored log. Re-run with the " +
        "roots from the external anchors (see `roots`/anchorRef) for a real verdict.",
    )
  }

  const knownRoots = new Map<string, string | null>()
  for (const cp of bundle.checkpoints) knownRoots.set(cp.root, cp.anchorRef)

  for (const entry of bundle.entries) {
    const seq = entry.event.seq
    const root = entry.proof.checkpointRoot
    if (!root) {
      failed.push({
        seq,
        reason: "no checkpoint root (event not committed at export time)",
      })
      continue
    }
    if (!knownRoots.has(root)) {
      failed.push({
        seq,
        reason: "proof's checkpoint root is not in the bundle's checkpoint list",
      })
      continue
    }
    if (trusted && !trusted.has(root)) {
      failed.push({
        seq,
        reason: "proof's checkpoint root is not among the supplied trusted roots",
      })
      continue
    }
    if (!verifyInclusionProof(entry.proof, root)) {
      failed.push({
        seq,
        reason: "inclusion proof does not recompute to the daily root",
      })
      continue
    }
    if (entry.event.redacted) {
      commitmentOnly++
    } else if (entry.event.canonical) {
      if (leafHash(entry.event.canonical) !== entry.proof.leaf) {
        failed.push({
          seq,
          reason: "leaf hash does not match the event content (leaf binding failed)",
        })
        continue
      }
      contentVerified++
    } else {
      failed.push({
        seq,
        reason: "unredacted entry is missing its canonical preimage",
      })
    }
  }

  // Check per-tenant sequence contiguity (completeness / omission detection)
  let lastTenantSeq: bigint | null = null
  for (const entry of bundle.entries) {
    const tenantSeqStr = entry.event.canonical?.tenantSeq
    if (tenantSeqStr != null) {
      const currentTenantSeq = BigInt(tenantSeqStr)
      if (lastTenantSeq !== null && currentTenantSeq !== lastTenantSeq + 1n) {
        failed.push({
          seq: entry.event.seq,
          reason: `per-tenant omission detected: sequence gap between tenantSeq ${lastTenantSeq.toString()} and ${currentTenantSeq.toString()}`,
        })
      }
      lastTenantSeq = currentTenantSeq
    }
  }

  const roots = [...knownRoots.entries()].map(([root, anchorRef]) => ({
    root,
    anchorRef,
  }))
  const ok = failed.length === 0 && bundle.entries.length > 0 && !!trusted
  if (!trusted && failed.length === 0 && bundle.entries.length > 0) {
    notes.push("All entries internally consistent; supply --roots for an independent verdict.")
  }
  return {
    ok,
    total: bundle.entries.length,
    contentVerified,
    commitmentOnly,
    failed,
    roots,
    notes,
  }
}
