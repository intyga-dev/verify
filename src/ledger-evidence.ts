import { type AlgorithmRegistry, AUDIT_PROFILE } from "./ledger-bundle.js"
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

/**
 * DEWP §6.3/§16 redaction record. `COMMITMENT_ONLY` means content was lawfully purged under a
 * retention or erasure policy while the Merkle commitment was preserved — recording *that* it was
 * purged and *why* is what lets an auditor tell lawful redaction from tampering.
 */
export interface RedactionRecord {
  mode: "NONE" | "COMMITMENT_ONLY"
  removedFields?: string[]
  redactedAt?: string
  reason?: string
  commitment?: { leaf: string; tenantSeq?: string | null }
}

export interface EvidenceEntry {
  event: {
    seq: string
    createdAt: string
    type: string
    outcome: string
    /** DEWP §6.3 redaction record. Preferred over the legacy `redacted` boolean below. */
    redaction?: RedactionRecord
    /** Legacy boolean form, still read so bundles exported before `redaction` keep verifying. */
    redacted?: boolean
    /**
     * Per-tenant monotonic counter, present on redacted entries too (DEWP §16). The gapless check
     * below reads THIS, not `canonical.tenantSeq`: a redacted entry has no canonical preimage, so
     * keying completeness off the preimage makes redacted entries invisible to the check and turns
     * a lawfully redacted log into a phantom gap.
     */
    tenantSeq?: string | null
    signerDid: string | null
    sigAlg: string | null
    /** Full canonical preimage — present only for unredacted entries. */
    canonical?: AuditLeaf
  }
  proof: InclusionProof
}

export interface EvidenceBundle {
  /** DEWP §6.3 envelope. Absent on bundles exported before the envelope was added. */
  protocol?: string
  kind: typeof EVIDENCE_BUNDLE_KIND | (typeof EVIDENCE_BUNDLE_KIND_ALIASES)[number]
  version: string | number
  /** Canonical-preimage Application Profile (§4.5). */
  profile?: string
  algorithmRegistry?: AlgorithmRegistry
  exportedAt: string
  tenant: { id: string; name: string | null }
  range: { from: string; to: string }
  /**
   * The contiguous committed tenantSeq range this bundle CLAIMS to cover (§6.3). Checking the entries
   * against it is what turns "these entries happen to be contiguous" into "nothing was dropped from
   * the range that was asked for" — without it, a producer could silently narrow the export.
   */
  tenantSequenceCommitment?: {
    tenantId: string
    firstTenantSeq: string
    lastTenantSeq: string
  }
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
  // Unknown canonical layout ⇒ leaf binding is not attempted (see verifyBundle for the rationale).
  const unknownProfile = bundle.profile !== undefined && bundle.profile !== AUDIT_PROFILE
  if (unknownProfile) {
    notes.push(
      `Unknown canonical profile "${bundle.profile}" — this verifier implements "${AUDIT_PROFILE}", so ` +
        "entry content cannot be bound to its leaf. Commitment verification is unaffected.",
    )
  }

  /** DEWP §6.3 redaction, reading the `redaction` object and falling back to the legacy boolean. */
  const isRedacted = (event: EvidenceEntry["event"]): boolean =>
    event.redaction ? event.redaction.mode === "COMMITMENT_ONLY" : event.redacted === true

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
    if (isRedacted(entry.event)) {
      // §16: a COMMITMENT_ONLY entry MUST keep the ORIGINAL leaf hash — it is what still verifies
      // against the anchored root. If the redaction record names a different one, the commitment was
      // rewritten during redaction, which is exactly what redaction must not be able to do.
      const retained = entry.event.redaction?.commitment?.leaf
      if (retained !== undefined && retained !== entry.proof.leaf) {
        failed.push({
          seq,
          reason: "redaction commitment leaf does not match the proof leaf (commitment was altered)",
        })
        continue
      }
      commitmentOnly++
    } else if (unknownProfile) {
      // Commitment verified above; content cannot be bound under an unrecognised layout.
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

  // Check per-tenant sequence contiguity (completeness / omission detection). DEWP §3 Invariant 4
  // requires rejecting gaps, duplicates AND out-of-order values, so compare against tenantSeq_N + 1
  // exactly rather than merely checking for forward movement.
  //
  // The counter is read from the ENTRY, falling back to the canonical preimage for bundles exported
  // before entries carried it. A redacted entry has no preimage, so reading only the preimage would
  // skip it and report the hole it leaves as an omission — flagging lawful redaction as tampering.
  let lastTenantSeq: bigint | null = null
  let firstTenantSeq: bigint | null = null
  let sawUncountedEntry = false
  for (const entry of bundle.entries) {
    const tenantSeqStr = entry.event.tenantSeq ?? entry.event.canonical?.tenantSeq
    if (tenantSeqStr == null) {
      sawUncountedEntry = true
      continue
    }
    const currentTenantSeq = BigInt(tenantSeqStr)
    if (lastTenantSeq !== null && currentTenantSeq !== lastTenantSeq + 1n) {
      failed.push({
        seq: entry.event.seq,
        reason:
          currentTenantSeq <= lastTenantSeq
            ? `per-tenant sequence is not strictly increasing: tenantSeq ${currentTenantSeq.toString()} follows ${lastTenantSeq.toString()}`
            : `per-tenant omission detected: sequence gap between tenantSeq ${lastTenantSeq.toString()} and ${currentTenantSeq.toString()}`,
      })
    }
    if (firstTenantSeq === null) firstTenantSeq = currentTenantSeq
    lastTenantSeq = currentTenantSeq
  }
  if (sawUncountedEntry) {
    notes.push(
      "Some entries carry no tenantSeq, so gapless completeness could not be checked across them. " +
        "(Bundles exported before redacted entries carried tenantSeq — re-export for a complete check.)",
    )
  }

  // DEWP §6.3: the bundle asserts WHICH contiguous tenantSeq range it covers. Confirm the entries
  // actually span it — contiguity alone only proves the entries present are consecutive, not that the
  // producer did not quietly truncate either end of the range it claimed to export.
  const commitment = bundle.tenantSequenceCommitment
  if (commitment) {
    const firstSeen = firstTenantSeq
    const lastSeen = lastTenantSeq
    if (firstSeen === null || lastSeen === null) {
      notes.push(
        "Bundle declares a tenantSequenceCommitment but no entry carries a tenantSeq to check it against.",
      )
    } else {
      if (firstSeen !== BigInt(commitment.firstTenantSeq))
        failed.push({
          seq: bundle.entries[0]?.event.seq ?? "?",
          reason: `bundle claims it starts at tenantSeq ${commitment.firstTenantSeq} but the first entry is ${firstSeen.toString()}`,
        })
      if (lastSeen !== BigInt(commitment.lastTenantSeq))
        failed.push({
          seq: bundle.entries.at(-1)?.event.seq ?? "?",
          reason: `bundle claims it ends at tenantSeq ${commitment.lastTenantSeq} but the last entry is ${lastSeen.toString()}`,
        })
      if (commitment.tenantId !== bundle.tenant.id)
        notes.push(
          `tenantSequenceCommitment names tenant ${commitment.tenantId}, which differs from the bundle's tenant ${bundle.tenant.id}.`,
        )
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
