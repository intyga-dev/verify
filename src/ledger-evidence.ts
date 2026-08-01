import {
  type AnchorKeyResolver,
  type AnchorPolicy,
  type ExternalAnchorKeys,
  type SignedAnchor,
  verifyAnchorQuorum,
} from "./ledger-anchor.js"
import { type AlgorithmRegistry, AUDIT_PROFILE } from "./ledger-bundle.js"
import { type AuditLeaf, leafHash } from "./ledger-leaf.js"
import { type InclusionProof, verifyInclusionProof } from "./ledger-proof.js"

// Multi-entry auditor evidence bundle (date-range export from the console's Audit page). Each entry
// carries its own two-hop inclusion proof. REDACTED entries (content removed by the retention
// ladder) carry only the leaf digest: they verify as COMMITMENT-ONLY — "an event with this digest
// existed at this position under this anchored root" — while unredacted entries additionally bind
// the displayed content to the leaf (CONTENT-VERIFIED).

// DEWP canonical kind (docs/DEWP.md §6.3). Producers emit this form and verifiers require it; there
// is no vendor-prefixed alias, since no bundle has ever been exported under one.
export const EVIDENCE_BUNDLE_KIND = "dewp.audit.evidence-bundle"

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
     * Per-tenant monotonic counter, present on redacted entries too (DEWP §16).
     *
     * DISPLAY COPY. It is a sibling of `canonical` and is covered by nothing — not the leaf, not the
     * root, not any anchor. The gapless check therefore prefers `canonical.tenantSeq`, and where it
     * must fall back (redacted entries have no preimage) it says so in the verdict notes.
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
  kind: typeof EVIDENCE_BUNDLE_KIND
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
    /**
     * The §5.2 signed anchors over this checkpoint's root — the set the §5.3 quorum rule is
     * evaluated over (§6.3). Used as quorum candidates when the caller supplies none of its own;
     * they still verify only under keys the CALLER trusts, so a bundle cannot vouch for itself.
     */
    anchors?: SignedAnchor[]
    /** Producer claim of §5.3 quorum (distinct non-SELF issuers). Display only — never trusted. */
    externallyAnchored?: boolean
  }[]
}

export interface EvidenceVerification {
  ok: boolean
  total: number
  contentVerified: number
  commitmentOnly: number
  failed: { seq: string; reason: string }[]
  /**
   * Distinct daily roots the entries chain up to. `anchorVerified` is true only when a quorum of
   * trusted issuers signed that root (requires anchors + policy + resolver in the options); it is
   * null when no policy was supplied, i.e. nobody checked.
   */
  roots: {
    root: string
    anchorRef: string | null
    anchorVerified: boolean | null
    verifiedIssuers: string[]
  }[]
  notes: string[]
}

export interface EvidenceVerifyOptions {
  /** Daily roots obtained from the external anchor (root hex strings). When supplied, every entry
   * must chain to one of them for a trustworthy verdict. */
  trustedRoots?: string[]
  /**
   * Signed anchors for the roots below, fetched by YOU from each issuer (DEWP §5.3). When omitted,
   * quorum falls back to the anchors carried in the bundle's own `checkpoints[].anchors` — still
   * checked under YOUR keys via `resolveAnchorKey`, but see the divergence carve-out at the quorum
   * loop: only caller-fetched anchors can establish divergence.
   */
  anchors?: SignedAnchor[]
  anchorPolicy?: AnchorPolicy
  resolveAnchorKey?: AnchorKeyResolver
  /** Pinned external-log keys (Rekor). Unpinned ⇒ that anchor is unverifiable ⇒ it does not count. */
  externalKeys?: ExternalAnchorKeys
}

/**
 * Compare an entry's DISPLAYED fields against the committed preimage.
 *
 * The leaf commits to `canonical`. Every field duplicated next to it — seq, createdAt, type,
 * outcome, signerDid, sigAlg, tenantSeq — is unsigned, and this is the artifact a human, a console
 * or a SIEM actually reads. Without this check a bundle could carry genuine proofs under a real
 * anchored root while displaying `outcome: "SUCCESS"` over a committed `FAILURE`, and still come
 * back fully verified. Returns a reason on mismatch, or null.
 */
function displayMismatch(event: EvidenceEntry["event"]): string | null {
  const c = event.canonical
  if (!c) return null
  const differs = (label: string, shown: unknown, committed: unknown): string | null =>
    shown != null && String(shown) !== String(committed)
      ? `displayed ${label} ("${String(shown)}") does not match the committed value ("${String(committed)}")`
      : null
  return (
    differs("seq", event.seq, c.seq) ??
    differs("createdAt", event.createdAt, c.createdAt) ??
    differs("type", event.type, c.event) ??
    differs("outcome", event.outcome, c.outcome) ??
    differs("signerDid", event.signerDid, c.signerDid) ??
    differs("sigAlg", event.sigAlg, c.sigAlg) ??
    differs("tenantSeq", event.tenantSeq, c.tenantSeq)
  )
}

export function verifyEvidenceBundle(
  bundle: EvidenceBundle,
  opts: EvidenceVerifyOptions = {},
): EvidenceVerification {
  const notes: string[] = []
  const failed: { seq: string; reason: string }[] = []
  let contentVerified = 0
  let commitmentOnly = 0
  /** Entries whose displayed type/outcome rest on the producer's redaction record, not on the log. */
  let redactedDisplayed = 0

  // DEWP §6.5: "a compliant verifier MUST reject any other value." A note let a container of one
  // type be fed to the verifier for another and still come back ok — the caller would be reading a
  // verdict produced under semantics the artifact was never built for.
  if (bundle.kind !== EVIDENCE_BUNDLE_KIND) {
    failed.push({
      seq: "-",
      reason: `refusing bundle kind "${bundle.kind}" (expected "${EVIDENCE_BUNDLE_KIND}") — DEWP §6.5`,
    })
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

  /**
   * `tenantSeq` arrives as an untrusted string. Bare `BigInt(x)` THROWS on anything non-numeric, so a
   * malformed counter propagated a SyntaxError out of this function instead of returning a verdict —
   * fail-closed only by accident of the CLI exiting non-zero, and an exception for any library
   * consumer. Oversized digit strings are also superlinear to parse, hence the length bound: a 64-bit
   * counter needs 20 digits.
   */
  const parseCounter = (raw: string): bigint | null => {
    if (typeof raw !== "string" || !/^-?\d{1,20}$/.test(raw)) return null
    try {
      return BigInt(raw)
    } catch {
      return null
    }
  }

  const trusted = opts.trustedRoots ? new Set(opts.trustedRoots) : null
  if (!trusted) {
    notes.push(
      "No independent roots supplied — verifying against the roots inside the bundle. This proves " +
        "internal consistency, NOT that the bundle matches Intyga's anchored log. Re-run with the " +
        "roots from the external anchors (see `roots`/anchorRef) for a real verdict.",
    )
  }

  const knownRoots = new Map<string, string | null>()
  const bundleAnchorsByRoot = new Map<string, SignedAnchor[]>()
  for (const cp of bundle.checkpoints) {
    knownRoots.set(cp.root, cp.anchorRef)
    if (cp.anchors?.length) bundleAnchorsByRoot.set(cp.root, cp.anchors)
  }

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
    // A redaction marker is read from the bundle, so it must not be able to switch off a check the
    // entry's own data would otherwise satisfy. DEWP §15 says a verifier MUST NOT attempt
    // contentVerified for a COMMITMENT_ONLY entry *because the preimage is intentionally absent* —
    // an entry that ships a preimage AND claims redaction is self-contradictory, and the preimage is
    // the thing that can actually be checked. Bind it. Otherwise a fabricated `canonical` plus
    // `redaction: {mode: "COMMITMENT_ONLY"}` relabels any real committed leaf to anything at all.
    if (isRedacted(entry.event) && !entry.event.canonical) {
      // §15: a COMMITMENT_ONLY entry MUST keep the ORIGINAL leaf hash — it is what still verifies
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
      redactedDisplayed++
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
      // The leaf commits to `canonical`. Everything ALONGSIDE it on the entry is a display copy that
      // nothing signs, so it has to be checked against the committed value or it is just a caption.
      const bad = displayMismatch(entry.event)
      if (bad) {
        failed.push({ seq, reason: bad })
        continue
      }
      // The entry belongs to THIS bundle's tenant. canonical.tenantId is committed; without this an
      // entry from another tenant, with a genuine proof under a root the auditor trusts, counts as
      // one of this tenant's own records.
      if (
        entry.event.canonical.tenantId != null &&
        bundle.tenant?.id != null &&
        entry.event.canonical.tenantId !== bundle.tenant.id
      ) {
        failed.push({
          seq,
          reason: `entry belongs to tenant ${entry.event.canonical.tenantId}, not ${bundle.tenant.id}`,
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
  // The counter is read from the COMMITTED preimage first. Reading `entry.tenantSeq` first was the
  // bug: that field is a sibling of `canonical` and is covered by nothing — not the leaf, not the
  // root, not any anchor. A producer could omit the incriminating events, keep the honest entries
  // with their genuine proofs, renumber the display counters to close the hole, and the contiguity
  // check would report no gap (verified). A redacted entry has no preimage, so it falls back to the
  // redaction commitment and then to the entry, or the hole lawful redaction leaves would read as an
  // omission — but those values are NOT leaf-bound, which the note below now says plainly.
  let lastTenantSeq: bigint | null = null
  let firstTenantSeq: bigint | null = null
  let sawUncountedEntry = false
  let sawUnboundCounter = false
  for (const entry of bundle.entries) {
    const bound = entry.event.canonical?.tenantSeq
    const tenantSeqStr = bound ?? entry.event.redaction?.commitment?.tenantSeq ?? entry.event.tenantSeq
    if (bound == null && tenantSeqStr != null) sawUnboundCounter = true
    if (tenantSeqStr == null) {
      sawUncountedEntry = true
      continue
    }
    const currentTenantSeq = parseCounter(tenantSeqStr)
    if (currentTenantSeq === null) {
      failed.push({
        seq: entry.event.seq,
        reason: `tenantSeq ${JSON.stringify(tenantSeqStr)} is not a valid integer counter`,
      })
      continue
    }
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
  if (redactedDisplayed > 0) {
    notes.push(
      `${redactedDisplayed} entr${redactedDisplayed === 1 ? "y is" : "ies are"} COMMITMENT_ONLY: inclusion ` +
        "is proven against the retained leaf, but the displayed type/outcome/detail are NOT covered by " +
        "it — the preimage they would be checked against is gone. They rest on the producer's redaction " +
        "record (DEWP §15), not on the anchored log.",
    )
  }
  if (sawUncountedEntry) {
    notes.push(
      "Some entries carry no tenantSeq, so gapless completeness could not be checked across them. " +
        "(Bundles exported before redacted entries carried tenantSeq — re-export for a complete check.)",
    )
  }
  if (sawUnboundCounter) {
    notes.push(
      "Some entries' tenantSeq is NOT covered by the Merkle leaf (redacted entries have no preimage). " +
        "Gaplessness across those rests on the producer's redaction record, not on the anchored log.",
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
      const claimedFirst = parseCounter(commitment.firstTenantSeq)
      const claimedLast = parseCounter(commitment.lastTenantSeq)
      if (claimedFirst === null || claimedLast === null) {
        failed.push({
          seq: bundle.entries[0]?.event.seq ?? "?",
          reason: "tenantSequenceCommitment carries a non-numeric firstTenantSeq/lastTenantSeq",
        })
      } else {
        if (firstSeen !== claimedFirst)
          failed.push({
            seq: bundle.entries[0]?.event.seq ?? "?",
            reason: `bundle claims it starts at tenantSeq ${commitment.firstTenantSeq} but the first entry is ${firstSeen.toString()}`,
          })
        if (lastSeen !== claimedLast)
          failed.push({
            seq: bundle.entries.at(-1)?.event.seq ?? "?",
            reason: `bundle claims it ends at tenantSeq ${commitment.lastTenantSeq} but the last entry is ${lastSeen.toString()}`,
          })
      }
      if (commitment.tenantId !== bundle.tenant.id)
        notes.push(
          `tenantSequenceCommitment names tenant ${commitment.tenantId}, which differs from the bundle's tenant ${bundle.tenant.id}.`,
        )
    }
  }

  // DEWP §5.3 anchor quorum, per distinct root. Candidate anchors come from the caller when
  // supplied, otherwise from the bundle's own per-checkpoint `anchors` — the §6.3 set the quorum
  // rule is defined over. Either way the check only runs when the caller supplied a policy AND a key
  // resolver: signatures are checked against keys the VERIFIER trusts, so a bundle cannot vouch for
  // itself by shipping anchors it signed with its own key.
  //
  // Bundle-carried anchors may COUNT toward quorum but may never trigger the fatal DIVERGENCE
  // verdict (mirrors verifyBundle): an anchor's signed preimage carries no checkpoint identity, so a
  // genuine anchor from another day is indistinguishable from a conflicting one, and appending a
  // real, publicly available anchor would be enough to make a valid bundle read as tampering. Only
  // anchors the caller fetched itself, per checkpoint, can establish divergence.
  // Gated on the CALLER having asked (policy + resolver), never on candidates existing: a producer
  // who strips `checkpoints[].anchors` must get "quorum not met (0/N)", not a skipped check. Gating
  // on candidates was the same shape as the trap verifyBundle documents — a check the prover can
  // switch off — with the CLI then printing VERIFIED under a policy nobody evaluated.
  const canCheckAnchors = Boolean(opts.anchorPolicy && opts.resolveAnchorKey)
  const usedBundleAnchors = canCheckAnchors && !opts.anchors?.length && bundleAnchorsByRoot.size > 0
  const roots = [...knownRoots.entries()].map(([root, anchorRef]) => {
    if (!canCheckAnchors || !opts.anchorPolicy || !opts.resolveAnchorKey) {
      return { root, anchorRef, anchorVerified: null, verifiedIssuers: [] as string[] }
    }
    const candidates = opts.anchors?.length ? opts.anchors : (bundleAnchorsByRoot.get(root) ?? [])
    const q = verifyAnchorQuorum(candidates, root, opts.anchorPolicy, opts.resolveAnchorKey, {
      divergenceAnchors: opts.anchors ?? [],
      externalKeys: opts.externalKeys,
    })
    if (q.divergence) {
      failed.push({ seq: "-", reason: `ANCHOR DIVERGENCE for root ${root.slice(0, 16)}…: ${q.reason}` })
    } else if (!q.ok && q.reason) {
      notes.push(`Root ${root.slice(0, 16)}…: ${q.reason}`)
    }
    // RFC 3161 honesty: a TSA anchor is real evidence this tool cannot check offline; say so rather
    // than let "quorum not met" read as "unanchored".
    if (q.note) notes.push(`Root ${root.slice(0, 16)}…: ${q.note}`)
    return { root, anchorRef, anchorVerified: q.ok, verifiedIssuers: q.verifiedIssuers }
  })
  if (usedBundleAnchors) {
    notes.push(
      "Anchor quorum was evaluated over the anchors carried in the bundle's checkpoints. They verify " +
        "only under keys YOU trust, so the result is sound — but divergence detection needs anchors " +
        "you fetched per checkpoint yourself (pass `anchors`).",
    )
  }
  if (!canCheckAnchors && !(opts.anchorPolicy || opts.resolveAnchorKey)) {
    notes.push(
      "No anchor policy supplied — the roots above were compared, but no independent signature over " +
        "them was checked. Pass anchorPolicy + resolveAnchorKey (and optionally your own anchors) " +
        "for a DEWP §5.3 verdict.",
    )
  } else if (!canCheckAnchors) {
    notes.push(
      "Anchor policy incomplete — both anchorPolicy AND resolveAnchorKey are required for a DEWP " +
        "§5.3 verdict; neither alone can check a signature.",
    )
  }
  // When a policy WAS supplied, every root must reach quorum; a bundle resting on an unanchored root
  // is not independently attested no matter how well its proofs verify.
  const allAnchored = !canCheckAnchors || roots.every((r) => r.anchorVerified === true)
  const ok = failed.length === 0 && bundle.entries.length > 0 && !!trusted && allAnchored
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
