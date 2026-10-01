import {
  type AnchorKeyResolver,
  type AnchorPolicy,
  type ExternalAnchorKeys,
  type SignedAnchor,
  verifyAnchorQuorum,
} from "./ledger-anchor.js"
import {
  type AlgorithmRegistry,
  AUDIT_PROFILE,
  leafCountMismatch,
  supportedEnvelope,
  type TrustedCheckpoint,
} from "./ledger-bundle.js"
import {
  verifyAuditSignature,
  uncheckedSignature,
  type AuditSignaturePolicy,
  type AuditSignatureCheck,
} from "./ledger-signature.js"
import { chainHash } from "./ledger-chain.js"
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
     * root, not any anchor. The gapless check reads `canonical.tenantSeq` whenever a preimage is
     * present, and falls back to the redaction record or this copy only for an entry with no preimage
     * (a COMMITMENT_ONLY redaction), saying so in the verdict notes (DEWP §7.2).
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
  /**
   * The tenant the bundle is for. Every content-verified entry must carry this `tenantId` (or none),
   * so `tenantSeq` contiguity is judged over ONE tenant's counter. Absent or null, any entry that
   * names a tenant is refused (DEWP §7.2).
   */
  tenant?: { id: string | null; name: string | null } | null
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
     * The §5.4 chain fields. With them the verifier recomputes `chainHash`, and every anchor must bind
     * that chain hash — which commits to the checkpoint's range, commit time and every earlier root.
     * Absent on exports made before anchors bound position.
     */
    entryCount?: number
    prevChainHash?: string | null
    chainHash?: string | null
    /**
     * The §5.2 signed anchors over this checkpoint's root — the set the §5.3 quorum rule is
     * evaluated over (§6.3). Used as quorum candidates when the caller supplies none of its own;
     * they still verify only under keys the CALLER trusts, so a bundle cannot vouch for itself.
     */
    anchors?: SignedAnchor[]
    /** Producer claim of §5.3 quorum (distinct INDEPENDENT issuers). Display only — never trusted. */
    externallyAnchored?: boolean
    /** The quorum size that claim was evaluated against (§6.3). Absent on older exports. */
    externallyAnchoredRequired?: number
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
    /** Authenticated external witness time per issuer, Unix seconds (see AnchorQuorumResult). */
    witnessTimes: Record<string, number>
  }[]
  /**
   * Per-event mathematical signature checks, with explicit status and caller-key trust.
   * WebAuthn uses committed metadata.webauthn plus caller-selected keys, origin and RP ID.
   * No authorization/quorum is inferred; use verifyApprovalReceipt for the full approval policy.
   * By default an invalid signature is reported without treating the ledger inclusion as invalid.
   * requireSignatures additionally fails the bundle unless EVERY entry has a trusted signature.
   */
  signatures: {
    checks?: Array<AuditSignatureCheck & { seq: string }>
    verified: number
    invalid: { seq: string }[]
    notCheckable: number
  }
  notes: string[]
}

/**
 * Caller-fetched anchors, either flat or attributed to the checkpoint each one vouches for.
 *
 * The keyed form maps a checkpoint's `id` OR its `root` (as the bundle states it) to the anchors YOU
 * fetched for that checkpoint. Attribution is what makes a DIVERGENCE verdict meaningful on a bundle
 * spanning more than one day. An anchor's signed seq range now names its checkpoint too, and one
 * naming a different range than the checkpoint it is keyed to is discarded as divergence evidence;
 * attribution still decides which checkpoint a caller vouches it was fetched for.
 */
export type EvidenceAnchorSet = SignedAnchor[] | Record<string, SignedAnchor[]>

export interface EvidenceVerifyOptions {
  signaturePolicy?: AuditSignaturePolicy
  requireSignatures?: boolean
  /**
   * Daily roots to verify against (root hex strings). When supplied, every entry must chain to one of
   * them. They are only as independent as their source: roots recorded earlier or taken from the
   * published roots file are; roots copied out of this bundle are not. (An external anchor cannot
   * supply one — Rekor stores a hash of the anchor digest and a TSA the digest, not the root.)
   */
  trustedRoots?: string[]
  /**
   * Checkpoint records YOU hold — normally the chain-verified lines of the published roots file
   * (DEWP §5.4.1). Their roots count as trusted roots. For a bundle checkpoint over one of these roots,
   * every field both carry must agree, or the bundle fails; and anchors are held to YOUR record's
   * range, chain hash and claimed time rather than to the bundle's, so a producer cannot re-date a
   * checkpoint to make a late witness look prompt (§5.3). A record's `entryCount` also bounds the
   * proofs' leaf counts.
   */
  trustedCheckpoints?: TrustedCheckpoint[]
  /**
   * Signed anchors for the roots below, fetched by YOU from each issuer (DEWP §5.3). When omitted,
   * quorum falls back to the anchors carried in the bundle's own `checkpoints[].anchors` — still
   * checked under YOUR keys via `resolveAnchorKey`, but see the divergence carve-out at the quorum
   * loop: only caller-fetched anchors can establish divergence.
   *
   * Prefer the `EvidenceAnchorSet` keyed form on a multi-checkpoint bundle (a date-range export
   * routinely is one): a flat list cannot say which checkpoint each anchor was fetched for.
   */
  anchors?: EvidenceAnchorSet
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
  const signatureChecks = new Map<string, AuditSignatureCheck>()
  let signaturesVerified = 0
  let signaturesNotCheckable = 0
  const signaturesInvalid: { seq: string }[] = []

  // DEWP §6.5: "a compliant verifier MUST reject any other value." A note let a container of one
  // type be fed to the verifier for another and still come back ok — the caller would be reading a
  // verdict produced under semantics the artifact was never built for.
  if (bundle.kind !== EVIDENCE_BUNDLE_KIND || !supportedEnvelope(bundle)) {
    failed.push({
      seq: "-",
      reason: `refusing bundle kind "${bundle.kind}", protocol, version or algorithm registry (DEWP §7/§12)`,
    })
  }
  // Unknown canonical layout ⇒ leaf binding is not attempted (see verifyBundle for the rationale). That
  // is a check the PRODUCER can switch off, so an entry that ships a preimage under such a profile
  // fails below rather than passing as commitment-only: its content, tenant and tenantSeq would all be
  // unbound, and the contiguity verdict would be computed over counters nothing commits to.
  const unknownProfile = bundle.profile !== undefined && bundle.profile !== AUDIT_PROFILE
  if (unknownProfile) {
    notes.push(
      `Unknown canonical profile "${bundle.profile}" — this verifier implements "${AUDIT_PROFILE}", so ` +
        "entry content cannot be bound to its leaf. Entries without a preimage are still checked for " +
        "commitment; an entry that carries one cannot be verified and fails.",
    )
  }
  const bundleTenantId = bundle.tenant?.id ?? null

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

  const trustedRecords = opts.trustedCheckpoints ?? []
  const trusted =
    opts.trustedRoots || opts.trustedCheckpoints
      ? new Set([...(opts.trustedRoots ?? []), ...trustedRecords.map((r) => r.root)])
      : null
  /** Root → the caller's own record for it (first wins). */
  const trustedRecordByRoot = new Map<string, TrustedCheckpoint>()
  for (const r of trustedRecords) if (!trustedRecordByRoot.has(r.root)) trustedRecordByRoot.set(r.root, r)
  if (!trusted) {
    notes.push(
      "No roots supplied — verifying against the roots inside the bundle. This proves internal " +
        "consistency, NOT that the bundle matches the producer's anchored log. Re-run with roots you " +
        "obtained earlier or from the published roots file for a real verdict.",
    )
  }

  // §5.4 chain fields, where the export carries them: the chain hash must recompute from the
  // checkpoint's own fields, or the anchors that bind it would be binding something the bundle does
  // not actually describe.
  for (const cp of bundle.checkpoints) {
    if (cp.chainHash == null) continue
    const complete =
      typeof cp.prevChainHash === "string" &&
      typeof cp.anchoredAt === "string" &&
      typeof cp.entryCount === "number" &&
      Number.isSafeInteger(cp.entryCount)
    const recomputed = complete
      ? chainHash({
          prevChainHash: cp.prevChainHash as string,
          root: cp.root,
          seqStart: cp.seqStart,
          seqEnd: cp.seqEnd,
          entryCount: cp.entryCount as number,
          anchoredAt: cp.anchoredAt as string,
        })
      : null
    if (recomputed !== cp.chainHash) {
      failed.push({
        seq: "-",
        reason: complete
          ? `checkpoint ${cp.id} chainHash does not recompute from its root, range, entry count and anchoredAt`
          : `checkpoint ${cp.id} carries a chainHash without the prevChainHash/entryCount/anchoredAt it commits to`,
      })
    }
  }

  // A checkpoint the caller holds its own record for must agree with that record on every field both
  // state. The bundle's copy is the producer's; the caller's is what the roots-file chain verified. A
  // re-dated `anchoredAt` with a self-consistent chainHash over a made-up predecessor recomputes fine
  // above, and is caught only here.
  for (const cp of bundle.checkpoints) {
    const record = trustedRecordByRoot.get(cp.root)
    if (!record) continue
    const pairs: [string, unknown, unknown][] = [
      ["seqStart", cp.seqStart, record.seqStart],
      ["seqEnd", cp.seqEnd, record.seqEnd],
      ["entryCount", cp.entryCount, record.entryCount],
      ["anchoredAt", cp.anchoredAt, record.anchoredAt],
      ["chainHash", cp.chainHash, record.chainHash],
    ]
    for (const [field, shown, held] of pairs) {
      if (shown != null && held != null && shown !== held) {
        failed.push({
          seq: "-",
          reason: `checkpoint ${cp.id} ${field} contradicts your trusted checkpoint record for its root`,
        })
      }
    }
  }
  /**
   * The position and time anchors over `root` are held to: the caller's record where it states a
   * field, the bundle's checkpoint otherwise.
   */
  const effectiveCheckpoint = (root: string, cp: EvidenceBundle["checkpoints"][number] | undefined) => {
    const record = trustedRecordByRoot.get(root)
    return {
      seqStart: record?.seqStart ?? cp?.seqStart ?? null,
      seqEnd: record?.seqEnd ?? cp?.seqEnd ?? null,
      entryCount: record?.entryCount ?? cp?.entryCount ?? null,
      chainHash: record?.chainHash ?? cp?.chainHash ?? null,
      anchoredAt: record?.anchoredAt ?? cp?.anchoredAt ?? null,
    }
  }

  const knownRoots = new Map<string, string | null>()
  /** Root → the checkpoint that states it (first wins), for the anchors' expected position. */
  const checkpointByRoot = new Map<string, EvidenceBundle["checkpoints"][number]>()
  const bundleAnchorsByRoot = new Map<string, SignedAnchor[]>()
  /** Checkpoint id OR root → root, so the caller may key its anchors by either. */
  const checkpointKeyToRoot = new Map<string, string>()
  for (const cp of bundle.checkpoints) {
    knownRoots.set(cp.root, cp.anchorRef)
    if (!checkpointByRoot.has(cp.root)) checkpointByRoot.set(cp.root, cp)
    if (cp.anchors?.length) bundleAnchorsByRoot.set(cp.root, cp.anchors)
    if (cp.id) checkpointKeyToRoot.set(cp.id, cp.root)
  }
  // Roots last: a checkpoint whose id happens to equal another checkpoint's root must not shadow it.
  for (const cp of bundle.checkpoints) checkpointKeyToRoot.set(cp.root, cp.root)

  // Caller-fetched anchors in two views: the flat union is the quorum candidate pool (as before —
  // verifyAnchorQuorum only counts anchors whose dailyRoot IS the root under evaluation), while
  // `callerAnchorsByRoot` records which checkpoint the caller said each one was fetched for. Only the
  // second may feed divergence; see the quorum loop.
  const callerAnchors: SignedAnchor[] = []
  const callerAnchorsByRoot = new Map<string, SignedAnchor[]>()
  const callerKeyed = Boolean(opts.anchors) && !Array.isArray(opts.anchors)
  let unattributedKeys = false
  if (Array.isArray(opts.anchors)) {
    callerAnchors.push(...opts.anchors)
  } else if (opts.anchors) {
    for (const [key, list] of Object.entries(opts.anchors)) {
      if (!Array.isArray(list) || list.length === 0) continue
      callerAnchors.push(...list)
      const root = checkpointKeyToRoot.get(key)
      if (root === undefined) {
        // Keyed to a checkpoint this bundle does not contain. Still a quorum candidate, but it
        // cannot be divergence evidence for a checkpoint nobody can identify.
        unattributedKeys = true
        continue
      }
      callerAnchorsByRoot.set(root, [...(callerAnchorsByRoot.get(root) ?? []), ...list])
    }
  }

  // One committed event appears once. A genuine leaf used twice (or two entries claiming one seq) can
  // otherwise fill two holes in the tenant sequence from a single real event.
  const seenLeaves = new Set<string>()
  const seenSeqs = new Set<string>()
  /** Leaf counts are properties of a TREE: every proof into one block/checkpoint must agree on them. */
  const blockLeafCounts = new Map<string, number>()
  const checkpointLeafCounts = new Map<string, number>()
  for (const entry of bundle.entries) {
    const seq = entry.event.seq
    const root = entry.proof.checkpointRoot
    if (seenLeaves.has(entry.proof.leaf) || seenSeqs.has(seq)) {
      failed.push({ seq, reason: "duplicate entry: this leaf or seq already appears in the bundle" })
      continue
    }
    seenLeaves.add(entry.proof.leaf)
    seenSeqs.add(seq)
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
    // DEWP §17.3: the prover supplies the leaf counts, so an interior node of a larger block can
    // otherwise pass as a leaf of a smaller one. Bind them to each other and to the entry count.
    const priorBlock = blockLeafCounts.get(entry.proof.blockRoot)
    const priorCheckpoint = checkpointLeafCounts.get(root)
    const countBad =
      (priorBlock !== undefined && priorBlock !== entry.proof.blockLeafCount) ||
      (priorCheckpoint !== undefined && priorCheckpoint !== entry.proof.checkpointLeafCount)
        ? "proofs into the same block or checkpoint disagree on its leaf count"
        : leafCountMismatch(entry.proof, effectiveCheckpoint(root, checkpointByRoot.get(root)).entryCount)
    if (countBad) {
      failed.push({ seq, reason: countBad })
      continue
    }
    blockLeafCounts.set(entry.proof.blockRoot, entry.proof.blockLeafCount)
    checkpointLeafCounts.set(root, entry.proof.checkpointLeafCount)
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
    } else if (unknownProfile && entry.event.canonical) {
      // The preimage cannot be bound under a layout this verifier does not implement, and a pass here
      // would let the producer switch leaf binding off (DEWP §4.5/§7.2 rule 1) — mirrors verifyBundle.
      failed.push({
        seq,
        reason: `canonical preimage under unknown profile "${bundle.profile}" cannot be bound to its leaf`,
      })
    } else if (unknownProfile) {
      // Commitment verified above; there is no content to bind.
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
      // The redaction record is unsigned. Where a preimage exists it is not a counter source (§7.2),
      // so one that disagrees with the committed counter is a caption contradicting the evidence.
      const redactionSeq = entry.event.redaction?.commitment?.tenantSeq
      if (redactionSeq != null && redactionSeq !== entry.event.canonical.tenantSeq) {
        failed.push({
          seq,
          reason: `redaction record tenantSeq ("${redactionSeq}") does not match the committed value ("${String(entry.event.canonical.tenantSeq)}")`,
        })
        continue
      }
      // The entry belongs to THIS bundle's tenant. canonical.tenantId is committed; without this an
      // entry from another tenant, with a genuine proof under a root the auditor trusts, counts as
      // one of this tenant's own records. A bundle that declares no tenant has none to belong to:
      // skipping the check there let entries of several tenants be spliced into one "contiguous"
      // sequence, since tenantSeq is a per-tenant counter.
      if (entry.event.canonical.tenantId != null && entry.event.canonical.tenantId !== bundleTenantId) {
        failed.push({
          seq,
          reason:
            bundleTenantId == null
              ? `entry belongs to tenant ${entry.event.canonical.tenantId}, but the bundle declares no tenant`
              : `entry belongs to tenant ${entry.event.canonical.tenantId}, not ${bundleTenantId}`,
        })
        continue
      }
      // §7.1 signatureVerified. Runs only once the leaf binding above passed, so the signature we
      // check is provably the committed one rather than something the bundle attached.
      const canonical = entry.event.canonical
      const signature = verifyAuditSignature(canonical, opts.signaturePolicy)
      signatureChecks.set(seq, signature)
      if (signature.status === "verified") signaturesVerified++
      else if (signature.status === "invalid") signaturesInvalid.push({ seq })
      else signaturesNotCheckable++
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
  //
  // The fallback is for entries WITHOUT a preimage only (§7.2 rule 2). An entry with a preimage whose
  // committed tenantSeq is null has no counter (rule 5): falling through to the unsigned redaction
  // record let a genuine tenantless system leaf, tagged `redaction: {mode: "NONE", commitment:
  // {tenantSeq: "N"}}`, fill tenant T's hole at N while counting as fully content-verified.
  let lastTenantSeq: bigint | null = null
  let firstTenantSeq: bigint | null = null
  let sawUncountedEntry = false
  let sawUnboundCounter = false
  for (const entry of bundle.entries) {
    const canonical = entry.event.canonical
    // Under an unknown profile a preimage is not leaf-bound; that entry has already failed above.
    if (canonical && unknownProfile) continue
    const tenantSeqStr = canonical
      ? canonical.tenantSeq
      : (entry.event.redaction?.commitment?.tenantSeq ?? entry.event.tenantSeq)
    if (!canonical && tenantSeqStr != null) sawUnboundCounter = true
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
      "Some entries carry no canonical preimage (COMMITMENT_ONLY redaction), so their tenantSeq was read " +
        "from the redaction record or the display copy and is NOT covered by the Merkle leaf. " +
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
      if (commitment.tenantId !== bundleTenantId)
        notes.push(
          `tenantSequenceCommitment names tenant ${commitment.tenantId}, which differs from the bundle's tenant ${String(bundleTenantId)}.`,
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
  // verdict (mirrors verifyBundle): the producer chooses what the bundle carries, so its anchors are
  // no evidence that nothing conflicting exists, and appending a real, publicly available anchor
  // from another checkpoint must never make a valid bundle read as tampering. Only anchors the caller
  // fetched itself, per checkpoint, can establish divergence — and one whose signed seq range names
  // another checkpoint cannot.
  //
  // The same misbinding applies to the caller's own anchors once a bundle spans more than one
  // checkpoint, which a date-range export routinely does: passing the whole flat list to EVERY root
  // read a genuine anchor for checkpoint A as divergence while evaluating checkpoint B, and turned a
  // sound multi-day export into a tamper alarm. So caller anchors are attributed to a checkpoint
  // first. The keyed form is exact. A flat list can only be attributed by elimination — an anchor
  // over ANOTHER checkpoint's root in this same bundle is explainable and is therefore not
  // divergence evidence — which keeps the single-checkpoint behaviour identical and leaves one gap
  // stated in the note below: a producer who appends a decoy checkpoint carrying the real root can
  // absorb the conflicting anchor that way. That downgrades the verdict from DIVERGENCE to "quorum
  // not met" for the checkpoint it forged, never to ok.
  // Gated on the CALLER having asked (policy + resolver), never on candidates existing: a producer
  // who strips `checkpoints[].anchors` must get "quorum not met (0/N)", not a skipped check. Gating
  // on candidates was the same shape as the trap verifyBundle documents — a check the prover can
  // switch off — with the CLI then printing VERIFIED under a policy nobody evaluated.
  const canCheckAnchors = Boolean(opts.anchorPolicy && (opts.resolveAnchorKey || opts.externalKeys))
  const usedBundleAnchors = canCheckAnchors && callerAnchors.length === 0 && bundleAnchorsByRoot.size > 0
  const roots = [...knownRoots.entries()].map(([root, anchorRef]) => {
    if (!canCheckAnchors || !opts.anchorPolicy) {
      return {
        root,
        anchorRef,
        anchorVerified: null,
        verifiedIssuers: [] as string[],
        witnessTimes: {} as Record<string, number>,
      }
    }
    // Anchors bind a POSITION: they count for this root only if their signed range, chain hash and
    // time are this checkpoint's own.
    const expected = effectiveCheckpoint(root, checkpointByRoot.get(root))
    // §5.3/§6.3: an anchor is held to its checkpoint's chain hash and claimed time. A checkpoint that
    // states neither (and has no caller record to supply them) cannot hold anything to anything, and
    // skipping it silently is what let a producer strip `anchoredAt`/`chainHash` to turn off the time
    // bound. So it never counts as anchored — divergence is still evaluated, so stripping the fields
    // cannot also turn a tamper alarm into a mere "not anchored".
    const positionUnknown = expected.chainHash == null || expected.anchoredAt == null
    if (positionUnknown) {
      notes.push(
        `Root ${root.slice(0, 16)}…: its checkpoint carries no chainHash/anchoredAt and no trusted checkpoint ` +
          "record supplies them, so its anchors cannot be held to a position and time (DEWP §5.3) — not anchored.",
      )
    }
    const candidates = callerAnchors.length ? callerAnchors : (bundleAnchorsByRoot.get(root) ?? [])
    const divergenceAnchors = callerKeyed
      ? (callerAnchorsByRoot.get(root) ?? [])
      : callerAnchors.filter((a) => a.dailyRoot === root || !knownRoots.has(a.dailyRoot))
    const q = verifyAnchorQuorum(candidates, root, opts.anchorPolicy, opts.resolveAnchorKey ?? (() => null), {
      divergenceAnchors,
      externalKeys: opts.externalKeys,
      checkpoint: {
        seqStart: expected.seqStart,
        seqEnd: expected.seqEnd,
        chainHash: expected.chainHash,
        anchoredAt: expected.anchoredAt,
      },
    })
    if (q.divergence) {
      failed.push({ seq: "-", reason: `ANCHOR DIVERGENCE for root ${root.slice(0, 16)}…: ${q.reason}` })
    } else if (!q.ok && q.reason) {
      notes.push(`Root ${root.slice(0, 16)}…: ${q.reason}`)
    }
    // Report TSA evidence that could not be verified under the caller's configuration.
    if (q.note) notes.push(`Root ${root.slice(0, 16)}…: ${q.note}`)
    return {
      root,
      anchorRef,
      anchorVerified: q.ok && !positionUnknown,
      verifiedIssuers: positionUnknown ? [] : q.verifiedIssuers,
      witnessTimes: q.witnessTimes,
    }
  })
  if (usedBundleAnchors) {
    notes.push(
      "Anchor quorum was evaluated over the anchors carried in the bundle's checkpoints. They verify " +
        "only under keys YOU trust, so the result is sound — but divergence detection needs anchors " +
        "you fetched per checkpoint yourself (pass `anchors`).",
    )
  }
  if (canCheckAnchors && callerAnchors.length > 0 && !callerKeyed && knownRoots.size > 1) {
    notes.push(
      `The anchors you supplied came as one flat list while this bundle spans ${knownRoots.size} checkpoints, ` +
        "so each one could only be attributed by its own root. Divergence is therefore reported only for " +
        "anchors over a root this bundle does not claim at all. Key them by checkpoint id or root " +
        "(`anchors: { [checkpointId]: [...] }`) for a per-checkpoint divergence verdict.",
    )
  }
  if (unattributedKeys) {
    notes.push(
      "Some supplied anchors are keyed to a checkpoint id/root this bundle does not contain. They still " +
        "count toward quorum for a root they sign, but they cannot establish divergence — check the keys " +
        "against `checkpoints[]`, because a producer renaming a checkpoint would look exactly like this.",
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
      "Anchor policy incomplete — anchorPolicy and either resolveAnchorKey or externalKeys are required for a DEWP " +
        "§5.3 verdict; neither alone can check a signature.",
    )
  }
  // When a policy WAS supplied, every root must reach quorum; a bundle resting on an unanchored root
  // is not independently attested no matter how well its proofs verify.
  const allAnchored = !opts.anchorPolicy || (canCheckAnchors && roots.every((r) => r.anchorVerified === true))
  const ok = failed.length === 0 && bundle.entries.length > 0 && !!trusted && allAnchored
  if (!trusted && failed.length === 0 && bundle.entries.length > 0) {
    notes.push("All entries internally consistent; supply --roots for an independent verdict.")
  }
  if (signaturesInvalid.length > 0) {
    notes.push(
      `${signaturesInvalid.length} entr${signaturesInvalid.length === 1 ? "y" : "ies"} carr${
        signaturesInvalid.length === 1 ? "ies" : "y"
      } ES256 proof material that does NOT verify (seq ${signaturesInvalid
        .map((s) => s.seq)
        .join(", ")}). The signature bytes are themselves committed, so this is not bundle tampering — ` +
        "it means the producer anchored a signature that does not check out.",
    )
  }
  const checks = bundle.entries.map((e) => ({
    seq: e.event.seq,
    ...(signatureChecks.get(e.event.seq) ?? uncheckedSignature()),
  }))
  if (opts.requireSignatures)
    for (const check of checks) {
      if (check.status !== "verified" || !check.trusted)
        failed.push({ seq: check.seq, reason: `Required trusted signature: ${check.reason}` })
    }
  return {
    ok: ok && failed.length === 0,
    total: bundle.entries.length,
    contentVerified,
    commitmentOnly,
    failed,
    roots,
    signatures: {
      checks,
      verified: signaturesVerified,
      invalid: signaturesInvalid,
      notCheckable: signaturesNotCheckable,
    },
    notes,
  }
}
