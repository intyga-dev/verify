import crypto from "node:crypto"
import type { ExternalAnchorKeys } from "./ledger-anchor.js"
import {
  type AnchorKeyResolver,
  type AnchorPolicy,
  type SignedAnchor,
  verifyAnchorQuorum,
} from "./ledger-anchor.js"
import { type AuditLeaf, leafHash } from "./ledger-leaf.js"
import { type InclusionProof, verifyInclusionProof } from "./ledger-proof.js"

// The downloadable proof bundle a member exports (GET /api/audit/proof/:seq) and what it means to
// verify one. A verdict is only as strong as the daily root you check against: use a root you
// obtained before and independently of this bundle — one you recorded earlier, or one from the
// published roots file — never one copied out of the bundle itself. (An external anchor cannot hand
// you the root: Rekor stores a hash of the anchor digest and a TSA the digest, neither reveals it.)

// DEWP canonical kind (docs/DEWP.md §6.2). Producers emit this form and verifiers require it; there
// is no vendor-prefixed alias, since no bundle has ever been exported under one.
export const BUNDLE_KIND = "dewp.audit.inclusion-proof"

/** DEWP envelope discriminator and specification version this producer/verifier implements (§6). */
export const DEWP_PROTOCOL = "DEWP"
export const DEWP_VERSION = "1.0"

/**
 * The Application Profile this ledger's canonical preimage uses (DEWP §4.5, reverse-DNS
 * `vendor.profileName.vVersion`). Core fields 0..10 followed by six profile fields
 * (isBillable, tenantId, actorNodeId, subjectNodeId, edgeId, challengeId), with `tenantSeq` last —
 * 18 elements in total, versus the 12-element bare Core.
 *
 * Declaring it on the wire is what lets a verifier REFUSE a preimage layout it does not know, instead
 * of hashing an unfamiliar array with this one's field ordering and reporting a leaf mismatch that
 * looks like tampering.
 */
export const AUDIT_PROFILE = "trust.intyga.audit.v1"

/** DEWP §6.1 algorithm registry — what this implementation commits to. */
export const ALGORITHM_REGISTRY = {
  hashAlgorithm: "SHA-256",
  serialization: "RFC8785-JCS",
  merkleVersion: 1,
  signatureAlgorithms: ["ES256", "WEBAUTHN", "AUTO_APPROVED"],
} as const

export interface AlgorithmRegistry {
  hashAlgorithm: string
  serialization: string
  merkleVersion: number
  signatureAlgorithms?: string[]
}

export interface ProofBundle {
  /** DEWP §6.2 envelope. Absent on bundles exported before the envelope was added. */
  protocol?: string
  kind: typeof BUNDLE_KIND
  /** Spec version. String ("1.0") per §6.2; older exports carried the numeric bundle revision. */
  version: string | number
  /** Canonical-preimage Application Profile (§4.5). Absent ⇒ assumed to be this implementation's. */
  profile?: string
  algorithmRegistry?: AlgorithmRegistry
  exportedAt: string
  event: {
    seq: string
    /** Opaque event identifier (§4.2) — distinct from the numeric ordering counter `seq`. */
    id?: string
    createdAt: string
    type: string
    outcome: string
    detail: string | null
    actorDid: string | null
    subjectDid: string | null
    signerDid: string | null
    signature: string | null
    sigAlg: string | null
    // The full canonical leaf preimage. When present, the verifier can confirm the leaf hash actually
    // corresponds to this event (leaf binding) — without it a bundle can never exceed
    // COMMITMENT_VERIFIED. Omitted for redacted events, whose content is gone by design.
    canonical?: AuditLeaf
  }
  proof: InclusionProof
  /**
   * A SIGNED anchor over this bundle's daily root (DEWP §5.2/§6.2) — `dailyRoot`, `timestamp`,
   * `issuer`, `keyId`, `algorithm`, `signature`. Present only when the root has actually been signed;
   * a mere publication receipt is NOT an anchor and belongs in `anchorRef`.
   */
  anchor?: SignedAnchor
  /** Independently-issued signed anchors over the same daily root, for quorum verification (§5.3). */
  anchors?: SignedAnchor[]
  /** External publication reference for the daily root (transparency-log id, commit hash, receipt). */
  anchorRef?: string | null
  /**
   * Producer claim that a publication receipt exists — COMMITMENT only. The producer writes one for
   * every checkpoint, so this being true says nothing about independence; see `externallyAnchored`.
   */
  anchored?: boolean
  /**
   * Producer claim that a §5.3 external anchor quorum (distinct INDEPENDENT issuers >= the producer's
   * configured requirement) exists for this root. Absent on bundles exported before the field
   * shipped. Display/triage only — independence is established by THIS verifier's own quorum
   * evaluation (`anchorVerified`), never by trusting the flag.
   */
  externallyAnchored?: boolean
  /**
   * The quorum size the producer evaluated that claim against (DEWP §6.2). Absent on bundles exported
   * before it shipped. Still a producer claim: it says what the producer required, not what happened.
   */
  externallyAnchoredRequired?: number
  /**
   * Legacy pre-§6.2 shape, where `anchor` carried the root and publication status rather than a
   * signature. Read for backward compatibility only; new exports use the fields above.
   */
  legacyAnchor?: {
    dailyRoot: string | null
    anchorRef: string | null
    anchored: boolean
  }
  selfVerified?: boolean
  howToVerify?: string
}

export interface CheckResult {
  /** true = passed, false = failed, null = not applicable / could not be evaluated. */
  pass: boolean | null
  detail: string
}

/**
 * The four INDEPENDENT DEWP verification properties (docs/DEWP.md §7.1). They are orthogonal —
 * anchor verification is not a strict superset of signature verification — so a relying party can
 * apply its own policy over them rather than reading only the summary level.
 */
export interface VerificationProperties {
  /** Leaf is committed under the checkpoint root (two-hop inclusion recomputes). */
  commitmentVerified: boolean
  /** commitmentVerified AND the canonical preimage is present and its leaf hash matches. */
  contentVerified: boolean
  /** contentVerified AND the embedded event signature (ES256 over signedPayload) verifies offline. */
  signatureVerified: boolean
  /**
   * The checkpoint root was verified against an ANCHOR QUORUM under the caller's §5.3 policy — DEWP
   * §3 Invariant 7 makes this an if-and-only-if. Supplying a trusted root out of band is weaker
   * provenance, not this property: it is reported by `rootSource`, and leaves this false.
   */
  anchorVerified: boolean
}

/** DEWP summary verification level, derived from the four properties (docs/DEWP.md §7.1). */
export type VerificationLevel =
  | "INVALID"
  | "COMMITMENT_VERIFIED"
  | "CONTENT_VERIFIED"
  | "SIGNATURE_VERIFIED"
  | "FULLY_VERIFIED"

export interface BundleVerification {
  /** Overall verdict. Only true when the caller supplied the root AND every applicable check passed. */
  ok: boolean
  dailyRoot: string | null
  /**
   * Where the root verified against came from. `caller-supplied` means only that: the caller passed
   * it in. This verifier cannot tell a root recorded independently from one copied out of this very
   * bundle, so it never labels a root "independent" — that is the caller's claim to make, and it is
   * only true of a root obtained before and apart from the export (an earlier record, or the
   * published roots file). `self-asserted` is the bundle's own root; `none` means there was none.
   */
  rootSource: "caller-supplied" | "self-asserted" | "none"
  /**
   * Authenticated external witness time per anchor issuer, Unix seconds (Rekor integratedTime, TSA
   * genTime), for every external anchor whose evidence verified — including ones refused by the
   * time bound. Empty when no quorum was evaluated.
   */
  witnessTimes: Record<string, number>
  /** DEWP §7.1 independent properties. */
  properties: VerificationProperties
  /** DEWP §7.1 summary level derived from `properties`. */
  verificationLevel: VerificationLevel
  checks: {
    inclusion: CheckResult // event leaf → block root → daily root recomputes
    rootConsistency: CheckResult // the root inside the proof equals the root we verified against
    leafBinding: CheckResult // leaf hash actually corresponds to the event fields (needs canonical)
    /** Displayed header fields equal the committed preimage — they are otherwise unsigned copies. */
    headerBinding: CheckResult
    /**
     * The producer's external-anchoring CLAIM (`externallyAnchored`), reported for display/triage.
     * It is self-asserted either way — `anchorVerified` is the actual check. `pass: null` on bundles
     * exported before the claim shipped, whose legacy `anchored` flag meant only "publication
     * receipt exists" and must not read as independence.
     */
    anchored: CheckResult
  }
  notes: string[]
}

/**
 * Verify the event's embedded DIV signature (ES256 over `signedPayload`) from the leaf alone. Only
 * ES256 is checkable here: a WEBAUTHN receipt also needs authenticatorData/clientDataJSON, which the
 * audit leaf does not carry, and AUTO_APPROVED has no human signature. Returns false for those.
 */
export function verifyEmbeddedSignature(canonical: AuditLeaf): boolean {
  if (canonical.sigAlg !== "ES256") return false
  if (!canonical.signerPublicKey || !canonical.signature || !canonical.signedPayload) return false
  try {
    const keyObject = crypto.createPublicKey({
      key: Buffer.from(canonical.signerPublicKey, "base64"),
      format: "der",
      type: "spki",
    })
    if (keyObject.asymmetricKeyType !== "ec") return false
    if (keyObject.asymmetricKeyDetails?.namedCurve !== "prime256v1") return false
    const sig = Buffer.from(canonical.signature, "base64")
    const data = Buffer.from(canonical.signedPayload, "utf8")
    const tryEncoding = (dsaEncoding: "der" | "ieee-p1363"): boolean => {
      try {
        return crypto.verify("sha256", data, { key: keyObject, dsaEncoding }, sig)
      } catch {
        return false
      }
    }
    if (sig.length === 64 && tryEncoding("ieee-p1363")) return true
    return tryEncoding("der")
  } catch {
    return false
  }
}

/** Derive the DEWP §7.1 summary level from the four properties and whether a signer was present. */
export function deriveVerificationLevel(p: VerificationProperties, hasSigner: boolean): VerificationLevel {
  if (!p.commitmentVerified) return "INVALID"
  if (!p.contentVerified) return "COMMITMENT_VERIFIED"
  // FULLY_VERIFIED needs anchorVerified plus, for a SIGNED event, signatureVerified. An unsigned
  // event has no signature to require.
  if (p.anchorVerified && (p.signatureVerified || !hasSigner)) return "FULLY_VERIFIED"
  if (p.signatureVerified) return "SIGNATURE_VERIFIED"
  return "CONTENT_VERIFIED"
}

export interface VerifyOptions {
  /**
   * Pinned public keys for EXTERNAL logs (Rekor today). A Rekor anchor carries no DEWP signature —
   * its Signed Entry Timestamp is the attestation — so without the log key it cannot be verified and
   * does not count toward quorum. Supply from Sigstore's TUF root, never from the bundle.
   */
  externalKeys?: ExternalAnchorKeys

  /**
   * The daily root to verify against. Required for `ok`. It is only as independent as its source:
   * a root recorded earlier or taken from the published roots file is; a root copied from this
   * bundle is not, and the verdict labels it `caller-supplied` either way.
   */
  trustedRoot?: string
  /**
   * Signed anchor objects over the daily root (DEWP §5.2). When supplied with `anchorPolicy` and
   * `resolveAnchorKey`, `anchorVerified` reflects a real multi-anchor quorum check (signatures over
   * the 0x03-tagged digest) instead of the weaker "a root was handed to me" signal.
   */
  anchors?: SignedAnchor[]
  anchorPolicy?: AnchorPolicy
  resolveAnchorKey?: AnchorKeyResolver
  /**
   * The checkpoint this proof's root belongs to, as YOU hold it — normally the chain-verified line of
   * the published roots file for that root (DEWP §5.4.1). A single proof carries no checkpoint of its
   * own, so this is the only checkpoint time and chain hash an anchor can be held to: without it an
   * external witness (Rekor, RFC 3161) does not count, because the §5.3 time bound would be measured
   * against the anchor's own producer-chosen `timestamp`. Its `root` stands in for `trustedRoot` when
   * that is absent, and must equal it when both are given; its `entryCount` bounds the proof's leaf
   * counts.
   */
  trustedCheckpoint?: TrustedCheckpoint
}

/**
 * A checkpoint record the CALLER trusts (DEWP §5.4.1 roots-file line). Every field but `root` is
 * optional because a hand-built minimal list may carry only roots; a field that is present is binding.
 */
export interface TrustedCheckpoint {
  root: string
  seqStart?: string | null
  seqEnd?: string | null
  entryCount?: number | null
  anchoredAt?: string | null
  chainHash?: string | null
}

/**
 * Why a proof's leaf counts cannot belong to a checkpoint committing `entryCount` events, or null.
 *
 * `blockLeafCount`/`checkpointLeafCount` arrive inside the proof, so a prover can shrink them: an
 * interior node of a 4-leaf block then verifies as "leaf 0 of a 2-leaf block" — a redacted event that
 * never existed. A checkpoint's entry count is the sum of its blocks' leaf counts, which bounds both.
 */
export function leafCountMismatch(
  proof: InclusionProof,
  entryCount: number | null | undefined,
): string | null {
  if (typeof entryCount !== "number" || !Number.isSafeInteger(entryCount) || entryCount < 0) return null
  const { blockLeafCount, checkpointLeafCount } = proof
  if (!Number.isSafeInteger(blockLeafCount) || !Number.isSafeInteger(checkpointLeafCount)) return null
  if (
    checkpointLeafCount > entryCount ||
    blockLeafCount + checkpointLeafCount - 1 > entryCount ||
    (checkpointLeafCount === 1 && blockLeafCount !== entryCount)
  ) {
    return (
      `proof claims ${blockLeafCount} leaves in its block and ${checkpointLeafCount} block(s) under the ` +
      `checkpoint, which cannot sum to the checkpoint's ${entryCount} committed events`
    )
  }
  return null
}

/** DEWP §7 check 1 / §12: never interpret a future protocol under today's algorithms.
 * Numeric revisions 1 and 2 without a protocol is the explicitly supported legacy export format.
 */
export function supportedEnvelope(bundle: {
  protocol?: string
  version: unknown
  algorithmRegistry?: AlgorithmRegistry
}): boolean {
  if (bundle.protocol != null && bundle.protocol !== "DEWP") return false
  if (
    bundle.version !== "1.0" &&
    !(bundle.protocol == null && (bundle.version === 1 || bundle.version === 2))
  )
    return false
  const a = bundle.algorithmRegistry
  return (
    a === undefined ||
    (a !== null &&
      a.hashAlgorithm === "SHA-256" &&
      a.serialization === "RFC8785-JCS" &&
      a.merkleVersion === 1)
  )
}

export function verifyBundle(bundle: ProofBundle, opts: VerifyOptions = {}): BundleVerification {
  const notes: string[] = []

  // DEWP §6.5: "a compliant producer MUST emit these forms and a compliant verifier MUST reject any
  // other value." A note let a container of one type be fed to the verifier for another and still
  // come back ok — the caller would be reading a verdict produced under semantics the artifact was
  // never built for. `verifyEvidenceBundle` has always rejected; this is the same rule.
  const kindRejected = bundle.kind !== BUNDLE_KIND || !supportedEnvelope(bundle)
  if (kindRejected) {
    notes.push("Refusing bundle kind, protocol, version or algorithm registry (DEWP §7/§12).")
  }

  // An unknown Application Profile means an unknown canonical-array layout (DEWP §4.5). Recomputing
  // the leaf hash under THIS profile's field order would produce a mismatch indistinguishable from
  // tampering, so refuse to attempt leaf binding rather than report a misleading failure.
  const unknownProfile = bundle.profile !== undefined && bundle.profile !== AUDIT_PROFILE

  // The root the bundle asserts about itself. Read from the signed anchor when there is one, then the
  // legacy pre-§6.2 `anchor` object, then the proof's own checkpoint root — all three are equally
  // self-asserted, which is exactly why none of them can produce a trustworthy verdict on their own.
  const selfAssertedRoot =
    bundle.anchor?.dailyRoot ?? bundle.legacyAnchor?.dailyRoot ?? bundle.proof.checkpointRoot ?? null
  const anchorRef = bundle.anchorRef ?? bundle.legacyAnchor?.anchorRef ?? bundle.proof.anchorRef ?? null
  const anchoredFlag = bundle.anchored ?? bundle.legacyAnchor?.anchored ?? bundle.proof.anchored

  // Which root do we verify against, and how much do we trust its provenance?
  let dailyRoot: string | null
  let rootSource: BundleVerification["rootSource"]
  const trustedCheckpoint = opts.trustedCheckpoint
  const callerRoot = opts.trustedRoot || trustedCheckpoint?.root
  // Two caller inputs naming different roots: which one the caller meant is unknowable, so neither wins.
  const checkpointConflict = Boolean(
    opts.trustedRoot && trustedCheckpoint && trustedCheckpoint.root !== opts.trustedRoot,
  )
  if (checkpointConflict) {
    notes.push(
      "The supplied trustedCheckpoint names a different root than trustedRoot — refusing to pick one.",
    )
  }
  if (callerRoot) {
    dailyRoot = callerRoot
    rootSource = "caller-supplied"
  } else if (selfAssertedRoot) {
    dailyRoot = selfAssertedRoot
    rootSource = "self-asserted"
    notes.push(
      "No root supplied — verifying against the root inside the bundle. This proves the bundle is " +
        "internally consistent, NOT that it matches the producer's anchored log. Re-run with a root " +
        "you obtained earlier or from the published roots file for a real verdict.",
    )
  } else {
    dailyRoot = null
    rootSource = "none"
    notes.push("No daily root available (event not yet committed to an anchored checkpoint).")
  }

  // DEWP §17.3: the proof's own leaf counts are bound to the trusted checkpoint's entry count.
  const countMismatch =
    trustedCheckpoint && dailyRoot === trustedCheckpoint.root
      ? leafCountMismatch(bundle.proof, trustedCheckpoint.entryCount)
      : null
  const inclusion: CheckResult =
    dailyRoot === null
      ? { pass: null, detail: "No daily root to verify against." }
      : countMismatch
        ? { pass: false, detail: `${countMismatch} — the proof is not for this checkpoint's tree.` }
        : verifyInclusionProof(bundle.proof, dailyRoot)
          ? {
              pass: true,
              detail: "Event leaf recomputes to the daily root through block and checkpoint.",
            }
          : {
              pass: false,
              detail: "Recomputed root does not match — proof is invalid for this root.",
            }

  const rootConsistency: CheckResult =
    dailyRoot === null
      ? { pass: null, detail: "No daily root to compare." }
      : bundle.proof.checkpointRoot === dailyRoot
        ? {
            pass: true,
            detail: "Proof's checkpoint root equals the verified daily root.",
          }
        : {
            pass: false,
            detail: "Proof's checkpoint root differs from the root being verified against.",
          }

  // The displayed header must BE the committed data, not a caption over it. ProofBundle.event
  // duplicates seq/createdAt/type/outcome/detail/signerDid/signature/sigAlg alongside `canonical`,
  // and only `canonical` is hashed into the leaf. Unchecked, a bundle could show
  // outcome "SUCCESS" over a committed "FAILURE" and still return FULLY_VERIFIED.
  const headerBinding: CheckResult = bundle.event.canonical
    ? (() => {
        const c = bundle.event.canonical
        const e = bundle.event
        const differs = (label: string, shown: unknown, committed: unknown): string | null =>
          shown != null && String(shown) !== String(committed)
            ? `displayed ${label} ("${String(shown)}") does not match the committed value ("${String(committed)}")`
            : null
        const bad =
          differs("seq", e.seq, c.seq) ??
          differs("proof.seq", bundle.proof.seq, c.seq) ??
          differs("createdAt", e.createdAt, c.createdAt) ??
          differs("type", e.type, c.event) ??
          differs("outcome", e.outcome, c.outcome) ??
          differs("detail", e.detail, c.detail) ??
          differs("signerDid", e.signerDid, c.signerDid) ??
          differs("signature", e.signature, c.signature) ??
          differs("sigAlg", e.sigAlg, c.sigAlg)
        return bad === null
          ? { pass: true as const, detail: "Displayed fields match the committed preimage." }
          : {
              pass: false as const,
              detail: `${bad} — the bundle displays something other than what was committed.`,
            }
      })()
    : {
        pass: null,
        detail: "No canonical preimage, so the displayed fields cannot be bound to the commitment.",
      }

  const leafBinding: CheckResult = unknownProfile
    ? {
        pass: null,
        detail:
          `Canonical preimage uses an unknown Application Profile "${bundle.profile}" — this verifier ` +
          `implements "${AUDIT_PROFILE}" and cannot reproduce that layout, so leaf binding was not attempted.`,
      }
    : bundle.event.canonical
      ? leafHash(bundle.event.canonical) === bundle.proof.leaf
        ? { pass: true, detail: "Leaf hash matches the canonical event content." }
        : {
            pass: false,
            detail: "Leaf hash does NOT match the event content — the bundle is inconsistent.",
          }
      : {
          pass: null,
          detail:
            "No canonical event preimage in this bundle, so the leaf can be located in the tree but not " +
            "bound to the displayed fields. (Redacted events omit it by design.)",
        }
  if (unknownProfile) {
    notes.push(
      `Unknown canonical profile "${bundle.profile}" — commitment can still be verified, but the event ` +
        "content cannot be bound to the leaf.",
    )
  }

  // The producer's independence CLAIM. The historic `anchored` flag is commitment-only (the producer
  // writes a publication receipt for every checkpoint, so it is structurally always true) and MUST
  // NOT read as external anchoring — that wiring previously made the CLI print "[PASS] anchored" for
  // roots no third party had ever seen. Only the explicit quorum-derived `externallyAnchored` claim
  // can pass this check, and even then it is reported as a claim: `anchorVerified` is the check.
  const externallyAnchoredClaim = bundle.externallyAnchored ?? bundle.proof.externallyAnchored
  // The quorum size behind the claim. Without it "true" is unreadable — a 1-of-1 deployment and a
  // 2-of-N deployment publish the same boolean — so state it whenever the producer supplies it.
  const claimedRequired = bundle.externallyAnchoredRequired ?? bundle.proof.externallyAnchoredRequired
  const anchored: CheckResult =
    externallyAnchoredClaim === true
      ? {
          pass: true,
          detail:
            `Producer claims a §5.3 external anchor quorum of ${
              claimedRequired ?? "an unstated number of"
            } distinct independent issuer(s) for this root` +
            `${anchorRef ? ` (${anchorRef})` : ""}. Claim only — anchorVerified is the check.`,
        }
      : externallyAnchoredClaim === false
        ? {
            pass: false,
            detail: "Root is committed and self-signed only — the producer claims no external anchor quorum.",
          }
        : {
            pass: null,
            detail:
              "Bundle predates the externallyAnchored claim — external anchoring is unknown from the " +
              `bundle${anchoredFlag ? " (its legacy `anchored` flag means only that a publication receipt exists)" : ""}. ` +
              "Evaluate the signed anchors under your own policy (anchorVerified).",
          }

  // `ok` is the flag callers branch on (`if (!ok) throw`), so it must mean what its doc comment says:
  // every APPLICABLE check passed. Two traps, both previously open:
  //
  //  - `headerBinding` was computed and then left out of this expression, so a bundle displaying
  //    outcome "SUCCESS" over a committed "FAILURE" returned ok:true with headerBinding.pass:false.
  //  - `leafBinding.pass === null` is legitimate ONLY when there is no canonical preimage to bind
  //    (a redacted, commitment-only entry). It must never be accepted because an attacker-supplied
  //    `profile` made this verifier skip the check on content the bundle did ship — that is a check
  //    the prover can switch off. DEWP §4.5 requires reporting contentVerified:false and continuing
  //    to evaluate commitmentVerified, which we do; it does not make the bundle ok.
  const contentBoundWhenPresent = bundle.event.canonical ? leafBinding.pass === true : true
  const ok =
    !kindRejected &&
    !checkpointConflict &&
    rootSource === "caller-supplied" &&
    inclusion.pass === true &&
    rootConsistency.pass === true &&
    leafBinding.pass !== false &&
    headerBinding.pass !== false &&
    contentBoundWhenPresent

  // DEWP §7.1 independent properties.
  const commitmentVerified = inclusion.pass === true && rootConsistency.pass === true
  const contentVerified = commitmentVerified && leafBinding.pass === true && headerBinding.pass !== false
  const hasSigner = Boolean(bundle.event.canonical?.signature && bundle.event.canonical?.signerPublicKey)
  const signatureVerified =
    contentVerified && bundle.event.canonical ? verifyEmbeddedSignature(bundle.event.canonical) : false
  // Anchor verification (DEWP §5.3). If signed anchors + a policy are supplied, require a real quorum
  // over the daily root. Otherwise fall back to the weaker signal: the checkpoint root was handed to
  // us by the caller (not the bundle's own self-asserted flag).
  //
  // Anchors carried INSIDE the bundle are used only when the caller supplied a policy and a key
  // resolver — the signatures are then checked against keys the VERIFIER trusts, so a bundle cannot
  // vouch for itself by shipping anchors it signed with its own key.
  const candidateAnchors = opts.anchors ?? [
    ...(bundle.anchors ?? []),
    ...(bundle.anchor ? [bundle.anchor] : []),
  ]
  // Bundle-carried anchors may COUNT toward quorum — they still have to verify under a key the
  // caller trusts, so a bundle cannot vouch for itself. They may not, however, trigger the fatal
  // DIVERGENCE verdict. A single proof carries no checkpoint position of its own to hold an anchor's
  // signed seq range against, so a genuine anchor from another day is indistinguishable here from a
  // conflicting one, and appending a real, publicly available anchor would be enough to make a valid
  // proof read as tampering. Only anchors the caller fetched itself, per checkpoint, can establish
  // divergence.
  const divergenceAnchors = opts.anchors ?? []
  let anchorVerified: boolean
  let witnessTimes: Record<string, number> = {}
  // Gated on the CALLER having asked (policy + resolver), never on candidates existing: a bundle
  // shipped with its anchors stripped must evaluate to "quorum not met (0/N)" under a supplied
  // policy — falling back to the weaker caller-supplied-root signal there would let the prover switch
  // off the very check the caller configured.
  if (opts.anchorPolicy && (opts.resolveAnchorKey || opts.externalKeys) && dailyRoot) {
    const q = verifyAnchorQuorum(
      candidateAnchors,
      dailyRoot,
      opts.anchorPolicy,
      opts.resolveAnchorKey ?? (() => null),
      {
        divergenceAnchors,
        externalKeys: opts.externalKeys,
        // A single proof carries no checkpoint, so the only position and time an anchor can be held
        // to is the caller's own record. Naming an EMPTY checkpoint when there is none is deliberate:
        // it keeps an external witness from being bounded by the anchor's producer-chosen timestamp.
        checkpoint: trustedCheckpoint
          ? {
              seqStart: trustedCheckpoint.seqStart,
              seqEnd: trustedCheckpoint.seqEnd,
              chainHash: trustedCheckpoint.chainHash,
              anchoredAt: trustedCheckpoint.anchoredAt,
            }
          : {},
      },
    )
    anchorVerified = commitmentVerified && q.ok
    witnessTimes = q.witnessTimes
    if (q.divergence) {
      notes.push(`ANCHOR DIVERGENCE — ${q.reason}. Treating as INVALID.`)
    } else if (!q.ok && q.reason) {
      notes.push(q.reason)
    } else if (q.ok) {
      notes.push(`Anchor quorum met: ${q.verifiedIssuers.length} independent issuer(s) signed this root.`)
    }
    // Report TSA evidence that could not be verified under the caller's configuration.
    if (q.note) notes.push(q.note)
    // A divergent anchor is fatal regardless of inclusion.
    if (q.divergence) {
      return {
        ok: false,
        dailyRoot,
        rootSource,
        witnessTimes,
        properties: {
          commitmentVerified,
          contentVerified,
          signatureVerified,
          anchorVerified: false,
        },
        verificationLevel: "INVALID",
        checks: { inclusion, rootConsistency, leafBinding, headerBinding, anchored },
        notes,
      }
    }
  } else {
    // DEWP §3 Invariant 7 / §7.1: anchorVerified holds IF AND ONLY IF the root was verified against
    // an anchor quorum. Being handed a root out of band is not that check — no anchor signature was
    // examined — so it cannot make this property true, and FULLY_VERIFIED must stay out of reach.
    // `rootSource: "caller-supplied"` already reports the weaker provenance signal on its own.
    anchorVerified = false
    if (opts.anchorPolicy) {
      notes.push(
        "Anchor quorum could not be evaluated: a daily root and resolveAnchorKey or externalKeys are required.",
      )
    } else if (commitmentVerified && rootSource === "caller-supplied") {
      notes.push(
        "A caller-supplied root was used, but no anchor policy was given, so no anchor " +
          "signature or quorum was evaluated (DEWP §5.2/§5.3): anchorVerified stays false and " +
          "FULLY_VERIFIED is not reachable. Supply anchors + anchorPolicy + resolveAnchorKey for a " +
          "real quorum verdict.",
      )
    }
  }
  const properties: VerificationProperties = {
    commitmentVerified,
    contentVerified,
    signatureVerified,
    anchorVerified,
  }
  // A refused `kind` is not a partially-verified bundle: the container was never the one these
  // semantics apply to, so it reports INVALID rather than a level derived from checks we should not
  // have run at all.
  const verificationLevel = kindRejected ? "INVALID" : deriveVerificationLevel(properties, hasSigner)

  return {
    // A configured policy is an applicable check even when its anchors or resolver are missing.
    ok: ok && (!opts.anchorPolicy || anchorVerified),
    dailyRoot,
    rootSource,
    witnessTimes,
    properties,
    verificationLevel,
    checks: { inclusion, rootConsistency, leafBinding, headerBinding, anchored },
    notes,
  }
}
