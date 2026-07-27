import crypto from "node:crypto"
import {
  type AnchorKeyResolver,
  type AnchorPolicy,
  type SignedAnchor,
  verifyAnchorQuorum,
} from "./ledger-anchor.js"
import { type AuditLeaf, leafHash } from "./ledger-leaf.js"
import { type InclusionProof, verifyInclusionProof } from "./ledger-proof.js"

// The downloadable proof bundle a member exports (GET /api/audit/proof/:seq) and what it means to
// verify one. A verdict is only as strong as the daily root you check against: obtain that root from
// the EXTERNAL anchor (anchorRef), never from the bundle itself.

// DEWP canonical kind (docs/DEWP.md §6.2). The legacy `sakra.audit.*` form is accepted as an alias
// on read (§6.5) so previously-exported bundles still verify.
export const BUNDLE_KIND = "dewp.audit.inclusion-proof"
export const BUNDLE_KIND_ALIASES = ["sakra.audit.inclusion-proof"] as const

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
export const AUDIT_PROFILE = "trust.sakra.audit.v1"

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
  kind: typeof BUNDLE_KIND | (typeof BUNDLE_KIND_ALIASES)[number]
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
  /** Whether the daily root was published to the external anchoring medium. */
  anchored?: boolean
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
  /** The checkpoint root was validated against an independently-supplied (external anchor) root. */
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
  /** Overall verdict. Only true when the root was supplied independently AND every applicable check passed. */
  ok: boolean
  dailyRoot: string | null
  rootSource: "independent" | "self-asserted" | "none"
  /** DEWP §7.1 independent properties. */
  properties: VerificationProperties
  /** DEWP §7.1 summary level derived from `properties`. */
  verificationLevel: VerificationLevel
  checks: {
    inclusion: CheckResult // event leaf → block root → daily root recomputes
    rootConsistency: CheckResult // the root inside the proof equals the root we verified against
    leafBinding: CheckResult // leaf hash actually corresponds to the event fields (needs canonical)
    anchored: CheckResult // the daily root is claimed to be externally anchored
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
  /** The daily root obtained from the external anchor. Required for a trustworthy verdict. */
  trustedRoot?: string
  /**
   * Signed anchor objects over the daily root (DEWP §5.2). When supplied with `anchorPolicy` and
   * `resolveAnchorKey`, `anchorVerified` reflects a real multi-anchor quorum check (signatures over
   * the 0x03-tagged digest) instead of the weaker "an independent root was handed to me" signal.
   */
  anchors?: SignedAnchor[]
  anchorPolicy?: AnchorPolicy
  resolveAnchorKey?: AnchorKeyResolver
}

export function verifyBundle(bundle: ProofBundle, opts: VerifyOptions = {}): BundleVerification {
  const notes: string[] = []

  if (bundle.kind !== BUNDLE_KIND && !BUNDLE_KIND_ALIASES.includes(bundle.kind as never)) {
    notes.push(`Unexpected bundle kind "${bundle.kind}" (expected "${BUNDLE_KIND}").`)
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
  if (opts.trustedRoot) {
    dailyRoot = opts.trustedRoot
    rootSource = "independent"
  } else if (selfAssertedRoot) {
    dailyRoot = selfAssertedRoot
    rootSource = "self-asserted"
    notes.push(
      "No independent root supplied — verifying against the root inside the bundle. This proves the " +
        "bundle is internally consistent, NOT that it matches SÄKRA's anchored log. Re-run with the " +
        "root from the external anchor (anchorRef) for a real verdict.",
    )
  } else {
    dailyRoot = null
    rootSource = "none"
    notes.push("No daily root available (event not yet committed to an anchored checkpoint).")
  }

  const inclusion: CheckResult =
    dailyRoot === null
      ? { pass: null, detail: "No daily root to verify against." }
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

  const anchored: CheckResult =
    anchoredFlag && bundle.proof.anchored
      ? {
          pass: true,
          detail: `Daily root anchored externally${anchorRef ? ` (${anchorRef})` : ""}.`,
        }
      : { pass: false, detail: "Daily root not yet externally anchored." }

  const ok =
    rootSource === "independent" &&
    inclusion.pass === true &&
    rootConsistency.pass === true &&
    leafBinding.pass !== false

  // DEWP §7.1 independent properties.
  const commitmentVerified = inclusion.pass === true && rootConsistency.pass === true
  const contentVerified = commitmentVerified && leafBinding.pass === true
  const hasSigner = Boolean(bundle.event.canonical?.signature && bundle.event.canonical?.signerPublicKey)
  const signatureVerified =
    contentVerified && bundle.event.canonical ? verifyEmbeddedSignature(bundle.event.canonical) : false
  // Anchor verification (DEWP §5.3). If signed anchors + a policy are supplied, require a real quorum
  // over the daily root. Otherwise fall back to the weaker signal: the checkpoint root was handed to
  // us from an independent external source (not the bundle's own self-asserted flag).
  //
  // Anchors carried INSIDE the bundle are used only when the caller supplied a policy and a key
  // resolver — the signatures are then checked against keys the VERIFIER trusts, so a bundle cannot
  // vouch for itself by shipping anchors it signed with its own key.
  const candidateAnchors = opts.anchors ?? [
    ...(bundle.anchors ?? []),
    ...(bundle.anchor ? [bundle.anchor] : []),
  ]
  let anchorVerified: boolean
  if (candidateAnchors.length > 0 && opts.anchorPolicy && opts.resolveAnchorKey && dailyRoot) {
    const q = verifyAnchorQuorum(candidateAnchors, dailyRoot, opts.anchorPolicy, opts.resolveAnchorKey)
    anchorVerified = commitmentVerified && q.ok
    if (q.divergence) {
      notes.push(`ANCHOR DIVERGENCE — ${q.reason}. Treating as INVALID.`)
    } else if (!q.ok && q.reason) {
      notes.push(q.reason)
    } else if (q.ok) {
      notes.push(`Anchor quorum met: ${q.verifiedIssuers.length} independent issuer(s) signed this root.`)
    }
    // A divergent anchor is fatal regardless of inclusion.
    if (q.divergence) {
      return {
        ok: false,
        dailyRoot,
        rootSource,
        properties: {
          commitmentVerified,
          contentVerified,
          signatureVerified,
          anchorVerified: false,
        },
        verificationLevel: "INVALID",
        checks: { inclusion, rootConsistency, leafBinding, anchored },
        notes,
      }
    }
  } else {
    anchorVerified = commitmentVerified && rootSource === "independent"
  }
  const properties: VerificationProperties = {
    commitmentVerified,
    contentVerified,
    signatureVerified,
    anchorVerified,
  }
  const verificationLevel = deriveVerificationLevel(properties, hasSigner)

  return {
    ok,
    dailyRoot,
    rootSource,
    properties,
    verificationLevel,
    checks: { inclusion, rootConsistency, leafBinding, anchored },
    notes,
  }
}
