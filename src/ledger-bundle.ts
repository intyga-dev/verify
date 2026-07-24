import { type AuditLeaf, leafHash } from "./ledger-leaf.js"
import { type InclusionProof, verifyInclusionProof } from "./ledger-proof.js"

// The downloadable proof bundle a member exports (GET /api/audit/proof/:seq) and what it means to
// verify one. A verdict is only as strong as the daily root you check against: obtain that root from
// the EXTERNAL anchor (anchorRef), never from the bundle itself.

export const BUNDLE_KIND = "sakra.audit.inclusion-proof"

export interface ProofBundle {
  kind: typeof BUNDLE_KIND
  version: number
  exportedAt: string
  event: {
    seq: string
    createdAt: string
    type: string
    outcome: string
    detail: string | null
    actorDid: string | null
    subjectDid: string | null
    signerDid: string | null
    signature: string | null
    sigAlg: string | null
    // v2+: the full canonical leaf preimage. When present, the verifier can confirm the leaf hash
    // actually corresponds to this event (leaf binding). v1 bundles omit this — see SPEC "Leaf binding".
    canonical?: AuditLeaf
  }
  proof: InclusionProof
  anchor: {
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

export interface BundleVerification {
  /** Overall verdict. Only true when the root was supplied independently AND every applicable check passed. */
  ok: boolean
  dailyRoot: string | null
  rootSource: "independent" | "self-asserted" | "none"
  checks: {
    inclusion: CheckResult // event leaf → block root → daily root recomputes
    rootConsistency: CheckResult // the root inside the proof equals the root we verified against
    leafBinding: CheckResult // leaf hash actually corresponds to the event fields (needs canonical)
    anchored: CheckResult // the daily root is claimed to be externally anchored
  }
  notes: string[]
}

export interface VerifyOptions {
  /** The daily root obtained from the external anchor. Required for a trustworthy verdict. */
  trustedRoot?: string
}

export function verifyBundle(bundle: ProofBundle, opts: VerifyOptions = {}): BundleVerification {
  const notes: string[] = []

  if (bundle.kind !== BUNDLE_KIND) {
    notes.push(`Unexpected bundle kind "${bundle.kind}" (expected "${BUNDLE_KIND}").`)
  }

  // Which root do we verify against, and how much do we trust its provenance?
  let dailyRoot: string | null
  let rootSource: BundleVerification["rootSource"]
  if (opts.trustedRoot) {
    dailyRoot = opts.trustedRoot
    rootSource = "independent"
  } else if (bundle.anchor.dailyRoot) {
    dailyRoot = bundle.anchor.dailyRoot
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

  const leafBinding: CheckResult = bundle.event.canonical
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
          "bound to the displayed fields. (v1 bundles omit it — see SPEC 'Leaf binding'.)",
      }

  const anchored: CheckResult =
    bundle.anchor.anchored && bundle.proof.anchored
      ? {
          pass: true,
          detail: `Daily root anchored externally${bundle.anchor.anchorRef ? ` (${bundle.anchor.anchorRef})` : ""}.`,
        }
      : { pass: false, detail: "Daily root not yet externally anchored." }

  const ok =
    rootSource === "independent" &&
    inclusion.pass === true &&
    rootConsistency.pass === true &&
    leafBinding.pass !== false

  return {
    ok,
    dailyRoot,
    rootSource,
    checks: { inclusion, rootConsistency, leafBinding, anchored },
    notes,
  }
}
