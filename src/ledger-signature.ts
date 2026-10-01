import { verifyWebAuthnWitness } from "./index.js"
import type { AuditLeaf } from "./ledger-leaf.js"
import { verifyEmbeddedSignature } from "./ledger-bundle.js"

/** Caller-owned identity/key mapping. WebAuthn keys use base64 COSE_Key; ES256 keys use SPKI. */
export interface AuditSignaturePolicy {
  trustedSigners: Record<string, string[]>
  expectedOrigin?: string
  expectedRpId?: string
}
export interface AuditSignatureCheck {
  status: "verified" | "invalid" | "not_checked" | "not_applicable"
  reason: string
  /** True only when the signature verified under a caller-provisioned key for this signer DID. */
  trusted: boolean
}
export const uncheckedSignature = (): AuditSignatureCheck => ({
  status: "not_checked",
  reason: "Content not verified or unavailable.",
  trusted: false,
})

/** Signature over the committed payload only — never a quorum, authorization or hardware verdict. */
export function verifyAuditSignature(c: AuditLeaf, policy?: AuditSignaturePolicy): AuditSignatureCheck {
  const result = (
    status: AuditSignatureCheck["status"],
    reason: string,
    trusted = false,
  ): AuditSignatureCheck => ({ status, reason, trusted })
  if (!c.sigAlg && (c.signature || c.signedPayload || c.signerPublicKey))
    return result("not_checked", "Signature algorithm is missing.")
  if (!c.sigAlg || c.sigAlg === "AUTO_APPROVED")
    return result("not_applicable", "No human signature is declared.")
  if (c.sigAlg !== "ES256" && c.sigAlg !== "WEBAUTHN")
    return result("not_checked", "Unsupported signature algorithm.")
  if (!c.signature || !c.signedPayload)
    return result("not_checked", "Signature or signed payload is missing.")
  // Preserve the legacy ES256 mathematical check, but never mistake an embedded key for trust.
  if (!policy && c.sigAlg === "ES256") {
    if (!c.signerPublicKey) return result("not_checked", "Signer public key is missing.")
    return verifyEmbeddedSignature(c)
      ? result("verified", "Signature valid under embedded key; signer identity is not established.")
      : result("invalid", "Signature does not verify.")
  }
  const keys =
    c.signerDid && policy?.trustedSigners && Object.hasOwn(policy.trustedSigners, c.signerDid)
      ? policy.trustedSigners[c.signerDid]
      : undefined
  if (!Array.isArray(keys) || keys.length === 0 || !keys.every((k) => typeof k === "string" && k.length > 0))
    return result("not_checked", "No caller-trusted key for this signer.")
  if (c.sigAlg === "WEBAUTHN" && (!policy?.expectedOrigin || !policy.expectedRpId))
    return result("not_checked", "Caller-selected WebAuthn origin and RP ID are required.")
  const m = c.metadata && typeof c.metadata === "object" ? (c.metadata as Record<string, unknown>) : {}
  const w = m.webauthn && typeof m.webauthn === "object" ? (m.webauthn as Record<string, unknown>) : {}
  if (
    c.sigAlg === "WEBAUTHN" &&
    (typeof w.authenticatorData !== "string" ||
      !w.authenticatorData ||
      typeof w.clientDataJSON !== "string" ||
      !w.clientDataJSON)
  )
    return result("not_checked", "WebAuthn authenticatorData or clientDataJSON is missing.")
  for (const key of keys) {
    const valid =
      c.sigAlg === "ES256"
        ? verifyEmbeddedSignature({ ...c, signerPublicKey: key })
        : Buffer.from(key, "base64")[0] !== 0x30 &&
          verifyWebAuthnWitness(
            {
              signedPayload: c.signedPayload,
              signature: c.signature,
              publicKey: key,
              authenticatorData: w.authenticatorData as string,
              clientDataJSON: w.clientDataJSON as string,
            },
            {
              expectedOrigin: policy?.expectedOrigin ?? "",
              expectedRpId: policy?.expectedRpId ?? "",
              requireUserVerification: true,
            },
          ).ok
    if (valid) return result("verified", "Signature valid under caller-trusted signer key.", true)
  }
  return result("invalid", "Signature or WebAuthn assertion does not verify under caller trust.")
}
