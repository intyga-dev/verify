import crypto from "node:crypto"

// Checkpoint continuity chain (DEWP §5.4) — the verification half. Zero deps beyond node:crypto.
//
// An inclusion proof says "this event is under daily root R". It says nothing about whether the
// SEQUENCE of daily roots was rewritten — a published roots file with one day silently replaced or
// removed is internally consistent and verifies fine. The chain closes that hole: each checkpoint
// commits to its predecessor under the 0x04 domain tag, so the sequence can be extended but not
// edited or reordered without breaking every link after the edit.
//
// SCOPE — read this before quoting it as a consistency proof. This is NOT an RFC 6962 consistency
// proof. It proves the root SEQUENCE is unrewritten. It does not prove the leaves under an earlier
// root are unchanged; that comes from each root being independently anchored to an external log
// (Rekor / RFC 3161) that the producer cannot edit. Chain + external anchors together are what make
// history-rewriting detectable — neither alone is sufficient.
//
// MUST stay byte-identical to the producer in @intyga/db (chain.ts).

const CHAIN_TAG = 0x04

/** The genesis predecessor. No real chain hash can collide: those are always 64 hex characters. */
export const GENESIS_PREV_CHAIN_HASH = ""

/** One line of a published `roots.jsonl` (v2), as far as chain verification is concerned. */
export interface RootsChainEntry {
  seqStart: string
  seqEnd: string
  entryCount: number
  root: string
  anchoredAt: string
  prevChainHash?: string
  chainHash?: string
}

export interface ChainInput {
  prevChainHash: string
  root: string
  seqStart: string
  seqEnd: string
  entryCount: number
  anchoredAt: string
}

/**
 * The canonical chain preimage: RFC 8785 JCS of a 6-element array of STRINGS. Every element is
 * stringified — including counts — so JCS reduces to plain `JSON.stringify` and no verifier has to
 * implement RFC 8785 number canonicalization. `anchorPreimage` makes the same trade.
 */
export function chainPreimage(c: ChainInput): string {
  return JSON.stringify([c.prevChainHash, c.root, c.seqStart, c.seqEnd, String(c.entryCount), c.anchoredAt])
}

/** The chain hash: `SHA-256(0x04 || UTF8(chainPreimage))`, hex. */
export function chainHash(c: ChainInput): string {
  return crypto
    .createHash("sha256")
    .update(Buffer.from([CHAIN_TAG]))
    .update(Buffer.from(chainPreimage(c), "utf8"))
    .digest("hex")
}

export interface ChainVerification {
  ok: boolean
  /** Entries whose chain hash recomputed AND linked to their predecessor. */
  verifiedCount: number
  /** Index of the first entry that failed, or -1 when everything verified. */
  brokenAt: number
  /**
   * True when the entries carry no chain fields at all — a pre-chain (v1) roots file. Reported
   * separately from a broken chain because "this file is older than the chain" and "someone edited
   * this file" are completely different findings and must never be conflated in an alert.
   */
  unchained: boolean
  reason?: string
}

function fail(brokenAt: number, reason: string, verifiedCount: number): ChainVerification {
  return { ok: false, verifiedCount, brokenAt, unchained: false, reason }
}

/**
 * Verify a published roots sequence: recompute every chain hash, check each entry links to its
 * predecessor, and check the covered seq ranges advance without overlapping.
 *
 * On global seq: `AuditLog.seq` is a Postgres `autoincrement()` sequence, and Postgres sequences are
 * NON-transactional — a rolled-back audit insert burns its value permanently. Global seq therefore
 * has legitimate holes in healthy operation, which is exactly why DEWP uses the transactionally
 * allocated per-tenant `tenantSeq` for gapless completeness and calls global `seq` "ordering only".
 * So this checks `seqStart(N+1) > seqEnd(N)` (monotonic, non-overlapping) and NOT `== seqEnd(N) + 1`:
 * the strict form would fire on ordinary rollbacks and train operators to ignore the alarm. Deletion
 * of an entry is caught by the chain link, which is the mechanism that actually detects it.
 *
 * `entries` MUST be in published order (ascending `seqEnd`), which is the order they appear in the file.
 */
export function verifyRootsChain(entries: RootsChainEntry[]): ChainVerification {
  if (entries.length === 0) {
    return { ok: true, verifiedCount: 0, brokenAt: -1, unchained: false }
  }

  const chained = entries.filter((e) => e.chainHash !== undefined)
  if (chained.length === 0) {
    return {
      ok: false,
      verifiedCount: 0,
      brokenAt: -1,
      unchained: true,
      reason: "roots file carries no chain hashes (pre-DEWP-5.4 v1 file); continuity cannot be checked",
    }
  }
  if (chained.length !== entries.length) {
    // A partially chained file means someone spliced old and new lines together. Refuse to guess
    // which half is authentic.
    return fail(
      entries.findIndex((e) => e.chainHash === undefined),
      "roots file mixes chained and unchained entries",
      0,
    )
  }

  let verifiedCount = 0
  let prev: RootsChainEntry | undefined

  for (let i = 0; i < entries.length; i++) {
    const e = entries[i]
    if (e === undefined) return fail(i, "roots entry missing", verifiedCount)

    const expectedPrev = prev === undefined ? GENESIS_PREV_CHAIN_HASH : (prev.chainHash ?? "")
    const declaredPrev = e.prevChainHash ?? GENESIS_PREV_CHAIN_HASH
    if (declaredPrev !== expectedPrev) {
      return fail(
        i,
        `chain link broken at seqEnd=${e.seqEnd}: prevChainHash ${declaredPrev || "(genesis)"} does not match predecessor ${expectedPrev || "(genesis)"}`,
        verifiedCount,
      )
    }

    const recomputed = chainHash({
      prevChainHash: declaredPrev,
      root: e.root,
      seqStart: e.seqStart,
      seqEnd: e.seqEnd,
      entryCount: e.entryCount,
      anchoredAt: e.anchoredAt,
    })
    if (recomputed !== e.chainHash) {
      return fail(
        i,
        `chain hash mismatch at seqEnd=${e.seqEnd}: recomputed ${recomputed}, file says ${e.chainHash}`,
        verifiedCount,
      )
    }

    if (prev !== undefined) {
      let prevEnd: bigint
      let thisStart: bigint
      let thisEnd: bigint
      try {
        prevEnd = BigInt(prev.seqEnd)
        thisStart = BigInt(e.seqStart)
        thisEnd = BigInt(e.seqEnd)
      } catch {
        return fail(i, `non-integer seq range at index ${i}`, verifiedCount)
      }
      if (thisStart <= prevEnd) {
        return fail(
          i,
          `seq ranges overlap or regress: entry starts at ${thisStart} but predecessor ended at ${prevEnd}`,
          verifiedCount,
        )
      }
      if (thisEnd < thisStart) {
        return fail(i, `seq range inverted: seqStart=${thisStart} > seqEnd=${thisEnd}`, verifiedCount)
      }
    }

    verifiedCount++
    prev = e
  }

  return { ok: true, verifiedCount, brokenAt: -1, unchained: false }
}
