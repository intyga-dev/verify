import { spawn, spawnSync } from "node:child_process"
import { createHash } from "node:crypto"
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { isAbsolute, join, resolve } from "node:path"
import { anchorDigest, isWellFormedAnchor, type SignedAnchor } from "./ledger-anchor.js"

/** Caller-owned TSA trust. Never populate this from an evidence bundle. Requires OpenSSL 3. */
export interface Rfc3161Trust {
  caPem: string
  /** SHA-256 of the DER signer certificate, pinned specifically to this issuer. */
  signerCertificateSha256: string
  /** Explicit choice: check caller-supplied offline CRLs, or make no revocation assertion. */
  revocation: "crl" | "unchecked"
  crlPem?: string
  untrustedPem?: string
  /** Certificate/CRL evaluation time, Unix seconds. Defaults to current time rounded up to the next second. */
  verificationTime?: number
  opensslPath?: string
}
export interface Rfc3161Verification {
  ok: boolean
  reason?: string
  /** Authenticated TSA time, Unix seconds (fractional seconds are discarded). */
  genTime?: number
}
const LIMIT = 1024 * 1024
const FAILURE = "RFC 3161 token could not be verified under the supplied TSA trust and time policy"

// Only framing and TSTInfo time are read here. CMS, ESSCertID, signature, imprint, EKU and X.509
// validation belong to OpenSSL; this is deliberately not a second cryptographic ASN.1 stack.
function field(b: Buffer, offset: number): { tag: number; start: number; end: number } {
  const tag = b[offset],
    first = b[offset + 1]
  if (tag === undefined || first === undefined) throw new Error(FAILURE)
  let start = offset + 2,
    length = first
  if (first >= 128) {
    const n = first & 127
    if (n === 0 || n > 4 || b[start] === 0 || start + n > b.length) throw new Error(FAILURE)
    length = 0
    for (let i = 0; i < n; i++) {
      const byte = b[start + i]
      if (byte === undefined) throw new Error(FAILURE)
      length = length * 256 + byte
    }
    if (length < 128) throw new Error(FAILURE)
    start += n
  }
  if (start + length > b.length) throw new Error(FAILURE)
  return { tag, start, end: start + length }
}
function sequence(b: Buffer): Buffer {
  const f = field(b, 0)
  if (f.tag !== 0x30 || f.end !== b.length) throw new Error(FAILURE)
  return b.subarray(f.start, f.end)
}
function children(b: Buffer): { tag: number; value: Buffer }[] {
  const out: { tag: number; value: Buffer }[] = []
  for (let offset = 0; offset < b.length; ) {
    const f = field(b, offset)
    if (out.length >= 8) throw new Error(FAILURE)
    out.push({ tag: f.tag, value: b.subarray(f.start, f.end) })
    offset = f.end
  }
  return out
}
function cmsDigest(token: Buffer): void {
  const algorithm = (b: Buffer): string => {
    const a = children(b)
    if (a[0]?.tag !== 6 || a.length > 2 || (a[1] && (a[1].tag !== 5 || a[1].value.length !== 0)))
      throw new Error(FAILURE)
    const oid = a[0].value.toString("hex")
    if (!["608648016503040201", "608648016503040202", "608648016503040203"].includes(oid))
      throw new Error(FAILURE)
    return oid
  }
  const content = children(sequence(token))
  if (
    content.length !== 2 ||
    content[0]?.tag !== 6 ||
    content[0].value.toString("hex") !== "2a864886f70d010702" ||
    content[1]?.tag !== 0xa0
  )
    throw new Error(FAILURE)
  const data = children(sequence(content[1].value))
  if (data[0]?.tag !== 2 || data[1]?.tag !== 0x31 || data[2]?.tag !== 0x30) throw new Error(FAILURE)
  const declared = children(data[1].value)
  if (declared.length !== 1 || declared[0]?.tag !== 0x30) throw new Error(FAILURE)
  const digest = algorithm(declared[0].value)
  let i = 3
  if (data[i]?.tag === 0xa0) i++
  if (data[i]?.tag === 0xa1) i++
  const signerInfos = data[i]
  if (data.length !== i + 1 || signerInfos?.tag !== 0x31) throw new Error(FAILURE)
  const signers = children(signerInfos.value)
  if (signers.length !== 1 || signers[0]?.tag !== 0x30) throw new Error(FAILURE)
  const signer = children(signers[0].value)
  if (
    signer[0]?.tag !== 2 ||
    ![0x30, 0x80].includes(signer[1]?.tag ?? -1) ||
    signer[2]?.tag !== 0x30 ||
    algorithm(signer[2].value) !== digest
  )
    throw new Error(FAILURE)
}
function timestamp(info: Buffer, now: number): number {
  const b = sequence(info)
  let offset = 0
  for (const tag of [2, 6, 0x30, 2]) {
    const f = field(b, offset)
    if (f.tag !== tag) throw new Error(FAILURE)
    if (offset === 0 && (f.end - f.start !== 1 || b[f.start] !== 1)) throw new Error(FAILURE)
    offset = f.end
  }
  const f = field(b, offset)
  if (f.tag !== 0x18) throw new Error(FAILURE)
  const t = b.subarray(f.start, f.end).toString("utf8")
  if (!/^\d{14}(?:\.\d*[1-9])?Z$/.test(t)) throw new Error(FAILURE)
  const iso = `${t.slice(0, 4)}-${t.slice(4, 6)}-${t.slice(6, 8)}T${t.slice(8, 10)}:${t.slice(10, 12)}:${t.slice(12, 14)}.000Z`
  const d = new Date(iso),
    seconds = d.getTime() / 1000
  if (
    !Number.isFinite(seconds) ||
    d.toISOString() !== iso ||
    seconds < 0 ||
    seconds > now ||
    (t.includes(".") && seconds === now)
  )
    throw new Error(FAILURE)
  return seconds
}
function boundedText(value: unknown, required = false): value is string | undefined {
  return value === undefined
    ? !required
    : typeof value === "string" &&
        Buffer.byteLength(value, "utf8") <= LIMIT &&
        (!required || value.length > 0)
}

/** Offline RFC 3161 verification. No shell, downloads, OS trust store, or implicit TSA trust. */
export function verifyRfc3161Anchor(anchor: SignedAnchor, trust: Rfc3161Trust): Rfc3161Verification {
  try {
    if (
      anchor.kind !== "RFC3161" ||
      !isWellFormedAnchor(anchor) ||
      !["ES256", "Ed25519", "RSA-PSS"].includes(anchor.algorithm) ||
      typeof anchor.issuer !== "string" ||
      typeof anchor.timestamp !== "string"
    )
      return { ok: false, reason: FAILURE }
    return verifyRfc3161Timestamp(anchor.evidence, anchorDigest(anchor), trust)
  } catch {
    return { ok: false, reason: FAILURE }
  }
}

/** Producer helper: validate a token against the requested SHA-256 imprint and optional original
 * DER request (including its nonce). Trust and request must come from the caller, not the token. */
interface OpenSslCommand {
  executable: string
  args: string[]
  cwd: string
  env: NodeJS.ProcessEnv
}
function runSync(command: OpenSslCommand): boolean {
  const r = spawnSync(command.executable, command.args, {
    cwd: command.cwd,
    env: command.env,
    timeout: 5000,
    killSignal: "SIGKILL",
    stdio: "ignore",
  })
  return !r.error && r.status === 0
}
function runAsync(command: OpenSslCommand): Promise<boolean> {
  return new Promise((resolveResult) => {
    const child = spawn(command.executable, command.args, {
      cwd: command.cwd,
      env: command.env,
      stdio: "ignore",
    })
    let failed = false
    const timer = setTimeout(() => {
      failed = true
      child.kill("SIGKILL")
    }, 5000)
    child.on("error", () => {
      failed = true
    })
    // close follows error or exit and ensures the child has been reaped before temp cleanup.
    child.on("close", (code) => {
      clearTimeout(timer)
      resolveResult(!failed && code === 0)
    })
  })
}

export function verifyRfc3161Timestamp(
  evidence: string | null | undefined,
  digest: Uint8Array,
  trust: Rfc3161Trust,
  request?: Uint8Array,
): Rfc3161Verification {
  const checks = timestampChecks(evidence, digest, trust, request)
  try {
    let next = checks.next()
    while (!next.done) {
      if (!runSync(next.value)) return { ok: false, reason: FAILURE }
      next = checks.next()
    }
    return next.value
  } catch {
    return { ok: false, reason: FAILURE }
  } finally {
    checks.return({ ok: false, reason: FAILURE })
  }
}

/** Asynchronous producer equivalent: identical checks without blocking the gateway event loop. */
export async function verifyRfc3161TimestampAsync(
  evidence: string | null | undefined,
  digest: Uint8Array,
  trust: Rfc3161Trust,
  request?: Uint8Array,
): Promise<Rfc3161Verification> {
  const checks = timestampChecks(evidence, digest, trust, request)
  try {
    let next = checks.next()
    while (!next.done) {
      if (!(await runAsync(next.value))) return { ok: false, reason: FAILURE }
      next = checks.next()
    }
    return next.value
  } catch {
    return { ok: false, reason: FAILURE }
  } finally {
    checks.return({ ok: false, reason: FAILURE })
  }
}

function* timestampChecks(
  evidence: string | null | undefined,
  digest: Uint8Array,
  trust: Rfc3161Trust,
  request?: Uint8Array,
): Generator<OpenSslCommand, Rfc3161Verification, void> {
  let dir: string | undefined
  try {
    const now = trust?.verificationTime ?? Math.ceil(Date.now() / 1000)
    if (
      !trust ||
      !boundedText(trust.caPem, true) ||
      !boundedText(trust.crlPem) ||
      !boundedText(trust.untrustedPem) ||
      !/^[0-9a-f]{64}$/.test(trust.signerCertificateSha256) ||
      !["crl", "unchecked"].includes(trust.revocation) ||
      (trust.revocation === "crl" && !boundedText(trust.crlPem, true)) ||
      !Number.isSafeInteger(now) ||
      now < 0 ||
      now > 253402300799 ||
      (trust.opensslPath !== undefined &&
        (typeof trust.opensslPath !== "string" || !trust.opensslPath || trust.opensslPath.includes("\0"))) ||
      !(digest instanceof Uint8Array) ||
      digest.length !== 32 ||
      (request !== undefined && (request.length === 0 || request.length > LIMIT)) ||
      typeof evidence !== "string" ||
      evidence.length > Math.ceil(LIMIT / 3) * 4
    )
      return { ok: false, reason: FAILURE }
    const token = Buffer.from(evidence, "base64")
    if (token.length === 0 || token.length > LIMIT || token.toString("base64") !== evidence)
      return { ok: false, reason: FAILURE }
    cmsDigest(token)
    // `dir` (outer) is what `finally` removes; `workDir` is the same path, typed as present.
    const workDir = mkdtempSync(join(tmpdir(), "intyga-tsa-"))
    dir = workDir
    const path = (name: string) => join(workDir, name)
    const write = (name: string, value: string | Buffer) => writeFileSync(path(name), value, { mode: 0o600 })
    const read = (name: string) => {
      if (statSync(path(name)).size > LIMIT) throw new Error(FAILURE)
      return readFileSync(path(name))
    }
    mkdirSync(path("empty"), { mode: 0o700 })
    write("openssl.cnf", "")
    write("token.der", token)
    write("trust.pem", `${trust.caPem}\n${trust.crlPem ?? ""}`)
    if (trust.untrustedPem) write("intermediates.pem", trust.untrustedPem)
    write(
      "query.tsq",
      Buffer.concat([
        Buffer.from("30360201013031300d060960864801650304020105000420", "hex"),
        Buffer.from(digest),
      ]),
    )
    const executable = trust.opensslPath ?? "openssl"
    const openssl = !isAbsolute(executable) && /[\\/]/.test(executable) ? resolve(executable) : executable
    const command = (args: string[]): OpenSslCommand => ({
      executable: openssl,
      args,
      cwd: workDir,
      env: {
        ...process.env,
        OPENSSL_CONF: path("openssl.cnf"),
        SSL_CERT_FILE: path("trust.pem"),
        SSL_CERT_DIR: path("empty"),
      },
    })
    yield command([
      "cms",
      "-verify",
      "-binary",
      "-inform",
      "DER",
      "-in",
      path("token.der"),
      "-noverify",
      "-signer",
      path("signer.pem"),
      "-out",
      path("info.der"),
    ])
    const signer = read("signer.pem").toString("ascii")
    const cert = /^-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END CERTIFICATE-----\s*$/.exec(
      signer,
    )
    const body = cert?.[1]
    if (body === undefined) throw new Error(FAILURE)
    const der = Buffer.from(body.replace(/\s/g, ""), "base64")
    if (createHash("sha256").update(der).digest("hex") !== trust.signerCertificateSha256)
      throw new Error(FAILURE)
    const genTime = timestamp(read("info.der"), now)
    // `ts -verify` never loads OpenSSL's default trust locations; it trusts only what is passed. No
    // `-CAstore`: OpenSSL 3.0 loads a store URI eagerly and fails on an empty one (3.5 is lazy), which
    // made every valid token fail closed on Ubuntu 24.04's 3.0.13.
    const args = [
      "ts",
      "-verify",
      "-token_in",
      "-in",
      path("token.der"),
      "-queryfile",
      path("query.tsq"),
      "-CAfile",
      path("trust.pem"),
      "-CApath",
      path("empty"),
      "-auth_level",
      "2",
      "-x509_strict",
    ]
    if (trust.untrustedPem) args.push("-untrusted", path("intermediates.pem"))
    yield command([
      ...args,
      "-attime",
      String(now),
      ...(trust.revocation === "crl" ? ["-crl_check_all"] : []),
    ])
    if (request) {
      write("original.tsq", Buffer.from(request))
      yield command([
        ...args.map((arg) => (arg === path("query.tsq") ? path("original.tsq") : arg)),
        "-attime",
        String(now),
      ])
    }
    // Historical certificate validity is checked independently of current CRL freshness.
    yield command([...args, "-attime", String(genTime)])
    return { ok: true, genTime }
  } catch {
    return { ok: false, reason: FAILURE }
  } finally {
    if (dir) {
      try {
        rmSync(dir, { recursive: true, force: true })
      } catch {
        /* Result remains fail-closed; no secrets are written. */
      }
    }
  }
}
