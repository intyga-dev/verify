// Regenerate ONLY the `enrolledDevice` section of verifier-parity-vectors.json and merge it into the
// committed file, leaving every other section byte-identical (the full generator rotates every key).
// Run: node --import tsx src/scripts/generate-enrolled-device-vectors.ts
import { readFileSync, writeFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { buildEnrolledDeviceVectors } from "./enrolled-device-vectors.js"

const path = fileURLToPath(
  new URL("../../../mcp-schemas/vectors/verifier-parity-vectors.json", import.meta.url),
)
const current = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>
writeFileSync(
  path,
  `${JSON.stringify({ ...current, enrolledDevice: buildEnrolledDeviceVectors() }, null, 2)}\n`,
)
console.log(`enrolledDevice section written to ${path}`)
