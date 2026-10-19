// Regenerate ONLY the `executionEvidence` section of verifier-parity-vectors.json and merge it into
// the committed file, leaving every other section byte-identical. The full generator
// (generate-verifier-parity-vectors.ts) draws fresh keys for every section, so it is the wrong tool
// for changing one. Run: node --import tsx src/scripts/generate-execution-evidence-vectors.ts
import { readFileSync, writeFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { buildExecutionEvidenceVectors } from "./execution-evidence-vectors.js"

const path = fileURLToPath(
  new URL("../../../mcp-schemas/vectors/verifier-parity-vectors.json", import.meta.url),
)
const current = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>
writeFileSync(
  path,
  `${JSON.stringify({ ...current, executionEvidence: buildExecutionEvidenceVectors() }, null, 2)}\n`,
)
console.log(`executionEvidence section written to ${path}`)
