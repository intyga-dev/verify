import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"
import { test } from "node:test"
import { fileURLToPath } from "node:url"
import {
  canonicalAuthorizationPayload,
  canonicalAuthorizationPayloadV3,
  verificationCode,
} from "./index.ts"

const vectorsPath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "vectors",
  "canonical-vectors.json",
)
const vectors = JSON.parse(fs.readFileSync(vectorsPath, "utf8"))

test("canonical payload builders match golden vectors", () => {
  for (const c of vectors.authorizationPayloads) {
    assert.equal(canonicalAuthorizationPayload(c.input), c.expected)
  }
  for (const c of vectors.authorizationPayloadsV3) {
    assert.equal(canonicalAuthorizationPayloadV3(c.input), c.expected)
  }
})
