import test from "node:test";
import assert from "node:assert/strict";
import { checkMalwareBazaar, checkUrlhaus } from "../modules/threatIntelligence.js";

test("checkMalwareBazaar handles empty hash gracefully", async () => {
  const result = await checkMalwareBazaar("");
  assert.equal(result.status, "no_hash");
  assert.equal(result.flagged, false);
});

test("checkUrlhaus handles invalid URL gracefully", async () => {
  const result = await checkUrlhaus("not-a-valid-url");
  assert.equal(result.status, "invalid_url");
  assert.equal(result.flagged, false);
});
