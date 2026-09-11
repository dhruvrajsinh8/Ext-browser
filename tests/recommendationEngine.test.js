import test from "node:test";
import assert from "node:assert/strict";
import { getRecommendation } from "../modules/recommendationEngine.js";

test("getRecommendation returns safe for high trust scores with no flags", () => {
  const result = getRecommendation(
    { trustScore: 85, safeBrowsingOverride: false },
    { looksLikeTyposquat: false, integrityStatus: "matches_known_good", chromeDanger: "safe" }
  );

  assert.equal(result.riskLevel, "safe");
  assert.equal(result.headline, "Safe to Install");
});

test("getRecommendation returns warning for moderate trust scores", () => {
  const result = getRecommendation(
    { trustScore: 65, safeBrowsingOverride: false },
    { looksLikeTyposquat: false, integrityStatus: "no_reference_hash", chromeDanger: "safe" }
  );

  assert.equal(result.riskLevel, "warning");
});

test("getRecommendation forces dangerous on Safe Browsing override", () => {
  const result = getRecommendation(
    { trustScore: 90, safeBrowsingOverride: true },
    { looksLikeTyposquat: false, integrityStatus: "matches_known_good", chromeDanger: "safe" }
  );

  assert.equal(result.riskLevel, "dangerous");
  assert.equal(result.headline, "Delete Immediately");
});

test("getRecommendation forces dangerous on typosquatting flag", () => {
  const result = getRecommendation(
    { trustScore: 85, safeBrowsingOverride: false },
    { looksLikeTyposquat: true, integrityStatus: "no_reference_hash", chromeDanger: "safe" }
  );

  assert.equal(result.riskLevel, "dangerous");
});

test("getRecommendation forces dangerous on hash mismatch", () => {
  const result = getRecommendation(
    { trustScore: 85, safeBrowsingOverride: false },
    { looksLikeTyposquat: false, integrityStatus: "hash_mismatch_possible_tampering", chromeDanger: "safe" }
  );

  assert.equal(result.riskLevel, "dangerous");
});

test("getRecommendation forces dangerous on Chrome danger flag", () => {
  const result = getRecommendation(
    { trustScore: 85, safeBrowsingOverride: false },
    { looksLikeTyposquat: false, integrityStatus: "no_reference_hash", chromeDanger: "unwanted" }
  );

  assert.equal(result.riskLevel, "dangerous");
});

test("getRecommendation forces dangerous on MalwareBazaar flagged sample", () => {
  const result = getRecommendation(
    { trustScore: 85, safeBrowsingOverride: false },
    { malwareBazaarFlagged: true, malwareBazaarSignature: "AgentTesla" }
  );

  assert.equal(result.riskLevel, "dangerous");
  assert.equal(result.headline, "Malware Detected (MalwareBazaar)");
  assert.match(result.detail, /AgentTesla/);
});

test("getRecommendation forces dangerous on URLhaus flagged distribution host", () => {
  const result = getRecommendation(
    { trustScore: 85, safeBrowsingOverride: false },
    { urlhausFlagged: true }
  );

  assert.equal(result.riskLevel, "dangerous");
  assert.equal(result.headline, "Malware Host Flagged (URLhaus)");
});

test("getRecommendation flags active weaponized exploit", () => {
  const result = getRecommendation(
    { trustScore: 85, safeBrowsingOverride: false },
    {
      hasExploits: true,
      exploits: [{ id: "CVE-2023-38831", exploitSource: "CISA KEV" }]
    }
  );

  assert.equal(result.riskLevel, "dangerous");
  assert.equal(result.headline, "Active Exploit Detected");
  assert.match(result.detail, /CVE-2023-38831/);
});

