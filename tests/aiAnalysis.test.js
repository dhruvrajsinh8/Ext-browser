import test from "node:test";
import assert from "node:assert/strict";
import { runHeuristicAiExplanation } from "../modules/aiAnalysis.js";

test("runHeuristicAiExplanation generates structured security narrative for safe download", () => {
  const data = {
    kind: "download_scan",
    filename: "firefox-setup.exe",
    domain: "mozilla.org",
    trustScore: 95,
    riskLevel: "safe",
    isHttps: true,
    isKnownOfficialSource: true,
    hasExploits: false
  };

  const result = runHeuristicAiExplanation(data);
  assert.equal(result.ok, true);
  assert.ok(result.narrative.length > 20);
  assert.ok(Array.isArray(result.topReasons));
  assert.ok(result.topReasons.length > 0);
});

test("runHeuristicAiExplanation flags dangerous exploit alerts in narrative", () => {
  const data = {
    kind: "download_scan",
    filename: "vulnerable-app.exe",
    domain: "sketchy-downloads.com",
    trustScore: 15,
    riskLevel: "dangerous",
    isHttps: false,
    looksLikeTyposquat: true,
    suspiciouslyCloseTo: "microsoft.com",
    hasExploits: true,
    exploitsCount: 2
  };

  const result = runHeuristicAiExplanation(data);
  assert.equal(result.ok, true);
  assert.match(result.narrative, /dangerous|threat|high-risk/i);
  assert.ok(result.additionalConcern.includes("Exploit alert"));
});
