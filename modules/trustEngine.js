// modules/trustEngine.js
// Module 8: Trust Engine.
// Pure function: takes the individual scores produced by every analysis
// module and combines them via the weighted formula. Kept separate from
// those modules so the formula itself is easy to audit in one place.
//
// IMPORTANT: a check that didn't run (no API key configured) or couldn't
// reach a real conclusion (e.g. no reference hash to compare against) is
// NOT the same as a mediocre result. Scoring it a flat neutral 50 and
// blending it into the weighted average punishes downloads for the user's
// setup, not for anything about the file — a clean download from an
// official site could land in the 70s just because VirusTotal wasn't
// configured. Instead, each factor carries an `applicable` flag; only
// applicable factors are weighted, and their weights are renormalized to
// sum to 100% among themselves. The published percentages in the README
// describe the formula when every check is configured and conclusive.

import { WEIGHTS } from "./config.js";

/**
 * @param {object} scores
 * @param {number} scores.officialWebsiteScore
 * @param {number} scores.publisherVerificationScore
 * @param {number} scores.vtScore
 * @param {boolean} scores.vtApplicable
 * @param {number} scores.vulnerabilityScore
 * @param {boolean} scores.vulnerabilityApplicable
 * @param {number} scores.httpsScore
 * @param {number} scores.integrityScore
 * @param {boolean} scores.integrityApplicable
 * @param {number} scores.sourceReputationScore
 * @param {boolean} scores.safeBrowsingFlagged
 */
export function calculateTrustScore(scores) {
  const factors = {
    officialWebsite: { score: scores.officialWebsiteScore, applicable: true },
    publisherVerification: { score: scores.publisherVerificationScore, applicable: true },
    virusTotal: { score: scores.vtScore, applicable: scores.vtApplicable !== false },
    staticAnalysis: { score: scores.staticAnalysisScore, applicable: scores.staticAnalysisApplicable !== false },
    vulnerability: { score: scores.vulnerabilityScore, applicable: scores.vulnerabilityApplicable !== false },
    https: { score: scores.httpsScore, applicable: true },
    fileIntegrity: { score: scores.integrityScore, applicable: scores.integrityApplicable !== false },
    sourceReputation: { score: scores.sourceReputationScore, applicable: true }
  };

  const applicableWeightSum = Object.entries(factors)
    .filter(([, f]) => f.applicable)
    .reduce((sum, [key]) => sum + WEIGHTS[key], 0);

  // Extremely defensive: if literally nothing was applicable, fall back to
  // a neutral 50 rather than dividing by zero.
  if (applicableWeightSum === 0) {
    return {
      trustScore: 50,
      rawWeightedScore: 50,
      safeBrowsingOverride: false,
      checksApplicable: 0,
      checksTotal: Object.keys(factors).length,
      contributions: {}
    };
  }

  const contributions = {};
  let total = 0;
  for (const [key, f] of Object.entries(factors)) {
    if (!f.applicable) {
      contributions[key] = null; // shown in the UI as "not configured / n/a"
      continue;
    }
    const renormalizedWeight = WEIGHTS[key] / applicableWeightSum;
    const contribution = (f.score ?? 50) * renormalizedWeight;
    contributions[key] = Math.round(contribution * 10) / 10;
    total += contribution;
  }

  // Safe Browsing, MalwareBazaar, URLhaus, or Chrome built-in threat detection acts as a hard override:
  // confirmed flags are unambiguous ground truth.
  const chromeDangerFlagged = Boolean(scores.chromeDanger && !["safe", "accepted"].includes(scores.chromeDanger));
  const threatIntelFlagged = scores.safeBrowsingFlagged === true ||
    scores.malwareBazaarFlagged === true ||
    scores.urlhausFlagged === true ||
    chromeDangerFlagged;
  const overridden = threatIntelFlagged;
  let finalScore = overridden ? Math.min(total, 10) : total;
  if (!overridden && scores.hasExploits) {
    finalScore = Math.min(finalScore, 40);
  }

  return {
    trustScore: Math.round(Math.max(0, Math.min(100, finalScore))),
    rawWeightedScore: Math.round(total),
    safeBrowsingOverride: overridden,
    malwareBazaarFlagged: Boolean(scores.malwareBazaarFlagged),
    urlhausFlagged: Boolean(scores.urlhausFlagged),
    chromeDangerFlagged,
    checksApplicable: Object.values(factors).filter((f) => f.applicable).length,
    checksTotal: Object.keys(factors).length,
    contributions
  };

}
