// modules/sourceVerification.js
// Module 3: Source Verification & Website Vulnerability Engine.
// Verifies website authenticity, checks for domain typosquatting / spoofing,
// inspects HTTP security headers, and generates detailed security audit steps.

import { KNOWN_PUBLISHERS, VULNERABILITY_DEFINITIONS } from "./config.js";

const SUSPICIOUS_TLDS = new Set(["top", "xyz", "cc", "click", "download", "link", "gq", "work", "cf", "tk", "ml", "ga"]);
const MULTIPART_TLDS = new Set(["co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au", "edu.au", "co.nz", "co.jp", "com.br"]);
const levenshteinCache = new Map();

// Well-known popular independent domains that should never be falsely flagged as typosquats
const BENIGN_DOMAINS = new Set([
  "gitlab.com", "bitbucket.org", "wikipedia.org", "stackoverflow.com", "reddit.com",
  "amazon.com", "netflix.com", "linkedin.com", "twitter.com", "x.com", "facebook.com",
  "instagram.com", "medium.com", "cloudflare.com", "bing.com", "yahoo.com", "duckduckgo.com"
]);

export function levenshtein(a, b) {
  if (a === b) return 0;
  const lenDiff = Math.abs(a.length - b.length);
  if (lenDiff > 2) return lenDiff;
  const key = a < b ? `${a}:${b}` : `${b}:${a}`;
  if (levenshteinCache.has(key)) return levenshteinCache.get(key);

  const dp = Array.from({ length: a.length + 1 }, (_, i) =>
    Array(b.length + 1).fill(0).map((_, j) => (i === 0 ? j : 0))
  );

  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }

  const result = dp[a.length][b.length];
  if (levenshteinCache.size < 5000) {
    levenshteinCache.set(key, result);
  }
  return result;
}

export function registrableDomain(hostname) {
  if (!hostname) return "";
  const parts = hostname.toLowerCase().split(".");
  if (parts.length <= 2) return hostname;
  
  const lastTwo = parts.slice(-2).join(".");
  if (MULTIPART_TLDS.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

/**
 * Checks if string contains common homoglyph/typo substitutions (0 for o, 1 for l/i, etc.)
 */
function hasHomoglyphSpoof(domain, target) {
  const normalizedDomain = domain.replace(/0/g, "o").replace(/1/g, "l").replace(/vv/g, "w").replace(/rn/g, "m");
  return normalizedDomain === target || levenshtein(normalizedDomain, target) < levenshtein(domain, target);
}

export function verifySource(domain, extraTrustedDomains = []) {
  const reg = registrableDomain(domain);
  const trustedList = [
    ...KNOWN_PUBLISHERS.flatMap(p => p.domains),
    ...extraTrustedDomains
  ];

  const isKnownOfficial = trustedList.some(d => reg === d || domain === d || domain.endsWith(`.${d}`));

  if (isKnownOfficial) {
    return {
      domain,
      registrableDomain: reg,
      isKnownOfficial: true,
      looksLikeTyposquat: false,
      suspiciouslyCloseTo: null,
      officialWebsiteScore: 100,
      sourceReputationScore: 100
    };
  }

  // If the domain is a known benign independent site, don't flag as typosquat
  if (BENIGN_DOMAINS.has(reg)) {
    return {
      domain,
      registrableDomain: reg,
      isKnownOfficial: false,
      looksLikeTyposquat: false,
      suspiciouslyCloseTo: null,
      officialWebsiteScore: 75,
      sourceReputationScore: 80
    };
  }

  let closestMatch = null;
  let closestDistance = Infinity;
  let isHomoglyphMatch = false;

  for (const d of trustedList) {
    const dist = levenshtein(reg, d);
    const homoglyph = hasHomoglyphSpoof(reg, d);

    if (dist < closestDistance) {
      closestDistance = dist;
      closestMatch = d;
      isHomoglyphMatch = homoglyph;
    }
  }

  // To prevent false positives:
  // Typosquat requires either:
  // 1) A homoglyph substitution (e.g. go0gle.com, micros0ft.com) OR
  // 2) Distance <= 2 on domains with long enough length (> 5) where relative difference is small (< 25%),
  //    and the domain name does not represent a completely different dictionary/brand entity.
  const relativeDiff = closestMatch ? closestDistance / Math.max(reg.length, closestMatch.length) : 1;
  const looksLikeTyposquat = closestMatch !== null &&
    closestDistance > 0 &&
    (isHomoglyphMatch || (closestDistance <= 2 && reg.length > 5 && relativeDiff <= 0.22));

  let officialScore;
  if (looksLikeTyposquat) officialScore = 0;
  else officialScore = 65;

  return {
    domain,
    registrableDomain: reg,
    isKnownOfficial: false,
    looksLikeTyposquat,
    suspiciouslyCloseTo: looksLikeTyposquat ? closestMatch : null,
    officialWebsiteScore: officialScore,
    sourceReputationScore: looksLikeTyposquat ? 0 : 65
  };
}

export function verifyHttps(url) {
  const isHttps = url.startsWith("https://");
  return {
    isHttps,
    httpsScore: isHttps ? 100 : 0
  };
}

/**
 * Performs comprehensive security audit of a website with step-by-step audit details.
 *
 * @param {string} url
 * @param {object} [headers]
 * @param {string[]} [extraTrustedDomains]
 * @param {object} [threatIntel]
 */
export function analyzeWebsiteVulnerabilities(url, headers = {}, extraTrustedDomains = [], threatIntel = {}) {
  let domain = "";
  try {
    domain = new URL(url).hostname.toLowerCase();
  } catch {
    domain = url;
  }

  const sourceCheck = verifySource(domain, extraTrustedDomains);
  const isHttps = url.startsWith("https://");
  const vulnerabilities = [];
  const passedProtections = [];

  const normalizedHeaders = {};
  for (const [k, v] of Object.entries(headers || {})) {
    normalizedHeaders[k.toLowerCase()] = String(v);
  }

  // Step 1: Protocol / HTTPS
  if (!isHttps) {
    vulnerabilities.push({
      key: "NO_HTTPS",
      ...VULNERABILITY_DEFINITIONS.NO_HTTPS
    });
  } else {
    passedProtections.push({
      name: "Encrypted Transport (HTTPS)",
      detail: "Traffic between browser and server is encrypted against eavesdropping."
    });
  }

  // Step 2: Strict Transport Security (HSTS)
  const hsts = normalizedHeaders["strict-transport-security"];
  if (isHttps && !hsts) {
    vulnerabilities.push({
      key: "MISSING_HSTS",
      ...VULNERABILITY_DEFINITIONS.MISSING_HSTS
    });
  } else if (hsts) {
    passedProtections.push({
      name: "HSTS Policy Active",
      detail: "Forces future browser connections to use HTTPS, defeating SSL-strip attacks."
    });
  }

  // Step 3: Content Security Policy (CSP)
  const csp = normalizedHeaders["content-security-policy"];
  if (!csp) {
    vulnerabilities.push({
      key: "MISSING_CSP",
      ...VULNERABILITY_DEFINITIONS.MISSING_CSP
    });
  } else {
    passedProtections.push({
      name: "Content-Security-Policy (CSP)",
      detail: "Restricts unauthorized script execution and helps mitigate XSS attacks."
    });
  }

  // Step 4: Cross-Origin Resource Sharing (CORS)
  const corsOrigin = normalizedHeaders["access-control-allow-origin"];
  if (corsOrigin === "*") {
    vulnerabilities.push({
      key: "PERMISSIVE_CORS",
      ...VULNERABILITY_DEFINITIONS.PERMISSIVE_CORS
    });
  } else {
    passedProtections.push({
      name: "Restricted CORS Policy",
      detail: "Prevents arbitrary external web origins from reading sensitive responses."
    });
  }

  // Step 5: Clickjacking (X-Frame-Options or CSP frame-ancestors)
  const xfo = normalizedHeaders["x-frame-options"];
  const hasFrameAncestors = csp && csp.includes("frame-ancestors");
  if (!xfo && !hasFrameAncestors) {
    vulnerabilities.push({
      key: "MISSING_CLICKJACKING_PROTECTION",
      ...VULNERABILITY_DEFINITIONS.MISSING_CLICKJACKING_PROTECTION
    });
  } else {
    passedProtections.push({
      name: "Clickjacking Defense",
      detail: "X-Frame-Options or CSP frame-ancestors prevents invisible iframe overlays."
    });
  }

  // Step 6: MIME Sniffing Protection (X-Content-Type-Options)
  const xcto = normalizedHeaders["x-content-type-options"];
  if (!xcto || !xcto.toLowerCase().includes("nosniff")) {
    vulnerabilities.push({
      key: "MISSING_MIME_PROTECTION",
      ...VULNERABILITY_DEFINITIONS.MISSING_MIME_PROTECTION
    });
  } else {
    passedProtections.push({
      name: "MIME-Type Sniffing Protection",
      detail: "X-Content-Type-Options: nosniff prevents executable script disguises."
    });
  }

  // Step 7: Typosquatting / Domain Spoofing
  if (sourceCheck.looksLikeTyposquat) {
    vulnerabilities.push({
      key: "TYPOSQUATTING_RISK",
      ...VULNERABILITY_DEFINITIONS.TYPOSQUATTING_RISK,
      unethicalHarm: `Phishing & Malware Delivery: Domain mimics "${sourceCheck.suspiciouslyCloseTo}". Users are likely being deceived into downloading malicious payloads disguised as official software.`
    });
  } else if (sourceCheck.isKnownOfficial) {
    passedProtections.push({
      name: "Verified Official Publisher",
      detail: `Domain is verified as official legitimate software or platform infrastructure.`
    });
  }

  // Step 8: TLD Risk Check
  const tld = domain.split(".").pop();
  if (SUSPICIOUS_TLDS.has(tld)) {
    vulnerabilities.push({
      key: "SUSPICIOUS_TLD",
      ...VULNERABILITY_DEFINITIONS.SUSPICIOUS_TLD
    });
  }

  // Step 9: Threat Intelligence Integration (URLhaus / SafeBrowsing)
  if (threatIntel.urlhausFlagged || threatIntel.safeBrowsingFlagged) {
    vulnerabilities.push({
      key: "THREAT_INTEL_BLACKLIST",
      title: "Listed on Threat Intelligence Blacklists",
      threatLevel: "Critical",
      levelCode: 4,
      owaspCategory: "A07:2021 - Identification & Authentication Failures",
      unethicalHarm: "Active Threat Campaign: This URL is flagged by Google Safe Browsing or URLhaus as hosting active malware, spyware, or phishing."
    });
  }

  // Calculate score
  let score = 100;
  if (!isHttps) score -= 40;
  if (sourceCheck.looksLikeTyposquat) score -= 45;
  if (!hsts) score -= 10;
  if (!csp) score -= 10;
  if (corsOrigin === "*") score -= 15;
  if (!xfo && !hasFrameAncestors) score -= 10;
  if (!xcto) score -= 5;
  if (SUSPICIOUS_TLDS.has(tld)) score -= 15;
  if (threatIntel.urlhausFlagged || threatIntel.safeBrowsingFlagged) score -= 60;
  if (sourceCheck.isKnownOfficial) score += 10;

  score = Math.max(0, Math.min(100, Math.round(score)));

  let overallRisk = "safe";
  if (score < 50) overallRisk = "dangerous";
  else if (score < 80) overallRisk = "warning";

  // Step-by-step scanning details for Requirement 5
  const scanSteps = [
    {
      id: "ssl",
      title: "SSL/TLS Protocol Verification",
      status: isHttps ? "secure" : "insecure",
      detail: isHttps ? "Encrypted HTTPS connection active" : "Insecure HTTP connection without encryption"
    },
    {
      id: "headers",
      title: "HTTP Defense Header Audit",
      status: (!hsts || !csp) ? "warning" : "secure",
      detail: `Checked HSTS (${hsts ? "Present" : "Missing"}), CSP (${csp ? "Present" : "Missing"}), XFO (${xfo || hasFrameAncestors ? "Protected" : "Missing"})`
    },
    {
      id: "domain",
      title: "Domain Reputation & Typosquat Analysis",
      status: sourceCheck.looksLikeTyposquat ? "danger" : sourceCheck.isKnownOfficial ? "verified" : "neutral",
      detail: sourceCheck.looksLikeTyposquat
        ? `Suspected impersonation of "${sourceCheck.suspiciouslyCloseTo}"`
        : sourceCheck.isKnownOfficial
        ? "Verified official domain"
        : "Standard domain without brand impersonation"
    },
    {
      id: "threat_intel",
      title: "Live Threat Intelligence Feeds",
      status: (threatIntel.urlhausFlagged || threatIntel.safeBrowsingFlagged) ? "danger" : "secure",
      detail: (threatIntel.urlhausFlagged || threatIntel.safeBrowsingFlagged)
        ? "Flagged by global malware/phishing feeds"
        : "No active threat listings found"
    },
    {
      id: "risk_posture",
      title: "Security Posture Synthesis",
      status: overallRisk,
      detail: `Calculated safety score: ${score}/100 (${overallRisk.toUpperCase()})`
    }
  ];

  return {
    url,
    domain,
    isHttps,
    isKnownOfficial: sourceCheck.isKnownOfficial,
    websiteSecurityScore: score,
    overallRisk,
    vulnerabilities,
    passedProtections,
    scanSteps,
    securityHeaders: {
      hsts: hsts || "Not Set",
      csp: csp ? "Configured" : "Not Set",
      cors: corsOrigin || "Default",
      xfo: xfo || (hasFrameAncestors ? "frame-ancestors" : "Not Set"),
      xcto: xcto || "Not Set"
    }
  };
}