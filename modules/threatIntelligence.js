// modules/threatIntelligence.js
// Module 6: Threat Intelligence.
// Queries VirusTotal (URL + file hash reports) and Google Safe Browsing.
// Both require API keys the user supplies in Options — this module never
// ships a bundled key. If a key is missing, that check is skipped and
// reported as "not_configured" rather than silently failing.

import { ENDPOINTS, VT_UPLOAD_MAX_BYTES, VT_ANALYSIS_POLL_MS, VT_ANALYSIS_MAX_POLLS } from "./config.js";

function toBase64Url(str) {
  return btoa(str).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

export async function checkVirusTotal({ url, sha256 }, apiKey) {
  if (!apiKey) {
    return { vtScore: 50, status: "not_configured", malicious: 0, suspicious: 0, harmless: 0 };
  }

  try {
    // Prefer a hash lookup when we have one — it's a direct file report.
    if (sha256) {
      const res = await fetch(`${ENDPOINTS.virusTotalFileReport}/${sha256}`, {
        headers: { "x-apikey": apiKey }
      });
      if (res.status === 404) {
        return { vtScore: 60, status: "unseen_by_virustotal", malicious: 0, suspicious: 0, harmless: 0 };
      }
      if (!res.ok) throw new Error(`VirusTotal file lookup failed: ${res.status}`);
      const data = await res.json();
      const stats = data?.data?.attributes?.last_analysis_stats || {};
      return scoreFromStats(stats, "file_hash");
    }

    // Fall back to a URL report.
    const id = toBase64Url(url);
    const res = await fetch(`${ENDPOINTS.virusTotalUrlReport}/${id}`, {
      headers: { "x-apikey": apiKey }
    });
    if (res.status === 404) {
      return { vtScore: 60, status: "unseen_by_virustotal", malicious: 0, suspicious: 0, harmless: 0 };
    }
    if (!res.ok) throw new Error(`VirusTotal URL lookup failed: ${res.status}`);
    const data = await res.json();
    const stats = data?.data?.attributes?.last_analysis_stats || {};
    return scoreFromStats(stats, "url");
  } catch (err) {
    return { vtScore: 50, status: "error", error: String(err), malicious: 0, suspicious: 0, harmless: 0 };
  }
}

/**
 * Submits the actual file bytes to VirusTotal for a fresh multi-engine scan.
 * Only called when: the hash lookup came back unseen (404), the user has
 * explicitly opted in (settings.allowVirusTotalUpload), and the file is
 * under VT_UPLOAD_MAX_BYTES. This is the real "look at the exact bytes"
 * check — a hash lookup only tells you if VT has seen this file *before*.
 *
 * @param {ArrayBuffer} buffer
 * @param {string} filename
 * @param {string} apiKey
 */
export async function uploadFileToVirusTotal(buffer, filename, apiKey) {
  if (!apiKey) {
    return { vtScore: 50, status: "not_configured", malicious: 0, suspicious: 0, harmless: 0 };
  }
  if (!buffer || buffer.byteLength === 0) {
    return { vtScore: 50, status: "no_content", malicious: 0, suspicious: 0, harmless: 0 };
  }
  if (buffer.byteLength > VT_UPLOAD_MAX_BYTES) {
    return { vtScore: 55, status: "too_large_for_upload", malicious: 0, suspicious: 0, harmless: 0 };
  }

  try {
    const form = new FormData();
    form.append("file", new Blob([buffer]), filename || "download.bin");

    const uploadRes = await fetch(ENDPOINTS.virusTotalFileUpload, {
      method: "POST",
      headers: { "x-apikey": apiKey },
      body: form
    });
    if (!uploadRes.ok) throw new Error(`VirusTotal upload failed: ${uploadRes.status}`);
    const uploadData = await uploadRes.json();
    const analysisId = uploadData?.data?.id;
    if (!analysisId) throw new Error("VirusTotal upload returned no analysis id");

    // Poll the analysis endpoint until it completes or we hit the poll cap —
    // a fresh scan across 70+ engines isn't instant.
    for (let attempt = 0; attempt < VT_ANALYSIS_MAX_POLLS; attempt++) {
      await new Promise(r => setTimeout(r, VT_ANALYSIS_POLL_MS));
      const analysisRes = await fetch(`${ENDPOINTS.virusTotalAnalysis}/${analysisId}`, {
        headers: { "x-apikey": apiKey }
      });
      if (!analysisRes.ok) continue;
      const analysisData = await analysisRes.json();
      const status = analysisData?.data?.attributes?.status;
      if (status === "completed") {
        const stats = analysisData?.data?.attributes?.stats || {};
        return scoreFromStats(stats, "fresh_upload");
      }
    }

    // Scan didn't finish within our poll budget — not an error, just inconclusive for now.
    return { vtScore: 55, status: "scan_pending", malicious: 0, suspicious: 0, harmless: 0, analysisId };
  } catch (err) {
    return { vtScore: 50, status: "error", error: String(err), malicious: 0, suspicious: 0, harmless: 0 };
  }
}

function scoreFromStats(stats, source) {
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const harmless = stats.harmless || 0;
  const total = malicious + suspicious + harmless + (stats.undetected || 0);

  let vtScore;
  if (total === 0) {
    vtScore = 60; // neutral / unseen
  } else if (malicious >= 3) {
    vtScore = Math.max(0, 30 - malicious * 5);
  } else if (malicious === 2) {
    vtScore = 35;
  } else if (malicious === 1 && suspicious === 0) {
    // Single engine detection on VT is very often a false positive (e.g. generic heuristic flags)
    vtScore = 65;
  } else if (malicious === 1 && suspicious > 0) {
    vtScore = 45;
  } else if (suspicious > 0) {
    vtScore = Math.max(45, 75 - suspicious * 8);
  } else {
    vtScore = 98; // Verified clean by multiple AV engines
  }

  return { vtScore, status: `analyzed_${source}`, malicious, suspicious, harmless, total };
}

export async function checkSafeBrowsing(url, apiKey) {
  if (!apiKey) {
    return { safeBrowsingScore: 50, status: "not_configured", flagged: false };
  }
  try {
    const body = {
      client: { clientId: "securedownload-ai", clientVersion: "1.0.0" },
      threatInfo: {
        threatTypes: [
          "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
        ],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    };
    const res = await fetch(`${ENDPOINTS.safeBrowsing}?key=${encodeURIComponent(apiKey)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    if (!res.ok) throw new Error(`Safe Browsing lookup failed: ${res.status}`);
    const data = await res.json();
    const flagged = Boolean(data.matches && data.matches.length);
    return {
      safeBrowsingScore: flagged ? 0 : 100,
      status: "analyzed",
      flagged,
      threatTypes: flagged ? data.matches.map(m => m.threatType) : []
    };
  } catch (err) {
    return { safeBrowsingScore: 50, status: "error", error: String(err), flagged: false };
  }
}

/**
 * Queries MalwareBazaar (abuse.ch) for a known malware sample matching the SHA256 hash.
 * Free public API; optional Auth-Key for higher tiers.
 *
 * @param {string} sha256 - lowercase SHA256 hash
 * @param {string} [apiKey] - optional MalwareBazaar Auth-Key
 */
export async function checkMalwareBazaar(sha256, apiKey = "") {
  if (!sha256) {
    return { mbScore: 60, status: "no_hash", flagged: false };
  }

  try {
    const formData = new URLSearchParams();
    formData.append("query", "get_info");
    formData.append("hash", sha256);

    const headers = { "Content-Type": "application/x-www-form-urlencoded" };
    if (apiKey) headers["Auth-Key"] = apiKey;

    const res = await fetch(ENDPOINTS.malwareBazaar, {
      method: "POST",
      headers,
      body: formData.toString()
    });

    if (!res.ok) throw new Error(`MalwareBazaar query failed: ${res.status}`);
    const data = await res.json();

    if (data.query_status === "ok" && Array.isArray(data.data) && data.data.length > 0) {
      const sample = data.data[0];
      return {
        mbScore: 0,
        status: "malware_found",
        flagged: true,
        signature: sample.signature || "Malware Sample",
        fileType: sample.file_type || "binary",
        deliveryMethod: sample.delivery_method || null,
        tags: sample.tags || []
      };
    }

    if (data.query_status === "hash_not_found") {
      return {
        mbScore: 85,
        status: "clean_or_unseen",
        flagged: false,
        signature: null,
        tags: []
      };
    }

    return { mbScore: 60, status: data.query_status || "unseen", flagged: false };
  } catch (err) {
    return { mbScore: 60, status: "error", error: String(err), flagged: false };
  }
}

/**
 * Queries URLhaus (abuse.ch) to determine if a URL or its host is a recognized
 * malware distribution endpoint. Free public intelligence.
 *
 * @param {string} url
 * @param {string} [apiKey]
 */
export async function checkUrlhaus(url, apiKey = "") {
  if (!url || !url.startsWith("http")) {
    return { urlhausScore: 60, status: "invalid_url", flagged: false };
  }

  try {
    const formData = new URLSearchParams();
    formData.append("url", url);

    const headers = { "Content-Type": "application/x-www-form-urlencoded" };
    if (apiKey) headers["Auth-Key"] = apiKey;

    const res = await fetch(ENDPOINTS.urlhaus, {
      method: "POST",
      headers,
      body: formData.toString()
    });

    if (!res.ok) throw new Error(`URLhaus query failed: ${res.status}`);
    const data = await res.json();

    if (data.query_status === "ok") {
      const isOnline = data.url_status === "online";
      return {
        urlhausScore: 0,
        status: "malicious",
        flagged: true,
        threat: data.threat || "malware_download",
        urlStatus: data.url_status || "unknown",
        tags: data.tags || []
      };
    }

    if (data.query_status === "no_results") {
      return {
        urlhausScore: 95,
        status: "clean",
        flagged: false,
        threat: null
      };
    }

    return { urlhausScore: 60, status: data.query_status || "unseen", flagged: false };
  } catch (err) {
    return { urlhausScore: 60, status: "error", error: String(err), flagged: false };
  }
}

