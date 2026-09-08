// background.js
// Module 1: Download Monitor + top-level pipeline & Website Security orchestration.

import { parseDownloadItem } from "./modules/downloadParser.js";
import { verifySource, verifyHttps, analyzeWebsiteVulnerabilities } from "./modules/sourceVerification.js";
import { verifyPublisher } from "./modules/publisherVerification.js";
import { checkFileIntegrity } from "./modules/fileIntegrity.js";
import { checkVirusTotal, checkSafeBrowsing, uploadFileToVirusTotal } from "./modules/threatIntelligence.js";
import { checkVulnerabilities } from "./modules/vulnerabilityIntelligence.js";
import { runStaticAnalysis } from "./modules/staticAnalysis.js";
import { calculateTrustScore } from "./modules/trustEngine.js";
import { getRecommendation } from "./modules/recommendationEngine.js";
import {
  saveScanRecord, getSettings, getCached, setCached, getPublisherList, pruneExpiredCache,
  saveEmailScanRecord, getScannedEmailIds, markEmailIdsScanned
} from "./modules/storageManager.js";
import { setInFlightScan, getInFlightScan, removeInFlightScan, getAllInFlightScans } from "./modules/stateStore.js";
import { checkDomainBlocklist } from "./modules/domainBlocklist.js";
import { notifyResult, notifyEmailResult } from "./modules/notificationEngine.js";
import { CACHE_TTL_MS } from "./modules/config.js";
import { getValidAccessToken } from "./modules/emailAuth.js";
import { listRecentMessageIds, getMessage } from "./modules/gmailClient.js";
import { analyzeEmailForPhishing } from "./modules/phishingAnalysis.js";

const CACHE_PRUNE_ALARM = "sd_cache_prune";
const EMAIL_SCAN_ALARM = "sd_email_scan";

chrome.downloads.onCreated.addListener(async (item) => {
  console.log("[SecureDownload AI] onCreated fired:", item.id, item.url, item.filename);
  const settings = await getSettings();
  if (!settings.autoAnalyze) {
    console.log("[SecureDownload AI] autoAnalyze is off — skipping.");
    return;
  }

  let freshItem = item;
  try {
    const [searched] = await chrome.downloads.search({ id: item.id });
    if (searched) freshItem = searched;
  } catch (err) {
    console.warn("[SecureDownload AI] downloads.search failed, using raw item", err);
  }

  const parsed = parseDownloadItem(freshItem);
  console.log("[SecureDownload AI] parsed download:", parsed);

  // User blocklist is a hard stop that runs before any network work: if the
  // user has explicitly blocked this domain there is nothing to analyse.
  const blockCheck = checkDomainBlocklist(parsed.domain, settings.blockedDomains);
  if (blockCheck.blocked) {
    console.log("[SecureDownload AI] domain is on the user blocklist:", blockCheck.matchedEntry);
    await handleBlockedDomain(parsed, blockCheck);
    return;
  }

  // Monitor & pause download while running the audit
  try {
    await chrome.downloads.pause(item.id);
    console.log("[SecureDownload AI] paused download", item.id);
  } catch (err) {
    console.warn("[SecureDownload AI] could not pause (may already be complete):", err);
  }

  runAnalysisPipeline(parsed, settings)
    .then(() => console.log("[SecureDownload AI] pipeline complete for", parsed.filename))
    .catch(async (err) => {
      console.error("[SecureDownload AI] pipeline failed", err);
      try {
        await chrome.downloads.resume(item.id);
      } catch (resumeErr) {
        console.warn("[SecureDownload AI] could not resume download after failure:", resumeErr);
      }
      chrome.notifications.create(`sd_err_${item.id}`, {
        type: "basic",
        iconUrl: chrome.runtime.getURL("icons/icon128.png"),
        title: "Security Audit Failure",
        message: `Download resumed unscanned: ${parsed.filename || "file"}.\nError: ${err.message || String(err)}`,
        priority: 1
      });
    });
});

async function runAnalysisPipeline(parsed, settings) {
  // Fetch site headers for vulnerability scanning
  const headers = await fetchSiteHeaders(parsed.url);
  const websiteSecurity = analyzeWebsiteVulnerabilities(parsed.url, headers, settings.extraTrustedDomains);

  // Integrity check fetches hash & buffer
  const integrityResult = await checkFileIntegrity(parsed.url, settings.knownGoodHashes, parsed.filename);
  const vtKeyMaterial = integrityResult.sha256 || parsed.url;
  const publisherList = await getPublisherList();

  const [sourceResult, httpsResult, publisherResult, vtResult, sbResult, vulnResult] =
    await Promise.all([
      Promise.resolve(verifySource(parsed.domain, settings.extraTrustedDomains)),
      Promise.resolve(verifyHttps(parsed.url)),
      Promise.resolve(verifyPublisher(parsed, settings.extraTrustedDomains, publisherList)),
      cachedThreatCheck("vt", vtKeyMaterial, () => checkVirusTotal({ url: parsed.url, sha256: integrityResult.sha256 }, settings.virusTotalApiKey)),
      cachedThreatCheck("sb", parsed.url, () => checkSafeBrowsing(parsed.url, settings.safeBrowsingApiKey)),
      cachedThreatCheck("nvd", parsed.filename, () => checkVulnerabilities(parsed.filename, settings.nvdApiKey))
    ]);

  const staticResult = runStaticAnalysis(integrityResult.buffer, parsed);
  let finalVtResult = vtResult;

  if (
    vtResult.status === "unseen_by_virustotal" &&
    settings.allowVirusTotalUpload &&
    settings.virusTotalApiKey &&
    integrityResult.buffer
  ) {
    finalVtResult = await uploadFileToVirusTotal(integrityResult.buffer, parsed.filename, settings.virusTotalApiKey);
    await setCached(`vt:${vtKeyMaterial}`, finalVtResult, CACHE_TTL_MS.virusTotal);
  }

  const staticAnalysisCritical = staticResult.findings.some(f => f.severity === "critical");
  const trustResult = calculateTrustScore({
    officialWebsiteScore: sourceResult.officialWebsiteScore,
    publisherVerificationScore: publisherResult.publisherVerificationScore,
    vtScore: finalVtResult.vtScore,
    vtApplicable: finalVtResult.status !== "not_configured",
    staticAnalysisScore: staticResult.staticAnalysisScore,
    staticAnalysisApplicable: staticResult.status !== "no_content",
    vulnerabilityScore: vulnResult.vulnerabilityScore,
    vulnerabilityApplicable: !["no_version_detected", "error"].includes(vulnResult.status),
    httpsScore: httpsResult.httpsScore,
    integrityScore: integrityResult.integrityScore,
    integrityApplicable: ["matches_known_good", "hash_mismatch_possible_tampering"].includes(integrityResult.status),
    sourceReputationScore: sourceResult.sourceReputationScore,
    safeBrowsingFlagged: sbResult.flagged,
    chromeDanger: parsed.danger
  });

  const recommendation = getRecommendation(trustResult, {
    looksLikeTyposquat: sourceResult.looksLikeTyposquat,
    integrityStatus: integrityResult.status,
    chromeDanger: parsed.danger,
    staticAnalysisCritical,
    staticAnalysisFindings: staticResult.findings
  });

  // Strip raw ArrayBuffer before persistence
  const { buffer: _discardBuffer, ...integrityForRecord } = integrityResult;
  const record = {
    downloadId: parsed.downloadId,
    filename: parsed.filename,
    extension: parsed.extension,
    category: parsed.category,
    url: parsed.url,
    domain: parsed.domain,
    scannedAt: new Date().toISOString(),
    trustScore: trustResult.trustScore,
    contributions: trustResult.contributions,
    checksApplicable: trustResult.checksApplicable,
    checksTotal: trustResult.checksTotal,
    riskLevel: recommendation.riskLevel,
    recommendation,
    websiteSecurity,
    details: {
      source: sourceResult,
      https: httpsResult,
      publisher: publisherResult,
      integrity: integrityForRecord,
      staticAnalysis: staticResult,
      virusTotal: finalVtResult,
      safeBrowsing: sbResult,
      vulnerability: vulnResult,
      websiteSecurity
    },
    action: "pending"
  };

  const isSafe = recommendation.riskLevel === "safe";
  let autoResumed = false;
  if (isSafe) {
    try {
      await chrome.downloads.resume(parsed.downloadId);
      console.log("[SecureDownload AI] auto-resumed safe download", parsed.downloadId);
      record.action = "resumed";
      autoResumed = true;
    } catch (err) {
      console.warn("[SecureDownload AI] could not auto-resume download:", err);
    }
  }

  await setInFlightScan(parsed.downloadId, { parsed, record });
  await saveScanRecord(record);

  const settingsNow = await getSettings();
  if (settingsNow.blockDangerousByDefault && recommendation.riskLevel === "dangerous") {
    await resolveDownload(parsed.downloadId, "deleted");
    record.action = "deleted";
  }

  notifyResult(record, autoResumed);

  if (record.action !== "pending") {
    await removeInFlightScan(parsed.downloadId);
  }

  chrome.runtime.sendMessage({ type: "SD_ANALYSIS_COMPLETE", record, autoResumed }).catch(() => {});
}

async function handleBlockedDomain(parsed, blockCheck) {
  await chrome.downloads.cancel(parsed.downloadId).catch(() => {});
  await chrome.downloads.removeFile(parsed.downloadId).catch(() => {});

  const record = {
    downloadId: parsed.downloadId,
    filename: parsed.filename,
    extension: parsed.extension,
    category: parsed.category,
    url: parsed.url,
    domain: parsed.domain,
    scannedAt: new Date().toISOString(),
    trustScore: 0,
    riskLevel: "dangerous",
    recommendation: {
      riskLevel: "dangerous",
      emoji: "🔴",
      headline: "Blocked by Your Blocklist",
      detail: `Downloads from "${blockCheck.matchedEntry}" are blocked by your personal blocklist.`
    },
    details: { blocklist: blockCheck },
    action: "deleted"
  };

  await saveScanRecord(record);
  notifyResult(record, false);
  chrome.runtime.sendMessage({ type: "SD_ANALYSIS_COMPLETE", record, autoResumed: false }).catch(() => {});
}

async function fetchSiteHeaders(url) {
  try {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), 4000);
    let res = await fetch(url, { method: "HEAD", signal: controller.signal });
    clearTimeout(id);

    if (!res.ok || Array.from(res.headers.keys()).length === 0) {
      const getController = new AbortController();
      const getId = setTimeout(() => getController.abort(), 4000);
      res = await fetch(url, { method: "GET", headers: { Range: "bytes=0-0" }, signal: getController.signal });
      clearTimeout(getId);
    }

    const headers = {};
    for (const [k, v] of res.headers.entries()) {
      headers[k.toLowerCase()] = v;
    }
    return headers;
  } catch (err) {
    console.warn("[SecureDownload AI] could not fetch headers for", url, err);
    return {};
  }
}

async function cachedThreatCheck(prefix, keyMaterial, fn) {
  const cacheKey = `${prefix}:${keyMaterial}`;
  const cached = await getCached(cacheKey);
  if (cached) return cached;
  const result = await fn();
  await setCached(cacheKey, result, CACHE_TTL_MS[prefix === "vt" ? "virusTotal" : prefix === "sb" ? "safeBrowsing" : "nvd"]);
  return result;
}

async function resolveDownload(downloadId, action) {
  const entry = await getInFlightScan(downloadId);
  if (entry) {
    entry.record.action = action;
    await saveScanRecord(entry.record);
  }
  if (action === "resumed") {
    await chrome.downloads.resume(downloadId).catch(() => {});
  } else if (action === "deleted") {
    await chrome.downloads.cancel(downloadId).catch(() => {});
    await chrome.downloads.removeFile(downloadId).catch(() => {});
  }
  await removeInFlightScan(downloadId);
}

async function scanEmailInbox({ manual = false } = {}) {
  const settings = await getSettings();
  if (!settings.emailScanEnabled && !manual) {
    return { scanned: 0, skipped: "disabled" };
  }
  const accessToken = await getValidAccessToken();
  if (!accessToken) {
    return { scanned: 0, error: "not_connected" };
  }

  const alreadyScanned = await getScannedEmailIds();
  let ids;
  try {
    ids = await listRecentMessageIds(accessToken, settings.emailMaxMessagesPerScan);
  } catch (err) {
    console.warn("[SecureDownload AI] Gmail message list failed:", err);
    return { scanned: 0, error: String(err.message || err) };
  }

  const newIds = ids.filter((id) => !alreadyScanned.has(id));
  const results = [];
  for (const id of newIds) {
    try {
      const message = await getMessage(accessToken, id);
      const analysis = analyzeEmailForPhishing(message, settings.extraTrustedDomains);
      const record = { ...analysis, scannedAt: new Date().toISOString() };
      await saveEmailScanRecord(record);
      results.push(record);
      if (record.riskLevel === "dangerous") {
        notifyEmailResult(record);
      }
    } catch (err) {
      console.warn("[SecureDownload AI] email scan failed for message", id, err);
    }
  }

  if (newIds.length) {
    await markEmailIdsScanned(newIds);
  }

  chrome.runtime.sendMessage({ type: "SD_EMAIL_SCAN_COMPLETE", scanned: results.length }).catch(() => {});
  return { scanned: results.length };
}

async function configureEmailAlarm() {
  const settings = await getSettings();
  await chrome.alarms.clear(EMAIL_SCAN_ALARM);
  if (settings.emailScanEnabled) {
    chrome.alarms.create(EMAIL_SCAN_ALARM, {
      periodInMinutes: Math.max(5, settings.emailScanIntervalMinutes || 15)
    });
  }
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create(CACHE_PRUNE_ALARM, { periodInMinutes: 60 });
  configureEmailAlarm();
});

chrome.runtime.onStartup.addListener(() => {
  chrome.alarms.create(CACHE_PRUNE_ALARM, { periodInMinutes: 60 });
  configureEmailAlarm();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === CACHE_PRUNE_ALARM) {
    pruneExpiredCache().catch((err) => console.warn("[SecureDownload AI] cache prune failed:", err));
  } else if (alarm.name === EMAIL_SCAN_ALARM) {
    scanEmailInbox().catch((err) => console.warn("[SecureDownload AI] email alarm scan failed:", err));
  }
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.sd_settings) {
    configureEmailAlarm();
  }
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === "SD_GET_PENDING") {
    getAllInFlightScans().then((pending) => sendResponse({ pending }));
    return true;
  }
  if (message.type === "SD_RESOLVE_DOWNLOAD") {
    resolveDownload(message.downloadId, message.action).then(() => sendResponse({ ok: true }));
    return true;
  }
  if (message.type === "SD_ANALYZE_WEBSITE") {
    (async () => {
      const settings = await getSettings();
      const headers = await fetchSiteHeaders(message.url);
      const audit = analyzeWebsiteVulnerabilities(message.url, headers, settings.extraTrustedDomains);
      sendResponse({ audit });
    })();
    return true;
  }
  if (message.type === "SD_GET_ACTIVE_TAB_SECURITY") {
    (async () => {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || !tab.url || !tab.url.startsWith("http")) {
          sendResponse({ error: "No active HTTP/HTTPS webpage found." });
          return;
        }
        const settings = await getSettings();
        const headers = await fetchSiteHeaders(tab.url);
        const audit = analyzeWebsiteVulnerabilities(tab.url, headers, settings.extraTrustedDomains);
        sendResponse({ tabUrl: tab.url, tabTitle: tab.title, audit });
      } catch (err) {
        sendResponse({ error: String(err) });
      }
    })();
    return true;
  }
  if (message.type === "SD_EMAIL_SCAN_NOW") {
    scanEmailInbox({ manual: true }).then(sendResponse);
    return true;
  }
  return false;
});

chrome.notifications.onButtonClicked.addListener(async (notificationId, buttonIndex) => {
  if (notificationId.startsWith("sd_email_")) {
    chrome.action.openPopup().catch(() => {});
    return;
  }
  const downloadId = Number(notificationId.replace("sd_", ""));
  const entry = await getInFlightScan(downloadId);
  if (!entry) return;

  const isDangerous = entry.record.riskLevel === "dangerous";
  if (isDangerous && buttonIndex === 0) {
    await resolveDownload(downloadId, "deleted");
  } else {
    chrome.action.openPopup().catch(() => {});
  }
});