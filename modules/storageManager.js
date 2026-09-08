// modules/storageManager.js
// Module 10: Storage Manager.
// Single place that touches chrome.storage.local, so every other module
// deals with plain JS objects instead of the callback/promise storage API.

import { MAX_HISTORY_ITEMS, CACHE_TTL_MS, KNOWN_PUBLISHERS } from "./config.js";

const KEYS = {
  history: "sd_history",
  stats: "sd_stats",
  cache: "sd_cache",           // { [cacheKey]: { value, expiresAt } }
  settings: "sd_settings",     // API keys, trusted domains, known-good hashes
  remotePublishers: "sd_remote_publishers",
  emailHistory: "sd_email_history",
  emailStats: "sd_email_stats",
  emailScannedIds: "sd_email_scanned_ids" // bounded set of Gmail message IDs already scanned
};

const MAX_EMAIL_HISTORY_ITEMS = 200;
const MAX_SCANNED_ID_CACHE = 1000;

export async function saveEmailScanRecord(record) {
  const { [KEYS.emailHistory]: history = [] } = await chrome.storage.local.get(KEYS.emailHistory);
  const existingIdx = history.findIndex(h => h.messageId === record.messageId);
  let updated;
  if (existingIdx >= 0) {
    updated = [...history];
    updated[existingIdx] = record;
  } else {
    updated = [record, ...history].slice(0, MAX_EMAIL_HISTORY_ITEMS);
    await bumpEmailStats(record);
  }
  await chrome.storage.local.set({ [KEYS.emailHistory]: updated });
  return updated;
}

export async function getEmailHistory() {
  const { [KEYS.emailHistory]: history = [] } = await chrome.storage.local.get(KEYS.emailHistory);
  return history;
}

export async function getEmailStats() {
  const { [KEYS.emailStats]: stats = defaultEmailStats() } = await chrome.storage.local.get(KEYS.emailStats);
  return stats;
}

function defaultEmailStats() {
  return { totalScanned: 0, safe: 0, suspicious: 0, phishing: 0 };
}

async function bumpEmailStats(record) {
  const stats = await getEmailStats();
  stats.totalScanned += 1;
  if (record.riskLevel === "safe") stats.safe += 1;
  else if (record.riskLevel === "warning") stats.suspicious += 1;
  else if (record.riskLevel === "dangerous") stats.phishing += 1;
  await chrome.storage.local.set({ [KEYS.emailStats]: stats });
}

// Tracks which Gmail message IDs have already been scanned so periodic
// alarms don't re-fetch/re-score the same inbox repeatedly.
export async function getScannedEmailIds() {
  const { [KEYS.emailScannedIds]: ids = [] } = await chrome.storage.local.get(KEYS.emailScannedIds);
  return new Set(ids);
}

export async function markEmailIdsScanned(newIds = []) {
  const existing = await getScannedEmailIds();
  for (const id of newIds) existing.add(id);
  // Bound the set — keep the most recently added tail.
  const trimmed = [...existing].slice(-MAX_SCANNED_ID_CACHE);
  await chrome.storage.local.set({ [KEYS.emailScannedIds]: trimmed });
}

export async function getPublisherList() {
  try {
    const { [KEYS.remotePublishers]: remote } = await chrome.storage.local.get(KEYS.remotePublishers);
    if (Array.isArray(remote) && remote.length > 0) {
      return remote;
    }
  } catch (err) {
    console.warn("[SecureDownload AI] error reading remote publishers from storage:", err);
  }
  return KNOWN_PUBLISHERS;
}

// NOTE: a previous version of this file shipped a `refreshRemotePublishers()`
// that fetched a publisher list from a hardcoded, unowned GitHub URL and
// wholesale-replaced the trusted-publisher list with whatever it returned —
// no signature check, no merge/diff, no user visibility. That's a real
// trust-list-poisoning vector for a security tool and was never actually
// wired to any UI. Removed rather than fixed in place: if this feature is
// wanted later, it needs an explicit user-supplied URL (no silent default),
// a merge (not replace) against KNOWN_PUBLISHERS, and a review step before
// entries are trusted.

export async function saveScanRecord(record) {

  const { [KEYS.history]: history = [] } = await chrome.storage.local.get(KEYS.history);
  const existingIdx = history.findIndex(h => h.downloadId === record.downloadId);
  let updated;
  if (existingIdx >= 0) {
    updated = [...history];
    updated[existingIdx] = record;
  } else {
    updated = [record, ...history].slice(0, MAX_HISTORY_ITEMS);
    await bumpStats(record);
  }
  await chrome.storage.local.set({ [KEYS.history]: updated });
  return updated;
}


export async function getHistory() {
  const { [KEYS.history]: history = [] } = await chrome.storage.local.get(KEYS.history);
  return history;
}

export async function getStats() {
  const { [KEYS.stats]: stats = defaultStats() } = await chrome.storage.local.get(KEYS.stats);
  return stats;
}

function defaultStats() {
  return { totalScanned: 0, safe: 0, warning: 0, dangerous: 0, filesBlocked: 0 };
}

async function bumpStats(record) {
  const stats = await getStats();
  stats.totalScanned += 1;
  if (record.riskLevel === "safe") stats.safe += 1;
  else if (record.riskLevel === "warning") stats.warning += 1;
  else if (record.riskLevel === "dangerous") stats.dangerous += 1;
  if (record.action === "deleted") stats.filesBlocked += 1;
  await chrome.storage.local.set({ [KEYS.stats]: stats });
}

export async function getCached(key) {
  const { [KEYS.cache]: cache = {} } = await chrome.storage.local.get(KEYS.cache);
  const entry = cache[key];
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) return null;
  return entry.value;
}

export async function setCached(key, value, ttlMs = CACHE_TTL_MS.virusTotal) {
  const { [KEYS.cache]: cache = {} } = await chrome.storage.local.get(KEYS.cache);
  cache[key] = { value, expiresAt: Date.now() + ttlMs };
  await chrome.storage.local.set({ [KEYS.cache]: cache });
}

// Expired entries were previously only ever dropped lazily, on the exact
// key being re-read after expiry — which almost never happens, since cache
// keys are per-file-hash/per-URL and rarely repeat. That left the single
// `sd_cache` object growing without bound for as long as the extension was
// used. Since it's one object under one storage key, growth here also means
// every single get/set pays the cost of reading/writing the whole blob, not
// just an unbounded key count — worth pruning on a schedule, not just
// capping. Called from a periodic chrome.alarms handler in background.js.
export async function pruneExpiredCache() {
  const { [KEYS.cache]: cache = {} } = await chrome.storage.local.get(KEYS.cache);
  const now = Date.now();
  let removed = 0;
  for (const key of Object.keys(cache)) {
    if (!cache[key] || now > cache[key].expiresAt) {
      delete cache[key];
      removed++;
    }
  }
  if (removed > 0) {
    await chrome.storage.local.set({ [KEYS.cache]: cache });
  }
  return removed;
}

export async function getSettings() {
  const { [KEYS.settings]: settings = defaultSettings() } = await chrome.storage.local.get(KEYS.settings);
  return settings;
}

export async function saveSettings(partial) {
  const current = await getSettings();
  const updated = { ...current, ...partial };
  await chrome.storage.local.set({ [KEYS.settings]: updated });
  return updated;
}

function defaultSettings() {
  return {
    virusTotalApiKey: "",
    safeBrowsingApiKey: "",
    nvdApiKey: "",
    extraTrustedDomains: [],
    blockedDomains: [],       // user-defined hard blocklist, see modules/domainBlocklist.js
    knownGoodHashes: {},        // { filename_lowercase: sha256 }
    autoAnalyze: true,
    blockDangerousByDefault: false,
    // Off by default: uploading sends the actual file bytes to VirusTotal,
    // which is a real privacy tradeoff a hash lookup doesn't have. Only
    // applies when the hash is unseen and the file is under the size cap.
    allowVirusTotalUpload: false,
    // Email security (Gmail, OAuth) — see modules/emailAuth.js
    emailScanEnabled: false,
    emailScanIntervalMinutes: 15,
    emailMaxMessagesPerScan: 25,
    // On-device AI narrative (Chrome's built-in Prompt API / Gemini Nano) —
    // see modules/aiAnalysis.js. Nothing ever leaves the device for this
    // feature, but it's still opt-in because the *first* use on a given
    // device can trigger a multi-gigabyte model download — that's the
    // tradeoff, not privacy.
    aiExplanationsEnabled: false
  };
}
