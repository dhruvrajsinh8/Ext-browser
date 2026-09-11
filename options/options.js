// options/options.js

import { getSettings, saveSettings } from "../modules/storageManager.js";
import { connectGmail, disconnectGmail, isGmailConnected, getStoredClientId } from "../modules/emailAuth.js";

const els = {
  geminiKey: document.getElementById("geminiKey"),
  vtKey: document.getElementById("vtKey"),
  sbKey: document.getElementById("sbKey"),
  mbKey: document.getElementById("mbKey"),
  uhKey: document.getElementById("uhKey"),
  nvdKey: document.getElementById("nvdKey"),
  autoAnalyze: document.getElementById("autoAnalyze"),
  blockDangerous: document.getElementById("blockDangerous"),
  enableWebsiteScanOverlay: document.getElementById("enableWebsiteScanOverlay"),
  enableDownloadOverlay: document.getElementById("enableDownloadOverlay"),
  allowVtUpload: document.getElementById("allowVtUpload"),
  trustedDomains: document.getElementById("trustedDomains"),
  knownHashes: document.getElementById("knownHashes"),
  aiExplanationsEnabled: document.getElementById("aiExplanationsEnabled"),
  bypassedDomainsList: document.getElementById("bypassedDomainsList"),
  clearBypassesBtn: document.getElementById("clearBypassesBtn"),
  saveBtn: document.getElementById("saveBtn"),
  savedMsg: document.getElementById("savedMsg"),

  gmailClientId: document.getElementById("gmailClientId"),
  connectGmailBtn: document.getElementById("connectGmailBtn"),
  disconnectGmailBtn: document.getElementById("disconnectGmailBtn"),
  gmailStatus: document.getElementById("gmailStatus"),
  emailScanEnabled: document.getElementById("emailScanEnabled"),
  emailScanInterval: document.getElementById("emailScanInterval"),
  emailMaxMessages: document.getElementById("emailMaxMessages")
};

init();

async function init() {
  const settings = await getSettings();
  els.geminiKey.value = settings.geminiApiKey || "";
  els.vtKey.value = settings.virusTotalApiKey || "";
  els.sbKey.value = settings.safeBrowsingApiKey || "";
  els.mbKey.value = settings.malwareBazaarApiKey || "";
  els.uhKey.value = settings.urlhausApiKey || "";
  els.nvdKey.value = settings.nvdApiKey || "";
  els.autoAnalyze.checked = settings.autoAnalyze !== false;
  els.blockDangerous.checked = Boolean(settings.blockDangerousByDefault);
  els.enableWebsiteScanOverlay.checked = settings.enableWebsiteScanOverlay !== false;
  els.enableDownloadOverlay.checked = settings.enableDownloadOverlay !== false;
  els.allowVtUpload.checked = Boolean(settings.allowVirusTotalUpload);
  els.trustedDomains.value = (settings.extraTrustedDomains || []).join("\n");
  els.aiExplanationsEnabled.checked = settings.aiExplanationsEnabled !== false;
  els.knownHashes.value = Object.entries(settings.knownGoodHashes || {})
    .map(([name, hash]) => `${name} = ${hash}`)
    .join("\n");

  const bypassed = settings.bypassedWarningDomains || [];
  if (els.bypassedDomainsList) {
    els.bypassedDomainsList.textContent = bypassed.length
      ? bypassed.join(", ")
      : "No active bypasses.";
  }

  els.emailScanEnabled.checked = Boolean(settings.emailScanEnabled);
  els.emailScanInterval.value = settings.emailScanIntervalMinutes || 15;
  els.emailMaxMessages.value = settings.emailMaxMessagesPerScan || 25;
  els.gmailClientId.value = await getStoredClientId();

  els.saveBtn.addEventListener("click", onSave);
  if (els.clearBypassesBtn) {
    els.clearBypassesBtn.addEventListener("click", async () => {
      await chrome.runtime.sendMessage({ type: "SD_CLEAR_BYPASS_DOMAINS" });
      if (els.bypassedDomainsList) {
        els.bypassedDomainsList.textContent = "No active bypasses.";
      }
    });
  }
  els.connectGmailBtn.addEventListener("click", onConnectGmail);
  els.disconnectGmailBtn.addEventListener("click", onDisconnectGmail);

  await refreshGmailStatus();
}

async function refreshGmailStatus() {
  const connected = await isGmailConnected();
  els.gmailStatus.textContent = connected
    ? "✅ Gmail connected — read-only access."
    : "Not connected. Enter your Client ID above and click Connect.";
}

async function onConnectGmail() {
  els.connectGmailBtn.disabled = true;
  els.gmailStatus.textContent = "Opening Google sign-in…";
  const result = await connectGmail(els.gmailClientId.value);
  els.connectGmailBtn.disabled = false;

  if (result.ok) {
    await refreshGmailStatus();
  } else {
    els.gmailStatus.textContent = `❌ ${result.error}`;
  }
}

async function onDisconnectGmail() {
  await disconnectGmail();
  await refreshGmailStatus();
}

async function onSave() {
  const extraTrustedDomains = els.trustedDomains.value
    .split("\n")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);

  const knownGoodHashes = {};
  for (const line of els.knownHashes.value.split("\n")) {
    const [name, hash] = line.split("=").map((s) => s && s.trim());
    if (name && hash) knownGoodHashes[name.toLowerCase()] = hash;
  }

  await saveSettings({
    geminiApiKey: els.geminiKey.value.trim(),
    virusTotalApiKey: els.vtKey.value.trim(),
    safeBrowsingApiKey: els.sbKey.value.trim(),
    malwareBazaarApiKey: els.mbKey.value.trim(),
    urlhausApiKey: els.uhKey.value.trim(),
    nvdApiKey: els.nvdKey.value.trim(),
    autoAnalyze: els.autoAnalyze.checked,
    blockDangerousByDefault: els.blockDangerous.checked,
    enableWebsiteScanOverlay: els.enableWebsiteScanOverlay.checked,
    enableDownloadOverlay: els.enableDownloadOverlay.checked,
    allowVirusTotalUpload: els.allowVtUpload.checked,
    extraTrustedDomains,
    knownGoodHashes,
    aiExplanationsEnabled: els.aiExplanationsEnabled.checked,
    emailScanEnabled: els.emailScanEnabled.checked,
    emailScanIntervalMinutes: Math.max(5, Number(els.emailScanInterval.value) || 15),
    emailMaxMessagesPerScan: Math.min(100, Math.max(1, Number(els.emailMaxMessages.value) || 25))
  });

  els.savedMsg.classList.remove("hidden");
  setTimeout(() => els.savedMsg.classList.add("hidden"), 1800);
}
