// popup/popup.js
import { WEIGHTS } from "../modules/config.js";
import { getHistory, getStats, getEmailHistory, getSettings } from "../modules/storageManager.js";
import { isGmailConnected } from "../modules/emailAuth.js";
import { getAiAvailability, explainDownloadScan } from "../modules/aiAnalysis.js";

function escapeHtml(str) {
  if (typeof str !== "string") return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

const FACTOR_META = [
  {
    key: "officialWebsite",
    label: "Official Website",
    from: (r) => r.details.source.officialWebsiteScore,
    reason: (r) => r.details.source.isKnownOfficial ? "Verified official publisher domain" : r.details.source.looksLikeTyposquat ? `Possible impersonation of ${r.details.source.suspiciouslyCloseTo}` : "Unverified third-party host",
    applicable: () => true
  },
  {
    key: "publisherVerification",
    label: "Publisher Trust",
    from: (r) => r.details.publisher.publisherVerificationScore,
    reason: (r) => r.details.publisher.claimedPublisher ? `Recognized vendor: ${r.details.publisher.claimedPublisher}` : "Unknown software vendor signature",
    applicable: () => true
  },
  {
    key: "virusTotal",
    label: "VirusTotal",
    from: (r) => r.details.virusTotal.vtScore,
    reason: (r) => r.details.virusTotal.status === "not_configured" ? "API key not configured in Settings" : `${r.details.virusTotal.malicious || 0} engine flags`,
    applicable: (r) => r.details.virusTotal.status !== "not_configured"
  },
  {
    key: "staticAnalysis",
    label: "Byte-Level Scan",
    from: (r) => r.details.staticAnalysis.staticAnalysisScore,
    reason: (r) => r.details.staticAnalysis.reason || (r.details.staticAnalysis.findings?.length ? r.details.staticAnalysis.findings[0].label : "Passed structural bytecode checks"),
    applicable: (r) => r.details.staticAnalysis && r.details.staticAnalysis.status !== "no_content"
  },
  {
    key: "vulnerability",
    label: "Vulnerabilities",
    from: (r) => r.details.vulnerability.vulnerabilityScore,
    reason: (r) => r.details.vulnerability.status === "cves_found" ? `${r.details.vulnerability.cves.length} CVEs matched version` : "No known CVE matches",
    applicable: (r) => !["no_version_detected", "error"].includes(r.details.vulnerability.status)
  },
  {
    key: "https",
    label: "HTTPS Security",
    from: (r) => r.details.https.httpsScore,
    reason: (r) => r.details.https.isHttps ? "TLS/SSL Encrypted transfer" : "Insecure cleartext HTTP transfer",
    applicable: () => true
  },
  {
    key: "fileIntegrity",
    label: "File Integrity",
    from: (r) => r.details.integrity.integrityScore,
    reason: (r) => r.details.integrity.status === "matches_known_good" ? "Exact SHA-256 hash match" : r.details.integrity.status === "hash_mismatch_possible_tampering" ? "Hash mismatch detected" : "No baseline hash configured",
    applicable: (r) => ["matches_known_good", "hash_mismatch_possible_tampering"].includes(r.details.integrity.status)
  },
  {
    key: "sourceReputation",
    label: "Source Rep.",
    from: (r) => r.details.source.sourceReputationScore,
    reason: (r) => r.details.source.isKnownOfficial ? "High reputation distribution CDN" : "Standard domain reputation",
    applicable: () => true
  }
];

const GAUGE_R = 72;
const GAUGE_CIRCUMFERENCE = 2 * Math.PI * GAUGE_R;
const FACTOR_R = 84;
const FACTOR_CIRCUMFERENCE = 2 * Math.PI * FACTOR_R;

const els = {
  tabDownload: document.getElementById("tabDownload"),
  tabWebsite: document.getElementById("tabWebsite"),
  tabHistory: document.getElementById("tabHistory"),
  tabEmail: document.getElementById("tabEmail"),
  downloadView: document.getElementById("downloadView"),
  websiteView: document.getElementById("websiteView"),
  historyPanel: document.getElementById("historyPanel"),
  emailPanel: document.getElementById("emailPanel"),
  emptyState: document.getElementById("emptyState"),
  resultView: document.getElementById("resultView"),
  fileExtBadge: document.getElementById("fileExtBadge"),
  fileName: document.getElementById("fileName"),
  fileDomain: document.getElementById("fileDomain"),
  gaugeSvg: document.getElementById("gaugeSvg"),
  gaugeProgress: document.getElementById("gaugeProgress"),
  gaugeFactorTrack: document.getElementById("gaugeFactorTrack"),
  gaugeScore: document.getElementById("gaugeScore"),
  gaugeRiskBadge: document.getElementById("gaugeRiskBadge"),
  gaugeRiskLabel: document.getElementById("gaugeRiskLabel"),
  recommendationBanner: document.getElementById("recommendationBanner"),
  recIcon: document.getElementById("recIcon"),
  recHeadline: document.getElementById("recHeadline"),
  recDetail: document.getElementById("recDetail"),
  factorList: document.getElementById("factorList"),
  aiExplainSection: document.getElementById("aiExplainSection"),
  aiExplainBtn: document.getElementById("aiExplainBtn"),
  aiExplainBtnText: document.getElementById("aiExplainBtnText"),
  aiNarrativeBox: document.getElementById("aiNarrativeBox"),
  aiNarrativeText: document.getElementById("aiNarrativeText"),
  aiReasonsList: document.getElementById("aiReasonsList"),
  aiConcernText: document.getElementById("aiConcernText"),
  resumeBtn: document.getElementById("resumeBtn"),
  deleteBtn: document.getElementById("deleteBtn"),
  exportReportBtn: document.getElementById("exportReportBtn"),
  scanActiveTabBtn: document.getElementById("scanActiveTabBtn"),
  scanBtnText: document.getElementById("scanBtnText"),
  webDomain: document.getElementById("webDomain"),
  webSslBadge: document.getElementById("webSslBadge"),
  webScoreRing: document.getElementById("webScoreRing"),
  webScoreBadge: document.getElementById("webScoreBadge"),
  hstsStatus: document.getElementById("hstsStatus"),
  cspStatus: document.getElementById("cspStatus"),
  corsStatus: document.getElementById("corsStatus"),
  xfoStatus: document.getElementById("xfoStatus"),
  vulnList: document.getElementById("vulnList"),
  historyList: document.getElementById("historyList"),
  statsLine: document.getElementById("statsLine"),
  optionsBtn: document.getElementById("optionsBtn"),
  emailScanNowBtn: document.getElementById("emailScanNowBtn"),
  emailScanBtnText: document.getElementById("emailScanBtnText"),
  emailConnectionStatus: document.getElementById("emailConnectionStatus"),
  emailHistoryList: document.getElementById("emailHistoryList")
};

let currentRecord = null;
let displayedScore = 0;
let animationFrameId = null;
let aiExplanationsEnabled = false;

init();

async function init() {
  wireTabsAndButtons();
  if (els.gaugeProgress) {
    els.gaugeProgress.style.strokeDasharray = `${GAUGE_CIRCUMFERENCE}`;
    els.gaugeProgress.style.strokeDashoffset = `${GAUGE_CIRCUMFERENCE}`;
  }

  const settings = await getSettings().catch(() => ({}));
  aiExplanationsEnabled = Boolean(settings.aiExplanationsEnabled);

  const { pending } = await chrome.runtime.sendMessage({ type: "SD_GET_PENDING" }).catch(() => ({ pending: [] }));
  if (pending && pending.length) {
    renderResult(pending[0]);
  } else {
    const history = await getHistory();
    if (history.length) {
      renderResult(history[0], { readOnly: true });
    } else {
      els.emptyState.classList.remove("hidden");
      els.resultView.classList.add("hidden");
    }
  }

  renderStatsLine();
  autoScanActiveTabIfOnWebTab();
}

function wireTabsAndButtons() {
  els.optionsBtn.addEventListener("click", () => chrome.runtime.openOptionsPage());

  els.tabDownload.addEventListener("click", () => switchTab("download"));
  els.tabWebsite.addEventListener("click", () => {
    switchTab("website");
    triggerActiveTabScan();
  });
  els.tabHistory.addEventListener("click", () => {
    switchTab("history");
    renderHistoryView();
  });
  els.tabEmail.addEventListener("click", () => {
    switchTab("email");
    renderEmailView();
  });

  els.scanActiveTabBtn.addEventListener("click", triggerActiveTabScan);
  els.resumeBtn.addEventListener("click", () => resolveCurrent("resumed"));
  els.deleteBtn.addEventListener("click", () => resolveCurrent("deleted"));
  els.exportReportBtn.addEventListener("click", exportAuditReport);
  els.emailScanNowBtn.addEventListener("click", triggerEmailScanNow);
  els.aiExplainBtn.addEventListener("click", onAiExplainClick);
}

async function onAiExplainClick() {
  if (!currentRecord) return;
  els.aiExplainBtn.disabled = true;
  els.aiNarrativeBox.classList.add("hidden");
  els.aiExplainBtnText.textContent = "Checking on-device model…";

  const availability = await getAiAvailability();
  if (availability === "unsupported") {
    els.aiExplainBtnText.textContent = "AI unavailable — update Chrome to use this";
    els.aiExplainBtn.disabled = false;
    return;
  }
  if (availability === "unavailable") {
    els.aiExplainBtnText.textContent = "On-device AI not available on this device";
    els.aiExplainBtn.disabled = false;
    return;
  }

  els.aiExplainBtnText.textContent = availability === "available"
    ? "Generating explanation…"
    : "Downloading on-device model…";

  const result = await explainDownloadScan(currentRecord, (pct) => {
    if (availability !== "available") {
      els.aiExplainBtnText.textContent = `Downloading on-device model… ${pct}%`;
    }
  });

  els.aiExplainBtn.disabled = false;
  els.aiExplainBtnText.textContent = "Explain with On-Device AI";

  if (!result.ok) {
    const messages = {
      unsupported: "This version of Chrome doesn't support on-device AI.",
      unavailable: "On-device AI isn't available on this device.",
      timed_out: "The on-device model took too long to respond. Try again.",
      error: "Couldn't generate an explanation right now."
    };
    els.aiNarrativeText.textContent = messages[result.reason] || messages.error;
    els.aiReasonsList.innerHTML = "";
    els.aiConcernText.classList.add("hidden");
    els.aiNarrativeBox.classList.remove("hidden");
    return;
  }

  els.aiNarrativeText.textContent = result.narrative;
  els.aiReasonsList.innerHTML = result.topReasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("");
  if (result.additionalConcern) {
    els.aiConcernText.textContent = `⚠ Worth a second look: ${result.additionalConcern}`;
    els.aiConcernText.classList.remove("hidden");
  } else {
    els.aiConcernText.classList.add("hidden");
  }
  els.aiNarrativeBox.classList.remove("hidden");
}

function exportAuditReport() {
  if (!currentRecord) return;
  const reportPayload = {
    reportTitle: "SecureDownload AI - Security Audit Report",
    generatedAt: new Date().toISOString(),
    fileDetails: {
      filename: currentRecord.filename,
      category: currentRecord.category,
      domain: currentRecord.domain,
      sourceUrl: currentRecord.url,
      trustScore: currentRecord.trustScore,
      riskLevel: currentRecord.riskLevel
    },
    recommendation: currentRecord.recommendation,
    securityChecks: currentRecord.details
  };

  const jsonStr = JSON.stringify(reportPayload, null, 2);
  const blob = new Blob([jsonStr], { type: "application/json" });
  const blobUrl = URL.createObjectURL(blob);
  const safeFilename = `security-report-${currentRecord.filename.replace(/[^a-zA-Z0-9_-]/g, "_")}.json`;

  const downloadLink = document.createElement("a");
  downloadLink.href = blobUrl;
  downloadLink.download = safeFilename;
  document.body.appendChild(downloadLink);
  downloadLink.click();
  document.body.removeChild(downloadLink);
  URL.revokeObjectURL(blobUrl);
}

function switchTab(target) {
  els.tabDownload.classList.toggle("active", target === "download");
  els.tabWebsite.classList.toggle("active", target === "website");
  els.tabHistory.classList.toggle("active", target === "history");
  els.tabEmail.classList.toggle("active", target === "email");

  els.downloadView.classList.toggle("hidden", target !== "download");
  els.websiteView.classList.toggle("hidden", target !== "website");
  els.historyPanel.classList.toggle("hidden", target !== "history");
  els.emailPanel.classList.toggle("hidden", target !== "email");
}

async function renderEmailView() {
  const connected = await isGmailConnected();
  els.emailConnectionStatus.textContent = connected
    ? "Gmail connected — scanning recent inbox mail."
    : "Gmail not connected. Open Settings to connect your account.";
  await renderEmailHistoryView();
}

async function triggerEmailScanNow() {
  els.emailScanBtnText.textContent = "Scanning...";
  const result = await chrome.runtime.sendMessage({ type: "SD_EMAIL_SCAN_NOW" }).catch(() => null);
  els.emailScanBtnText.textContent = "Scan Inbox Now";
  if (result?.error === "not_connected") {
    els.emailConnectionStatus.textContent = "Gmail not connected. Open Settings to connect your account.";
  } else {
    await renderEmailHistoryView();
  }
}

async function renderEmailHistoryView() {
  const history = await getEmailHistory();
  els.emailHistoryList.textContent = "";
  if (!history.length) {
    const emptyNotice = document.createElement("p");
    emptyNotice.className = "empty-sub text-center";
    emptyNotice.style.padding = "16px";
    emptyNotice.textContent = "No emails scanned yet.";
    els.emailHistoryList.appendChild(emptyNotice);
    return;
  }

  for (const record of history) {
    const item = document.createElement("div");
    item.className = "history-item";

    const meta = document.createElement("div");
    meta.className = "h-meta";

    const name = document.createElement("span");
    name.className = "h-name";
    name.textContent = record.subject || "(no subject)";
    name.title = record.subject || "";

    const sub = document.createElement("span");
    sub.className = "h-sub";
    sub.textContent = `${record.senderDomain || "unknown"} • ${record.riskLevel}`;

    meta.appendChild(name);
    meta.appendChild(sub);

    const badge = document.createElement("span");
    badge.className = "h-score-badge";
    const badgeColor = scoreColor(record.emailTrustScore);
    badge.style.background = `${badgeColor}20`;
    badge.style.color = badgeColor;
    badge.style.border = `1px solid ${badgeColor}40`;
    badge.textContent = `${record.emailTrustScore}`;

    item.appendChild(meta);
    item.appendChild(badge);
    els.emailHistoryList.appendChild(item);
  }
}

function renderResult(record, { readOnly = false } = {}) {
  currentRecord = record;
  els.emptyState.classList.add("hidden");
  els.resultView.classList.remove("hidden");

  const ext = (record.extension || "FILE").slice(0, 5).toUpperCase();
  els.fileExtBadge.textContent = ext;
  els.fileExtBadge.className = `file-ext-badge cat-${record.category || "other"}`;
  els.fileName.textContent = record.filename;
  els.fileName.title = record.filename;
  els.fileDomain.textContent = record.domain;

  const score = Math.max(0, Math.min(100, Math.round(record.trustScore || 0)));
  const risk = record.riskLevel || getRiskLevelText(score);
  els.gaugeRiskLabel.textContent = risk;

  updateGauge(score, record);

  const recRisk = record.recommendation ? record.recommendation.riskLevel : (score >= 80 ? "safe" : score >= 50 ? "warning" : "dangerous");
  els.recommendationBanner.className = `recommendation-banner risk-${recRisk}`;
  els.recHeadline.textContent = record.recommendation ? record.recommendation.headline : "Security Assessment Completed";
  els.recDetail.textContent = record.recommendation ? record.recommendation.detail : "Review the factor breakdown below.";

  updateRecIcon(recRisk);
  renderFactors(record);

  els.aiExplainSection.classList.toggle("hidden", !aiExplanationsEnabled);
  els.aiNarrativeBox.classList.add("hidden");
  els.aiExplainBtnText.textContent = "Explain with On-Device AI";
  els.aiExplainBtn.disabled = false;

  const pendingActions = !readOnly && record.action === "pending";
  els.resumeBtn.classList.toggle("hidden", !pendingActions);
  els.deleteBtn.classList.toggle("hidden", !pendingActions);

  if (record.websiteSecurity) {
    renderWebsiteSecurity(record.websiteSecurity);
  }
}

function updateGauge(targetScore, record) {
  const color = scoreColor(targetScore);
  document.documentElement.style.setProperty("--gauge-color", color);
  const offset = GAUGE_CIRCUMFERENCE * (1 - targetScore / 100);
  els.gaugeProgress.style.strokeDashoffset = `${offset}`;
  animateScoreCounter(targetScore);
  renderFactorSegments(record);
}

function animateScoreCounter(targetScore) {
  if (animationFrameId) cancelAnimationFrame(animationFrameId);
  const startScore = displayedScore;
  const startTime = performance.now();
  const duration = 600;

  function step(now) {
    const elapsed = now - startTime;
    const progress = Math.min(1, elapsed / duration);
    const easeProgress = 1 - (1 - progress) * (1 - progress);
    displayedScore = Math.round(startScore + (targetScore - startScore) * easeProgress);
    els.gaugeScore.textContent = displayedScore;
    if (progress < 1) {
      animationFrameId = requestAnimationFrame(step);
    } else {
      displayedScore = targetScore;
      els.gaugeScore.textContent = targetScore;
    }
  }

  animationFrameId = requestAnimationFrame(step);
}

function renderFactorSegments(record) {
  const track = els.gaugeFactorTrack;
  track.innerHTML = "";
  let currentOffset = 0;
  const gapPixels = 4;

  for (const meta of FACTOR_META) {
    const weight = WEIGHTS[meta.key] || 0.1;
    const segmentLength = weight * FACTOR_CIRCUMFERENCE;
    const visibleLength = Math.max(2, segmentLength - gapPixels);

    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("cx", "100");
    circle.setAttribute("cy", "100");
    circle.setAttribute("r", `${FACTOR_R}`);
    circle.setAttribute("fill", "none");
    circle.setAttribute("stroke-width", "3");

    const segColor = meta.applicable(record) ? scoreColor(meta.from(record)) : "rgba(255, 255, 255, 0.08)";
    circle.setAttribute("stroke", segColor);
    circle.setAttribute("stroke-dasharray", `${visibleLength} ${FACTOR_CIRCUMFERENCE - visibleLength}`);
    circle.setAttribute("stroke-dashoffset", `${-currentOffset}`);

    track.appendChild(circle);
    currentOffset += segmentLength;
  }
}

function scoreColor(score) {
  if (score >= 80) return "var(--accent-safe)";
  if (score >= 50) return "var(--accent-warn)";
  return "var(--accent-danger)";
}

function getRiskLevelText(score) {
  if (score >= 80) return "SAFE";
  if (score >= 50) return "CAUTION";
  return "HIGH RISK";
}

function updateRecIcon(riskLevel) {
  if (riskLevel === "safe") {
    els.recIcon.innerHTML = `
      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
      <polyline points="22 4 12 14.01 9 11.01"/>
    `;
  } else if (riskLevel === "warning") {
    els.recIcon.innerHTML = `
      <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3z"/>
      <line x1="12" y1="9" x2="12" y2="13"/>
      <line x1="12" y1="17" x2="12.01" y2="17"/>
    `;
  } else {
    els.recIcon.innerHTML = `
      <circle cx="12" cy="12" r="10"/>
      <line x1="15" y1="9" x2="9" y2="15"/>
      <line x1="9" y1="9" x2="15" y2="15"/>
    `;
  }
}

function renderFactors(record) {
  els.factorList.innerHTML = "";
  for (const meta of FACTOR_META) {
    const row = document.createElement("div");
    row.className = "factor-row";

    if (!meta.applicable(record)) {
      row.innerHTML = `
        <div class="factor-row-main">
          <span class="factor-label">${meta.label}</span>
          <span class="factor-track"><span class="factor-fill factor-fill-na"></span></span>
          <span class="factor-value factor-value-na">N/A</span>
        </div>
        <span class="factor-reason">${escapeHtml(meta.reason(record))}</span>
      `;
      els.factorList.appendChild(row);
      continue;
    }

    const score = Math.round(meta.from(record));
    row.innerHTML = `
      <div class="factor-row-main">
        <span class="factor-label">${meta.label}</span>
        <span class="factor-track"><span class="factor-fill" style="width:${score}%;background:${scoreColor(score)}"></span></span>
        <span class="factor-value">${score}%</span>
      </div>
      <span class="factor-reason">${escapeHtml(meta.reason(record))}</span>
    `;
    els.factorList.appendChild(row);
  }

  const { checksApplicable, checksTotal } = record;
  if (typeof checksApplicable === "number" && checksApplicable < checksTotal) {
    const note = document.createElement("div");
    note.className = "factor-note";
    note.textContent = `Score reflects ${checksApplicable} of ${checksTotal} active checks. Set API keys in Settings for VirusTotal scans.`;
    els.factorList.appendChild(note);
  }

  renderStaticFindings(record.details?.staticAnalysis);
}

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

// Renders each finding as evidence rather than a bullet: what was observed,
// why it matters in plain language, and the raw observation behind it. A user
// can act on "imports VirtualAllocEx, WriteProcessMemory, CreateRemoteThread";
// they cannot act on a number.
function renderStaticFindings(staticAnalysis) {
  const findings = staticAnalysis?.findings || [];
  if (!findings.length) return;

  const sorted = [...findings].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)
  );

  const box = document.createElement("div");
  box.className = "evidence-block";

  const heading = document.createElement("div");
  heading.className = "evidence-heading";
  heading.textContent = `File inspection: ${findings.length} finding${findings.length === 1 ? "" : "s"}`;
  box.appendChild(heading);

  for (const f of sorted) {
    const card = document.createElement("div");
    card.className = `evidence-card evidence-${escapeHtml(f.severity)}`;

    const mitreTag = f.mitre
      ? `<span class="evidence-mitre">${escapeHtml(f.mitre)}</span>`
      : "";
    const evidenceLines = (f.evidence || []).length
      ? `<ul class="evidence-detail">${f.evidence
          .map(e => `<li><code>${escapeHtml(e)}</code></li>`)
          .join("")}</ul>`
      : "";

    card.innerHTML = `
      <div class="evidence-top">
        <span class="evidence-sev">${escapeHtml(f.severity)}</span>
        <span class="evidence-title">${escapeHtml(f.label)}</span>
        ${mitreTag}
      </div>
      ${f.explain ? `<p class="evidence-explain">${escapeHtml(f.explain)}</p>` : ""}
      ${evidenceLines}
    `;
    box.appendChild(card);
  }

  const structure = staticAnalysis.structure;
  if (structure?.type === "pe") {
    const note = document.createElement("div");
    note.className = "evidence-structure";
    const dlls = (structure.importedDlls || []).slice(0, 6).join(", ") || "none";
    note.textContent =
      `Windows executable · ${structure.machine} · ${structure.subsystem} · ` +
      `${structure.signed ? "signed" : "unsigned"} · ` +
      `${structure.importedFunctionCount} imports from ${dlls}`;
    box.appendChild(note);
  } else if (structure?.type === "zip") {
    const note = document.createElement("div");
    note.className = "evidence-structure";
    note.textContent = `Archive · ${structure.entryCount} entries · ${structure.entries.slice(0, 4).join(", ")}`;
    box.appendChild(note);
  }

  els.factorList.appendChild(box);
}

async function triggerActiveTabScan() {
  els.scanBtnText.textContent = "Auditing Webpage Security...";
  const res = await chrome.runtime.sendMessage({ type: "SD_GET_ACTIVE_TAB_SECURITY" }).catch(() => null);
  els.scanBtnText.textContent = "Scan Current Webpage";
  if (res && res.audit) {
    renderWebsiteSecurity(res.audit);
  } else if (res && res.error) {
    els.vulnList.innerHTML = `<p class="empty-sub text-center" style="padding:16px;color:var(--accent-warn)">${escapeHtml(res.error)}</p>`;
  }
}

async function autoScanActiveTabIfOnWebTab() {
  chrome.tabs.query({ active: true, currentWindow: true }, async ([tab]) => {
    if (tab && tab.url && tab.url.startsWith("http")) {
      const res = await chrome.runtime.sendMessage({ type: "SD_ANALYZE_WEBSITE", url: tab.url }).catch(() => null);
      if (res && res.audit) {
        renderWebsiteSecurity(res.audit);
      }
    }
  });
}

function renderWebsiteSecurity(audit) {
  els.webDomain.textContent = audit.domain || "website";
  els.webSslBadge.textContent = audit.isHttps ? "HTTPS SSL" : "INSECURE HTTP";
  els.webSslBadge.className = `badge ${audit.isHttps ? "badge-safe" : "badge-danger"}`;

  const score = audit.websiteSecurityScore ?? 50;
  els.webScoreBadge.textContent = score;
  els.webScoreRing.style.background = scoreColor(score);

  const sh = audit.securityHeaders || {};
  setValPill(els.hstsStatus, sh.hsts !== "Not Set", sh.hsts);
  setValPill(els.cspStatus, sh.csp !== "Not Set", sh.csp);
  setValPill(els.corsStatus, sh.cors !== "*", sh.cors);
  setValPill(els.xfoStatus, sh.xfo !== "Not Set", sh.xfo);

  els.vulnList.innerHTML = "";
  const vulns = audit.vulnerabilities || [];
  if (!vulns.length) {
    els.vulnList.innerHTML = `
      <div class="vuln-card clean">
        <div class="vuln-header">
          <span class="v-title">✓ No Critical Vulnerabilities Detected</span>
          <span class="threat-tag level-safe">SECURE</span>
        </div>
        <p class="v-harm text-muted">The website enforces HTTPS, security headers, and domain trust parameters.</p>
      </div>
    `;
    return;
  }

  for (const v of vulns) {
    const card = document.createElement("div");
    const threatClass = `level-${escapeHtml((v.threatLevel || "medium").toLowerCase())}`;
    const owaspTag = v.owaspCategory ? `<div class="owasp-badge">${escapeHtml(v.owaspCategory)}</div>` : "";

    card.className = "vuln-card";
    card.innerHTML = `
      <div class="vuln-header">
        <span class="v-title">${escapeHtml(v.title)}</span>
        <span class="threat-tag ${threatClass}">${escapeHtml(v.threatLevel.toUpperCase())} THREAT</span>
      </div>
      ${owaspTag}
      <div class="harm-box">
        <span class="harm-title">Unethical Harm & Exploit Risk</span>
        <p class="v-harm">${escapeHtml(v.unethicalHarm)}</p>
      </div>
    `;
    els.vulnList.appendChild(card);
  }
}

function setValPill(el, isGood, text) {
  el.textContent = text || (isGood ? "Active" : "Missing");
  el.className = `h-val ${isGood ? "val-good" : "val-warn"}`;
}

async function resolveCurrent(action) {
  if (!currentRecord) return;
  await chrome.runtime.sendMessage({
    type: "SD_RESOLVE_DOWNLOAD",
    downloadId: currentRecord.downloadId,
    action
  });
  currentRecord.action = action;
  els.resumeBtn.classList.add("hidden");
  els.deleteBtn.classList.add("hidden");
  renderStatsLine();
}

async function renderStatsLine() {
  const stats = await getStats();
  els.statsLine.textContent = `${stats.totalScanned} scanned • ${stats.filesBlocked} blocked`;
}

async function renderHistoryView() {
  const history = await getHistory();
  els.historyList.innerHTML = "";
  if (!history.length) {
    els.historyList.innerHTML = `<p style="color:var(--text-muted);font-size:12px;padding:12px 6px;">No scan audit history recorded yet.</p>`;
  } else {
    for (const record of history) {
      const item = document.createElement("div");
      item.className = "history-item";
      const badgeColor = scoreColor(record.trustScore);
      item.innerHTML = `
        <div class="h-meta">
          <span class="h-name" title="${escapeHtml(record.filename)}">${escapeHtml(record.filename)}</span>
          <span class="h-sub">${escapeHtml(record.domain)} • ${escapeHtml((record.extension || "file").toUpperCase())}</span>
        </div>
        <span class="h-score-badge" style="background:${badgeColor}20;color:${badgeColor};border:1px solid ${badgeColor}40">${record.trustScore}</span>
      `;
      item.addEventListener("click", () => {
        switchTab("download");
        renderResult(record, { readOnly: true });
      });
      els.historyList.appendChild(item);
    }
  }
}

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "SD_ANALYSIS_COMPLETE") {
    renderResult(message.record);
    renderStatsLine();
  }
});