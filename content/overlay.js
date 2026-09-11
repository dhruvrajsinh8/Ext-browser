// content/overlay.js
// On-page Security HUD & Download Guard Toast for SecureDownload AI.

(() => {
  const api = (typeof browser !== "undefined") ? browser : chrome;
  if (!api || !api.runtime) return;

  const BANNER_ID = "sd-ai-overlay-banner";
  const HUD_ROOT_ID = "sd-ai-hud-root";
  const TOAST_ROOT_ID = "sd-ai-download-toast-root";

  // ==================== 1. ClickFix & Alert Banner ====================
  const LEVEL_STYLE = {
    dangerous: { bar: "#b3261e", label: "DANGER" },
    warning:   { bar: "#9c6100", label: "CAUTION" },
    safe:      { bar: "#1a7f45", label: "OK" },
    info:      { bar: "#0b3f7d", label: "INFO" }
  };

  function removeBanner() {
    const el = document.getElementById(BANNER_ID);
    if (el) el.remove();
  }

  function showBanner({ level = "warning", title = "SecureDownload AI", detail = "" } = {}) {
    try {
      removeBanner();
      if (!document.body) return;
      const style = LEVEL_STYLE[level] || LEVEL_STYLE.info;

      const wrap = document.createElement("div");
      wrap.id = BANNER_ID;
      wrap.setAttribute("role", "alert");
      wrap.style.setProperty("border-left-color", style.bar, "important");

      const tag = document.createElement("span");
      tag.className = "sd-ai-tag";
      tag.textContent = style.label;
      tag.style.setProperty("background", style.bar, "important");

      const body = document.createElement("div");
      body.className = "sd-ai-body";
      const h = document.createElement("strong");
      h.textContent = title;
      const p = document.createElement("span");
      p.textContent = detail;
      body.appendChild(h);
      body.appendChild(p);

      const close = document.createElement("button");
      close.className = "sd-ai-close";
      close.type = "button";
      close.setAttribute("aria-label", "Dismiss");
      close.textContent = "×";
      close.addEventListener("click", removeBanner);

      wrap.appendChild(tag);
      wrap.appendChild(body);
      wrap.appendChild(close);
      document.body.appendChild(wrap);
    } catch (_e) {}
  }

  // ==================== 2. Scanning HUD Overlay ====================
  let hudState = {
    visible: false,
    minimized: false,
    step: 0,
    score: null,
    risk: null,
    domain: window.location.hostname
  };

  const HUD_STEPS = [
    "Verifying SSL/TLS Protocol & Cipher Suites",
    "Auditing HTTP Security Headers (HSTS, CSP, XFO, CORS)",
    "Checking Anti-Typosquatting & Domain Reputation",
    "Cross-referencing Threat Intelligence Databases",
    "Calculating Overall Security Posture & Grade"
  ];

  function getOrCreateHudRoot() {
    let root = document.getElementById(HUD_ROOT_ID);
    if (!root && document.body) {
      root = document.createElement("div");
      root.id = HUD_ROOT_ID;
      document.body.appendChild(root);
    }
    return root;
  }

  function renderHud() {
    const root = getOrCreateHudRoot();
    if (!root) return;
    root.innerHTML = "";

    if (!hudState.visible) return;

    if (hudState.minimized) {
      // Minimized floating shield badge
      const badge = document.createElement("div");
      badge.className = "sd-ai-shield-badge";
      const badgeColor = hudState.risk === "dangerous" ? "#ef4444" : hudState.risk === "warning" ? "#f59e0b" : "#10b981";
      badge.style.borderColor = badgeColor;

      badge.innerHTML = `
        <svg class="sd-ai-badge-icon" style="color:${badgeColor}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <polyline points="9 12 11 14 15 10"/>
        </svg>
        <span class="sd-ai-badge-score">${hudState.score != null ? hudState.score : "95"}%</span>
        <span class="sd-ai-badge-grade" style="color:${badgeColor};background:${badgeColor}25">${(hudState.risk || "SAFE").toUpperCase()}</span>
      `;
      badge.title = "SecureDownload AI: Click to expand website security details";
      badge.addEventListener("click", () => {
        hudState.minimized = false;
        renderHud();
      });
      root.appendChild(badge);
      return;
    }

    // Expanded HUD Card
    const card = document.createElement("div");
    card.className = "sd-ai-hud-card";

    // Header
    const header = document.createElement("div");
    header.className = "sd-ai-hud-header";
    header.innerHTML = `
      <div class="sd-ai-hud-brand">
        <svg class="sd-ai-radar-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
          <path d="M12 2a10 10 0 0 1 10 10"/>
        </svg>
        <span>Security Radar · ${escapeHtml(hudState.domain)}</span>
      </div>
      <div class="sd-ai-hud-actions">
        <button class="sd-ai-hud-btn" id="sd-ai-hud-minimize" title="Minimize" aria-label="Minimize">─</button>
        <button class="sd-ai-hud-btn" id="sd-ai-hud-close" title="Close" aria-label="Close">×</button>
      </div>
    `;

    // Step items
    const stepsList = document.createElement("div");
    stepsList.className = "sd-ai-steps-list";

    HUD_STEPS.forEach((stepName, idx) => {
      const stepItem = document.createElement("div");
      let statusClass = "pending";
      let icon = "";
      if (idx < hudState.step) {
        statusClass = "done";
        icon = "✓";
      } else if (idx === hudState.step) {
        statusClass = "active";
      }

      stepItem.className = `sd-ai-step-item ${statusClass}`;
      stepItem.innerHTML = `
        <span class="sd-ai-step-indicator">${icon}</span>
        <span>${stepName}</span>
      `;
      stepsList.appendChild(stepItem);
    });

    // Footer
    const isCompleted = hudState.step >= HUD_STEPS.length;
    const footer = document.createElement("div");
    footer.className = "sd-ai-hud-footer";
    const badgeColor = hudState.risk === "dangerous" ? "#ef4444" : hudState.risk === "warning" ? "#f59e0b" : "#10b981";

    footer.innerHTML = `
      <div class="sd-ai-hud-grade-wrap">
        <span class="sd-ai-hud-status-text">${isCompleted ? "Audit Complete" : "Inspecting Posture..."}</span>
      </div>
      <span class="sd-ai-badge-grade" style="color:${badgeColor};background:${badgeColor}25">
        ${isCompleted ? `${hudState.score}% ${hudState.risk.toUpperCase()}` : "SCANNING"}
      </span>
    `;

    card.appendChild(header);
    card.appendChild(stepsList);
    card.appendChild(footer);
    root.appendChild(card);

    const minBtn = card.querySelector("#sd-ai-hud-minimize");
    if (minBtn) {
      minBtn.addEventListener("click", () => {
        hudState.minimized = true;
        renderHud();
      });
    }

    const closeBtn = card.querySelector("#sd-ai-hud-close");
    if (closeBtn) {
      closeBtn.addEventListener("click", () => {
        hudState.visible = false;
        renderHud();
      });
    }
  }

  function startScanningAnimation(auditResult) {
    hudState.visible = true;
    hudState.minimized = false;
    hudState.step = 0;
    renderHud();

    let currentStep = 0;
    const interval = setInterval(() => {
      currentStep++;
      hudState.step = currentStep;
      if (currentStep >= HUD_STEPS.length) {
        clearInterval(interval);
        hudState.score = auditResult?.score ?? 95;
        hudState.risk = auditResult?.riskLevel ?? (hudState.score >= 80 ? "safe" : hudState.score >= 50 ? "warning" : "dangerous");
        renderHud();
        // Auto minimize after 4 seconds
        setTimeout(() => {
          if (hudState.visible) {
            hudState.minimized = true;
            renderHud();
          }
        }, 4000);
      } else {
        renderHud();
      }
    }, 450);
  }

  // ==================== 3. Download Guard Toast ====================
  let activeDownloads = new Map();

  function getOrCreateToastRoot() {
    let root = document.getElementById(TOAST_ROOT_ID);
    if (!root && document.body) {
      root = document.createElement("div");
      root.id = TOAST_ROOT_ID;
      document.body.appendChild(root);
    }
    return root;
  }

  function renderDownloadToast(downloadInfo) {
    const root = getOrCreateToastRoot();
    if (!root) return;
    root.innerHTML = "";

    const { downloadId, filename, state, record, autoResumed } = downloadInfo;

    const toast = document.createElement("div");
    toast.className = "sd-ai-download-toast";

    const isPending = state === "auditing";
    const ext = (filename.split(".").pop() || "FILE").toUpperCase().slice(0, 4);

    let verdictHtml = "";
    let actionButtonsHtml = "";
    let exploitHtml = "";

    if (isPending) {
      verdictHtml = `
        <div class="sd-ai-toast-verdict warning">
          <span>Auditing security integrity... Paused for safety</span>
        </div>
      `;
    } else if (record) {
      const risk = record.riskLevel || (record.trustScore >= 80 ? "safe" : record.trustScore >= 50 ? "warning" : "dangerous");
      const trustScore = record.trustScore || 0;
      const statusText = autoResumed ? "Auto-Resumed (Safe)" : (risk === "dangerous" ? "Download Held (Danger Detected)" : "Download Paused (Review Needed)");

      verdictHtml = `
        <div class="sd-ai-toast-verdict ${risk}">
          <span>${statusText}</span>
          <span>Score: ${trustScore}/100</span>
        </div>
      `;

      if (record.details?.vulnerability?.hasExploits) {
        exploitHtml = `
          <div class="sd-ai-exploit-pill">
            <span>⚠ Active Exploit / Known Vulnerability Flagged</span>
          </div>
        `;
      }

      if (!autoResumed && record.action === "pending") {
        actionButtonsHtml = `
          <div class="sd-ai-toast-actions">
            <button class="sd-ai-action-btn sd-ai-btn-resume" id="sd-resume-btn">Keep / Resume</button>
            <button class="sd-ai-action-btn sd-ai-btn-discard" id="sd-discard-btn">Discard File</button>
          </div>
        `;
      }
    }

    toast.innerHTML = `
      <div class="sd-ai-toast-header">
        <div class="sd-ai-toast-title">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <polyline points="9 12 11 14 15 10"/>
          </svg>
          <span>Download Guard</span>
        </div>
        <button class="sd-ai-hud-btn" id="sd-toast-close" title="Dismiss">×</button>
      </div>

      <div class="sd-ai-toast-file">
        <div class="sd-ai-file-icon">${escapeHtml(ext)}</div>
        <div class="sd-ai-file-meta">
          <div class="sd-ai-filename" title="${escapeHtml(filename)}">${escapeHtml(filename)}</div>
          <div class="sd-ai-file-status">${isPending ? "Deep scanning in progress..." : "Scan finished"}</div>
        </div>
      </div>

      ${verdictHtml}
      ${exploitHtml}
      ${actionButtonsHtml}
    `;

    root.appendChild(toast);

    const closeBtn = toast.querySelector("#sd-toast-close");
    if (closeBtn) {
      closeBtn.addEventListener("click", () => {
        root.innerHTML = "";
      });
    }

    const resumeBtn = toast.querySelector("#sd-resume-btn");
    if (resumeBtn) {
      resumeBtn.addEventListener("click", () => {
        api.runtime.sendMessage({ type: "SD_RESOLVE_DOWNLOAD", downloadId, action: "resumed" });
        toast.querySelector(".sd-ai-toast-verdict").textContent = "Resumed by user.";
        toast.querySelector(".sd-ai-toast-verdict").className = "sd-ai-toast-verdict safe";
        const actWrap = toast.querySelector(".sd-ai-toast-actions");
        if (actWrap) actWrap.remove();
        setTimeout(() => { root.innerHTML = ""; }, 3000);
      });
    }

    const discardBtn = toast.querySelector("#sd-discard-btn");
    if (discardBtn) {
      discardBtn.addEventListener("click", () => {
        api.runtime.sendMessage({ type: "SD_RESOLVE_DOWNLOAD", downloadId, action: "deleted" });
        toast.querySelector(".sd-ai-toast-verdict").textContent = "Download discarded & deleted.";
        toast.querySelector(".sd-ai-toast-verdict").className = "sd-ai-toast-verdict dangerous";
        const actWrap = toast.querySelector(".sd-ai-toast-actions");
        if (actWrap) actWrap.remove();
        setTimeout(() => { root.innerHTML = ""; }, 3000);
      });
    }
  }

  // ==================== 4. Message Listeners ====================
  api.runtime.onMessage.addListener((msg) => {
    if (!msg || typeof msg !== "object") return;

    if (msg.type === "SD_SHOW_OVERLAY") showBanner(msg.payload || {});
    if (msg.type === "SD_HIDE_OVERLAY") removeBanner();

    if (msg.type === "SD_TRIGGER_PAGE_SCAN_HUD") {
      startScanningAnimation(msg.audit);
    }

    if (msg.type === "SD_DOWNLOAD_STARTED") {
      activeDownloads.set(msg.downloadId, {
        downloadId: msg.downloadId,
        filename: msg.filename,
        state: "auditing"
      });
      renderDownloadToast(activeDownloads.get(msg.downloadId));
    }

    if (msg.type === "SD_DOWNLOAD_ANALYSIS_COMPLETE") {
      const entry = {
        downloadId: msg.record?.downloadId,
        filename: msg.record?.filename || "file",
        state: "completed",
        record: msg.record,
        autoResumed: msg.autoResumed
      };
      if (entry.downloadId) {
        activeDownloads.set(entry.downloadId, entry);
      }
      renderDownloadToast(entry);
    }
  });

  // Request page scan HUD trigger if enabled
  try {
    api.runtime.sendMessage({ type: "SD_PAGE_LOADED", url: window.location.href });
  } catch (_e) {}

  // ==================== 5. ClickFix Guard ====================
  const CLICKFIX_RE = /(powershell|pwsh|mshta|cmd(?:\.exe)?\s|certutil|bitsadmin|curl\s+[^\n|]*\|\s*(?:ba)?sh|wget\s+[^\n|]*\|\s*(?:ba)?sh|iex\s*\(|invoke-expression|Win\s*\+\s*R)/i;

  function inspectClipboardText(text) {
    try {
      if (typeof text === "string" && CLICKFIX_RE.test(text)) {
        showBanner({
          level: "dangerous",
          title: "Possible ClickFix / Clipboard Hijack Attack",
          detail: "This page just copied a system command to your clipboard. Do NOT paste it into a terminal or the Run dialog."
        });
        try { api.runtime.sendMessage({ type: "SD_CLICKFIX_DETECTED", url: location.href, snippet: String(text).slice(0, 200) }); } catch (_e) {}
      }
    } catch (_e) {}
  }

  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      const orig = navigator.clipboard.writeText.bind(navigator.clipboard);
      navigator.clipboard.writeText = function (text) {
        inspectClipboardText(text);
        return orig(text);
      };
    }
    document.addEventListener("copy", () => {
      try { inspectClipboardText((window.getSelection() || "").toString()); } catch (_e) {}
    }, true);
  } catch (_e) {}

  function escapeHtml(str) {
    if (typeof str !== "string") return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
})();
