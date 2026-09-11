// warning/warning.js

const params = new URLSearchParams(window.location.search);
const targetUrl = params.get("url") || "";
const targetDomain = params.get("domain") || (targetUrl ? new URL(targetUrl).hostname : "Suspicious Site");
const reasonsParam = params.get("reasons") || "";

const els = {
  dangerDomain: document.getElementById("dangerDomain"),
  dangerUrl: document.getElementById("dangerUrl"),
  threatList: document.getElementById("threatList"),
  safetyBtn: document.getElementById("safetyBtn"),
  detailsBtn: document.getElementById("detailsBtn"),
  technicalDetails: document.getElementById("technicalDetails"),
  chevronIcon: document.getElementById("chevronIcon"),
  proceedBtn: document.getElementById("proceedBtn")
};

function init() {
  if (els.dangerDomain) els.dangerDomain.textContent = targetDomain;
  if (els.dangerUrl) els.dangerUrl.textContent = targetUrl || "Unknown address";

  const reasons = reasonsParam ? reasonsParam.split(",").map(r => r.trim()).filter(Boolean) : [];
  if (reasons.length === 0) {
    reasons.push("Flagged by automated threat intelligence checks");
  }

  if (els.threatList) {
    els.threatList.innerHTML = "";
    for (const r of reasons) {
      const li = document.createElement("li");
      li.textContent = r;
      els.threatList.appendChild(li);
    }
  }

  // Safety button
  if (els.safetyBtn) {
    els.safetyBtn.addEventListener("click", () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = "https://www.google.com";
      }
    });
  }

  // Details toggle
  let detailsVisible = false;
  if (els.detailsBtn && els.technicalDetails) {
    els.detailsBtn.addEventListener("click", () => {
      detailsVisible = !detailsVisible;
      els.technicalDetails.classList.toggle("hidden", !detailsVisible);
      if (els.chevronIcon) {
        els.chevronIcon.style.transform = detailsVisible ? "rotate(180deg)" : "rotate(0deg)";
      }
    });
  }

  // Proceed button
  if (els.proceedBtn) {
    els.proceedBtn.addEventListener("click", async () => {
      try {
        await chrome.runtime.sendMessage({
          type: "SD_BYPASS_DOMAIN",
          domain: targetDomain
        });
      } catch (_e) {}

      if (targetUrl) {
        window.location.href = targetUrl;
      } else {
        window.location.href = `https://${targetDomain}`;
      }
    });
  }
}

init();
