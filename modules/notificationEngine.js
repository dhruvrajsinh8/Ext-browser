// modules/notificationEngine.js
// Module 11: Notification Engine.

// Firefox's notifications API rejects the Chrome-only `buttons` property with a
// synchronous validation error. Because notifyResult() is called from inside the
// download pipeline, an unguarded throw there would abort the scan and resume the
// download unscanned — so degrade to a plain notification instead of failing.
function createNotification(id, options) {
  try {
    chrome.notifications.create(id, options);
  } catch {
    const { buttons: _unsupported, ...withoutButtons } = options;
    try {
      chrome.notifications.create(id, withoutButtons);
    } catch (err) {
      console.warn("[SecureDownload AI] notification could not be shown:", err);
    }
  }
}

export function notifyResult(record, autoResumed = false) {
  const { filename, trustScore, recommendation, action } = record;

  let title = `${recommendation.emoji} ${recommendation.headline}`;
  if (autoResumed || action === "resumed") {
    title = `🟢 Verified Safe (Score: ${trustScore}) — Download Continuing`;
  } else if (action === "deleted") {
    title = `🔴 DANGEROUS DOWNLOAD BLOCKED & DELETED (Score: ${trustScore})`;
  } else if (recommendation.riskLevel === "dangerous") {
    title = `🔴 DANGEROUS DOWNLOAD PAUSED — ACTION REQUIRED (Score: ${trustScore})`;
  } else {
    title = `🟡 Download Paused for Audit: ${recommendation.headline}`;
  }


  const buttons = autoResumed
    ? [{ title: "View Analysis" }]
    : recommendation.riskLevel === "dangerous"
      ? [{ title: "Delete File" }, { title: "View Details" }]
      : [{ title: "Resume Download" }, { title: "View Details" }];

  createNotification(`sd_${record.downloadId}`, {
    type: "basic",
    iconUrl: chrome.runtime.getURL("icons/icon128.png"),
    title,
    message: `${filename}\nTrust Score: ${trustScore}/100 — ${recommendation.detail}`,
    priority: recommendation.riskLevel === "dangerous" ? 2 : 1,
    buttons
  });
}

// Only fires for emails that scored "dangerous" — suspicious-but-not-clearly-
// phishing mail is left for the popup's Email tab rather than interrupting
// the user for every borderline message.
export function notifyEmailResult(emailRecord) {
  const { subject, senderDomain, findings } = emailRecord;
  const topFinding = findings[0]?.label || "Multiple phishing indicators detected";

  createNotification(`sd_email_${emailRecord.messageId}`, {
    type: "basic",
    iconUrl: chrome.runtime.getURL("icons/icon128.png"),
    title: "🎣 Suspected Phishing Email",
    message: `From ${senderDomain}: "${subject}"\n${topFinding}`,
    priority: 2,
    buttons: [{ title: "View in Email Tab" }]
  });
}

