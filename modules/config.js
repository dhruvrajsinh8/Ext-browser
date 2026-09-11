// modules/config.js
// Central configuration: weights, endpoints, defaults.
// Nothing here should require a rebuild to change — everything user-tunable
// (API keys, extra trusted domains) lives in chrome.storage, not this file.

export const WEIGHTS = {
  officialWebsite: 0.17,
  publisherVerification: 0.17,
  virusTotal: 0.18,        // hash lookup OR, when opted in, a real fresh-scan result
  staticAnalysis: 0.12,    // local magic-byte / entropy / macro / script-pattern checks
  vulnerability: 0.11,
  https: 0.08,
  fileIntegrity: 0.12,     // known-good hash match, when a reference hash exists
  sourceReputation: 0.05
};

// Sanity check at load time — if these ever drift from 1.0 the formula in
// trustEngine.js silently produces a score out of the wrong range.
export const WEIGHT_SUM = Object.values(WEIGHTS).reduce((a, b) => a + b, 0);

if (Math.abs(WEIGHT_SUM - 1.0) > 0.0001) {
  throw new Error(`[SecureDownload AI] Invalid weight configuration: WEIGHT_SUM is ${WEIGHT_SUM}, must equal 1.0`);
}

export const RISK_THRESHOLDS = {
  safe: 80,      // >= 80  -> Safe to Install / Visit
  caution: 50,   // 50-79  -> Proceed with Caution / Verify Official Site
  danger: 0      // < 50   -> Delete Immediately / High Risk
};

export const EXECUTABLE_EXTENSIONS = new Set([
  "exe", "msi", "msix", "appx", "dmg", "pkg", "app",
  "deb", "rpm", "appimage", "sh", "bat", "cmd", "ps1",
  "jar", "apk", "vbs", "com", "gadget"
]);

export const ARCHIVE_EXTENSIONS = new Set([
  "zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "iso", "img", "cab"
]);

export const DOCUMENT_EXTENSIONS = new Set([
  "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf", "txt", "csv"
]);

export const SCRIPT_EXTENSIONS = new Set([
  "js", "ts", "py", "rb", "php", "pl", "sh", "ps1", "bat", "cmd", "vbs", "wsf"
]);

export const MEDIA_EXTENSIONS = new Set([
  "png", "jpg", "jpeg", "gif", "svg", "webp", "mp3", "wav", "mp4", "mkv", "avi", "mov"
]);

export const CODE_EXTENSIONS = new Set([
  "c", "cpp", "h", "cs", "java", "go", "rs", "html", "css", "json", "xml", "yaml", "yml", "sql"
]);

// Seed list of well-known software publishers and their official domains + CDN domains.
export const KNOWN_PUBLISHERS = [
  {
    name: "Google",
    domains: ["google.com", "gstatic.com", "googleusercontent.com", "dl.google.com", "gvt1.com", "chrome.com"]
  },
  {
    name: "Anthropic / Claude",
    domains: ["anthropic.com", "claude.ai", "claude.site", "claude.usercontent.com"]
  },
  {
    name: "OpenAI",
    domains: ["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"]
  },
  {
    name: "Microsoft",
    domains: ["microsoft.com", "live.com", "office.com", "windows.com", "officecdn.microsoft.com", "azureedge.net", "visualstudio.com", "github.com", "githubusercontent.com"]
  },
  {
    name: "Mozilla",
    domains: ["mozilla.org", "mozilla.com", "download-installer.cdn.mozilla.net"]
  },
  {
    name: "Adobe",
    domains: ["adobe.com", "adobe.io", "adobelogin.com"]
  },
  {
    name: "Cloudflare",
    domains: ["cloudflare.com", "cdnjs.cloudflare.com", "workers.dev"]
  },
  {
    name: "HuggingFace",
    domains: ["huggingface.co", "hf.space"]
  },
  {
    name: "Vercel",
    domains: ["vercel.com", "vercel.app"]
  },
  {
    name: "Supabase",
    domains: ["supabase.com", "supabase.co"]
  },
  {
    name: "Zoom",
    domains: ["zoom.us", "zoom.com"]
  },
  {
    name: "Slack",
    domains: ["slack.com", "slack-edge.com"]
  },
  {
    name: "Discord",
    domains: ["discord.com", "discordapp.com", "discord.gg"]
  },
  {
    name: "GitHub",
    domains: ["github.com", "githubusercontent.com", "objects.githubusercontent.com", "github.io"]
  },
  {
    name: "Notion",
    domains: ["notion.so", "notion.site"]
  },
  {
    name: "VideoLAN (VLC)",
    domains: ["videolan.org"]
  },
  {
    name: "7-Zip",
    domains: ["7-zip.org"]
  },
  {
    name: "Apple",
    domains: ["apple.com", "cdn-apple.com", "icloud.com"]
  },
  {
    name: "Python Software Foundation",
    domains: ["python.org", "pypi.org"]
  },
  {
    name: "Node.js Foundation",
    domains: ["nodejs.org"]
  },
  {
    name: "JetBrains",
    domains: ["jetbrains.com"]
  },
  {
    name: "Brave",
    domains: ["brave.com", "laptop-updates.brave.com"]
  },
  {
    name: "Notepad++",
    domains: ["notepad-plus-plus.org"]
  }
];

export const VULNERABILITY_DEFINITIONS = {
  NO_HTTPS: {
    title: "Insecure Protocol (HTTP)",
    threatLevel: "Critical",
    levelCode: 4,
    owaspCategory: "A02:2021 - Cryptographic Failures",
    unethicalHarm: "Attainable Man-in-the-Middle (MitM) exploitation: Attackers on local/public Wi-Fi networks can eavesdrop, intercept unencrypted data, inject malicious executable code, or spoof download files directly."
  },
  MISSING_HSTS: {
    title: "Missing Strict-Transport-Security (HSTS)",
    threatLevel: "High",
    levelCode: 3,
    owaspCategory: "A05:2021 - Security Misconfiguration",
    unethicalHarm: "SSL Strip Attacks: Attackers can force encrypted connections to drop down to unencrypted HTTP, allowing session hijacking, credential theft, or silent redirecting to malware mirrors."
  },
  WEAK_HSTS: {
    title: "Weak HSTS Policy (Short max-age or no includeSubDomains)",
    threatLevel: "Medium",
    levelCode: 2,
    owaspCategory: "A05:2021 - Security Misconfiguration",
    unethicalHarm: "Subdomain SSL Strip: Short cache duration or missing subdomain enforcement leaves subdomains vulnerable to HTTP downgrade attacks."
  },
  MISSING_CSP: {
    title: "Missing Content-Security-Policy (CSP)",
    threatLevel: "High",
    levelCode: 3,
    owaspCategory: "A03:2021 - Injection (XSS)",
    unethicalHarm: "Cross-Site Scripting (XSS) Vulnerability: Without a restrictive CSP, attackers who find any input reflection can execute arbitrary JavaScript in the victim's session to steal cookies, tokens, or trigger unauthorized user actions."
  },
  WEAK_CSP: {
    title: "Weak Content-Security-Policy (unsafe-inline / unsafe-eval)",
    threatLevel: "Medium",
    levelCode: 2,
    owaspCategory: "A03:2021 - Injection (XSS)",
    unethicalHarm: "Bypassable Script Sandbox: Allowing unsafe-inline or unsafe-eval enables attackers to execute injected inline scripts despite CSP presence."
  },
  PERMISSIVE_CORS: {
    title: "Permissive CORS Policy (Wildcard Access)",
    threatLevel: "High",
    levelCode: 3,
    owaspCategory: "A01:2021 - Broken Access Control",
    unethicalHarm: "Cross-Domain Data Exfiltration: Malicious third-party websites visited in another tab can make authenticated API requests to read sensitive victim data from this site."
  },
  MISSING_CLICKJACKING_PROTECTION: {
    title: "Missing X-Frame-Options / Clickjacking Protection",
    threatLevel: "Medium",
    levelCode: 2,
    owaspCategory: "A04:2021 - Insecure Design",
    unethicalHarm: "UI Redirection & Clickjacking: Attackers can embed this website inside an invisible iframe on a phishing page and trick users into clicking buttons (e.g. confirming transfers or permissions)."
  },
  MISSING_MIME_PROTECTION: {
    title: "Missing X-Content-Type-Options (nosniff)",
    threatLevel: "Medium",
    levelCode: 2,
    owaspCategory: "A05:2021 - Security Misconfiguration",
    unethicalHarm: "MIME Sniffing Exploitation: Browsers may attempt to guess file content-types, allowing executable code disguised as benign images or text files to run."
  },
  TYPOSQUATTING_RISK: {
    title: "Suspected Typosquatting / Domain Spoofing",
    threatLevel: "Critical",
    levelCode: 4,
    owaspCategory: "A07:2021 - Identification & Authentication Failures",
    unethicalHarm: "Phishing & Malware Delivery: The domain closely mimics a legitimate brand name. Users are likely being deceived into downloading malicious payloads disguised as official software."
  },
  SUSPICIOUS_TLD: {
    title: "High-Risk Top-Level Domain (TLD)",
    threatLevel: "Medium",
    levelCode: 2,
    owaspCategory: "A05:2021 - Security Misconfiguration",
    unethicalHarm: "Abused Domain Infrastructure: TLDs with cheap or unverified registration frequently host short-lived malware distribution centers or scam campaigns."
  }
};


// Endpoints for external intelligence. All calls are made from background.js
// so API keys never touch the popup UI thread.
export const ENDPOINTS = {
  virusTotalUrlReport: "https://www.virustotal.com/api/v3/urls",
  virusTotalFileReport: "https://www.virustotal.com/api/v3/files",
  virusTotalFileUpload: "https://www.virustotal.com/api/v3/files",
  virusTotalAnalysis: "https://www.virustotal.com/api/v3/analyses",
  safeBrowsing: "https://safebrowsing.googleapis.com/v4/threatMatches:find",
  malwareBazaar: "https://mb-api.abuse.ch/api/v1/",
  urlhaus: "https://urlhaus-api.abuse.ch/v1/url/",
  urlhausHost: "https://urlhaus-api.abuse.ch/v1/host/",
  cisaKev: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  geminiGenerate: "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent",
  nvdCves: "https://services.nvd.nist.gov/rest/json/cves/2.0",
  gmailMessages: "https://gmail.googleapis.com/gmail/v1/users/me/messages",
  gmailProfile: "https://gmail.googleapis.com/gmail/v1/users/me/profile"
};

// VirusTotal free-tier constraints. Uploading is opt-in (see settings.allowVirusTotalUpload)
// because, unlike a hash lookup, it sends the actual file bytes to a third party.
export const VT_UPLOAD_MAX_BYTES = 32 * 1024 * 1024; // 32MB free-tier ceiling
export const VT_ANALYSIS_POLL_MS = 4000;
export const VT_ANALYSIS_MAX_POLLS = 15; // ~60s ceiling before giving up and reporting "pending"

// File signature ("magic bytes") table for detecting extension spoofing —
// e.g. an .exe renamed to .pdf. Values are hex-encoded byte prefixes.
export const FILE_SIGNATURES = [
  { hex: "4d5a", type: "pe_executable", categories: ["executable"] },              // MZ
  { hex: "7f454c46", type: "elf_executable", categories: ["executable"] },          // .ELF
  { hex: "cafebabe", type: "macho_or_java_class", categories: ["executable", "code"] },
  { hex: "25504446", type: "pdf", categories: ["document"] },                       // %PDF
  { hex: "504b0304", type: "zip_based", categories: ["archive", "document", "executable"] }, // PK.. (zip, docx, jar, apk...)
  { hex: "526172211a0700", type: "rar", categories: ["archive"] },
  { hex: "377abcaf271c", type: "7z", categories: ["archive"] },
  { hex: "89504e47", type: "png", categories: ["media"] },
  { hex: "ffd8ff", type: "jpeg", categories: ["media"] },
  { hex: "d0cf11e0a1b11ae1", type: "ole_compound", categories: ["document"] }        // old .doc/.xls (also carries VBA macros)
];

// Text patterns worth flagging inside script files — not proof of malice on
// their own, but each is a real technique used by download-and-execute /
// obfuscated malware loaders, and near-never appears in ordinary scripts.
export const SUSPICIOUS_SCRIPT_PATTERNS = [
  { key: "PS_ENCODED_COMMAND", rx: /-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{40,}/i, label: "PowerShell -EncodedCommand with a large Base64 blob" },
  { key: "PS_DOWNLOAD_EXEC", rx: /(new-object\s+net\.webclient|invoke-webrequest|iwr\s).{0,80}(downloadstring|downloadfile|\.exe)/i, label: "PowerShell download-and-execute pattern" },
  { key: "PS_IEX", rx: /iex\s*\(/i, label: "PowerShell Invoke-Expression on dynamic content" },
  { key: "JS_EVAL_ATOB", rx: /eval\s*\(\s*atob\s*\(/i, label: "JavaScript eval() of a decoded Base64 string" },
  { key: "VBS_SHELL_EXEC", rx: /(wscript\.shell|createobject\(["']wscript\.shell["']\))/i, label: "VBScript shell execution object" },
  { key: "CURL_PIPE_SH", rx: /(curl|wget)\s+.{0,80}\|\s*(sh|bash)/i, label: "Download-piped-to-shell pattern" }
];

// Static-analysis entropy threshold. Shannon entropy above this on a file
// whose extension implies plain text/structured content (script, document,
// code) suggests packed, encrypted, or obfuscated payload content.
export const HIGH_ENTROPY_THRESHOLD = 7.2; // bits/byte, max is 8.0

export const STATIC_ANALYSIS_MAX_BYTES = 25 * 1024 * 1024; // cap the JS-side scan cost

// Gmail readonly scope — least privilege that still lets us read message
// content for phishing analysis. Never request modify/send scopes.
export const GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly";

export const PHISHING_URGENCY_PATTERNS = [
  /verify your (account|identity|password)/i,
  /account (has been |will be )?(suspended|locked|limited|disabled)/i,
  /(click|log ?in|sign ?in) (here|now|immediately)/i,
  /unusual (sign-?in|activity|login) (attempt|detected)/i,
  /your (payment|invoice|order) (failed|is overdue|could not be processed)/i,
  /confirm your (payment|billing|card) details/i,
  /you have (won|been selected)/i,
  /act now|urgent action required|final notice/i
];

export const CACHE_TTL_MS = {
  virusTotal: 1000 * 60 * 60 * 6,   // 6 hours
  safeBrowsing: 1000 * 60 * 60 * 6, // 6 hours
  malwareBazaar: 1000 * 60 * 60 * 6,// 6 hours
  urlhaus: 1000 * 60 * 60 * 6,      // 6 hours
  nvd: 1000 * 60 * 60 * 24,         // 24 hours
  websiteAudit: 1000 * 60 * 15      // 15 mins
};

export const MAX_HISTORY_ITEMS = 200;
