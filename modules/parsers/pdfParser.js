// modules/parsers/pdfParser.js
// Structural scanner for PDF documents.
//
// A PDF is not a passive document format: it can execute JavaScript on open,
// launch external programs, embed whole files, and auto-trigger actions on
// page events. Those capabilities are declared as named objects in the file,
// so their presence is directly observable without rendering anything.
//
// Name obfuscation is handled first. The PDF spec allows any character in a
// name to be written as #xx hex, so `/JavaScript` and `/J#61v#61Script` are
// the same token to a reader — and malicious documents routinely use the
// second form specifically to defeat naive string scanners. Normalising
// before matching is what makes this detection meaningful.
//
// PURE STRUCTURE READER — no verdicts. Interpretation lives in malwareRules.js.

const MAX_SCAN_BYTES = 8 * 1024 * 1024;

// Each entry is a capability the format grants, not a judgement about it.
const PDF_MARKERS = [
  { key: "JAVASCRIPT", pattern: /\/JavaScript\b/g, label: "Embedded JavaScript (/JavaScript)" },
  { key: "JS_ABBREV", pattern: /\/JS\b/g, label: "Embedded JavaScript (/JS)" },
  { key: "OPEN_ACTION", pattern: /\/OpenAction\b/g, label: "Action triggered automatically on open (/OpenAction)" },
  { key: "ADDITIONAL_ACTION", pattern: /\/AA\b/g, label: "Additional event-triggered actions (/AA)" },
  { key: "LAUNCH", pattern: /\/Launch\b/g, label: "Launches an external application (/Launch)" },
  { key: "EMBEDDED_FILE", pattern: /\/EmbeddedFile\b/g, label: "Contains an embedded file (/EmbeddedFile)" },
  { key: "RICH_MEDIA", pattern: /\/RichMedia\b/g, label: "Embedded rich media / Flash (/RichMedia)" },
  { key: "SUBMIT_FORM", pattern: /\/SubmitForm\b/g, label: "Submits form data to a remote URL (/SubmitForm)" },
  { key: "GOTO_REMOTE", pattern: /\/GoToR\b/g, label: "Jumps to a remote document (/GoToR)" },
  { key: "URI_ACTION", pattern: /\/URI\b/g, label: "Contains URI actions (/URI)" },
  { key: "OBJECT_STREAM", pattern: /\/ObjStm\b/g, label: "Uses object streams (/ObjStm), which can conceal objects" },
  { key: "ENCRYPTED", pattern: /\/Encrypt\b/g, label: "Document is encrypted (/Encrypt)" },
  { key: "XFA_FORM", pattern: /\/XFA\b/g, label: "Contains an XFA form (/XFA)" }
];

/**
 * Resolve #xx hex escapes inside PDF names so obfuscated tokens match.
 * Only the escape sequences are rewritten; surrounding bytes are untouched.
 */
export function normalizePdfNames(text) {
  return text.replace(/#([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

/**
 * @param {ArrayBuffer} buffer
 * @returns {{
 *   ok: boolean,
 *   error: string|null,
 *   version: string|null,
 *   markers: Array<{key: string, label: string, count: number}>,
 *   usedHexObfuscation: boolean,
 *   objectCount: number,
 *   incrementalUpdates: number,
 *   truncated: boolean
 * }}
 */
export function parsePdf(buffer) {
  const empty = {
    ok: false, error: null, version: null, markers: [],
    usedHexObfuscation: false, objectCount: 0, incrementalUpdates: 0, truncated: false
  };

  if (!buffer || buffer.byteLength < 5) {
    return { ...empty, error: "buffer too small to contain a PDF" };
  }

  const truncated = buffer.byteLength > MAX_SCAN_BYTES;
  const scanLength = Math.min(buffer.byteLength, MAX_SCAN_BYTES);
  // latin1 maps every byte to exactly one code unit, so binary stream data
  // can never corrupt offsets or throw the way a UTF-8 decode would.
  const raw = new TextDecoder("latin1").decode(new Uint8Array(buffer, 0, scanLength));

  if (!raw.startsWith("%PDF-")) {
    return { ...empty, error: "missing %PDF- header", truncated };
  }

  const versionMatch = raw.match(/^%PDF-(\d+\.\d+)/);
  const normalized = normalizePdfNames(raw);
  const usedHexObfuscation = normalized !== raw;

  const markers = [];
  for (const marker of PDF_MARKERS) {
    // `pattern` is declared with /g and reused across calls, so lastIndex must
    // be reset or every second scan silently starts mid-buffer.
    marker.pattern.lastIndex = 0;
    const matches = normalized.match(marker.pattern);
    if (matches && matches.length) {
      markers.push({ key: marker.key, label: marker.label, count: matches.length });
    }
  }

  const objectCount = (normalized.match(/\d+\s+\d+\s+obj\b/g) || []).length;
  // More than one EOF marker means the file was appended to after signing or
  // publishing — normal for edited documents, but also how content gets added
  // to an otherwise-trusted PDF.
  const incrementalUpdates = Math.max(0, (normalized.match(/%%EOF/g) || []).length - 1);

  return {
    ok: true,
    error: null,
    version: versionMatch ? versionMatch[1] : null,
    markers,
    usedHexObfuscation,
    objectCount,
    incrementalUpdates,
    truncated
  };
}

/** True when the buffer starts with the %PDF- header. */
export function looksLikePdf(buffer) {
  if (!buffer || buffer.byteLength < 5) return false;
  const head = new TextDecoder("latin1").decode(new Uint8Array(buffer, 0, 5));
  return head === "%PDF-";
}
