// modules/parsers/zipParser.js
// Structural ZIP reader — walks the real central directory instead of
// regex-scanning the raw bytes for anything that looks like a filename.
//
// Why this matters for detection: a string scan reports "contains setup.exe"
// for any file that merely mentions that text (a README, an installer log, a
// PDF about installers), and misses entries whose names are only recorded in
// the central directory. Reading the actual records gives exact names plus the
// compressed/uncompressed sizes that zip-bomb and decoy-archive checks need.
//
// This is a PURE STRUCTURE READER. It makes no security judgements — those
// live in staticAnalysis.js, so the parsing stays independently testable.
//
// Format reference: PKWARE APPNOTE.TXT §4.3. All integers are little-endian.

const SIG_EOCD = 0x06054b50;        // End of central directory
const SIG_EOCD64 = 0x06064b50;      // Zip64 end of central directory
const SIG_EOCD64_LOCATOR = 0x07064b50;
const SIG_CENTRAL_FILE = 0x02014b50; // Central directory file header

const EOCD_MIN_SIZE = 22;
const MAX_COMMENT_SIZE = 0xffff;
const CENTRAL_HEADER_FIXED_SIZE = 46;

// A ZIP with more entries than this is either a bomb or something we have no
// business walking inside a service worker. We stop and report `truncated`.
const MAX_ENTRIES = 5000;

const UTF8_FLAG = 0x0800; // general purpose bit 11 -> filename is UTF-8

/**
 * Locate the End Of Central Directory record by scanning backwards.
 * The record is variable-position because it may be followed by a comment of
 * up to 65535 bytes, so there is no fixed offset to read.
 * @returns {number} byte offset of the EOCD signature, or -1
 */
function findEocdOffset(view) {
  const maxScan = Math.min(view.byteLength, MAX_COMMENT_SIZE + EOCD_MIN_SIZE);
  const start = view.byteLength - maxScan;
  for (let i = view.byteLength - EOCD_MIN_SIZE; i >= start; i--) {
    if (view.getUint32(i, true) === SIG_EOCD) {
      // Guard against the signature appearing inside file data: the declared
      // comment length must actually reach the end of the buffer.
      const commentLength = view.getUint16(i + 20, true);
      if (i + EOCD_MIN_SIZE + commentLength === view.byteLength) return i;
    }
  }
  return -1;
}

/**
 * Zip64 archives store the real central-directory offset/count in a separate
 * record, because the classic EOCD fields cap out at 0xffff / 0xffffffff.
 */
function readZip64Eocd(view, eocdOffset) {
  const locatorOffset = eocdOffset - 20;
  if (locatorOffset < 0) return null;
  if (view.getUint32(locatorOffset, true) !== SIG_EOCD64_LOCATOR) return null;

  // The locator stores a 64-bit offset; we only support archives addressable
  // within Number.MAX_SAFE_INTEGER, which every real-world file satisfies.
  const eocd64Offset = Number(view.getBigUint64(locatorOffset + 8, true));
  if (!Number.isSafeInteger(eocd64Offset) || eocd64Offset < 0 || eocd64Offset + 56 > view.byteLength) {
    return null;
  }
  if (view.getUint32(eocd64Offset, true) !== SIG_EOCD64) return null;

  return {
    totalEntries: Number(view.getBigUint64(eocd64Offset + 32, true)),
    centralDirOffset: Number(view.getBigUint64(eocd64Offset + 48, true))
  };
}

function decodeFilename(bytes, flags) {
  // Bit 11 promises UTF-8. Without it the spec says CP437, but in practice
  // archives are overwhelmingly UTF-8 anyway; latin1 is the safe fallback
  // because it never throws and never silently drops bytes.
  const encoding = (flags & UTF8_FLAG) ? "utf-8" : "latin1";
  return new TextDecoder(encoding, { fatal: false }).decode(bytes);
}

/**
 * Parse the central directory of a ZIP-based file (.zip, .docx, .xlsx, .jar,
 * .apk — all share this container).
 *
 * @param {ArrayBuffer} buffer
 * @returns {{
 *   ok: boolean,
 *   entries: Array<{name: string, compressedSize: number, uncompressedSize: number,
 *                   crc32: number, method: number, isDirectory: boolean, isEncrypted: boolean}>,
 *   totalEntries: number,
 *   truncated: boolean,
 *   error: string|null
 * }}
 */
export function parseZip(buffer) {
  const empty = { ok: false, entries: [], totalEntries: 0, truncated: false, error: null };

  if (!buffer || buffer.byteLength < EOCD_MIN_SIZE) {
    return { ...empty, error: "buffer too small to contain a ZIP structure" };
  }

  const view = new DataView(buffer);
  const eocdOffset = findEocdOffset(view);
  if (eocdOffset === -1) {
    // Common and benign: we only downloaded a prefix of a large archive, so
    // the central directory (which lives at the END) was never fetched.
    return { ...empty, error: "no end-of-central-directory record found (truncated or not a ZIP)" };
  }

  let totalEntries = view.getUint16(eocdOffset + 10, true);
  let centralDirOffset = view.getUint32(eocdOffset + 16, true);

  // 0xffff / 0xffffffff are Zip64 sentinels meaning "look in the Zip64 record".
  if (totalEntries === 0xffff || centralDirOffset === 0xffffffff) {
    const zip64 = readZip64Eocd(view, eocdOffset);
    if (zip64) {
      totalEntries = zip64.totalEntries;
      centralDirOffset = zip64.centralDirOffset;
    }
  }

  if (centralDirOffset >= view.byteLength) {
    return { ...empty, error: "central directory offset points outside the buffer" };
  }

  const entries = [];
  let offset = centralDirOffset;
  let truncated = false;

  while (entries.length < totalEntries) {
    if (entries.length >= MAX_ENTRIES) {
      truncated = true;
      break;
    }
    // Every read below is bounds-checked: a malformed archive is exactly the
    // input this parser is expected to receive.
    if (offset + CENTRAL_HEADER_FIXED_SIZE > view.byteLength) {
      truncated = true;
      break;
    }
    if (view.getUint32(offset, true) !== SIG_CENTRAL_FILE) {
      truncated = true;
      break;
    }

    const flags = view.getUint16(offset + 8, true);
    const method = view.getUint16(offset + 10, true);
    const crc32 = view.getUint32(offset + 16, true);
    const compressedSize = view.getUint32(offset + 20, true);
    const uncompressedSize = view.getUint32(offset + 24, true);
    const nameLength = view.getUint16(offset + 28, true);
    const extraLength = view.getUint16(offset + 30, true);
    const commentLength = view.getUint16(offset + 32, true);

    const nameStart = offset + CENTRAL_HEADER_FIXED_SIZE;
    const nameEnd = nameStart + nameLength;
    if (nameEnd > view.byteLength) {
      truncated = true;
      break;
    }

    const name = decodeFilename(new Uint8Array(buffer, nameStart, nameLength), flags);

    entries.push({
      name,
      compressedSize,
      uncompressedSize,
      crc32,
      method,
      isDirectory: name.endsWith("/"),
      isEncrypted: (flags & 0x0001) !== 0
    });

    offset = nameEnd + extraLength + commentLength;
  }

  return {
    ok: entries.length > 0,
    entries,
    totalEntries,
    truncated: truncated || entries.length < totalEntries,
    error: null
  };
}

/** True when the buffer starts with a local file header (PK\x03\x04). */
export function looksLikeZip(buffer) {
  if (!buffer || buffer.byteLength < 4) return false;
  return new DataView(buffer).getUint32(0, true) === 0x04034b50;
}
