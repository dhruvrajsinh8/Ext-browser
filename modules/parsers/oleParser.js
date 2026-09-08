// modules/parsers/oleParser.js
// Reader for OLE Compound File Binary documents — legacy Office formats
// (.doc, .xls, .ppt) and the .msi installer container.
//
// These predate the ZIP-based .docx family and are where VBA macros and
// Excel 4.0 (XLM) macros live. XLM in particular is worth detecting: it is a
// 1992 macro language that still executes in modern Excel and is used
// specifically because it bypasses many VBA-focused defences.
//
// SCOPE NOTE — this reads the header properly, then locates directory-entry
// names by scanning for their UTF-16LE encoding rather than walking the FAT
// sector chains. Full chain traversal would add substantial complexity for no
// detection gain here: stream names are what matter, they are stored
// uncompressed, and a scan cannot be defeated by chain manipulation the way
// a naive traversal can. It is a deliberate tradeoff, not an approximation
// of something that failed.
//
// PURE STRUCTURE READER — no verdicts.

const OLE_SIGNATURE = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const HEADER_SIZE = 512;
const MAX_SCAN_BYTES = 16 * 1024 * 1024;

// Directory-entry names that identify macro storage. Matching is done against
// the UTF-16LE bytes these names are stored as.
const STREAM_NAMES = [
  { name: "VBA", key: "VBA_STORAGE" },
  { name: "_VBA_PROJECT", key: "VBA_PROJECT" },
  { name: "Macros", key: "MACROS_STORAGE" },
  { name: "vbaProject.bin", key: "VBA_PROJECT_BIN" },
  { name: "WordDocument", key: "WORD_DOCUMENT" },
  { name: "Workbook", key: "WORKBOOK" },
  { name: "Book", key: "BOOK" },
  { name: "PowerPoint Document", key: "POWERPOINT_DOCUMENT" },
  { name: "ObjectPool", key: "OBJECT_POOL" },
  { name: "Ole10Native", key: "OLE10_NATIVE" }
];

function hasOleSignature(view) {
  if (view.byteLength < OLE_SIGNATURE.length) return false;
  return OLE_SIGNATURE.every((byte, i) => view.getUint8(i) === byte);
}

/** Encode an ASCII-range string the way OLE stores directory names. */
function toUtf16LeBytes(text) {
  const bytes = new Uint8Array(text.length * 2);
  for (let i = 0; i < text.length; i++) {
    bytes[i * 2] = text.charCodeAt(i) & 0xff;
    bytes[i * 2 + 1] = (text.charCodeAt(i) >> 8) & 0xff;
  }
  return bytes;
}

function containsBytes(haystack, needle) {
  if (needle.length === 0 || needle.length > haystack.length) return false;
  const first = needle[0];
  const limit = haystack.length - needle.length;
  outer: for (let i = 0; i <= limit; i++) {
    if (haystack[i] !== first) continue;
    for (let j = 1; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

/**
 * @param {ArrayBuffer} buffer
 * @returns {{
 *   ok: boolean,
 *   error: string|null,
 *   sectorSize: number,
 *   streams: string[],
 *   hasVbaMacros: boolean,
 *   hasExcel4Macros: boolean,
 *   hasEmbeddedOleObject: boolean,
 *   truncated: boolean
 * }}
 */
export function parseOle(buffer) {
  const empty = {
    ok: false, error: null, sectorSize: 0, streams: [],
    hasVbaMacros: false, hasExcel4Macros: false,
    hasEmbeddedOleObject: false, truncated: false
  };

  if (!buffer || buffer.byteLength < HEADER_SIZE) {
    return { ...empty, error: "buffer too small to contain an OLE header" };
  }

  const view = new DataView(buffer);
  if (!hasOleSignature(view)) {
    return { ...empty, error: "not an OLE compound file (signature mismatch)" };
  }

  // Sector size is stored as a power-of-two shift; 9 -> 512, 12 -> 4096.
  const sectorShift = view.getUint16(30, true);
  const sectorSize = sectorShift > 0 && sectorShift < 20 ? 1 << sectorShift : 512;

  const truncated = buffer.byteLength > MAX_SCAN_BYTES;
  const scanLength = Math.min(buffer.byteLength, MAX_SCAN_BYTES);
  const bytes = new Uint8Array(buffer, 0, scanLength);

  const streams = [];
  for (const stream of STREAM_NAMES) {
    if (containsBytes(bytes, toUtf16LeBytes(stream.name))) {
      streams.push(stream.key);
    }
  }

  const hasVbaMacros = streams.some(
    (s) => s === "VBA_STORAGE" || s === "VBA_PROJECT" || s === "MACROS_STORAGE" || s === "VBA_PROJECT_BIN"
  );

  // Excel 4.0 macro sheets are recorded in the workbook stream as BOUNDSHEET
  // entries with a macro sheet type. The "Excel 4.0 Macros" label is the
  // reliable observable without decoding the BIFF record stream.
  const hasExcel4Macros = containsBytes(bytes, toUtf16LeBytes("Excel 4.0 Macros")) ||
    containsBytes(bytes, new TextEncoder().encode("Excel 4.0 Macros"));

  return {
    ok: true,
    error: null,
    sectorSize,
    streams,
    hasVbaMacros,
    hasExcel4Macros,
    hasEmbeddedOleObject: streams.includes("OBJECT_POOL") || streams.includes("OLE10_NATIVE"),
    truncated
  };
}

/** True when the buffer starts with the OLE compound-file signature. */
export function looksLikeOle(buffer) {
  if (!buffer || buffer.byteLength < OLE_SIGNATURE.length) return false;
  return hasOleSignature(new DataView(buffer));
}
