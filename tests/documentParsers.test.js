import test from "node:test";
import assert from "node:assert/strict";
import { parsePdf, looksLikePdf, normalizePdfNames } from "../modules/parsers/pdfParser.js";
import { parseOle, looksLikeOle } from "../modules/parsers/oleParser.js";

function pdfBuffer(body) {
  return new TextEncoder().encode(`%PDF-1.7\n${body}\n%%EOF\n`).buffer;
}

// --- PDF ---

test("parsePdf reads the version and reports a clean document", () => {
  const pdf = parsePdf(pdfBuffer("1 0 obj\n<< /Type /Catalog >>\nendobj"));

  assert.equal(pdf.ok, true);
  assert.equal(pdf.version, "1.7");
  assert.equal(pdf.markers.length, 0);
  assert.equal(pdf.objectCount, 1);
});

test("parsePdf detects auto-executing JavaScript", () => {
  const pdf = parsePdf(pdfBuffer("1 0 obj\n<< /OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> >>\nendobj"));

  const keys = pdf.markers.map(m => m.key);
  assert.ok(keys.includes("OPEN_ACTION"));
  assert.ok(keys.includes("JAVASCRIPT"));
  assert.ok(keys.includes("JS_ABBREV"));
});

test("parsePdf sees through #xx hex name obfuscation", () => {
  // /J#61vaScript is /JavaScript to a conforming reader — a naive string
  // scanner misses it entirely, which is exactly why it gets used.
  const pdf = parsePdf(pdfBuffer("1 0 obj\n<< /S /J#61v#61Script >>\nendobj"));

  assert.equal(pdf.usedHexObfuscation, true);
  assert.ok(pdf.markers.map(m => m.key).includes("JAVASCRIPT"));
});

test("parsePdf detects /Launch and embedded files", () => {
  const pdf = parsePdf(pdfBuffer("<< /S /Launch /F (cmd.exe) >>\n<< /Type /EmbeddedFile >>"));

  const keys = pdf.markers.map(m => m.key);
  assert.ok(keys.includes("LAUNCH"));
  assert.ok(keys.includes("EMBEDDED_FILE"));
});

test("parsePdf counts incremental updates", () => {
  const buffer = new TextEncoder().encode("%PDF-1.4\n1 0 obj\nendobj\n%%EOF\n2 0 obj\nendobj\n%%EOF\n").buffer;
  assert.equal(parsePdf(buffer).incrementalUpdates, 1);
});

test("parsePdf marker counts are stable across repeated scans", () => {
  // Guards the /g-regex lastIndex reset: without it the second call would
  // start scanning mid-buffer and silently under-report.
  const buffer = pdfBuffer("<< /S /JavaScript >>");
  const first = parsePdf(buffer);
  const second = parsePdf(buffer);

  assert.deepEqual(
    first.markers.map(m => [m.key, m.count]),
    second.markers.map(m => [m.key, m.count])
  );
});

test("parsePdf rejects a non-PDF buffer", () => {
  const result = parsePdf(new TextEncoder().encode("MZ this is an exe").buffer);
  assert.equal(result.ok, false);
  assert.match(result.error, /%PDF-/);
});

test("normalizePdfNames resolves hex escapes", () => {
  assert.equal(normalizePdfNames("/J#61va"), "/Java");
});

test("looksLikePdf checks the header", () => {
  assert.equal(looksLikePdf(pdfBuffer("x")), true);
  assert.equal(looksLikePdf(new TextEncoder().encode("MZ....").buffer), false);
});

// --- OLE ---

function oleBuffer(streamNames = [], { extraAscii = "" } = {}) {
  const size = 2048;
  const bytes = new Uint8Array(size);
  bytes.set([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], 0);
  new DataView(bytes.buffer).setUint16(30, 9, true); // sector shift -> 512

  let cursor = HEADER_END;
  for (const name of streamNames) {
    for (let i = 0; i < name.length; i++) {
      bytes[cursor++] = name.charCodeAt(i) & 0xff;
      bytes[cursor++] = 0x00; // UTF-16LE high byte
    }
    cursor += 4;
  }
  if (extraAscii) {
    bytes.set(new TextEncoder().encode(extraAscii), cursor);
  }
  return bytes.buffer;
}
const HEADER_END = 512;

test("parseOle validates the signature and reads sector size", () => {
  const ole = parseOle(oleBuffer(["WordDocument"]));

  assert.equal(ole.ok, true);
  assert.equal(ole.sectorSize, 512);
  assert.ok(ole.streams.includes("WORD_DOCUMENT"));
});

test("parseOle detects VBA macro storage", () => {
  const ole = parseOle(oleBuffer(["WordDocument", "_VBA_PROJECT"]));

  assert.equal(ole.hasVbaMacros, true);
  assert.ok(ole.streams.includes("VBA_PROJECT"));
});

test("parseOle reports no macros for a plain document", () => {
  assert.equal(parseOle(oleBuffer(["WordDocument"])).hasVbaMacros, false);
});

test("parseOle detects Excel 4.0 macro sheets", () => {
  const ole = parseOle(oleBuffer(["Workbook"], { extraAscii: "Excel 4.0 Macros" }));
  assert.equal(ole.hasExcel4Macros, true);
});

test("parseOle detects embedded OLE objects", () => {
  assert.equal(parseOle(oleBuffer(["ObjectPool"])).hasEmbeddedOleObject, true);
});

test("parseOle rejects a non-OLE buffer", () => {
  const result = parseOle(new Uint8Array(1024).fill(0x41).buffer);
  assert.equal(result.ok, false);
  assert.match(result.error, /signature mismatch/);
});

test("looksLikeOle checks the compound-file signature", () => {
  assert.equal(looksLikeOle(oleBuffer([])), true);
  assert.equal(looksLikeOle(new TextEncoder().encode("%PDF-1.4").buffer), false);
});
