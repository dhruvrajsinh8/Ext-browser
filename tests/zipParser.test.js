import test from "node:test";
import assert from "node:assert/strict";
import { parseZip, looksLikeZip } from "../modules/parsers/zipParser.js";
import { buildZip } from "./helpers/zipBuilder.js";

test("parseZip reads real central-directory entry names", () => {
  const buffer = buildZip([
    { name: "readme.txt", content: "hello" },
    { name: "setup.exe", content: "MZ fake payload" }
  ]);
  const result = parseZip(buffer);

  assert.equal(result.ok, true);
  assert.equal(result.totalEntries, 2);
  assert.deepEqual(result.entries.map(e => e.name), ["readme.txt", "setup.exe"]);
});

test("parseZip records compressed and uncompressed sizes", () => {
  const buffer = buildZip([
    { name: "payload.bin", content: "x".repeat(100), compressedSize: 100, uncompressedSize: 5_000_000 }
  ]);
  const result = parseZip(buffer);

  assert.equal(result.entries[0].compressedSize, 100);
  assert.equal(result.entries[0].uncompressedSize, 5_000_000);
});

test("parseZip marks directory entries", () => {
  const buffer = buildZip([
    { name: "word/", content: "" },
    { name: "word/vbaProject.bin", content: "macro" }
  ]);
  const result = parseZip(buffer);

  assert.equal(result.entries[0].isDirectory, true);
  assert.equal(result.entries[1].isDirectory, false);
});

test("parseZip does NOT report filenames that only appear in file content", () => {
  // The whole point of structural parsing: a document that merely *mentions*
  // an executable must not be reported as containing one.
  const buffer = buildZip([
    { name: "manual.txt", content: "To install, run setup.exe from the DVD." }
  ]);
  const result = parseZip(buffer);

  assert.deepEqual(result.entries.map(e => e.name), ["manual.txt"]);
});

test("parseZip returns a clean error for a non-ZIP buffer", () => {
  const buffer = new TextEncoder().encode("%PDF-1.4 not a zip at all").buffer;
  const result = parseZip(buffer);

  assert.equal(result.ok, false);
  assert.match(result.error, /end-of-central-directory/);
});

test("parseZip handles an empty buffer without throwing", () => {
  const result = parseZip(new ArrayBuffer(0));
  assert.equal(result.ok, false);
  assert.equal(result.entries.length, 0);
});

test("parseZip survives a truncated central directory", () => {
  const full = buildZip([
    { name: "a.txt", content: "aaa" },
    { name: "b.txt", content: "bbb" }
  ]);
  // Corrupt the declared entry count so the walk runs past the real records.
  const bytes = new Uint8Array(full.slice(0));
  const view = new DataView(bytes.buffer);
  const eocdOffset = bytes.length - 22;
  view.setUint16(eocdOffset + 10, 99, true);

  const result = parseZip(bytes.buffer);
  assert.equal(result.truncated, true);
  assert.equal(result.entries.length, 2); // stopped cleanly at the real end
});

test("looksLikeZip detects the local file header signature", () => {
  const zip = buildZip([{ name: "a.txt", content: "x" }]);
  assert.equal(looksLikeZip(zip), true);
  assert.equal(looksLikeZip(new TextEncoder().encode("%PDF").buffer), false);
});
