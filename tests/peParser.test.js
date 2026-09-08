import test from "node:test";
import assert from "node:assert/strict";
import { parsePE, looksLikePE } from "../modules/parsers/peParser.js";
import { buildPE } from "./helpers/peBuilder.js";

test("parsePE reads COFF/optional header fields for a 32-bit binary", () => {
  const buffer = buildPE({ is64Bit: false, subsystem: 2 });
  const pe = parsePE(buffer);

  assert.equal(pe.ok, true);
  assert.equal(pe.machine, "x86");
  assert.equal(pe.is64Bit, false);
  assert.equal(pe.subsystem, "windows_gui");
  assert.equal(pe.isDll, false);
});

test("parsePE reads a 64-bit binary with the shifted PE32+ layout", () => {
  const buffer = buildPE({ is64Bit: true, subsystem: 3 });
  const pe = parsePE(buffer);

  assert.equal(pe.ok, true);
  assert.equal(pe.machine, "x64");
  assert.equal(pe.is64Bit, true);
  assert.equal(pe.subsystem, "windows_console");
});

test("parsePE extracts DLL names and imported function names (PE32)", () => {
  const buffer = buildPE({
    imports: [
      { dll: "KERNEL32.dll", functions: ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"] },
      { dll: "USER32.dll", functions: ["MessageBoxA"] }
    ]
  });
  const pe = parsePE(buffer);

  assert.equal(pe.imports.length, 2);
  assert.equal(pe.imports[0].dll, "KERNEL32.dll");
  assert.deepEqual(pe.imports[0].functions, ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]);
  assert.deepEqual(pe.imports[1].functions, ["MessageBoxA"]);
  assert.equal(pe.importedFunctionCount, 4);
});

test("parsePE extracts imports through 8-byte thunks (PE32+)", () => {
  const buffer = buildPE({
    is64Bit: true,
    imports: [{ dll: "KERNEL32.dll", functions: ["LoadLibraryA", "GetProcAddress"] }]
  });
  const pe = parsePE(buffer);

  assert.equal(pe.imports.length, 1);
  assert.deepEqual(pe.imports[0].functions, ["LoadLibraryA", "GetProcAddress"]);
});

test("parsePE reports section flags and entropy", () => {
  const buffer = buildPE({ sectionName: ".text", sectionCharacteristics: 0x60000020 });
  const pe = parsePE(buffer);

  assert.equal(pe.sections.length, 1);
  assert.equal(pe.sections[0].name, ".text");
  assert.equal(pe.sections[0].isExecutable, true);
  assert.equal(pe.sections[0].isWritable, false);
  assert.equal(typeof pe.sections[0].entropy, "number");
});

test("parsePE flags a writable AND executable section", () => {
  // W+X is the classic self-modifying / unpacking-stub layout.
  const buffer = buildPE({ sectionName: ".packed", sectionCharacteristics: 0xe0000020 });
  const pe = parsePE(buffer);

  assert.equal(pe.sections[0].isExecutable, true);
  assert.equal(pe.sections[0].isWritable, true);
});

test("parsePE detects an Authenticode certificate directory", () => {
  assert.equal(parsePE(buildPE({ hasSignature: true })).hasSignature, true);
  assert.equal(parsePE(buildPE({ hasSignature: false })).hasSignature, false);
});

test("parsePE measures overlay data appended after the last section", () => {
  const overlay = new TextEncoder().encode("SECOND_PAYLOAD_HIDDEN_HERE");
  const pe = parsePE(buildPE({ overlay }));

  assert.equal(pe.overlaySize, overlay.length);
});

test("parsePE reports a DLL as such", () => {
  assert.equal(parsePE(buildPE({ isDll: true })).isDll, true);
});

test("parsePE rejects a non-PE buffer cleanly", () => {
  const pdf = new TextEncoder().encode("%PDF-1.4 " + "content ".repeat(20)).buffer;
  const pe = parsePE(pdf);

  assert.equal(pe.ok, false);
  assert.match(pe.error, /MZ signature/);
});

test("parsePE handles a truncated buffer without throwing", () => {
  const full = buildPE({ imports: [{ dll: "KERNEL32.dll", functions: ["Sleep"] }] });
  const truncated = full.slice(0, 100);
  const pe = parsePE(truncated);

  assert.equal(pe.ok, false);
  assert.equal(typeof pe.error, "string");
});

test("parsePE survives an import directory pointing outside the file", () => {
  const bytes = new Uint8Array(buildPE({ imports: [{ dll: "A.dll", functions: ["B"] }] }));
  const view = new DataView(bytes.buffer);
  // Corrupt the import table RVA so translation fails.
  const optOffset = 0x40 + 4 + 20;
  view.setUint32(optOffset + 96 + 8, 0x7fffffff, true);

  const pe = parsePE(bytes.buffer);
  assert.equal(pe.ok, true);
  assert.equal(pe.imports.length, 0);
});

test("looksLikePE detects the MZ magic", () => {
  assert.equal(looksLikePE(buildPE({})), true);
  assert.equal(looksLikePE(new TextEncoder().encode("%PDF").buffer), false);
});
