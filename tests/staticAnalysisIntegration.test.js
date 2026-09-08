// End-to-end tests for the static analysis orchestrator: real file structures
// in, findings with evidence out. These are the tests that would catch a
// regression in how the parsers, rules, and scoring fit together.

import test from "node:test";
import assert from "node:assert/strict";
import { runStaticAnalysis } from "../modules/staticAnalysis.js";
import { buildPE } from "./helpers/peBuilder.js";
import { buildZip } from "./helpers/zipBuilder.js";

const keysOf = (result) => result.findings.map(f => f.key);

// --- PE behavioural detection ---

test("flags a PE importing the process-injection API set", () => {
  const buffer = buildPE({
    imports: [{
      dll: "KERNEL32.dll",
      functions: ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "OpenProcess"]
    }]
  });
  const result = runStaticAnalysis(buffer, { extension: "exe", category: "executable", filename: "setup.exe" });

  const injection = result.findings.find(f => f.key === "API_PROCESS_INJECTION");
  assert.ok(injection, "expected process injection finding");
  assert.equal(injection.severity, "critical");
  assert.equal(injection.mitre, "T1055");
  assert.equal(result.verdict, "malicious");
  assert.equal(result.staticAnalysisScore, 5);
});

test("injection finding cites the actual imported function names", () => {
  const buffer = buildPE({
    imports: [{ dll: "KERNEL32.dll", functions: ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"] }]
  });
  const result = runStaticAnalysis(buffer, { extension: "exe", category: "executable" });
  const injection = result.findings.find(f => f.key === "API_PROCESS_INJECTION");

  assert.match(injection.evidence[0], /VirtualAllocEx/);
  assert.match(injection.evidence[0], /CreateRemoteThread/);
});

test("flags a keylogger API combination", () => {
  const buffer = buildPE({
    imports: [{ dll: "USER32.dll", functions: ["SetWindowsHookExW", "GetAsyncKeyState"] }]
  });
  const result = runStaticAnalysis(buffer, { extension: "exe", category: "executable" });

  assert.ok(keysOf(result).includes("API_KEYLOGGING"));
});

test("flags a writable+executable section", () => {
  const buffer = buildPE({ sectionName: ".packed", sectionCharacteristics: 0xe0000020 });
  const result = runStaticAnalysis(buffer, { extension: "exe", category: "executable" });

  assert.ok(keysOf(result).includes("PE_WRITABLE_EXECUTABLE_SECTION"));
});

test("notes an unsigned executable as a low-severity observation only", () => {
  const buffer = buildPE({ imports: [{ dll: "KERNEL32.dll", functions: ["Sleep"] }] });
  const result = runStaticAnalysis(buffer, { extension: "exe", category: "executable" });

  const unsigned = result.findings.find(f => f.key === "PE_UNSIGNED");
  assert.equal(unsigned.severity, "low");
  // A low-severity-only file must not be branded malicious.
  assert.notEqual(result.verdict, "malicious");
});

test("a signed executable with ordinary imports produces no unsigned finding", () => {
  const buffer = buildPE({
    hasSignature: true,
    imports: [{ dll: "KERNEL32.dll", functions: ["CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "GetLastError", "HeapAlloc"] }]
  });
  const result = runStaticAnalysis(buffer, { extension: "exe", category: "executable" });

  assert.equal(keysOf(result).includes("PE_UNSIGNED"), false);
});

test("exposes a PE structure summary for the UI", () => {
  const buffer = buildPE({
    is64Bit: true,
    imports: [{ dll: "KERNEL32.dll", functions: ["Sleep", "CreateFileW"] }]
  });
  const result = runStaticAnalysis(buffer, { extension: "exe", category: "executable" });

  assert.equal(result.structure.type, "pe");
  assert.equal(result.structure.machine, "x64");
  assert.deepEqual(result.structure.importedDlls, ["KERNEL32.dll"]);
});

// --- Archive detection ---

test("flags an executable hidden inside an archive", () => {
  const buffer = buildZip([
    { name: "invoice.pdf", content: "%PDF-1.4 fake" },
    { name: "install.exe", content: "MZ payload" }
  ]);
  const result = runStaticAnalysis(buffer, { extension: "zip", category: "archive", filename: "docs.zip" });

  const found = result.findings.find(f => f.key === "EXECUTABLE_IN_ARCHIVE");
  assert.ok(found);
  assert.match(found.evidence.join(" "), /install\.exe/);
});

test("does NOT flag an archive whose documents merely mention an exe", () => {
  // The regression the structural parser exists to prevent.
  const buffer = buildZip([
    { name: "readme.txt", content: "Run setup.exe after extracting to install." },
    { name: "manual.pdf", content: "See install.exe in the parent folder." }
  ]);
  const result = runStaticAnalysis(buffer, { extension: "zip", category: "archive" });

  assert.equal(keysOf(result).includes("EXECUTABLE_IN_ARCHIVE"), false);
});

test("flags the decoy-documents-plus-payload archive layout", () => {
  const buffer = buildZip([
    { name: "report.pdf", content: "a" },
    { name: "photo.jpg", content: "b" },
    { name: "notes.docx", content: "c" },
    { name: "opener.exe", content: "MZ" }
  ]);
  const result = runStaticAnalysis(buffer, { extension: "zip", category: "archive" });

  assert.ok(keysOf(result).includes("ARCHIVE_DECOY_LAYOUT"));
});

test("flags a zip bomb by expansion ratio", () => {
  const buffer = buildZip([
    { name: "big.bin", content: "x".repeat(500), compressedSize: 500, uncompressedSize: 500_000_000 }
  ]);
  const result = runStaticAnalysis(buffer, { extension: "zip", category: "archive" });

  const bomb = result.findings.find(f => f.key === "ARCHIVE_ZIP_BOMB");
  assert.ok(bomb);
  assert.equal(bomb.mitre, "T1499");
});

test("detects a macro inside a real docx container", () => {
  const buffer = buildZip([
    { name: "[Content_Types].xml", content: "<xml/>" },
    { name: "word/document.xml", content: "<w:document/>" },
    { name: "word/vbaProject.bin", content: "macro bytes" }
  ]);
  const result = runStaticAnalysis(buffer, { extension: "docx", category: "document" });

  assert.ok(keysOf(result).includes("EMBEDDED_MACRO"));
});

// --- Filename deception ---

test("flags a double extension", () => {
  const result = runStaticAnalysis(
    new TextEncoder().encode("harmless text").buffer,
    { extension: "exe", category: "executable", filename: "invoice.pdf.exe" }
  );

  const found = result.findings.find(f => f.key === "FILENAME_DOUBLE_EXTENSION");
  assert.ok(found);
  assert.equal(found.severity, "critical");
});

test("flags a right-to-left override in the filename", () => {
  const result = runStaticAnalysis(
    new TextEncoder().encode("x").buffer,
    { extension: "exe", category: "executable", filename: "annex‮cod.txt" }
  );

  assert.ok(keysOf(result).includes("FILENAME_BIDI_OVERRIDE"));
});

test("filename tricks are still caught when no content was downloaded", () => {
  const result = runStaticAnalysis(null, {
    extension: "exe", category: "executable", filename: "photo.jpg.exe"
  });

  assert.equal(result.status, "findings");
  assert.ok(keysOf(result).includes("FILENAME_DOUBLE_EXTENSION"));
});

test("an ordinary filename with no content stays unknown, not suspicious", () => {
  const result = runStaticAnalysis(null, {
    extension: "exe", category: "executable", filename: "setup.exe"
  });

  assert.equal(result.status, "no_content");
  assert.equal(result.verdict, "unknown");
  assert.equal(result.staticAnalysisScore, 55);
});

// --- Byte rules through the orchestrator ---

test("flags ransomware shadow-copy deletion in a script", () => {
  const buffer = new TextEncoder().encode(
    "@echo off\r\nvssadmin delete shadows /all /quiet\r\n"
  ).buffer;
  const result = runStaticAnalysis(buffer, { extension: "bat", category: "script", filename: "run.bat" });

  const found = result.findings.find(f => f.key === "BYTE_SHADOW_COPY_DELETION");
  assert.ok(found);
  assert.equal(found.mitre, "T1490");
  assert.match(found.evidence[0], /offset \d+/);
});

test("flags a curl-piped-to-shell installer script", () => {
  const buffer = new TextEncoder().encode("curl -fsSL http://example.test/i.sh | sudo bash").buffer;
  const result = runStaticAnalysis(buffer, { extension: "sh", category: "script" });

  assert.ok(keysOf(result).includes("BYTE_CURL_PIPE_SHELL"));
});

// --- Clean baselines (false-positive guards) ---

test("a plain text file produces no findings", () => {
  const buffer = new TextEncoder().encode(
    "Release notes\n\nVersion 2.1 fixes a crash when opening large files.\n"
  ).buffer;
  const result = runStaticAnalysis(buffer, { extension: "txt", category: "document", filename: "notes.txt" });

  assert.deepEqual(result.findings, []);
  assert.equal(result.verdict, "clean");
  assert.equal(result.staticAnalysisScore, 95);
});

test("an ordinary docx produces no findings", () => {
  const buffer = buildZip([
    { name: "[Content_Types].xml", content: "<xml/>" },
    { name: "word/document.xml", content: "<w:document><w:body>Hello</w:body></w:document>" },
    { name: "word/styles.xml", content: "<w:styles/>" }
  ]);
  const result = runStaticAnalysis(buffer, { extension: "docx", category: "document", filename: "report.docx" });

  assert.deepEqual(result.findings, []);
  assert.equal(result.verdict, "clean");
});

test("a benign archive of documents produces no findings", () => {
  const buffer = buildZip([
    { name: "q1.pdf", content: "%PDF-1.4 report" },
    { name: "q2.pdf", content: "%PDF-1.4 report" }
  ]);
  const result = runStaticAnalysis(buffer, { extension: "zip", category: "archive", filename: "reports.zip" });

  assert.deepEqual(result.findings, []);
});

// --- Scoring model ---

test("score is graduated for non-critical findings, not binary", () => {
  const buffer = buildPE({ imports: [{ dll: "KERNEL32.dll", functions: ["Sleep"] }] });
  const result = runStaticAnalysis(buffer, { extension: "exe", category: "executable" });

  assert.ok(result.staticAnalysisScore > 5, "should not be floored like a critical finding");
  assert.ok(result.staticAnalysisScore < 95, "should be reduced from clean");
});

test("every finding carries the fields the UI renders", () => {
  const buffer = buildPE({
    imports: [{ dll: "KERNEL32.dll", functions: ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"] }]
  });
  const result = runStaticAnalysis(buffer, { extension: "exe", category: "executable", filename: "a.exe" });

  for (const f of result.findings) {
    assert.equal(typeof f.key, "string");
    assert.equal(typeof f.label, "string");
    assert.ok(["critical", "high", "medium", "low"].includes(f.severity));
    assert.equal(typeof f.confidence, "number");
    assert.ok(Array.isArray(f.evidence));
    assert.equal(typeof f.explain, "string");
  }
});
