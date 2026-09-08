// modules/staticAnalysis.js
// Module 5b: Local static file analysis — the orchestrator.
//
// This runs entirely on the downloaded bytes, on-device, with no API key and
// no network call. It combines four independent evidence sources:
//
//   filename    deception tricks visible before the file is even opened
//   structure   real format parsers (PE / ZIP / PDF / OLE)
//   behaviour   Windows API combinations a PE declares it will call
//   content     byte and string signatures
//
// Every finding carries the concrete observation that produced it, so the UI
// can tell a user *"this installer imports the process-injection API set"*
// rather than *"trust score: 34"*. That difference is the entire point.
//
// Judgement lives here; parsing lives in parsers/, and detection knowledge
// lives in malwareRules.js. Keeping the three separate means rules can be
// added without touching engine code, and parsers stay independently testable.

import {
  FILE_SIGNATURES,
  SUSPICIOUS_SCRIPT_PATTERNS,
  HIGH_ENTROPY_THRESHOLD,
  STATIC_ANALYSIS_MAX_BYTES
} from "./config.js";
import {
  API_RULES,
  BYTE_RULES,
  THRESHOLDS,
  DANGEROUS_ARCHIVE_EXTENSIONS,
  DECOY_EXTENSIONS
} from "./malwareRules.js";
import { matchApiRules, matchByteRules } from "./ruleEngine.js";
import { parsePE, looksLikePE } from "./parsers/peParser.js";
import { parseZip } from "./parsers/zipParser.js";
import { parsePdf, looksLikePdf } from "./parsers/pdfParser.js";
import { parseOle, looksLikeOle } from "./parsers/oleParser.js";

// Right-to-left override: renders "annexe[U+202E]cod.txt" as "annexetxt.doc".
const RLO_CHARACTERS = /[‪-‮⁦-⁩]/;

const SEVERITY_PENALTY = { critical: 90, high: 30, medium: 15, low: 5 };
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function shannonEntropy(bytes) {
  if (!bytes.length) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) counts[bytes[i]]++;
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (counts[i] === 0) continue;
    const p = counts[i] / bytes.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function detectFileType(buffer) {
  const head = new Uint8Array(buffer.slice(0, 16));
  const headHex = bytesToHex(head);
  for (const sig of FILE_SIGNATURES) {
    if (headHex.startsWith(sig.hex)) return sig;
  }
  return null;
}

function finding(key, severity, label, options = {}) {
  return {
    key,
    severity,
    label,
    confidence: options.confidence ?? 0.7,
    mitre: options.mitre ?? null,
    explain: options.explain ?? "",
    evidence: options.evidence ?? []
  };
}

function extensionOf(name) {
  const match = /\.([a-z0-9]+)$/i.exec(name || "");
  return match ? match[1].toLowerCase() : "";
}

// --- 1. Filename deception -------------------------------------------------

function analyzeFilename(parsed) {
  const findings = [];
  const filename = parsed.filename || "";
  if (!filename) return findings;

  if (RLO_CHARACTERS.test(filename)) {
    findings.push(finding(
      "FILENAME_BIDI_OVERRIDE", "critical",
      "Filename contains a right-to-left override character",
      {
        confidence: 0.95,
        mitre: "T1036.002",
        explain: "The filename contains an invisible character that reverses how the rest of it is displayed. This is used to make an executable appear to be a document — there is no legitimate reason for it.",
        evidence: [`raw filename: ${JSON.stringify(filename)}`]
      }
    ));
  }

  // A trailing executable extension preceded by a document-looking one.
  const parts = filename.toLowerCase().split(".");
  if (parts.length >= 3) {
    const finalExt = parts[parts.length - 1];
    const priorExt = parts[parts.length - 2];
    if (DANGEROUS_ARCHIVE_EXTENSIONS.has(finalExt) && DECOY_EXTENSIONS.has(priorExt)) {
      findings.push(finding(
        "FILENAME_DOUBLE_EXTENSION", "critical",
        `Double extension: looks like .${priorExt} but is actually .${finalExt}`,
        {
          confidence: 0.9,
          mitre: "T1036.007",
          explain: `The name suggests a ${priorExt.toUpperCase()} file, but the real type is .${finalExt}, which runs code when opened. Windows hides known extensions by default, so many users only ever see the ".${priorExt}" part.`,
          evidence: [`filename: ${filename}`]
        }
      ));
    }
  }

  return findings;
}

// --- 2. Windows executables ------------------------------------------------

function analyzePE(buffer, findings) {
  const pe = parsePE(buffer);
  if (!pe.ok) return null;

  // Behavioural rules over the declared import table.
  for (const match of matchApiRules(pe.imports, API_RULES)) {
    findings.push(finding(match.id, match.severity, match.title, {
      confidence: match.confidence,
      mitre: match.mitre,
      explain: match.explain,
      evidence: [`imports: ${match.matchedApis.join(", ")}`]
    }));
  }

  // Packed / obfuscated section layout.
  for (const section of pe.sections) {
    if (section.entropy !== null && section.entropy >= THRESHOLDS.packedSectionEntropy) {
      findings.push(finding(
        "PE_PACKED_SECTION", "medium",
        `Section "${section.name}" is packed or encrypted (entropy ${section.entropy.toFixed(2)}/8.0)`,
        {
          confidence: 0.6,
          mitre: "T1027.002",
          explain: "This part of the program is compressed or encrypted, so its real contents cannot be inspected until it runs. Used by commercial packers and by malware hiding from scanners.",
          evidence: [`section ${section.name}: entropy ${section.entropy.toFixed(2)}, raw size ${section.rawSize}`]
        }
      ));
    }

    if (section.isExecutable && section.isWritable) {
      findings.push(finding(
        "PE_WRITABLE_EXECUTABLE_SECTION", "high",
        `Section "${section.name}" is both writable and executable`,
        {
          confidence: 0.7,
          mitre: "T1027.002",
          explain: "A region of this program can rewrite its own code while running. Normal compilers never produce this; unpacking stubs and self-modifying malware do.",
          evidence: [`section ${section.name}: characteristics 0x${section.characteristics.toString(16)}`]
        }
      ));
    }

    if (section.rawSize > 0 && section.virtualSize > section.rawSize * THRESHOLDS.virtualSizeRatio) {
      findings.push(finding(
        "PE_SECTION_SIZE_MISMATCH", "medium",
        `Section "${section.name}" reserves far more memory than it occupies on disk`,
        {
          confidence: 0.55,
          mitre: "T1027.002",
          explain: "The program reserves a large empty memory region, typically to unpack hidden code into after it starts.",
          evidence: [`section ${section.name}: virtual ${section.virtualSize} vs raw ${section.rawSize}`]
        }
      ));
    }
  }

  // A stripped import table is itself the signal.
  if (pe.importedFunctionCount > 0 && pe.importedFunctionCount < THRESHOLDS.minimumExpectedImports) {
    findings.push(finding(
      "PE_MINIMAL_IMPORTS", "medium",
      `Unusually small import table (${pe.importedFunctionCount} functions)`,
      {
        confidence: 0.55,
        mitre: "T1027.002",
        explain: "Real applications import dozens of system functions. A near-empty import table means the real ones are resolved at runtime to hide what the program does.",
        evidence: [`${pe.importedFunctionCount} imported functions across ${pe.imports.length} DLL(s)`]
      }
    ));
  }

  if (!pe.hasSignature) {
    findings.push(finding(
      "PE_UNSIGNED", "low",
      "Executable is not digitally signed",
      {
        confidence: 0.3,
        explain: "There is no code signature, so the publisher cannot be verified. Common for small and open-source tools, but major commercial software is essentially always signed.",
        evidence: ["no Authenticode certificate directory present"]
      }
    ));
  }

  return pe;
}

// --- 3. ZIP-based containers ----------------------------------------------

function analyzeZipContainer(buffer, parsed, findings) {
  const zip = parseZip(buffer);

  if (!zip.ok) {
    // Degraded path: for a partial download the central directory (which
    // lives at the end of the file) simply was not fetched. Fall back to a
    // raw scan so a macro in a partial .docx is still caught.
    const text = new TextDecoder("latin1").decode(
      new Uint8Array(buffer, 0, Math.min(buffer.byteLength, STATIC_ANALYSIS_MAX_BYTES))
    );
    if (/vbaProject\.bin/i.test(text)) {
      findings.push(finding(
        "EMBEDDED_MACRO", "high",
        "Contains a VBA macro project (vbaProject.bin)",
        {
          confidence: 0.75,
          mitre: "T1059.005",
          explain: "This document carries embedded macro code that can run when the document is opened. Macros are the most common delivery method for document-based malware.",
          evidence: ["vbaProject.bin found in raw container bytes"]
        }
      ));
    }
    return zip;
  }

  const fileEntries = zip.entries.filter(e => !e.isDirectory);

  if (fileEntries.some(e => /(^|\/)vbaProject\.bin$/i.test(e.name))) {
    findings.push(finding(
      "EMBEDDED_MACRO", "high",
      "Contains a VBA macro project (vbaProject.bin)",
      {
        confidence: 0.8,
        mitre: "T1059.005",
        explain: "This document carries embedded macro code that can run when the document is opened. Macros are the most common delivery method for document-based malware.",
        evidence: ["archive entry: word/vbaProject.bin"]
      }
    ));
  }

  const executableEntries = fileEntries.filter(
    e => DANGEROUS_ARCHIVE_EXTENSIONS.has(extensionOf(e.name))
  );

  if (executableEntries.length && parsed.category === "archive") {
    const names = executableEntries.slice(0, 5).map(e => e.name);
    findings.push(finding(
      "EXECUTABLE_IN_ARCHIVE", "critical",
      `Archive contains ${executableEntries.length} executable or script file(s)`,
      {
        confidence: 0.75,
        mitre: "T1204.002",
        explain: "Opening this archive shows only its name; the executable inside runs only once a user double-clicks it. Packaging an executable inside an archive is a standard way to get past email and download filters.",
        evidence: names.map(n => `archive entry: ${n}`)
      }
    ));

    // The decoy shape: a pile of harmless-looking documents plus one payload.
    const decoyCount = fileEntries.filter(e => DECOY_EXTENSIONS.has(extensionOf(e.name))).length;
    if (decoyCount >= 2 && executableEntries.length <= 2) {
      findings.push(finding(
        "ARCHIVE_DECOY_LAYOUT", "high",
        "Archive pairs decoy documents with a small number of executables",
        {
          confidence: 0.65,
          mitre: "T1036",
          explain: "The archive is mostly ordinary-looking documents with one or two programs mixed in — a layout designed so the contents look routine at a glance.",
          evidence: [`${decoyCount} document entries, ${executableEntries.length} executable entries`]
        }
      ));
    }
  }

  if (fileEntries.some(e => e.isEncrypted)) {
    findings.push(finding(
      "ARCHIVE_ENCRYPTED", "medium",
      "Archive contents are password-protected",
      {
        confidence: 0.5,
        mitre: "T1027.013",
        explain: "Encrypted archives cannot be scanned by antivirus software. When the password is supplied in the same email or page, the encryption exists to defeat scanning, not to protect you.",
        evidence: ["one or more entries have the encryption flag set"]
      }
    ));
  }

  // Zip bomb: enormous declared expansion from a tiny archive.
  const totalCompressed = fileEntries.reduce((sum, e) => sum + e.compressedSize, 0);
  const totalUncompressed = fileEntries.reduce((sum, e) => sum + e.uncompressedSize, 0);
  if (
    totalCompressed > 0 &&
    totalUncompressed > THRESHOLDS.zipBombMinUncompressed &&
    totalUncompressed / totalCompressed > THRESHOLDS.zipBombRatio
  ) {
    const ratio = Math.round(totalUncompressed / totalCompressed);
    findings.push(finding(
      "ARCHIVE_ZIP_BOMB", "high",
      `Archive expands ${ratio}x when extracted`,
      {
        confidence: 0.8,
        mitre: "T1499",
        explain: "This archive is tiny but expands enormously, which can exhaust disk space or memory and crash the machine or its antivirus.",
        evidence: [`${totalCompressed} bytes compressed -> ${totalUncompressed} bytes extracted`]
      }
    ));
  }

  return zip;
}

// --- 4. Documents ----------------------------------------------------------

function analyzePdfDocument(buffer, findings) {
  const pdf = parsePdf(buffer);
  if (!pdf.ok) return null;

  const keys = new Set(pdf.markers.map(m => m.key));
  const hasScript = keys.has("JAVASCRIPT") || keys.has("JS_ABBREV");
  const autoRuns = keys.has("OPEN_ACTION") || keys.has("ADDITIONAL_ACTION");

  if (hasScript && autoRuns) {
    findings.push(finding(
      "PDF_AUTO_JAVASCRIPT", "critical",
      "PDF runs embedded JavaScript automatically when opened",
      {
        confidence: 0.85,
        mitre: "T1204.002",
        explain: "This document executes code the moment it is opened, without any further click. Ordinary documents never need this.",
        evidence: pdf.markers.filter(m => ["JAVASCRIPT", "JS_ABBREV", "OPEN_ACTION", "ADDITIONAL_ACTION"].includes(m.key))
          .map(m => `${m.label} x${m.count}`)
      }
    ));
  } else if (hasScript) {
    findings.push(finding(
      "PDF_JAVASCRIPT", "high",
      "PDF contains embedded JavaScript",
      {
        confidence: 0.65,
        mitre: "T1204.002",
        explain: "This document carries executable script. Legitimate uses exist (interactive forms), but it is also the standard route for PDF-based exploits.",
        evidence: pdf.markers.filter(m => ["JAVASCRIPT", "JS_ABBREV"].includes(m.key)).map(m => `${m.label} x${m.count}`)
      }
    ));
  }

  if (keys.has("LAUNCH")) {
    findings.push(finding(
      "PDF_LAUNCH_ACTION", "critical",
      "PDF can launch an external program (/Launch)",
      {
        confidence: 0.85,
        mitre: "T1204.002",
        explain: "This document is able to start another application on your computer. There is no benign reason for a document to do this.",
        evidence: ["/Launch action present"]
      }
    ));
  }

  if (keys.has("EMBEDDED_FILE")) {
    findings.push(finding(
      "PDF_EMBEDDED_FILE", "medium",
      "PDF contains an embedded file",
      {
        confidence: 0.55,
        mitre: "T1027.013",
        explain: "Another file is packaged inside this document and can be extracted or opened from it.",
        evidence: ["/EmbeddedFile object present"]
      }
    ));
  }

  if (pdf.usedHexObfuscation && (hasScript || keys.has("LAUNCH"))) {
    findings.push(finding(
      "PDF_NAME_OBFUSCATION", "high",
      "PDF hides its action names using hex escapes",
      {
        confidence: 0.8,
        mitre: "T1027",
        explain: "The document writes its instruction names in an encoded form that readers understand but simple scanners miss. Encoding is only worth doing if there is something to hide.",
        evidence: ["#xx hex escapes found in PDF name tokens"]
      }
    ));
  }

  return pdf;
}

function analyzeOleDocument(buffer, findings) {
  const ole = parseOle(buffer);
  if (!ole.ok) return null;

  if (ole.hasVbaMacros) {
    findings.push(finding(
      "EMBEDDED_MACRO", "high",
      "Legacy Office document contains VBA macros",
      {
        confidence: 0.8,
        mitre: "T1059.005",
        explain: "This document carries embedded macro code that can run when opened. Macros remain the most common delivery method for document-based malware.",
        evidence: ole.streams.map(s => `OLE stream: ${s}`)
      }
    ));
  }

  if (ole.hasExcel4Macros) {
    findings.push(finding(
      "EXCEL4_MACRO", "critical",
      "Spreadsheet contains Excel 4.0 (XLM) macros",
      {
        confidence: 0.85,
        mitre: "T1059.005",
        explain: "This uses a 1992-era macro language that modern Excel still executes. It is chosen specifically because many security tools only inspect newer VBA macros.",
        evidence: ["Excel 4.0 Macros sheet reference found"]
      }
    ));
  }

  if (ole.hasEmbeddedOleObject) {
    findings.push(finding(
      "OLE_EMBEDDED_OBJECT", "medium",
      "Document contains an embedded OLE object",
      {
        confidence: 0.5,
        mitre: "T1204.002",
        explain: "Another file or program is embedded in this document and can be run by double-clicking an icon inside it.",
        evidence: ole.streams.filter(s => s === "OBJECT_POOL" || s === "OLE10_NATIVE").map(s => `OLE stream: ${s}`)
      }
    ));
  }

  return ole;
}

// --- 5. Scoring ------------------------------------------------------------

function scoreFindings(findings) {
  if (!findings.length) return 95;
  if (findings.some(f => f.severity === "critical")) return 5;

  const penalty = findings.reduce(
    (sum, f) => sum + (SEVERITY_PENALTY[f.severity] ?? 10) * (f.confidence ?? 0.7),
    0
  );
  return Math.max(10, Math.min(95, Math.round(95 - penalty)));
}

function highestSeverity(findings) {
  return findings.reduce((worst, f) => {
    const rank = SEVERITY_RANK[f.severity] ?? 0;
    return rank > SEVERITY_RANK[worst] ? f.severity : worst;
  }, "low");
}

// --- Entry point -----------------------------------------------------------

/**
 * @param {ArrayBuffer|null} buffer  raw file bytes (may be null when the fetch was skipped)
 * @param {{extension?: string, category?: string, filename?: string}} parsed
 */
export function runStaticAnalysis(buffer, parsed = {}) {
  const filenameFindings = analyzeFilename(parsed);

  if (!buffer || buffer.byteLength === 0) {
    // Filename tricks are observable without any content at all, so a skipped
    // or failed download still produces a real verdict when one applies.
    if (filenameFindings.length) {
      return {
        staticAnalysisScore: scoreFindings(filenameFindings),
        status: "findings",
        detectedType: "unknown",
        findings: filenameFindings,
        verdict: "suspicious",
        reason: filenameFindings[0].label
      };
    }
    return {
      staticAnalysisScore: 55,
      status: "no_content",
      detectedType: "unknown",
      findings: [],
      verdict: "unknown",
      reason: "Empty file buffer"
    };
  }

  const findings = [...filenameFindings];
  const sampleBytes = new Uint8Array(
    buffer.slice(0, Math.min(buffer.byteLength, STATIC_ANALYSIS_MAX_BYTES))
  );

  // Extension spoofing: what the bytes say vs what the name claims.
  const detected = detectFileType(buffer);
  if (detected && !detected.categories.includes(parsed.category) && parsed.category !== "other") {
    findings.push(finding(
      "EXTENSION_MISMATCH", "critical",
      `File claims to be .${parsed.extension} (${parsed.category}) but signature is ${detected.type}`,
      {
        confidence: 0.9,
        mitre: "T1036.008",
        explain: `The file's actual contents are a ${detected.type.replace(/_/g, " ")}, not the ${parsed.category} its name claims. Renaming a program to look like a document is a deliberate deception.`,
        evidence: [`magic bytes: ${bytesToHex(sampleBytes.slice(0, 4))}`, `declared extension: .${parsed.extension}`]
      }
    ));
  }

  // Format-specific structural analysis.
  let structure = null;
  if (looksLikePE(buffer)) {
    structure = { type: "pe", data: analyzePE(buffer, findings) };
  } else if (looksLikePdf(buffer)) {
    structure = { type: "pdf", data: analyzePdfDocument(buffer, findings) };
  } else if (looksLikeOle(buffer)) {
    structure = { type: "ole", data: analyzeOleDocument(buffer, findings) };
  } else if (detected?.type === "zip_based" || parsed.category === "archive" || parsed.category === "document") {
    structure = { type: "zip", data: analyzeZipContainer(buffer, parsed, findings) };
  }

  // Byte/string signatures run over every file type.
  for (const match of matchByteRules(buffer, BYTE_RULES)) {
    findings.push(finding(match.id, match.severity, match.title, {
      confidence: match.confidence,
      mitre: match.mitre,
      explain: match.explain,
      evidence: match.matchedStrings.map(s => `"${s.name}" at offset ${s.offset}`)
    }));
  }

  // Entropy on formats that should be plain text or structured content.
  // Executables are excluded here because PE section entropy above is the
  // precise measurement — whole-file entropy on a compiled binary is noise.
  if (["script", "code", "document"].includes(parsed.category)) {
    const entropy = shannonEntropy(sampleBytes);
    if (entropy >= HIGH_ENTROPY_THRESHOLD) {
      findings.push(finding(
        "HIGH_ENTROPY", "medium",
        `High byte-entropy (${entropy.toFixed(2)}/8.0) — possible packed or obfuscated content`,
        {
          confidence: 0.55,
          mitre: "T1027",
          explain: "This file should be readable text but its contents look random, which means it is compressed, encrypted, or deliberately obfuscated.",
          evidence: [`Shannon entropy ${entropy.toFixed(2)} over ${sampleBytes.length} bytes`]
        }
      ));
    }
  }

  // Script-specific patterns.
  if (parsed.category === "script" || ["js", "ps1", "vbs", "bat", "cmd", "sh"].includes(parsed.extension)) {
    const text = new TextDecoder("utf-8", { fatal: false }).decode(sampleBytes);
    for (const pattern of SUSPICIOUS_SCRIPT_PATTERNS) {
      if (pattern.rx.test(text)) {
        findings.push(finding(pattern.key, "critical", pattern.label, {
          confidence: 0.8,
          mitre: "T1059",
          explain: "This script uses a technique associated with malware loaders: fetching or decoding code at runtime so that what actually executes is not visible in the file.",
          evidence: [pattern.label]
        }));
      }
    }
  }

  const staticAnalysisScore = scoreFindings(findings);
  const worst = findings.length ? highestSeverity(findings) : null;

  let verdict = "clean";
  if (worst === "critical") verdict = "malicious";
  else if (worst === "high") verdict = "suspicious";
  else if (worst) verdict = "low_risk";

  return {
    staticAnalysisScore,
    status: findings.length ? "findings" : "clean",
    detectedType: detected?.type || (structure?.type ?? "unknown"),
    verdict,
    findings,
    structure: structure?.data ? summarizeStructure(structure) : null,
    reason: findings.length
      ? findings.find(f => f.severity === "critical")?.label ?? findings[0].label
      : "Passed static signatures and structural checks"
  };
}

/** Compact, serialisable structure summary for the scan record and UI. */
function summarizeStructure(structure) {
  const { type, data } = structure;
  if (!data) return null;

  if (type === "pe") {
    return {
      type: "pe",
      machine: data.machine,
      subsystem: data.subsystem,
      isDll: data.isDll,
      isDotNet: data.isDotNet,
      signed: data.hasSignature,
      sectionCount: data.sections.length,
      importedDlls: data.imports.map(i => i.dll),
      importedFunctionCount: data.importedFunctionCount,
      overlaySize: data.overlaySize
    };
  }
  if (type === "zip") {
    return {
      type: "zip",
      entryCount: data.totalEntries,
      entries: data.entries.filter(e => !e.isDirectory).slice(0, 25).map(e => e.name),
      truncated: data.truncated
    };
  }
  if (type === "pdf") {
    return {
      type: "pdf",
      version: data.version,
      objectCount: data.objectCount,
      markers: data.markers.map(m => m.key),
      incrementalUpdates: data.incrementalUpdates
    };
  }
  if (type === "ole") {
    return { type: "ole", streams: data.streams, sectorSize: data.sectorSize };
  }
  return null;
}
