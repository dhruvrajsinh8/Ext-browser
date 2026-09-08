// modules/parsers/peParser.js
// Structural reader for Windows PE binaries (.exe, .dll, .sys, .scr).
//
// This is what turns "trust score: 34" into evidence a user can act on. A PE
// file declares, in its Import Address Table, every OS function it intends to
// call. Malware families are defined by their API combinations far more
// reliably than by any byte signature: a binary importing VirtualAllocEx +
// WriteProcessMemory + CreateRemoteThread is doing process injection, and
// there is no benign reading of that trio in a consumer download.
//
// PURE STRUCTURE READER — no verdicts here. Interpretation lives in
// malwareRules.js so the parsing stays independently testable and the
// detection logic stays independently reviewable.
//
// Format reference: PE/COFF Specification v11. All integers little-endian.

const SIG_DOS = 0x5a4d;        // "MZ"
const SIG_PE = 0x00004550;     // "PE\0\0"
const MAGIC_PE32 = 0x10b;
const MAGIC_PE32PLUS = 0x20b;

const COFF_HEADER_SIZE = 20;
const SECTION_HEADER_SIZE = 40;
const IMPORT_DESCRIPTOR_SIZE = 20;

// Bounds that keep a malformed or hostile binary from turning into an
// unbounded loop inside the service worker.
const MAX_SECTIONS = 96;
const MAX_DLLS = 256;
const MAX_FUNCTIONS_PER_DLL = 4096;
const MAX_NAME_LENGTH = 256;

const MACHINE_TYPES = {
  0x014c: "x86",
  0x8664: "x64",
  0x01c0: "ARM",
  0xaa64: "ARM64",
  0x0200: "IA64"
};

const SUBSYSTEMS = {
  1: "native",
  2: "windows_gui",
  3: "windows_console",
  5: "os2_console",
  7: "posix_console",
  9: "windows_ce_gui",
  10: "efi_application"
};

const SECTION_FLAGS = {
  CODE: 0x00000020,
  INITIALIZED_DATA: 0x00000040,
  UNINITIALIZED_DATA: 0x00000080,
  EXECUTE: 0x20000000,
  READ: 0x40000000,
  WRITE: 0x80000000
};

const DIRECTORY_IMPORT = 1;
const DIRECTORY_CERTIFICATE = 4;
const DIRECTORY_CLR = 14;

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

function readAsciiZ(view, offset, maxLength = MAX_NAME_LENGTH) {
  const bytes = [];
  for (let i = 0; i < maxLength; i++) {
    const pos = offset + i;
    if (pos >= view.byteLength) break;
    const byte = view.getUint8(pos);
    if (byte === 0) break;
    bytes.push(byte);
  }
  return String.fromCharCode(...bytes);
}

/** Translate a relative virtual address into a file offset via the section table. */
function rvaToOffset(rva, sections) {
  for (const section of sections) {
    const size = Math.max(section.virtualSize, section.rawSize);
    if (rva >= section.virtualAddress && rva < section.virtualAddress + size) {
      const delta = rva - section.virtualAddress;
      if (delta >= section.rawSize) return -1; // inside virtual padding, not on disk
      return section.rawOffset + delta;
    }
  }
  return -1;
}

function parseSections(view, buffer, offset, count) {
  const sections = [];
  for (let i = 0; i < count && i < MAX_SECTIONS; i++) {
    const base = offset + i * SECTION_HEADER_SIZE;
    if (base + SECTION_HEADER_SIZE > view.byteLength) break;

    const nameBytes = [];
    for (let j = 0; j < 8; j++) {
      const byte = view.getUint8(base + j);
      if (byte !== 0) nameBytes.push(byte);
    }

    const characteristics = view.getUint32(base + 36, true);
    const rawSize = view.getUint32(base + 16, true);
    const rawOffset = view.getUint32(base + 20, true);

    // Entropy is measured only over bytes we actually have. A packed section
    // reads near 8.0; ordinary compiled code sits around 6.0-6.5.
    let entropy = null;
    if (rawOffset > 0 && rawSize > 0 && rawOffset + rawSize <= buffer.byteLength) {
      entropy = shannonEntropy(new Uint8Array(buffer, rawOffset, Math.min(rawSize, 512 * 1024)));
    }

    sections.push({
      name: String.fromCharCode(...nameBytes),
      virtualSize: view.getUint32(base + 8, true),
      virtualAddress: view.getUint32(base + 12, true),
      rawSize,
      rawOffset,
      characteristics,
      entropy,
      isExecutable: (characteristics & SECTION_FLAGS.EXECUTE) !== 0,
      isWritable: (characteristics & SECTION_FLAGS.WRITE) !== 0,
      isCode: (characteristics & SECTION_FLAGS.CODE) !== 0
    });
  }
  return sections;
}

function parseImports(view, sections, importRva, isPE32Plus) {
  const imports = [];
  if (!importRva) return imports;

  const tableOffset = rvaToOffset(importRva, sections);
  if (tableOffset < 0) return imports;

  const thunkSize = isPE32Plus ? 8 : 4;
  const ordinalFlag = isPE32Plus ? 0x8000000000000000n : 0x80000000;

  for (let i = 0; i < MAX_DLLS; i++) {
    const base = tableOffset + i * IMPORT_DESCRIPTOR_SIZE;
    if (base + IMPORT_DESCRIPTOR_SIZE > view.byteLength) break;

    const lookupRva = view.getUint32(base, true);
    const nameRva = view.getUint32(base + 12, true);
    const addressRva = view.getUint32(base + 16, true);

    // An all-zero descriptor terminates the table.
    if (lookupRva === 0 && nameRva === 0 && addressRva === 0) break;

    const nameOffset = rvaToOffset(nameRva, sections);
    if (nameOffset < 0) continue;
    const dllName = readAsciiZ(view, nameOffset);
    if (!dllName) continue;

    // Prefer the import lookup table; fall back to the address table, which is
    // identical on disk and is all a bound-import binary has.
    const thunkRva = lookupRva || addressRva;
    const functions = [];
    const thunkOffset = rvaToOffset(thunkRva, sections);

    if (thunkOffset >= 0) {
      for (let j = 0; j < MAX_FUNCTIONS_PER_DLL; j++) {
        const entryOffset = thunkOffset + j * thunkSize;
        if (entryOffset + thunkSize > view.byteLength) break;

        let entry;
        let isOrdinal;
        if (isPE32Plus) {
          entry = view.getBigUint64(entryOffset, true);
          if (entry === 0n) break;
          isOrdinal = (entry & ordinalFlag) !== 0n;
        } else {
          entry = view.getUint32(entryOffset, true);
          if (entry === 0) break;
          isOrdinal = (entry & ordinalFlag) !== 0;
        }

        if (isOrdinal) {
          const ordinal = isPE32Plus ? Number(entry & 0xffffn) : (entry & 0xffff);
          functions.push(`#${ordinal}`);
          continue;
        }

        // Not an ordinal: the value is an RVA to { WORD hint, char name[] }.
        const hintRva = isPE32Plus ? Number(entry & 0x7fffffffn) : entry;
        const hintOffset = rvaToOffset(hintRva, sections);
        if (hintOffset < 0) continue;
        const funcName = readAsciiZ(view, hintOffset + 2);
        if (funcName) functions.push(funcName);
      }
    }

    imports.push({ dll: dllName, functions });
  }

  return imports;
}

/**
 * @param {ArrayBuffer} buffer
 * @returns {{
 *   ok: boolean,
 *   error: string|null,
 *   machine: string, is64Bit: boolean, subsystem: string,
 *   isDll: boolean, timestamp: number|null,
 *   entryPointRva: number, sizeOfImage: number,
 *   sections: Array<object>,
 *   imports: Array<{dll: string, functions: string[]}>,
 *   importedFunctionCount: number,
 *   hasSignature: boolean, isDotNet: boolean,
 *   overlaySize: number,
 *   truncated: boolean
 * }}
 */
export function parsePE(buffer) {
  const empty = {
    ok: false, error: null, machine: "unknown", is64Bit: false, subsystem: "unknown",
    isDll: false, timestamp: null, entryPointRva: 0, sizeOfImage: 0,
    sections: [], imports: [], importedFunctionCount: 0,
    hasSignature: false, isDotNet: false, overlaySize: 0, truncated: false
  };

  if (!buffer || buffer.byteLength < 64) {
    return { ...empty, error: "buffer too small to contain a PE header" };
  }

  const view = new DataView(buffer);
  if (view.getUint16(0, true) !== SIG_DOS) {
    return { ...empty, error: "not a PE file (missing MZ signature)" };
  }

  const peOffset = view.getUint32(0x3c, true);
  if (peOffset <= 0 || peOffset + COFF_HEADER_SIZE + 4 > view.byteLength) {
    return { ...empty, error: "PE header offset points outside the buffer" };
  }
  if (view.getUint32(peOffset, true) !== SIG_PE) {
    return { ...empty, error: "not a PE file (missing PE signature)" };
  }

  const coffOffset = peOffset + 4;
  const machine = view.getUint16(coffOffset, true);
  const sectionCount = view.getUint16(coffOffset + 2, true);
  const timestamp = view.getUint32(coffOffset + 4, true);
  const optionalHeaderSize = view.getUint16(coffOffset + 16, true);
  const characteristics = view.getUint16(coffOffset + 18, true);

  const optOffset = coffOffset + COFF_HEADER_SIZE;
  if (optionalHeaderSize === 0 || optOffset + 2 > view.byteLength) {
    return { ...empty, error: "PE has no optional header" };
  }

  const magic = view.getUint16(optOffset, true);
  const isPE32Plus = magic === MAGIC_PE32PLUS;
  if (magic !== MAGIC_PE32 && !isPE32Plus) {
    return { ...empty, error: `unrecognised optional header magic 0x${magic.toString(16)}` };
  }

  // The optional header's tail layout differs between PE32 and PE32+ because
  // PE32+ widens four size fields to 64 bits and drops BaseOfData.
  const dataDirCountOffset = optOffset + (isPE32Plus ? 108 : 92);
  const dataDirOffset = optOffset + (isPE32Plus ? 112 : 96);
  if (dataDirCountOffset + 4 > view.byteLength) {
    return { ...empty, error: "optional header truncated before data directories" };
  }

  const entryPointRva = view.getUint32(optOffset + 16, true);
  const sizeOfImage = view.getUint32(optOffset + 56, true);
  const subsystemValue = view.getUint16(optOffset + 68, true);
  const dataDirCount = view.getUint32(dataDirCountOffset, true);

  const readDirectory = (index) => {
    if (index >= dataDirCount) return { rva: 0, size: 0 };
    const base = dataDirOffset + index * 8;
    if (base + 8 > view.byteLength) return { rva: 0, size: 0 };
    return { rva: view.getUint32(base, true), size: view.getUint32(base + 4, true) };
  };

  const sectionTableOffset = optOffset + optionalHeaderSize;
  const sections = parseSections(view, buffer, sectionTableOffset, sectionCount);

  const importDir = readDirectory(DIRECTORY_IMPORT);
  const certificateDir = readDirectory(DIRECTORY_CERTIFICATE);
  const clrDir = readDirectory(DIRECTORY_CLR);

  let imports = [];
  try {
    imports = parseImports(view, sections, importDir.rva, isPE32Plus);
  } catch {
    // A deliberately corrupted import table must degrade to "no imports
    // readable", never take the whole scan down.
    imports = [];
  }

  // Data appended after the last section — installers legitimately use this for
  // payloads, but so do droppers hiding a second binary.
  const lastSectionEnd = sections.reduce(
    (max, s) => Math.max(max, s.rawOffset + s.rawSize), 0
  );
  const overlaySize = buffer.byteLength > lastSectionEnd ? buffer.byteLength - lastSectionEnd : 0;

  return {
    ok: true,
    error: null,
    machine: MACHINE_TYPES[machine] || `unknown(0x${machine.toString(16)})`,
    is64Bit: isPE32Plus,
    subsystem: SUBSYSTEMS[subsystemValue] || `unknown(${subsystemValue})`,
    isDll: (characteristics & 0x2000) !== 0,
    timestamp: timestamp || null,
    entryPointRva,
    sizeOfImage,
    sections,
    imports,
    importedFunctionCount: imports.reduce((sum, i) => sum + i.functions.length, 0),
    hasSignature: certificateDir.rva > 0 && certificateDir.size > 0,
    isDotNet: clrDir.rva > 0 && clrDir.size > 0,
    overlaySize,
    truncated: sections.length < sectionCount
  };
}

/** True when the buffer starts with the DOS "MZ" magic. */
export function looksLikePE(buffer) {
  if (!buffer || buffer.byteLength < 2) return false;
  return new DataView(buffer).getUint16(0, true) === SIG_DOS;
}

export { shannonEntropy };
