// tests/helpers/peBuilder.js
// Builds structurally-valid PE32 / PE32+ binaries with a real import table,
// so the parser tests exercise genuine RVA translation and thunk walking
// rather than a hand-faked byte layout.

const SECTION_RVA = 0x1000;
const SECTION_RAW_OFFSET = 0x200;
const FILE_ALIGNMENT = 0x200;
const PE_OFFSET = 0x40;

/**
 * @param {object} options
 * @param {Array<{dll: string, functions: string[]}>} options.imports
 * @param {boolean} [options.is64Bit]
 * @param {boolean} [options.hasSignature]
 * @param {number} [options.subsystem]  2 = GUI, 3 = console
 * @param {boolean} [options.isDll]
 * @param {string} [options.sectionName]
 * @param {number} [options.sectionCharacteristics]
 * @param {Uint8Array} [options.overlay] bytes appended after the last section
 * @returns {ArrayBuffer}
 */
export function buildPE({
  imports = [],
  is64Bit = false,
  hasSignature = false,
  subsystem = 3,
  isDll = false,
  sectionName = ".text",
  sectionCharacteristics = 0x60000020, // CODE | EXECUTE | READ
  overlay = null
} = {}) {
  const thunkSize = is64Bit ? 8 : 4;
  const optionalHeaderSize = is64Bit ? 240 : 224;

  // --- Lay out the import structures inside the section ---
  let cursor = (imports.length + 1) * 20; // descriptor array + null terminator
  const meta = imports.map((imp) => {
    const thunkRel = cursor;
    cursor += (imp.functions.length + 1) * thunkSize;
    return { imp, thunkRel, nameRel: 0, funcRels: [] };
  });

  for (const m of meta) {
    m.nameRel = cursor;
    cursor += m.imp.dll.length + 1;
    for (const fn of m.imp.functions) {
      m.funcRels.push(cursor);
      cursor += 2 + fn.length + 1; // hint word + name + NUL
    }
  }

  const sectionDataSize = Math.max(
    FILE_ALIGNMENT,
    Math.ceil(cursor / FILE_ALIGNMENT) * FILE_ALIGNMENT
  );

  const overlayBytes = overlay ?? new Uint8Array(0);
  const totalSize = SECTION_RAW_OFFSET + sectionDataSize + overlayBytes.length;
  const bytes = new Uint8Array(totalSize);
  const view = new DataView(bytes.buffer);

  // --- DOS header ---
  view.setUint16(0, 0x5a4d, true);      // "MZ"
  view.setUint32(0x3c, PE_OFFSET, true); // e_lfanew

  // --- PE signature + COFF header ---
  view.setUint32(PE_OFFSET, 0x00004550, true); // "PE\0\0"
  const coff = PE_OFFSET + 4;
  view.setUint16(coff, is64Bit ? 0x8664 : 0x014c, true); // Machine
  view.setUint16(coff + 2, 1, true);                     // NumberOfSections
  view.setUint32(coff + 4, 0x5f000000, true);            // TimeDateStamp
  view.setUint16(coff + 16, optionalHeaderSize, true);
  view.setUint16(coff + 18, isDll ? 0x2102 : 0x0102, true); // Characteristics

  // --- Optional header ---
  const opt = coff + 20;
  view.setUint16(opt, is64Bit ? 0x20b : 0x10b, true); // Magic
  view.setUint32(opt + 16, SECTION_RVA, true);         // AddressOfEntryPoint
  view.setUint32(opt + 56, 0x2000, true);              // SizeOfImage
  view.setUint16(opt + 68, subsystem, true);           // Subsystem

  // PE32+ widens four stack/heap fields, shifting the directory count and table.
  const dataDirCountOffset = opt + (is64Bit ? 108 : 92);
  const dataDirOffset = opt + (is64Bit ? 112 : 96);
  view.setUint32(dataDirCountOffset, 16, true);

  if (imports.length) {
    view.setUint32(dataDirOffset + 1 * 8, SECTION_RVA, true); // Import table RVA
    view.setUint32(dataDirOffset + 1 * 8 + 4, cursor, true);
  }
  if (hasSignature) {
    view.setUint32(dataDirOffset + 4 * 8, totalSize - 8, true); // Certificate RVA
    view.setUint32(dataDirOffset + 4 * 8 + 4, 8, true);
  }

  // --- Section header ---
  const sectionHeader = opt + optionalHeaderSize;
  const nameBytes = new TextEncoder().encode(sectionName.slice(0, 8));
  bytes.set(nameBytes, sectionHeader);
  view.setUint32(sectionHeader + 8, sectionDataSize, true);      // VirtualSize
  view.setUint32(sectionHeader + 12, SECTION_RVA, true);         // VirtualAddress
  view.setUint32(sectionHeader + 16, sectionDataSize, true);     // SizeOfRawData
  view.setUint32(sectionHeader + 20, SECTION_RAW_OFFSET, true);  // PointerToRawData
  view.setUint32(sectionHeader + 36, sectionCharacteristics, true);

  // --- Import descriptors ---
  const fileOffsetOf = (rel) => SECTION_RAW_OFFSET + rel;
  const rvaOf = (rel) => SECTION_RVA + rel;

  meta.forEach((m, i) => {
    const base = fileOffsetOf(i * 20);
    view.setUint32(base, rvaOf(m.thunkRel), true);      // OriginalFirstThunk
    view.setUint32(base + 12, rvaOf(m.nameRel), true);  // Name RVA
    view.setUint32(base + 16, rvaOf(m.thunkRel), true); // FirstThunk
  });
  // Null descriptor terminates the array (already zeroed).

  // --- Thunks, DLL names, hint/name entries ---
  const encoder = new TextEncoder();
  for (const m of meta) {
    m.funcRels.forEach((funcRel, j) => {
      const thunkOffset = fileOffsetOf(m.thunkRel + j * thunkSize);
      if (is64Bit) {
        view.setBigUint64(thunkOffset, BigInt(rvaOf(funcRel)), true);
      } else {
        view.setUint32(thunkOffset, rvaOf(funcRel), true);
      }
    });
    // Trailing zero thunk terminates the list (already zeroed).

    bytes.set(encoder.encode(m.imp.dll), fileOffsetOf(m.nameRel));

    m.funcRels.forEach((funcRel, j) => {
      const nameOffset = fileOffsetOf(funcRel);
      view.setUint16(nameOffset, j, true); // hint
      bytes.set(encoder.encode(m.imp.functions[j]), nameOffset + 2);
    });
  }

  if (overlayBytes.length) {
    bytes.set(overlayBytes, SECTION_RAW_OFFSET + sectionDataSize);
  }

  return bytes.buffer;
}

/** Fills a section with high-entropy bytes, the way a packer would. */
export function highEntropyBytes(length) {
  const bytes = new Uint8Array(length);
  let state = 0x2545f491;
  for (let i = 0; i < length; i++) {
    state ^= state << 13; state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5; state >>>= 0;
    bytes[i] = state & 0xff;
  }
  return bytes;
}
