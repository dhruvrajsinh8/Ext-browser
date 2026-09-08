// modules/ruleEngine.js
// A small YARA-inspired matcher plus an API-combination matcher.
//
// Two deliberately separate matchers, because malware presents two different
// kinds of observable:
//
//   1. BYTE RULES  — literal strings, hex patterns with wildcards, or regexes
//      found anywhere in the file. Good for commands, packer stubs, and
//      tool-specific artefacts.
//
//   2. API RULES   — combinations of Windows functions a PE declares it will
//      call. Far more robust than byte matching: a packer can obfuscate every
//      string in a binary, but the imports it needs to resolve at load time
//      still have to be declared.
//
// Rules are DATA (see malwareRules.js), so adding detections never means
// editing this file. Every match carries the concrete evidence that produced
// it — offsets for byte rules, the matched function names for API rules — so
// the UI can show a user *why*, not just a score.

const MAX_SCAN_BYTES = 16 * 1024 * 1024;
const PREVIEW_RADIUS = 24;

/** Decode once; every text-based rule reuses this. latin1 is byte-exact. */
function decodeLatin1(buffer, limit = MAX_SCAN_BYTES) {
  const length = Math.min(buffer.byteLength, limit);
  return new TextDecoder("latin1").decode(new Uint8Array(buffer, 0, length));
}

/**
 * Parse a hex pattern like "4d 5a ?? 00" into bytes plus a wildcard mask.
 * `??` matches any byte, which is how a signature tolerates addresses or
 * padding that vary between samples of the same family.
 */
export function parseHexPattern(pattern) {
  const tokens = pattern.trim().split(/\s+/);
  const bytes = new Uint8Array(tokens.length);
  const mask = new Uint8Array(tokens.length);
  tokens.forEach((token, i) => {
    if (token === "??") {
      mask[i] = 0;
      return;
    }
    const value = parseInt(token, 16);
    if (Number.isNaN(value)) throw new Error(`invalid hex token "${token}" in pattern`);
    bytes[i] = value;
    mask[i] = 1;
  });
  return { bytes, mask };
}

function findHexPattern(haystack, { bytes, mask }) {
  if (!bytes.length || bytes.length > haystack.length) return -1;
  const limit = haystack.length - bytes.length;
  outer: for (let i = 0; i <= limit; i++) {
    for (let j = 0; j < bytes.length; j++) {
      if (mask[j] && haystack[i + j] !== bytes[j]) continue outer;
    }
    return i;
  }
  return -1;
}

function previewAt(text, offset, length) {
  const start = Math.max(0, offset - PREVIEW_RADIUS);
  const end = Math.min(text.length, offset + length + PREVIEW_RADIUS);
  return text
    .slice(start, end)
    .replace(/[^\x20-\x7e]/g, ".") // render binary context readably
    .trim();
}

/**
 * Evaluate one string definition against the buffer.
 * @returns {{offset: number, preview: string}|null}
 */
function matchString(def, { text, lowerText, bytes }) {
  if (def.type === "hex") {
    const offset = findHexPattern(bytes, parseHexPattern(def.value));
    if (offset < 0) return null;
    return { offset, preview: def.value };
  }

  if (def.type === "regex") {
    // Rules are authored in this repo, never user-supplied, so there is no
    // untrusted-pattern risk here.
    const rx = new RegExp(def.value, def.caseSensitive ? "" : "i");
    const match = rx.exec(text);
    if (!match) return null;
    return { offset: match.index, preview: previewAt(text, match.index, match[0].length) };
  }

  // Default: literal text.
  const needle = def.caseSensitive ? def.value : def.value.toLowerCase();
  const haystack = def.caseSensitive ? text : lowerText;
  const offset = haystack.indexOf(needle);
  if (offset < 0) return null;
  return { offset, preview: previewAt(text, offset, def.value.length) };
}

function conditionSatisfied(condition, matchedCount, totalCount) {
  if (condition === "any") return matchedCount > 0;
  if (condition === "all") return matchedCount === totalCount;
  if (condition && typeof condition.atLeast === "number") return matchedCount >= condition.atLeast;
  return matchedCount === totalCount; // default to "all"
}

/**
 * Run byte/string rules over a file buffer.
 * @param {ArrayBuffer} buffer
 * @param {Array<object>} rules
 * @returns {Array<object>} matched rules with their evidence
 */
export function matchByteRules(buffer, rules) {
  if (!buffer || buffer.byteLength === 0 || !Array.isArray(rules)) return [];

  const text = decodeLatin1(buffer);
  const context = {
    text,
    lowerText: text.toLowerCase(),
    bytes: new Uint8Array(buffer, 0, Math.min(buffer.byteLength, MAX_SCAN_BYTES))
  };

  const results = [];
  for (const rule of rules) {
    const strings = rule.strings || [];
    if (!strings.length) continue;

    const matchedStrings = [];
    for (const def of strings) {
      let hit = null;
      try {
        hit = matchString(def, context);
      } catch {
        hit = null; // a malformed rule must never abort the whole scan
      }
      if (hit) matchedStrings.push({ name: def.name || def.value, ...hit });
    }

    if (conditionSatisfied(rule.condition, matchedStrings.length, strings.length)) {
      results.push({
        id: rule.id,
        title: rule.title,
        severity: rule.severity,
        confidence: rule.confidence ?? 0.7,
        mitre: rule.mitre || null,
        explain: rule.explain || "",
        source: "byte_rule",
        matchedStrings
      });
    }
  }
  return results;
}

/**
 * Normalise a Windows API name for comparison. Many APIs ship as an ANSI/wide
 * pair (CreateProcessA / CreateProcessW) that are the same function for our
 * purposes, so a rule naming the base form should match either.
 */
function apiVariants(name) {
  const lower = name.toLowerCase();
  const variants = new Set([lower]);
  if (lower.endsWith("a") || lower.endsWith("w")) variants.add(lower.slice(0, -1));
  variants.add(`${lower}a`);
  variants.add(`${lower}w`);
  return variants;
}

/**
 * Run API-combination rules over a parsed PE's import table.
 * @param {Array<{dll: string, functions: string[]}>} imports
 * @param {Array<object>} rules
 * @returns {Array<object>}
 */
export function matchApiRules(imports, rules) {
  if (!Array.isArray(imports) || !imports.length || !Array.isArray(rules)) return [];

  // Build a lookup that already contains every A/W variant of every import.
  const available = new Map(); // normalised name -> original name as declared
  for (const entry of imports) {
    for (const fn of entry.functions || []) {
      for (const variant of apiVariants(fn)) {
        if (!available.has(variant)) available.set(variant, fn);
      }
    }
  }

  const results = [];
  for (const rule of rules) {
    const wanted = rule.apis || [];
    if (!wanted.length) continue;

    const matchedApis = [];
    for (const api of wanted) {
      const found = available.get(api.toLowerCase());
      if (found && !matchedApis.includes(found)) matchedApis.push(found);
    }

    const required = rule.minMatches ?? wanted.length;
    if (matchedApis.length >= required) {
      results.push({
        id: rule.id,
        title: rule.title,
        severity: rule.severity,
        confidence: rule.confidence ?? 0.8,
        mitre: rule.mitre || null,
        explain: rule.explain || "",
        source: "api_rule",
        matchedApis
      });
    }
  }
  return results;
}
