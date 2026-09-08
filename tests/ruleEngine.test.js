import test from "node:test";
import assert from "node:assert/strict";
import { matchByteRules, matchApiRules, parseHexPattern } from "../modules/ruleEngine.js";
import { API_RULES, BYTE_RULES } from "../modules/malwareRules.js";

function bufferFrom(text) {
  return new TextEncoder().encode(text).buffer;
}

// --- byte rules ---

test("matchByteRules matches a literal string and reports its offset", () => {
  const rules = [{
    id: "TEST_LITERAL", title: "t", severity: "high", condition: "any",
    strings: [{ name: "marker", type: "text", value: "DANGEROUS_MARKER" }]
  }];
  const results = matchByteRules(bufferFrom("padding DANGEROUS_MARKER padding"), rules);

  assert.equal(results.length, 1);
  assert.equal(results[0].matchedStrings[0].offset, 8);
});

test("matchByteRules is case-insensitive unless the rule opts out", () => {
  const insensitive = [{
    id: "A", title: "t", severity: "low", condition: "any",
    strings: [{ type: "text", value: "PowerShell" }]
  }];
  const sensitive = [{
    id: "B", title: "t", severity: "low", condition: "any",
    strings: [{ type: "text", value: "PowerShell", caseSensitive: true }]
  }];

  assert.equal(matchByteRules(bufferFrom("run powershell now"), insensitive).length, 1);
  assert.equal(matchByteRules(bufferFrom("run powershell now"), sensitive).length, 0);
});

test("matchByteRules honours an 'all' condition", () => {
  const rules = [{
    id: "ALL", title: "t", severity: "high", condition: "all",
    strings: [
      { type: "text", value: "alpha" },
      { type: "text", value: "beta" }
    ]
  }];

  assert.equal(matchByteRules(bufferFrom("alpha only"), rules).length, 0);
  assert.equal(matchByteRules(bufferFrom("alpha and beta"), rules).length, 1);
});

test("matchByteRules honours an atLeast condition", () => {
  const rules = [{
    id: "TWO", title: "t", severity: "high", condition: { atLeast: 2 },
    strings: [
      { type: "text", value: "one" },
      { type: "text", value: "two" },
      { type: "text", value: "three" }
    ]
  }];

  assert.equal(matchByteRules(bufferFrom("just one"), rules).length, 0);
  assert.equal(matchByteRules(bufferFrom("one and two"), rules).length, 1);
});

test("matchByteRules supports hex patterns with wildcards", () => {
  const bytes = new Uint8Array([0x00, 0x4d, 0x5a, 0x99, 0x00, 0xff]);
  const rules = [{
    id: "HEX", title: "t", severity: "high", condition: "any",
    strings: [{ name: "mz", type: "hex", value: "4d 5a ?? 00" }]
  }];
  const results = matchByteRules(bytes.buffer, rules);

  assert.equal(results.length, 1);
  assert.equal(results[0].matchedStrings[0].offset, 1);
});

test("matchByteRules supports regex patterns", () => {
  const rules = [{
    id: "RX", title: "t", severity: "high", condition: "any",
    strings: [{ type: "regex", value: "-enc\\s+[A-Za-z0-9+/=]{10,}" }]
  }];
  const results = matchByteRules(bufferFrom("powershell -enc SQBFAFgAIAAoAA=="), rules);

  assert.equal(results.length, 1);
});

test("matchByteRules ignores a malformed rule instead of aborting the scan", () => {
  const rules = [
    { id: "BAD", title: "t", severity: "high", condition: "any", strings: [{ type: "hex", value: "zz zz" }] },
    { id: "GOOD", title: "t", severity: "high", condition: "any", strings: [{ type: "text", value: "findme" }] }
  ];
  const results = matchByteRules(bufferFrom("findme"), rules);

  assert.deepEqual(results.map(r => r.id), ["GOOD"]);
});

test("matchByteRules returns nothing for an empty buffer", () => {
  assert.deepEqual(matchByteRules(new ArrayBuffer(0), BYTE_RULES), []);
});

test("parseHexPattern builds bytes and a wildcard mask", () => {
  const { bytes, mask } = parseHexPattern("4d ?? 5a");
  assert.deepEqual(Array.from(bytes), [0x4d, 0x00, 0x5a]);
  assert.deepEqual(Array.from(mask), [1, 0, 1]);
});

// --- API rules ---

test("matchApiRules fires on a full process-injection API set", () => {
  const imports = [{
    dll: "KERNEL32.dll",
    functions: ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
  }];
  const results = matchApiRules(imports, API_RULES);

  const injection = results.find(r => r.id === "API_PROCESS_INJECTION");
  assert.ok(injection, "expected process-injection rule to match");
  assert.equal(injection.mitre, "T1055");
  assert.equal(injection.matchedApis.length, 3);
});

test("matchApiRules does not fire below the minMatches threshold", () => {
  const imports = [{ dll: "KERNEL32.dll", functions: ["VirtualAllocEx"] }];
  const results = matchApiRules(imports, API_RULES);

  assert.equal(results.find(r => r.id === "API_PROCESS_INJECTION"), undefined);
});

test("matchApiRules matches ANSI/wide API variants", () => {
  // Rule names SetWindowsHookEx; the binary imports SetWindowsHookExW.
  const imports = [{ dll: "USER32.dll", functions: ["SetWindowsHookExW", "GetAsyncKeyState"] }];
  const results = matchApiRules(imports, API_RULES);

  const keylog = results.find(r => r.id === "API_KEYLOGGING");
  assert.ok(keylog, "expected keylogging rule to match the W variant");
  assert.ok(keylog.matchedApis.includes("SetWindowsHookExW"));
});

test("matchApiRules reports the real imported names as evidence", () => {
  const imports = [{ dll: "ADVAPI32.dll", functions: ["OpenSCManagerA", "CreateServiceA", "StartServiceA"] }];
  const results = matchApiRules(imports, API_RULES);

  const service = results.find(r => r.id === "API_SERVICE_PERSISTENCE");
  assert.ok(service);
  assert.deepEqual(service.matchedApis, ["OpenSCManagerA", "CreateServiceA", "StartServiceA"]);
});

test("matchApiRules returns nothing for a binary with no imports", () => {
  assert.deepEqual(matchApiRules([], API_RULES), []);
});

// --- real rule set sanity ---

test("shipped byte rules detect a shadow-copy deletion command", () => {
  const results = matchByteRules(bufferFrom("cmd /c vssadmin delete shadows /all /quiet"), BYTE_RULES);
  const rule = results.find(r => r.id === "BYTE_SHADOW_COPY_DELETION");

  assert.ok(rule);
  assert.equal(rule.severity, "critical");
  assert.equal(rule.mitre, "T1490");
});

test("shipped byte rules detect hidden encoded PowerShell", () => {
  const payload = "powershell -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACkA";
  const results = matchByteRules(bufferFrom(payload), BYTE_RULES);

  assert.ok(results.find(r => r.id === "BYTE_POWERSHELL_HIDDEN_ENCODED"));
});

test("shipped byte rules detect Defender tampering", () => {
  const payload = "Add-MpPreference -ExclusionPath C:\\Users\\Public";
  const results = matchByteRules(bufferFrom(payload), BYTE_RULES);

  assert.ok(results.find(r => r.id === "BYTE_DEFENDER_TAMPERING"));
});

test("shipped byte rules do not fire on ordinary text", () => {
  const benign = "This installer sets up the application and creates a desktop shortcut.";
  const results = matchByteRules(bufferFrom(benign), BYTE_RULES);

  assert.deepEqual(results, []);
});

test("every shipped rule has the fields the UI renders", () => {
  for (const rule of [...API_RULES, ...BYTE_RULES]) {
    assert.equal(typeof rule.id, "string", `${rule.id}: id`);
    assert.equal(typeof rule.title, "string", `${rule.id}: title`);
    assert.ok(["critical", "high", "medium", "low"].includes(rule.severity), `${rule.id}: severity`);
    assert.equal(typeof rule.confidence, "number", `${rule.id}: confidence`);
    assert.ok(rule.confidence > 0 && rule.confidence <= 1, `${rule.id}: confidence range`);
    assert.ok(rule.explain.length > 20, `${rule.id}: explain should be user-readable`);
  }
});

test("rule ids are unique", () => {
  const ids = [...API_RULES, ...BYTE_RULES].map(r => r.id);
  assert.equal(new Set(ids).size, ids.length);
});
