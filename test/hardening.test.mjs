import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, writeFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { buildPatternSet } from "../patterns.js"
import { redactText } from "../engine.js"
import { redactDeep, restoreDeep } from "../deep.js"
import { PlaceholderSession, createSessionStore } from "../session.js"
import { extractSecretsFromText, loadProtectedKeywords } from "../secrets.js"

const AKIA = "AKIAIOSFODNN7EXAMPLE"
const GH = "ghp_" + "A".repeat(36)
const ANTHROPIC = "sk-ant-" + "B".repeat(32)

// Task 1: hardened secret defaults apply when builtin key is absent
test("defaults: secret patterns apply without explicit builtin", () => {
  const patterns = buildPatternSet({})
  const session = new PlaceholderSession({ prefix: "__VG_", ttlMs: 60_000, maxMappings: 100 })
  for (const secret of [AKIA, GH, ANTHROPIC, "postgres://u:Q9x!vT2#mK@host/db"]) {
    const out = redactText(`value ${secret} end`, patterns, session).text
    assert.ok(!out.includes(secret), `should redact ${secret.slice(0, 8)}...`)
  }
  const generic = redactText(`password = "hunter2hunter2"`, patterns, session).text
  assert.ok(!generic.includes("hunter2hunter2"), "should redact generic password assignment")
})

// Task 1b: explicit builtin list is respected (opt-out of secrets)
test("defaults: explicit builtin list opts out of secrets group", () => {
  const patterns = buildPatternSet({ builtin: ["email"] })
  const session = new PlaceholderSession({ prefix: "__VG_", ttlMs: 60_000, maxMappings: 100 })
  const out = redactText(`value ${AKIA} end`, patterns, session).text
  assert.ok(out.includes(AKIA), "explicit builtin list must not add secrets")
})

// Task 2: strict ipv4
test("ipv4: rejects invalid octets, accepts valid", () => {
  const patterns = buildPatternSet({ builtin: ["ipv4"] })
  const session = new PlaceholderSession({ prefix: "__VG_", ttlMs: 60_000, maxMappings: 100 })
  const bad = redactText(`addr 999.999.999.999 end`, patterns, session).text
  assert.ok(bad.includes("999.999.999.999"), "invalid octets must not redact")
  const good = redactText(`addr 192.168.1.1 end`, patterns, session).text
  assert.ok(!good.includes("192.168.1.1"), "valid ipv4 must redact")
})

// Task 3: Map/Set deep walk
test("deep: redacts and restores Map and Set values", () => {
  const patterns = buildPatternSet({ regex: [{ pattern: "sk-[A-Za-z0-9]{48}", category: "OPENAI_KEY" }] })
  const session = new PlaceholderSession({ prefix: "__VG_", ttlMs: 60_000, maxMappings: 100 })
  const key = "sk-" + "A".repeat(48)
  const input = { m: new Map([["k", `tok ${key}`]]), s: new Set([`tok ${key}`]) }
  const changed = redactDeep(input, patterns, session)
  assert.ok(changed > 0, "should redact inside Map/Set")
  assert.ok(![...input.m.values()].join().includes(key))
  assert.ok(![...input.s.values()].join().includes(key))
  restoreDeep(input, session)
  assert.ok([...input.m.values()].join().includes(key), "should restore Map values")
  assert.ok([...input.s.values()].join().includes(key), "should restore Set values")
})

// Task 4a: bounded session store (LRU)
test("sessions: store evicts oldest beyond max", () => {
  const store = createSessionStore({ maxSessions: 2 }, (k) => ({ id: k }))
  store.get("a")
  store.get("b")
  store.get("c")
  assert.equal(store.size(), 2)
  assert.equal(store.get("a").id, "a", "evicted entry is recreated")
})

// Task 4b: huge inputs are scanned completely (the old truncation let the tail leak)
test("engine: secrets at the end of huge input are still redacted", () => {
  const patterns = buildPatternSet({ regex: [{ pattern: "sk-[A-Za-z0-9]{48}", category: "OPENAI_KEY" }], max_text_chars: 100 })
  const session = new PlaceholderSession({ prefix: "__VG_", ttlMs: 60_000, maxMappings: 100 })
  const key = "sk-" + "A".repeat(48)
  const big = "x ".repeat(300_000) + key
  const res = redactText(big, patterns, session)
  assert.ok(!res.text.includes(key))
})

// Task 5: secret file extractor
test("secrets: extractor handles token files, env and yaml lines", () => {
  const single = extractSecretsFromText("my-token-value-12345\n", {})
  assert.ok(single.includes("my-token-value-12345"))
  const env = extractSecretsFromText('API_KEY="abc123xyz789"\n# comment\nEMPTY=\n', {})
  assert.ok(env.includes("abc123xyz789"))
  assert.ok(!env.some((v) => v.startsWith("#")))
  const yaml = extractSecretsFromText("ha_token: supersecrethax789\n", {})
  assert.ok(yaml.includes("supersecrethax789"))
  const junk = extractSecretsFromText("changeme\nxxx\nab\n", {})
  assert.equal(junk.length, 0)
})

test("secrets: loader reads protected files without logging values", async () => {
  const dir = mkdtempSync(join(tmpdir(), "vg-secrets-"))
  try {
    writeFileSync(join(dir, "tok"), "file-secret-abc123\n")
    const out = await loadProtectedKeywords([join(dir, "tok")], {})
    assert.ok(out.keywords.some((k) => k.value === "file-secret-abc123"))
    assert.equal(out.failed.length, 0)
    const missing = await loadProtectedKeywords([join(dir, "nope")], {})
    assert.equal(missing.keywords.length, 0)
    assert.equal(missing.failed.length, 1)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
