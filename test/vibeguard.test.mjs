import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, writeFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { buildPatternSet } from "../patterns.js"
import { redactText } from "../engine.js"
import { redactDeep, restoreDeep } from "../deep.js"
import { PlaceholderSession } from "../session.js"
import { loadConfig } from "../config.js"
import plugin from "../index.js"

const API_KEY = "sk-" + "A".repeat(48)
const EMAIL = ["red-team", "example.org"].join("@")
const EXCLUDED_EMAIL = ["excluded", "example.org"].join("@")

function makeConfigDir(config) {
  const dir = mkdtempSync(join(tmpdir(), "vibeguard-test-"))
  writeFileSync(join(dir, "vibeguard.config.json"), JSON.stringify(config))
  return dir
}

const PATTERNS = buildPatternSet({
  regex: [{ pattern: "sk-[A-Za-z0-9]{48}", category: "OPENAI_KEY" }],
  keywords: [{ value: "my-api-key-123", category: "API_KEY" }],
  builtin: ["email", "uuid", "ipv4"],
  exclude: [EXCLUDED_EMAIL],
})

test("engine: redacts and matches expected categories", () => {
  const session = new PlaceholderSession({ prefix: "__VG_", ttlMs: 60_000, maxMappings: 100 })
  const result = redactText(`mail me at ${EMAIL} or use ${API_KEY} and my-api-key-123`, PATTERNS, session)
  assert.match(result.text, /__VG_EMAIL_[a-f0-9]{12}__/)
  assert.match(result.text, /__VG_OPENAI_KEY_[a-f0-9]{12}__/)
  assert.match(result.text, /__VG_API_KEY_[a-f0-9]{12}__/)
  assert.ok(!result.text.includes(EMAIL))
  assert.ok(!result.text.includes(API_KEY))
  assert.ok(!result.text.includes("my-api-key-123"))
})

test("engine: exclude list and idempotency", () => {
  const session = new PlaceholderSession({ prefix: "__VG_", ttlMs: 60_000, maxMappings: 100 })
  const excluded = redactText(`reach me at ${EXCLUDED_EMAIL}`, PATTERNS, session)
  assert.equal(excluded.text, `reach me at ${EXCLUDED_EMAIL}`)
  const once = redactText(`key ${API_KEY}`, PATTERNS, session).text
  const twice = redactText(once, PATTERNS, session).text
  assert.equal(twice, once)
})

test("engine: invalid regex is reported, valid rules survive", () => {
  const patterns = buildPatternSet({
    regex: [
      { pattern: "(", category: "BROKEN" },
      { pattern: "sk-[A-Za-z0-9]{48}", category: "OPENAI_KEY" },
    ],
  })
  assert.equal(patterns.errors.length, 1)
  assert.ok(patterns.regex.length >= 1, "valid custom rule survives alongside secret defaults")
  const session = new PlaceholderSession({ prefix: "__VG_", ttlMs: 60_000, maxMappings: 100 })
  const result = redactText(`key ${API_KEY}`, patterns, session)
  assert.match(result.text, /__VG_OPENAI_KEY_[a-f0-9]{12}__/)
})

test("deep: redact and restore nested structures", () => {
  const session = new PlaceholderSession({ prefix: "__VG_", ttlMs: 60_000, maxMappings: 100 })
  const input = { nested: { list: [`key ${API_KEY}`, 42, { deep: EMAIL }] } }
  redactDeep(input, PATTERNS, session)
  assert.ok(!JSON.stringify(input).includes(API_KEY))
  assert.ok(!JSON.stringify(input).includes(EMAIL))
  restoreDeep(input, session)
  assert.equal(input.nested.list[0], `key ${API_KEY}`)
  assert.equal(input.nested.list[2].deep, EMAIL)
})

test("config: project config wins over fallback", async () => {
  const dir = makeConfigDir({ enabled: true })
  try {
    const config = await loadConfig(dir)
    assert.equal(config.loadedFrom, join(dir, "vibeguard.config.json"))
    assert.equal(config.enabled, true)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

function mockContext(dir, hooks) {
  return {
    location: { directory: dir },
    session: {
      hook: async (name, callback) => {
        hooks.set("session:" + name, callback)
      },
    },
    tool: {
      hook: async (name, callback) => {
        hooks.set("tool:" + name, callback)
      },
    },
  }
}

test("plugin: registers hooks, redacts requests, restores tool input", async () => {
  const dir = makeConfigDir({
    enabled: true,
    patterns: {
      regex: [{ pattern: "sk-[A-Za-z0-9]{48}", category: "OPENAI_KEY" }],
      builtin: ["email"],
      exclude: [],
    },
  })
  try {
    const hooks = new Map()
    await plugin.setup(mockContext(dir, hooks))

    for (const name of [
      "session:compaction",
      "session:context",
      "session:generate",
      "session:title",
      "session:http.request",
      "session:http.response",
      "tool:execute.before",
    ]) {
      assert.ok(hooks.has(name), `missing hook ${name}`)
    }

    const context = hooks.get("session:context")
    const event = {
      sessionID: "ses_test",
      system: [{ type: "text", text: `system ${API_KEY}` }],
      messages: [{ role: "user", content: [{ type: "text", text: `mail ${EMAIL} key ${API_KEY}` }] }],
    }
    await context(event)
    assert.match(event.system[0].text, /__VG_OPENAI_KEY_[a-f0-9]{12}__/)
    assert.match(event.messages[0].content[0].text, /__VG_EMAIL_[a-f0-9]{12}__/)

    const tool = hooks.get("tool:execute.before")
    const toolEvent = { sessionID: "ses_test", tool: "write", input: { content: event.messages[0].content[0].text } }
    await tool(toolEvent)
    assert.ok(toolEvent.input.content.includes(EMAIL))
    assert.ok(toolEvent.input.content.includes(API_KEY))

    const stringInput = { sessionID: "ses_test", tool: "bash", input: event.messages[0].content[0].text }
    await tool(stringInput)
    assert.ok(stringInput.input.includes(EMAIL))
    assert.ok(stringInput.input.includes(API_KEY))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test("plugin: disabled config is a no-op", async () => {
  const dir = makeConfigDir({ enabled: false })
  try {
    const hooks = new Map()
    await plugin.setup(mockContext(dir, hooks))
    assert.equal(hooks.size, 0)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
