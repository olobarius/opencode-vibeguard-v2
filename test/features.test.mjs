import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, writeFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { buildPatternSet } from "../patterns.js"
import { redactText } from "../engine.js"
import { KnownRegistry, PlaceholderSession, getPlaceholderRegex } from "../session.js"
import { restoreText } from "../restore.js"
import { envSecrets, secretVariants, collectKnownSecrets } from "../known.js"
import { buildRawPatterns, guardRequest } from "../guard.js"
import { createSseRestorer, holdbackIndex, restoreResponse } from "../stream.js"
import { normalizeConfig, loadConfig } from "../config.js"
import { ProtectedPaths, compileToolRules, toolEffect } from "../policy.js"
import plugin from "../index.js"

const GH = "ghp_" + "Z".repeat(36)
const PROJ = "sk-proj-" + "a1B2".repeat(12)
const PASSWORD = 'Tr0ub4dor&3"x\\y'

function session(known) {
  return new PlaceholderSession({ prefix: "__VG_", ttlMs: 60_000, maxMappings: 1000, known })
}

function knownSetup(entries, raw = { builtin: ["secrets"] }) {
  const patterns = buildPatternSet(raw, entries)
  const known = new KnownRegistry({ prefix: "__VG_", key: Buffer.alloc(32, 7) })
  known.load(patterns.keywords)
  return { patterns, known }
}

function tmp() {
  return mkdtempSync(join(tmpdir(), "vg-feat-"))
}

const quiet = { files: [], env: false, opencode_auth: false, windows_credentials: [] }

// --------------------------------------------------------------- detection

test("rules: modern OpenAI project keys and GitHub tokens are caught", () => {
  const p = buildPatternSet({})
  const s = session()
  const out = redactText(`a ${PROJ} b ${GH}`, p, s).text
  assert.ok(!out.includes(PROJ))
  assert.ok(!out.includes(GH))
})

test("rules: private key body is redacted, not just the header", () => {
  const p = buildPatternSet({})
  const s = session()
  const key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\nAAAAMwAAAAtzc2gtZWQyNTUxOQ\n-----END OPENSSH PRIVATE KEY-----"
  const out = redactText(`file:\n${key}\nend`, p, s).text
  assert.ok(!out.includes("b3BlbnNzaC1rZXktdjEA"))
  assert.ok(out.endsWith("\nend"))
})

test("rules: generic assignments redact only the value", () => {
  const p = buildPatternSet({})
  const s = session()
  const out = redactText(`DB_PASSWORD="s3cr3t-Value!"`, p, s).text
  assert.match(out, /^DB_PASSWORD="__VG_SECRET_[a-f0-9]{12}__"$/)
})

test("rules: bare word after a password key is still a secret", () => {
  const p = buildPatternSet({})
  const out = redactText("wlan password: sommerwiese", p, session()).text
  assert.match(out, /^wlan password: __VG_SECRET_[a-f0-9]{12}__$/)
})

test("rules: generic assignments ignore code and config noise", () => {
  const p = buildPatternSet({})
  const s = session()
  for (const line of [
    "password: string;",
    "max_tokens: 4096",
    "const password = userPassword;",
    "password = os.environ['DB_PASSWORD']",
    "api_key: ${API_KEY}",
    "token: process.env.TOKEN",
    'secret: "<your-secret-here>"',
    "PASSWORD=PASSWORD",
    "Bekannte Secrets: Dateien, Env",
    "API key: required",
  ]) {
    assert.equal(redactText(line, p, s).text, line, line)
  }
})

test("rules: url credentials keep host visible", () => {
  const p = buildPatternSet({})
  const s = session()
  const out = redactText("postgres://app:Sup3rS3cret@db.internal:5432/x", p, s).text
  assert.match(out, /^postgres:\/\/app:__VG_URL_PASSWORD_[a-f0-9]{12}__@db\.internal:5432\/x$/)
})

test("rules: iban and credit card need valid checksums", () => {
  const p = buildPatternSet({ builtin: ["iban", "credit_card"] })
  const s = session()
  assert.ok(!redactText("IBAN DE89 3704 0044 0532 0130 00", p, s).text.includes("DE89"))
  assert.ok(redactText("IBAN DE00 3704 0044 0532 0130 00", p, s).text.includes("DE00"))
  assert.ok(!redactText("card 4111 1111 1111 1111", p, s).text.includes("4111"))
  assert.ok(redactText("order 1234 5678 9012 3456", p, s).text.includes("1234"))
  // Luhn-valid epoch-ms timestamps are not cards (no issuer prefix)
  const ts = ["1792242613000", "1792242613001", "1792242613002", "1792242613003", "1792242613004", "1792242613005", "1792242613006", "1792242613007", "1792242613008", "1792242613009"]
  for (const t of ts) assert.ok(redactText(`"created":${t}`, p, s).text.includes(t), t)
  assert.ok(!redactText("amex 3782 822463 10005", p, s).text.includes("3782"))
})

// ----------------------------------------------------------- known values

test("known: named, stable placeholders shared by all sessions", () => {
  const { patterns, known } = knownSetup([{ value: "hunter2-but-longer", category: "MY_DB_PASSWORD" }])
  const a = redactText("pw hunter2-but-longer", patterns, session(known)).text
  const b = redactText("pw hunter2-but-longer", patterns, session(known)).text
  assert.equal(a, b)
  assert.match(a, /__VG_MY_DB_PASSWORD_[a-f0-9]{12}__/)
  // a brand-new session (e.g. after restart) can still restore it
  assert.equal(restoreText(a, session(known)), "pw hunter2-but-longer")
})

test("known: base64 and url-encoded variants are caught", () => {
  const value = "p@ss word/with+chars"
  const entries = [{ value, category: "PW" }]
  for (const [v, suffix] of secretVariants(value)) entries.push({ value: v, category: `PW_${suffix}` })
  const { patterns, known } = knownSetup(entries)
  const s = session(known)
  const b64 = Buffer.from(`user:${value}`).toString("base64")
  const out = redactText(`Authorization: Basic ${b64} and ${encodeURIComponent(value)}`, patterns, s).text
  assert.ok(!out.includes(encodeURIComponent(value)))
  assert.ok(!out.includes(b64.slice(8, 24)), "inner base64 core must be gone")
  assert.equal(restoreText(out, s), `Authorization: Basic ${b64} and ${encodeURIComponent(value)}`)
})

test("known: env scanning picks sensitive names only", () => {
  const out = envSecrets({}, {
    GITHUB_TOKEN: GH,
    PWD: "C:\\Users\\x",
    HOME: "/home/x",
    MY_API_KEY: "abcdefgh12345",
    SSH_AUTH_SOCK: "/tmp/ssh",
    DEBUG: "true",
  })
  const names = out.map((e) => e.category).sort()
  assert.deepEqual(names, ["ENV_GITHUB_TOKEN", "ENV_MY_API_KEY"])
})

test("known: secrets file with names, bare passwords and terms", async () => {
  const dir = tmp()
  try {
    const file = join(dir, "vibeguard.secrets")
    writeFileSync(file, `# comment\nexport GITHUB_PAT=${GH}\nCUSTOMER="Acme Rocket Corp"\nplainpassword123\nSHORT=ab\n`)
    const res = await collectKnownSecrets(normalizeConfig({ secrets: { ...quiet, files: [file] } }), dir)
    const cats = new Map(res.entries.map((e) => [e.value, e.category]))
    assert.equal(cats.get(GH), "GITHUB_PAT")
    assert.equal(cats.get("Acme Rocket Corp"), "CUSTOMER")
    assert.equal(cats.get("plainpassword123"), "SECRET")
    assert.ok(!cats.has("ab"))
    assert.ok(res.protectedPaths.some((p) => p.endsWith("vibeguard.secrets")))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

// ------------------------------------------------------------ placeholders

test("placeholders: adjacent placeholders restore individually", () => {
  const { patterns, known } = knownSetup([
    { value: "alpha-secret-1", category: "A" },
    { value: "beta-secret-22", category: "B" },
  ])
  const s = session(known)
  const out = redactText("alpha-secret-1beta-secret-22", patterns, s).text
  assert.equal(restoreText(out, s), "alpha-secret-1beta-secret-22")
})

test("placeholders: existing placeholders are never re-redacted", () => {
  const patterns = buildPatternSet({ builtin: [], regex: [{ pattern: "[a-f0-9]{12}", category: "HEX" }] })
  const s = session()
  const once = redactText("id deadbeef0123 x", patterns, s).text
  assert.equal(redactText(once, patterns, s).text, once)
  assert.equal(restoreText(once, s), "id deadbeef0123 x")
})

test("session: sliding ttl keeps used mappings alive", () => {
  const s = new PlaceholderSession({ prefix: "__VG_", ttlMs: 1000, maxMappings: 10 })
  const ph = s.getOrCreatePlaceholder("value-1", "X")
  const entry = s.forward.get(ph)
  entry.at -= 900
  s.lookup(ph) // touch
  s.cleanup(Date.now() + 500)
  assert.equal(s.lookup(ph), "value-1")
})

// ------------------------------------------------------------------- guard

test("guard: JSON-escaped known secret in raw body is replaced", async () => {
  const { patterns, known } = knownSetup([{ value: PASSWORD, category: "PW" }])
  const raw = buildRawPatterns(patterns, "strong")
  const s = session(known)
  const body = JSON.stringify({ tools: [{ description: `use ${PASSWORD} and ${GH}` }] })
  const req = new Request("https://api.example.test/v1", { method: "POST", headers: { "content-type": "application/json" }, body })
  const res = await guardRequest(req, raw, s)
  assert.equal(res.count, 2)
  const text = await res.request.text()
  assert.ok(!text.includes(JSON.stringify(PASSWORD).slice(1, -1)))
  assert.ok(!text.includes(GH))
  const parsed = JSON.parse(text)
  assert.equal(restoreText(parsed.tools[0].description, s), `use ${PASSWORD} and ${GH}`)
})

// ------------------------------------------------------------------ stream

function sseChat(deltas) {
  return deltas.map((d) => `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: d } }] })}\n\n`).join("") + "data: [DONE]\n\n"
}

function collectChat(out) {
  return out
    .split("\n\n")
    .filter((e) => e.startsWith("data: {"))
    .map((e) => JSON.parse(e.slice(6)).choices[0].delta.content ?? "")
    .join("")
}

test("stream: placeholder split across many deltas is restored", () => {
  const { patterns, known } = knownSetup([{ value: GH, category: "GITHUB_PAT" }])
  const s = session(known)
  const ph = redactText(GH, patterns, s).text
  const text = `token is ${ph} ok __bold__ end_`
  const parts = text.match(/.{1,3}/gs)
  const r = createSseRestorer(s)
  let out = ""
  const stream = sseChat(parts)
  for (let i = 0; i < stream.length; i += 7) out += r.push(stream.slice(i, i + 7))
  out += r.end()
  assert.equal(collectChat(out), `token is ${GH} ok __bold__ end_`)
})

test("stream: trailing partial prefix is flushed before [DONE]", () => {
  const s = session()
  const r = createSseRestorer(s)
  const out = r.push(sseChat(["hello ", "__"])) + r.end()
  assert.equal(collectChat(out), "hello __")
})

test("stream: tool-call arguments keep placeholders (policy applies later)", () => {
  const { patterns, known } = knownSetup([{ value: GH, category: "GITHUB_PAT" }])
  const s = session(known)
  const ph = redactText(GH, patterns, s).text
  const evt = { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: `{"t":"${ph}"}` } }] } }] }
  const r = createSseRestorer(s)
  const out = r.push(`data: ${JSON.stringify(evt)}\n\n`) + r.end()
  assert.ok(out.includes(ph))
  assert.ok(!out.includes(GH))
})

test("stream: reasoning channels stay verbatim (echoed back via provider metadata, signed)", () => {
  const { patterns, known } = knownSetup([{ value: GH, category: "GITHUB_PAT" }])
  const s = session(known)
  const ph = redactText(GH, patterns, s).text
  const r = createSseRestorer(s)
  const chunks = [
    { choices: [{ index: 0, delta: { reasoning_content: `think ${ph}` } }] },
    { choices: [{ index: 0, delta: { reasoning_details: [{ type: "reasoning.text", text: ph }] } }] },
    { type: "content_block_delta", index: 0, delta: { type: "thinking_delta", thinking: ph } },
  ]
  const out = r.push(chunks.map((c) => `data: ${JSON.stringify(c)}\n\n`).join("")) + r.end()
  assert.ok(!out.includes(GH))
})

test("stream: anthropic text deltas restore, event lines preserved", () => {
  const { patterns, known } = knownSetup([{ value: GH, category: "GITHUB_PAT" }])
  const s = session(known)
  const ph = redactText(GH, patterns, s).text
  const ev = (type, body) => `event: ${type}\ndata: ${JSON.stringify({ type, ...body })}\n\n`
  const half = Math.floor(ph.length / 2)
  const input =
    ev("content_block_start", { index: 0, content_block: { type: "text", text: "" } }) +
    ev("content_block_delta", { index: 0, delta: { type: "text_delta", text: `x ${ph.slice(0, half)}` } }) +
    ev("ping", {}) +
    ev("content_block_delta", { index: 0, delta: { type: "text_delta", text: `${ph.slice(half)} y` } }) +
    ev("content_block_stop", { index: 0 })
  const r = createSseRestorer(s)
  const out = r.push(input) + r.end()
  const text = out
    .split("\n\n")
    .filter((e) => e.includes("content_block_delta"))
    .map((e) => JSON.parse(e.split("\n").find((l) => l.startsWith("data: ")).slice(6)).delta.text)
    .join("")
  assert.equal(text, `x ${GH} y`)
  assert.ok(out.includes("event: content_block_delta"))
})

test("stream: response wrapper rewrites SSE bodies", async () => {
  const { patterns, known } = knownSetup([{ value: GH, category: "GITHUB_PAT" }])
  const s = session(known)
  const ph = redactText(GH, patterns, s).text
  const original = new Response(sseChat(["a ", ph.slice(0, 9), ph.slice(9), " b"]), {
    headers: { "content-type": "text/event-stream", "content-length": "999" },
  })
  const next = restoreResponse(original, s)
  assert.equal(next.headers.get("content-length"), null)
  assert.equal(collectChat(await next.text()), `a ${GH} b`)
})

test("stream: holdback index", () => {
  assert.equal(holdbackIndex("abc __V", "__VG_"), 4)
  assert.equal(holdbackIndex("abc __VG_FOO_12", "__VG_"), 4)
  assert.equal(holdbackIndex("abc __init__ x", "__VG_"), 14)
})

// ------------------------------------------------------------------ policy

test("policy: tool rules first match wins", () => {
  const rules = compileToolRules({ webfetch: "ask", "chrome-devtools_*": "deny", "*": "allow" })
  assert.equal(toolEffect("webfetch", rules), "ask")
  assert.equal(toolEffect("chrome-devtools_navigate_page", rules), "deny")
  assert.equal(toolEffect("bash", rules), "allow")
})

test("policy: protected paths match files, dirs and commands", () => {
  const dir = tmp()
  try {
    const pp = new ProtectedPaths([join(dir, "vibeguard.secrets"), join(dir, "keys")], dir)
    assert.ok(pp.matchPath(join(dir, "vibeguard.secrets")))
    assert.ok(pp.matchPath("vibeguard.secrets"))
    assert.ok(pp.matchPath(join(dir, "keys", "a.pem")))
    assert.equal(pp.matchPath(join(dir, "other.txt")), null)
    assert.ok(pp.matchCommand("cat ~/.config/opencode/vibeguard.secrets"))
    assert.equal(pp.matchCommand("ls -la"), null)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

// ------------------------------------------------------------------ config

test("config: jsonc with comments and plugin options merge", async () => {
  const dir = tmp()
  try {
    writeFileSync(join(dir, "vibeguard.config.jsonc"), `{\n // comment\n "enabled": true, "debug": false,\n}`)
    const cfg = await loadConfig(dir, { debug: true })
    assert.equal(cfg.enabled, true)
    assert.equal(cfg.debug, true)
    assert.deepEqual(cfg.patterns.builtin, ["secrets"])
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

// -------------------------------------------------------------- end to end

function mockCtx(dir, hooks, extra = {}) {
  const reg = (prefix) => async (name, cb) => {
    hooks.set(`${prefix}:${name}`, cb)
    return { dispose: async () => {} }
  }
  const store = new Map()
  return {
    location: { directory: dir },
    options: {},
    storage: { get: async (k) => store.get(k), set: async (k, v) => void store.set(k, v) },
    session: { hook: reg("session") },
    tool: { hook: reg("tool") },
    permission: { hook: reg("permission"), ...extra.permission },
  }
}

async function setupPlugin(config, extra) {
  const dir = tmp()
  writeFileSync(join(dir, "vibeguard.secrets"), `GITHUB_PAT=${GH}\n`)
  writeFileSync(join(dir, "vibeguard.config.json"), JSON.stringify({ enabled: true, audit: { path: join(dir, "audit.jsonl") }, ...config }))
  const hooks = new Map()
  await plugin.setup(mockCtx(dir, hooks, extra))
  return { dir, hooks }
}

const baseConfig = { secrets: { ...quiet, files: ["vibeguard.secrets"] } }

test("e2e: tool-call inputs are replaced by copies, history objects untouched", async () => {
  const { dir, hooks } = await setupPlugin(baseConfig)
  try {
    const input = { command: `curl -H "Authorization: token ${GH}"` }
    const event = {
      sessionID: "s1",
      system: [],
      messages: [{ role: "assistant", content: [{ type: "tool-call", id: "c1", name: "bash", input }] }],
    }
    await hooks.get("session:context")(event)
    assert.equal(input.command.includes(GH), true, "original args object must not be mutated")
    assert.match(event.messages[0].content[0].input.command, /__VG_GITHUB_PAT_[a-f0-9]{12}__/)
    assert.match(event.system.at(-1).text, /Privacy notice/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test("e2e: execute.before policies (allow, deny, keep, unknown, ask)", async () => {
  let asked = 0
  const { dir, hooks } = await setupPlugin(
    { ...baseConfig, restore: { tools: { execute: "keep", websearch: "deny", webfetch: "ask", "*": "allow" } } },
    { permission: { assert: async () => void asked++ } },
  )
  try {
    const ctxHook = hooks.get("session:context")
    const ev = { sessionID: "s1", system: [], messages: [{ role: "user", content: [{ type: "text", text: GH }] }] }
    await ctxHook(ev)
    const ph = ev.messages[0].content[0].text
    const before = hooks.get("tool:execute.before")

    const bash = { sessionID: "s1", tool: "bash", input: { command: `echo ${ph}` } }
    await before(bash)
    assert.equal(bash.input.command, `echo ${GH}`)

    await assert.rejects(before({ sessionID: "s1", tool: "websearch", input: { query: ph } }), /not allowed to receive/)

    const code = { sessionID: "s1", tool: "execute", input: { code: `x("${ph}")` } }
    await before(code)
    assert.ok(code.input.code.includes(ph))

    await assert.rejects(before({ sessionID: "s1", tool: "bash", input: { command: "echo __VG_FAKE_0123456789ab__" } }), /cannot be resolved/)

    const fetch1 = { sessionID: "s1", tool: "webfetch", input: { url: `https://x.test/?t=${ph}` } }
    await before(fetch1)
    await before({ sessionID: "s1", tool: "webfetch", input: { url: `https://x.test/?t=${ph}` } })
    assert.equal(asked, 1, "approval is asked once per session and tool")
    assert.ok(fetch1.input.url.includes(GH))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test("e2e: permission evaluate protects secret files and forces ask for secret hand-out", async () => {
  const { dir, hooks } = await setupPlugin(baseConfig)
  try {
    const evaluate = hooks.get("permission:evaluate")
    const read = { action: "read", resources: ["vibeguard.secrets"], effect: "allow" }
    await evaluate(read)
    assert.equal(read.effect, "deny")
    const shell = { action: "shell", resources: ["type vibeguard.secrets"], effect: "allow" }
    await evaluate(shell)
    assert.equal(shell.effect, "ask")
    const other = { action: "read", resources: ["src/index.js"], effect: "allow" }
    await evaluate(other)
    assert.equal(other.effect, "allow")
    const hand = { action: "vibeguard_secret", resources: ["webfetch:GITHUB_PAT"], effect: "allow" }
    await evaluate(hand)
    assert.equal(hand.effect, "ask")
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test("e2e: http.request safety net and http.response restore", async () => {
  const { dir, hooks } = await setupPlugin(baseConfig)
  try {
    const body = JSON.stringify({ messages: [{ role: "user", content: `x ${GH}` }] })
    const ev = {
      sessionID: "s1",
      kind: "primary",
      request: new Request("https://p.test", { method: "POST", headers: { "content-type": "application/json" }, body }),
    }
    await hooks.get("session:http.request")(ev)
    const sent = await ev.request.text()
    assert.ok(!sent.includes(GH))
    const ph = JSON.parse(sent).messages[0].content.slice(2)

    const res = {
      sessionID: "s1",
      kind: "primary",
      response: new Response(sseChat([`ok ${ph.slice(0, 4)}`, ph.slice(4)]), { headers: { "content-type": "text/event-stream" } }),
    }
    await hooks.get("session:http.response")(res)
    assert.equal(collectChat(await res.response.text()), `ok ${GH}`)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test("e2e: hot reload picks up new secrets", async () => {
  const { dir, hooks } = await setupPlugin({ ...baseConfig, secrets: { ...baseConfig.secrets, reload_interval: "1ms" } })
  try {
    writeFileSync(join(dir, "vibeguard.secrets"), `GITHUB_PAT=${GH}\nNEW_ONE=brand-new-secret-value\n# changed size\n`)
    await new Promise((r) => setTimeout(r, 20))
    const ev = { sessionID: "s1", system: [], messages: [{ role: "user", content: [{ type: "text", text: "brand-new-secret-value" }] }] }
    await hooks.get("session:context")(ev)
    assert.match(ev.messages[0].content[0].text, /^__VG_NEW_ONE_[a-f0-9]{12}__$/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test("placeholder regex matches only well-formed placeholders", () => {
  const re = getPlaceholderRegex("__VG_")
  assert.deepEqual("a __VG_X_0123456789ab__ __VG__bad__ __VG_Y_0123456789ab_2__".match(re), [
    "__VG_X_0123456789ab__",
    "__VG_Y_0123456789ab_2__",
  ])
})
