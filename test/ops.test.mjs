import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { buildPatternSet, shannon } from "../patterns.js"
import { redactText } from "../engine.js"
import { PlaceholderSession } from "../session.js"
import { createAudit } from "../audit.js"
import { runSelfTest } from "../selftest.js"
import { normalizeConfig } from "../config.js"
import { addToSecretsFile, removeFromSecretsFile, mask } from "../command.js"
import { keepassSecrets, parseCsv } from "../keepass.js"
import { listCredentials, writeCredential, deleteCredential, windowsCredentialSecrets } from "../wincred.js"
import plugin from "../index.js"

const tmp = () => mkdtempSync(join(tmpdir(), "vg-ops-"))
const session = () => new PlaceholderSession({ prefix: "__VG_", ttlMs: 60_000, maxMappings: 1000 })

// ----------------------------------------------------------------- entropy

test("entropy: shannon", () => {
  assert.equal(shannon("aaaa"), 0)
  assert.ok(shannon("aB3dE5gH7jK9mN1p") > 3.5)
})

test("entropy: random values next to key names are redacted", () => {
  const p = buildPatternSet({ builtin: ["entropy_secret"] })
  const s = session()
  for (const line of [
    "curl --token Zx81kQ0pLm7Rt2Vb9Wc4Yd6N",
    "x-auth: Hq7Lr2Mz9Kp4Ws8Tn3Vb6Cx1",
    'stripeKey "R2d8F0gH4jK7lM1nP5qS9tV3"',
    "signature a3f9c2e81b7d4f60a3f9c2e81b7d4f60",
  ]) {
    const out = redactText(line, p, s).text
    assert.match(out, /__VG_HIGH_ENTROPY_SECRET_[a-f0-9]{12}__/, line)
  }
})

test("entropy: low-entropy, wordy, paths and ids are left alone", () => {
  const p = buildPatternSet({ builtin: ["entropy_secret"] })
  const s = session()
  for (const line of [
    "primaryKey: user_profile_settings_id",
    "cacheKey: src/components/Button.tsx",
    "sessionKey: 550e8400-e29b-41d4-a716-446655440000",
    "tokenizer: cl100k_base_tokenizer",
    "authorKey 1234567890123456",
    "license-key aaaaaaaaaaaaaaaaaaaa",
    "signature deadbeef",
  ]) {
    assert.equal(redactText(line, p, s).text, line, line)
  }
})

test("entropy: thresholds are configurable", () => {
  const strict = buildPatternSet({ builtin: ["entropy_secret"], entropy: { min_bits: 5 } })
  assert.equal(redactText("--token Zx81kQ0pLm7Rt2Vb9Wc4Yd6N", strict, session()).text, "--token Zx81kQ0pLm7Rt2Vb9Wc4Yd6N")
})

// ------------------------------------------------------------------- audit

test("audit: jsonl lines, no values, rotation keeps max_files", () => {
  const dir = tmp()
  try {
    const file = join(dir, "audit.jsonl")
    const audit = createAudit({ path: file, maxBytes: 400, maxFiles: 3 })
    for (let i = 0; i < 30; i++) audit.write("redact", { count: i, categories: ["GITHUB_PAT"] })
    assert.ok(existsSync(file))
    assert.ok(existsSync(`${file}.1`))
    assert.ok(existsSync(`${file}.2`))
    assert.ok(!existsSync(`${file}.3`))
    const line = JSON.parse(readFileSync(file, "utf8").trim().split("\n").at(-1))
    assert.equal(line.schema_version, 1)
    assert.equal(line.type, "redact")
    assert.equal(line.count, 29)
    assert.equal(audit.tail(5).at(-1).count, 29)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test("audit: write failures never throw", () => {
  const audit = createAudit({ path: join(tmpdir(), "\0invalid", "a.jsonl") })
  audit.write("x")
  assert.equal(audit.failures(), 1)
})

// ---------------------------------------------------------------- selftest

test("selftest: passes with defaults; a bad custom rule is a warning, not a failure", () => {
  const good = runSelfTest(normalizeConfig({ enabled: true }))
  assert.equal(good.ok, true)
  assert.equal(good.warnings, 0)
  const bad = runSelfTest(normalizeConfig({ enabled: true, patterns: { regex: [{ pattern: "(", category: "X" }] } }))
  assert.equal(bad.ok, true)
  assert.equal(bad.warnings, 1)
  assert.ok(bad.checks.some((c) => c.name === "rules compile" && !c.ok && c.warn))
})

// ----------------------------------------------------------- secrets file

test("command: add/replace/remove in the secrets file, quoting", async () => {
  const dir = tmp()
  try {
    const file = join(dir, "s.secrets")
    writeFileSync(file, "# keep me\nA=1234567\n")
    await addToSecretsFile(file, "B", "with space #x")
    await addToSecretsFile(file, "A", "new-value-1")
    let text = readFileSync(file, "utf8")
    assert.match(text, /# keep me/)
    assert.match(text, /^B="with space #x"$/m)
    assert.match(text, /^A=new-value-1$/m)
    assert.equal(text.match(/^A=/gm).length, 1)
    assert.equal((await removeFromSecretsFile(file, "A")).removed, true)
    text = readFileSync(file, "utf8")
    assert.ok(!/^A=/m.test(text))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test("command: mask hides all but the first characters", () => {
  assert.equal(mask("ghp_abcdefghijkl"), "gh▒▒▒▒▒")
  assert.equal(mask("short"), "▒▒▒▒▒")
  assert.equal(mask("a-12-char-pw"), "▒▒▒▒▒")
  assert.equal(mask("ghp_abcdefghijkl", 0), "▒▒▒▒▒")
})

function mockCtx(dir, hooks, posted) {
  const reg = (prefix) => async (name, cb) => {
    hooks.set(`${prefix}:${name}`, cb)
    return { dispose: async () => {} }
  }
  const commands = []
  return {
    location: { directory: dir },
    options: {},
    session: { hook: reg("session"), synthetic: async (input) => void posted.push(input) },
    tool: { hook: reg("tool") },
    permission: { hook: reg("permission") },
    command: {
      transform: async (fn) => {
        fn({ add: (def) => commands.push(def) })
        hooks.set("command", commands)
        return { dispose: async () => {} }
      },
    },
  }
}

test("e2e: /vibeguard status, add inline, test, audit; values never echoed", async () => {
  const dir = tmp()
  try {
    writeFileSync(join(dir, "vg.secrets"), "EXISTING=existing-secret-value\n")
    writeFileSync(
      join(dir, "vibeguard.config.json"),
      JSON.stringify({
        enabled: true,
        audit: { path: join(dir, "audit.jsonl") },
        secrets: { files: ["vg.secrets"], env: false, opencode_auth: false, windows_credentials: [] },
      }),
    )
    const hooks = new Map()
    const posted = []
    await plugin.setup(mockCtx(dir, hooks, posted))
    const [cmd] = hooks.get("command")
    assert.equal(cmd.name, "vibeguard")

    await cmd.execute({ sessionID: "s1", prompt: { text: "" } })
    assert.match(posted.at(-1).text, /VibeGuard status/)
    assert.match(posted.at(-1).text, /EXISTING/)
    assert.ok(!posted.at(-1).text.includes("existing-secret-value"))
    assert.equal(posted.at(-1).resume, false)

    await cmd.execute({ sessionID: "s1", prompt: { text: "add NEW_PW=Fresh Secret 99!" } })
    assert.match(posted.at(-1).text, /Added \*\*NEW_PW\*\*/)
    assert.ok(!posted.at(-1).text.includes("Fresh Secret 99!"))
    assert.match(readFileSync(join(dir, "vg.secrets"), "utf8"), /^NEW_PW="Fresh Secret 99!"$/m)

    const ev = { sessionID: "s1", system: [], messages: [{ role: "user", content: [{ type: "text", text: "pw Fresh Secret 99!" }] }] }
    await hooks.get("session:context")(ev)
    assert.match(ev.messages[0].content[0].text, /^pw __VG_NEW_PW_[a-f0-9]{12}__$/)

    await cmd.execute({ sessionID: "s1", prompt: { text: "test" } })
    assert.match(posted.at(-1).text, /self-test: ✅ passed/)

    await cmd.execute({ sessionID: "s1", prompt: { text: "audit 50" } })
    const auditText = posted.at(-1).text
    assert.match(auditText, /command\.add/)
    assert.match(auditText, /redact/)
    const raw = readFileSync(join(dir, "audit.jsonl"), "utf8")
    assert.ok(!raw.includes("Fresh Secret 99!"))
    assert.ok(!raw.includes("existing-secret-value"))

    await cmd.execute({ sessionID: "s1", prompt: { text: "remove NEW_PW" } })
    assert.match(posted.at(-1).text, /Removed \*\*NEW_PW\*\*/)

    await cmd.execute({ sessionID: "s1", prompt: { text: "help" } })
    assert.match(posted.at(-1).text, /add NAME/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test("e2e: a self-test warning does not block requests", async () => {
  const dir = tmp()
  try {
    writeFileSync(
      join(dir, "vibeguard.config.json"),
      JSON.stringify({
        enabled: true,
        audit: { enabled: false },
        secrets: { files: [], env: false, opencode_auth: false, windows_credentials: [] },
        patterns: { regex: [{ pattern: "(", category: "BROKEN" }] },
      }),
    )
    const hooks = new Map()
    await plugin.setup(mockCtx(dir, hooks, []))
    const ev = { sessionID: "s", system: [], messages: [{ role: "user", content: [{ type: "text", text: "ghp_" + "Q".repeat(36) }] }] }
    await hooks.get("session:context")(ev)
    assert.match(ev.messages[0].content[0].text, /^__VG_GITHUB_TOKEN_/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

// ------------------------------------------------------------------ keepass

test("keepass: entries and group export via keepassxc-cli (fake cli)", async () => {
  const dir = tmp()
  try {
    const fake = join(dir, "fake-kpcli.mjs")
    writeFileSync(
      fake,
      `let pw = ""; process.stdin.on("data", (d) => (pw += d)); process.stdin.on("end", () => {
  if (pw.trim() !== "master-pw") { console.error("Invalid credentials"); process.exit(1) }
  const a = process.argv.slice(2)
  if (a[0] === "show") { process.stdout.write(a.at(-1) === "Dev/Db" ? "kp-db-password-1\\n" : ""); return }
  if (a[0] === "export") process.stdout.write('"Group","Title","Username","Password","URL","Notes"\\n"Root/VibeGuard","Api Key","u","kp-api-key-2","",""\\n"Root/Other","X","u","not-me-3","",""\\n')
})`,
    )
    process.env.VG_TEST_KP = "master-pw"
    const res = await keepassSecrets(
      { database: join(dir, "db.kdbx"), cli: [process.execPath, fake], password_env: "VG_TEST_KP", entries: [{ name: "DB_PASSWORD", entry: "Dev/Db" }], group: "VibeGuard" },
      dir,
    )
    assert.deepEqual(res.failed, [])
    const map = new Map(res.entries.map((e) => [e.value, e.category]))
    assert.equal(map.get("kp-db-password-1"), "DB_PASSWORD")
    assert.equal(map.get("kp-api-key-2"), "API_KEY")
    assert.ok(!map.has("not-me-3"))

    process.env.VG_TEST_KP = "wrong"
    const bad = await keepassSecrets({ database: join(dir, "db.kdbx"), cli: [process.execPath, fake], password_env: "VG_TEST_KP", entries: [{ entry: "Dev/Db" }] }, dir)
    assert.equal(bad.entries.length, 0)
    assert.match(bad.failed[0].message, /Invalid credentials/)
  } finally {
    delete process.env.VG_TEST_KP
    rmSync(dir, { recursive: true, force: true })
  }
})

test("keepass: csv parser handles quotes, commas and newlines", () => {
  assert.deepEqual(parseCsv('a,"b ""q"", c","d\ne"\n1,2,3\n'), [
    ["a", 'b "q", c', "d\ne"],
    ["1", "2", "3"],
  ])
})

// ------------------------------------------------- windows credential manager

test("wincred: write, list via filter, delete (Windows only)", { skip: process.platform !== "win32", timeout: 60_000 }, async () => {
  const target = `vibeguard-selftest:VG_TEST_${Date.now()}`
  const secret = "wincred-test-secret-äöü-42"
  try {
    assert.deepEqual(await writeCredential(target, secret), { ok: true })
    const listed = await listCredentials(["vibeguard-selftest:*"])
    assert.equal(listed.error, undefined)
    assert.equal(listed.items.find((c) => c.target === target)?.secret, secret)
    const res = await windowsCredentialSecrets([{ filter: "vibeguard-selftest:*" }])
    assert.ok(res.entries.some((e) => e.value === secret && e.category.startsWith("VG_TEST_")))
  } finally {
    assert.deepEqual(await deleteCredential(target), { ok: true })
  }
  const after = await listCredentials([target])
  assert.equal(after.items.length, 0)
})
