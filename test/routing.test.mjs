import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, writeFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import plugin from "../index.js"
import { compileRouting, sourcesForCall, toolNames, endpointFor, FingerprintRegistry } from "../routing.js"
import { normalizeConfig } from "../config.js"
import { extractBitwardenItems, bitwardenSecrets } from "../bitwarden.js"

const GH = "ghp_" + "Rt6".repeat(12)
const CLOUD = { providerID: "anthropic", id: "claude-x" }
const LOCAL = { providerID: "kk-local", id: "qwen" }
const MAIL = "Quarterly figures: revenue grew by 17 percent in the northern region, confidential until Friday."

function setup(extra = {}, storage = new Map()) {
  const dir = mkdtempSync(join(tmpdir(), "vg-route-"))
  writeFileSync(join(dir, "vg.secrets"), `GITHUB_PAT=${GH}\n`)
  writeFileSync(
    join(dir, "vibeguard.config.json"),
    JSON.stringify({
      enabled: true,
      audit: { enabled: false },
      secrets: { files: ["vg.secrets"], env: false, opencode_auth: false, windows_credentials: [] },
      endpoints: { local: { providers: ["kk-local"], base_urls: ["http://localai.test:30000/*"], trusted: true } },
      sources: {
        exchange: { tools: ["exchange_*"], allow: ["local"] },
        hr: { paths: [join(dir, "hr", "**")], allow: ["local"] },
        tagged: { tools: ["excel-mcp_*"] },
      },
      ...extra,
    }),
  )
  const hooks = new Map()
  const reg = (prefix) => async (name, cb) => {
    hooks.set(`${prefix}:${name}`, cb)
    return { dispose: async () => {} }
  }
  const ctx = {
    location: { directory: dir },
    options: {},
    storage: {
      get: async (k) => storage.get(k),
      set: async (k, v) => void storage.set(k, v),
      remove: async (k) => void storage.delete(k),
    },
    session: { hook: reg("session"), synthetic: async () => {} },
    tool: { hook: reg("tool") },
    permission: { hook: reg("permission") },
  }
  return { dir, hooks, ctx, storage, cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

const req = (sessionID, model, messages, system = []) => ({ sessionID, model, system, messages })
const user = (text) => ({ role: "user", content: [{ type: "text", text }] })
const toolTurn = (id, name, input, value) => [
  { role: "assistant", content: [{ type: "tool-call", id, name, input }] },
  { role: "tool", content: [{ type: "tool-result", id, name, result: { type: "text", value } }] },
]

test("routing: endpoint and source matching", () => {
  const r = compileRouting(
    normalizeConfig({
      endpoints: { local: { providers: ["kk-*"] } },
      sources: { exchange: { tools: ["exchange_*"], allow: ["local"] }, web: { urls: ["https://intra.example/*"] } },
    }),
    process.cwd(),
  )
  assert.equal(endpointFor(r, LOCAL)?.name, "local")
  assert.equal(endpointFor(r, CLOUD), null)
  assert.deepEqual(sourcesForCall(r, ["exchange_get_message"], {}), ["exchange"])
  assert.deepEqual(sourcesForCall(r, toolNames("execute", null, { code: 'await tools.exchange.search({q:"x"})' }), {}), ["exchange"])
  assert.deepEqual(sourcesForCall(r, ["webfetch"], { url: "https://intra.example/a" }), ["web"])
  assert.deepEqual(sourcesForCall(r, ["bash"], { command: "ls" }), [])
})

test("routing: trusted local endpoint gets plaintext, no substitution, placeholders restored", async () => {
  const t = await setupPlugin()
  try {
    const cloud = req("s1", CLOUD, [user(`token ${GH}`)])
    await t.hooks.get("session:context")(cloud)
    const ph = cloud.messages[0].content[0].text.slice(6)
    assert.match(ph, /^__VG_GITHUB_PAT_/)

    const local = req("s1", LOCAL, [user(`token ${GH}`), { role: "assistant", content: [{ type: "text", text: `using ${ph}` }] }])
    await t.hooks.get("session:context")(local)
    assert.equal(local.messages[0].content[0].text, `token ${GH}`)
    assert.equal(local.messages[1].content[0].text, `using ${GH}`)
    assert.ok(!local.system.some((p) => /Privacy notice/.test(p.text)), "no placeholder hint for trusted endpoints")

    const body = JSON.stringify({ messages: [{ content: `token ${GH}` }] })
    const http = { sessionID: "s1", kind: "primary", model: LOCAL, request: new Request("http://localai.test:30000/v1/chat", { method: "POST", headers: { "content-type": "application/json" }, body }) }
    await t.hooks.get("session:http.request")(http)
    assert.equal(await http.request.text(), body, "trusted request untouched")
  } finally {
    t.cleanup()
  }
})

test("routing: trusted provider pointing to an unlisted URL is blocked", async () => {
  const t = await setupPlugin()
  try {
    const http = { sessionID: "s1", kind: "primary", model: LOCAL, request: new Request("https://cloud.example/v1/chat", { method: "POST", body: "{}" }) }
    await assert.rejects(t.hooks.get("session:http.request")(http), /not in its base_urls/)
  } finally {
    t.cleanup()
  }
})

test("routing: preflight denies restricted tools while the session runs on a cloud model", async () => {
  const t = await setupPlugin()
  try {
    await t.hooks.get("session:context")(req("s1", CLOUD, [user("hi")]))
    await assert.rejects(t.hooks.get("tool:execute.before")({ sessionID: "s1", tool: "exchange_get_message", input: { id: "m1" } }), /may only be processed by/)
    await assert.rejects(t.hooks.get("tool:execute.before")({ sessionID: "s1", tool: "execute", input: { code: "await tools.exchange.get_message({id:'m1'})" } }), /exchange/)
    await assert.rejects(t.hooks.get("tool:execute.before")({ sessionID: "s1", tool: "read", input: { path: join(t.dir, "hr", "salaries.txt") } }), /"hr"/)
    await t.hooks.get("tool:execute.before")({ sessionID: "s1", tool: "excel-mcp_file", input: {} })

    // the denied call stays in the history as an error result: no data, no block
    const denied = [
      user("hi"),
      { role: "assistant", content: [{ type: "tool-call", id: "c9", name: "exchange_get_message", input: { id: "m1" } }] },
      { role: "tool", content: [{ type: "tool-result", id: "c9", name: "exchange_get_message", result: { type: "error", value: "denied" } }] },
    ]
    await t.hooks.get("session:context")(req("s1", CLOUD, denied))

    await t.hooks.get("session:context")(req("s2", LOCAL, [user("hi")]))
    await t.hooks.get("tool:execute.before")({ sessionID: "s2", tool: "exchange_get_message", input: { id: "m1" } })
  } finally {
    t.cleanup()
  }
})

test("routing: restricted data taints the session, survives restarts, and blocks cloud requests", async () => {
  const storage = new Map()
  const t = await setupPlugin({}, storage)
  try {
    await t.hooks.get("session:context")(req("s1", LOCAL, [user("read my mail")]))
    const after = { sessionID: "s1", tool: "exchange_get_message", input: { id: "m1" }, status: "completed", result: { content: [{ type: "text", text: MAIL }] } }
    await t.hooks.get("tool:execute.after")(after)
    assert.deepEqual(after.result.metadata.vibeguard.sources, ["exchange"])
    assert.deepEqual(storage.get("taint:s1"), ["exchange"])

    const history = [user("read my mail"), ...toolTurn("c1", "exchange_get_message", { id: "m1" }, MAIL)]
    await assert.rejects(t.hooks.get("session:context")(req("s1", CLOUD, history)), /restricted source\(s\) "exchange"/)

    // title requests are answered locally instead of failing
    const title = req("s1", CLOUD, history)
    await t.hooks.get("session:title")(title)
    assert.equal(title.result, "Session (restricted data)")

    // compaction may have removed the tool result: the persisted taint still blocks
    await assert.rejects(t.hooks.get("session:context")(req("s1", CLOUD, [user("summary: things happened")])), /session tainted/)
    await t.stop() // plugin unload (OpenCode restart) flushes the fingerprints
  } finally {
    t.cleanup()
  }

  // a fresh plugin instance with the same storage still knows the taint and the fingerprints
  const t2 = await setupPlugin({}, storage)
  try {
    await assert.rejects(t2.hooks.get("session:context")(req("s1", CLOUD, [user("hello again")])), /session tainted/)
    // copied content in a different (e.g. subagent) session is recognized by its fingerprint
    await assert.rejects(t2.hooks.get("session:context")(req("s9", CLOUD, [user(`Please analyse:\n${MAIL}`)])), /content fingerprint/)
    // unrelated sessions are fine
    await t2.hooks.get("session:context")(req("s3", CLOUD, [user("unrelated question")]))
  } finally {
    t2.cleanup()
  }
})

test("routing: http.request is the last line of defence for tainted sessions", async () => {
  const t = await setupPlugin()
  try {
    await t.hooks.get("tool:execute.after")({ sessionID: "s1", tool: "exchange_list", input: {}, status: "completed", result: { content: [{ type: "text", text: MAIL }] } })
    const body = JSON.stringify({ messages: [{ content: MAIL }] })
    const http = { sessionID: "s7", kind: "primary", model: CLOUD, request: new Request("https://api.cloud.example/v1", { method: "POST", headers: { "content-type": "application/json" }, body }) }
    await assert.rejects(t.hooks.get("session:http.request")(http), /content fingerprint/)
  } finally {
    t.cleanup()
  }
})

test("routing: withhold mode replaces restricted tool results instead of blocking", async () => {
  const t = await setupPlugin({ routing: { on_violation: "withhold" } })
  try {
    const history = [user("read my mail"), ...toolTurn("c1", "exchange_get_message", { id: "m1" }, MAIL)]
    const r = req("s1", CLOUD, history)
    await t.hooks.get("session:context")(r)
    assert.match(r.messages[2].content[0].result.value, /content withheld/)
    assert.ok(!JSON.stringify(r).includes("17 percent"))
  } finally {
    t.cleanup()
  }
})

test("routing: tagging-only sources never block", async () => {
  const t = await setupPlugin()
  try {
    const after = { sessionID: "s1", tool: "excel-mcp_read", input: {}, status: "completed", result: { content: [{ type: "text", text: MAIL.replace("confidential", "public") }] } }
    await t.hooks.get("tool:execute.after")(after)
    assert.deepEqual(after.result.metadata.vibeguard.sources, ["tagged"])
    await t.hooks.get("session:context")(req("s1", CLOUD, [user("ok"), ...toolTurn("c1", "excel-mcp_read", {}, "x")]))
  } finally {
    t.cleanup()
  }
})

test("fingerprints: copies are found, unrelated text is not", () => {
  const fp = new FingerprintRegistry(Buffer.alloc(32, 1))
  fp.add("exchange", `Subject: Budget\n${MAIL}\nRegards`)
  assert.ok((fp.check(`fyi: ${MAIL}`).get("exchange") ?? 0) >= 2)
  assert.equal(fp.check("Completely different text about the weather tomorrow.").size, 0)
})

// ---------------------------------------------------------------- bitwarden

test("bitwarden: item extraction defaults", () => {
  const items = [
    { name: "Router", login: { username: "admin", password: "Rt-pw-9x!Q", totp: "JBSWY3DPEHPK3PXP" } },
    { name: "Visa", card: { number: "4111111111111111", code: "123" } },
    { name: "API", fields: [{ name: "token", value: "tok-Zx81-aa", type: 1 }, { name: "note", value: "visible text", type: 0 }] },
    { name: "Gone", deletedDate: "2026-01-01", login: { password: "old-pw-1234" } },
  ]
  const e = new Map(extractBitwardenItems(items).map((x) => [x.value, x.category]))
  assert.equal(e.get("Rt-pw-9x!Q"), "ROUTER")
  assert.equal(e.get("JBSWY3DPEHPK3PXP"), "ROUTER_TOTP")
  assert.ok(!e.has("admin"), "usernames are opt-in")
  assert.equal(e.get("4111111111111111"), "VISA_CARD_NUMBER")
  assert.ok(!e.has("123"), "too short")
  assert.equal(e.get("tok-Zx81-aa"), "API_TOKEN")
  assert.ok(!e.has("visible text"))
  assert.ok(!e.has("old-pw-1234"))
})

test("bitwarden: folders via a fake bw CLI, session via env only", async () => {
  const dir = mkdtempSync(join(tmpdir(), "vg-bw-"))
  try {
    const fake = join(dir, "fake-bw.mjs")
    writeFileSync(
      fake,
      `const a = process.argv.slice(2)
if (process.env.BW_SESSION !== "sess-123") { console.error("Vault is locked."); process.exit(1) }
if (a.includes("--session")) { console.error("session on command line"); process.exit(2) }
if (a[0] === "sync") { console.log("Syncing complete."); process.exit(0) }
if (a[0] === "list" && a[1] === "folders") { console.log(JSON.stringify([{ id: "f1", name: "VibeGuard" }, { id: "f2", name: "Private" }])); process.exit(0) }
if (a[0] === "list" && a[1] === "items" && a[3] === "f1") { console.log(JSON.stringify([{ name: "NAS", login: { password: "nas-Pw-77x!" } }])); process.exit(0) }
console.log("[]")`,
    )
    process.env.VG_TEST_BW = "sess-123"
    const ok = await bitwardenSecrets({ cli: [process.execPath, fake], folders: ["VibeGuard"], session_env: "VG_TEST_BW" })
    assert.deepEqual(ok.failed, [])
    assert.deepEqual(ok.entries.map((e) => [e.category, e.source]), [["NAS", "bitwarden"]])
    assert.ok(!("BW_SESSION" in process.env), "session never enters OpenCode's own environment")

    const missing = await bitwardenSecrets({ cli: [process.execPath, fake], folders: ["Nope"], session_env: "VG_TEST_BW" })
    assert.match(missing.failed.map((f) => f.message).join(), /folder not found/)

    const whole = await bitwardenSecrets({ cli: [process.execPath, fake], session_env: "VG_TEST_BW" })
    assert.match(whole.failed[0].message, /never the whole vault/)

    process.env.VG_TEST_BW = "wrong"
    const locked = await bitwardenSecrets({ cli: [process.execPath, fake], folders: ["VibeGuard"], session_env: "VG_TEST_BW", session_wincred: "" })
    assert.equal(locked.entries.length, 0)
    assert.match(locked.failed.map((f) => f.message).join(), /locked/i)
  } finally {
    delete process.env.VG_TEST_BW
    rmSync(dir, { recursive: true, force: true })
  }
})

async function setupPlugin(extra, storage) {
  const t = setup(extra, storage)
  t.stop = await plugin.setup(t.ctx)
  return t
}
