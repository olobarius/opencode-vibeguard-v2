import { appendFileSync } from "node:fs"
import { randomBytes } from "node:crypto"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createAudit } from "./audit.js"
import { createCommandHandler } from "./command.js"
import { loadConfig } from "./config.js"
import { buildPatternSet } from "./patterns.js"
import { KnownRegistry, PlaceholderSession, createSessionStore, deriveKey } from "./session.js"
import { collectKnownSecrets, defaultDataDir, fingerprint } from "./known.js"
import { redactText } from "./engine.js"
import { redactValue } from "./deep.js"
import { createRestoreStats, restoreValue, scanPlaceholders } from "./restore.js"
import { buildRawPatterns, guardRawText, guardRequest } from "./guard.js"
import { restoreFrame, restoreResponse } from "./stream.js"
import { ProtectedPaths, compileToolRules, toolEffect } from "./policy.js"
import { runSelfTest } from "./selftest.js"
import { expandPath } from "./util.js"
import { restoreText } from "./restore.js"
import {
  FingerprintRegistry,
  allStrings,
  compileRouting,
  deniedSources,
  endpointFor,
  sourceAllowed,
  sourcesForCall,
  toolNames,
  urlVerified,
} from "./routing.js"

const TAG = "[opencode-vibeguard]"
const REQUEST_KINDS = ["context", "compaction", "generate", "title"]
const TEXT_MEDIA = /^(?:text\/|application\/(?:json|xml|yaml|x-yaml|toml|x-sh|javascript|typescript|x-ndjson))/i
const HINT_MARKER = "Privacy notice: secrets, passwords"

/**
 * Debug trace (`debug: true` or OPENCODE_VIBEGUARD_DEBUG): JSON lines in
 * `<tmpdir>/opencode-vibeguard-trace.log`. Counts only, never values.
 */
function createTrace(enabled) {
  if (!enabled) return () => {}
  const file = join(tmpdir(), "opencode-vibeguard-trace.log")
  return (event, data = {}) => {
    try {
      appendFileSync(file, `${new Date().toISOString()} ${event} ${JSON.stringify(data)}\n`)
    } catch {
      // never break a request because of tracing
    }
  }
}

function systemHint(prefix) {
  return (
    `${HINT_MARKER} and other sensitive values in this conversation are replaced by placeholders ` +
    `of the form ${prefix}<NAME>_<12 hex chars>__ . Treat each placeholder exactly like the real value: use it verbatim ` +
    `in tool calls, shell commands and file edits; it is substituted locally right before execution. Never guess, decode, ` +
    `shorten, alter or invent placeholders, and do not ask the user to reveal the underlying values. Some tools ` +
    `(e.g. web access) may refuse to receive secret values.`
  )
}

async function loadMasterKey(ctx) {
  try {
    const stored = await ctx.storage?.get?.("master-key")
    if (typeof stored === "string" && /^[a-f0-9]{64}$/.test(stored)) return Buffer.from(stored, "hex")
  } catch {
    // fall through to a fresh key
  }
  const key = randomBytes(32)
  try {
    await ctx.storage?.set?.("master-key", key.toString("hex"))
  } catch {
    // ephemeral key: known placeholders change after a restart
  }
  return key
}

/**
 * VibeGuard for OpenCode V2.
 *
 * Outbound (nothing sensitive reaches the provider):
 * - session hooks context/compaction/generate/title: structural redaction
 * - session hook http.request (+ experimental.ws.send): raw payload safety net
 * - session hook prompt (opt-in): redact the user prompt before it is persisted
 *
 * Inbound / local:
 * - session hook http.response (+ experimental.ws.receive): restore placeholders in answer text
 * - tool hook execute.before: restore real values for local tools (allow / ask / deny / keep)
 * - permission hook evaluate: block reading registered secret files
 *
 * Operations: `/vibeguard` command, JSONL audit log, startup self-test, live pipeline check.
 */
export default {
  id: "opencode-vibeguard",
  async setup(ctx) {
    const directory = ctx.location?.directory ?? process.cwd()
    const config = await loadConfig(directory, ctx.options)
    const debug = Boolean(process.env.OPENCODE_VIBEGUARD_DEBUG) || config.debug
    const trace = createTrace(debug)
    const auditCfg = config.audit ?? {}
    const audit = createAudit({
      enabled: config.enabled && auditCfg.enabled !== false,
      path: auditCfg.path ? expandPath(auditCfg.path, directory) : join(defaultDataDir(), "vibeguard", "audit.jsonl"),
      maxBytes: auditCfg.max_bytes,
      maxFiles: auditCfg.max_files,
    })
    /** Security event: audit log (always) + debug trace. Never pass secret values. */
    const record = (type, data = {}) => {
      audit.write(type, data)
      trace(type, data)
    }
    const log = (...args) => {
      if (debug) console.log(TAG, ...args)
    }

    for (const error of config.errors) console.error(`${TAG} unreadable config ${error}`)
    trace("setup", { directory, loadedFrom: config.loadedFrom, enabled: config.enabled })
    if (!config.loadedFrom) {
      console.error(
        `${TAG} DISABLED: no vibeguard.config.json(c) found (OPENCODE_VIBEGUARD_CONFIG, ./, ./.opencode/, ~/.config/opencode/) and no plugin options. Provider requests are NOT being redacted.`,
      )
    }
    if (!config.enabled) return

    const master = await loadMasterKey(ctx)
    const known = new KnownRegistry({ prefix: config.prefix, key: deriveKey(master, "known") })
    const protectedPaths = new ProtectedPaths([], directory)
    const toolRules = compileToolRules(config.restore.tools)
    const state = {
      patterns: null,
      raw: null,
      known: null,
      watch: [],
      fp: "",
      checkedAt: Date.now(),
      selftest: null,
      pipeline: "",
      protectedCount: 0,
      pipelineChecked: new Set(),
    }

    async function rebuild(reason, opts = {}) {
      const res = await collectKnownSecrets(config, directory, {
        slowCache: state.known?.slow,
        refreshSlow: opts.refreshSlow ?? !state.known,
      })
      const patterns = buildPatternSet(config.patterns, res.entries)
      known.load(patterns.keywords)
      state.patterns = patterns
      state.raw = buildRawPatterns(patterns, config.guard?.regex ?? "strong")
      state.known = res
      state.watch = res.watch
      state.fp = await fingerprint(res.watch)
      const extra = (Array.isArray(config.protect?.paths) ? config.protect.paths : []).map((p) => expandPath(p, directory))
      protectedPaths.set([...res.protectedPaths, ...extra])
      state.protectedCount = protectedPaths.list.length
      for (const e of patterns.errors) console.error(`${TAG} skipped invalid rule /${e.pattern}/${e.flags}: ${e.message}`)
      for (const f of res.failed) console.error(`${TAG} secret source unreadable: ${f.file}: ${f.message}`)
      log(`${reason}: ${res.named} known value(s) (${JSON.stringify(res.counts)}), ${patterns.regex.length} rule(s), ${protectedPaths.list.length} protected path(s)`)
      record("load", {
        reason,
        named: res.named,
        counts: res.counts,
        rules: patterns.regex.length,
        protected: protectedPaths.list.length,
        failed: res.failed.map((f) => f.file),
      })
      const weak = res.entries.filter((e) => !e.variant && e.strength === "weak")
      if (weak.length) {
        record("secrets.weak", { names: weak.map((e) => e.category), modes: weak.map((e) => e.mode) })
        log(`${weak.length} weak known secret(s) (only replaced in a credential context): ${weak.map((e) => e.category).join(", ")}`)
      }
    }
    await rebuild("setup", { refreshSlow: true })

    const selfTest = () => {
      const res = runSelfTest(config)
      state.selftest = res
      const failed = res.checks.filter((c) => !c.ok)
      record("selftest", { ok: res.ok, failed: failed.filter((c) => !c.warn).map((c) => c.name), warnings: failed.filter((c) => c.warn).map((c) => c.name) })
      for (const c of failed) {
        console.error(`${TAG} self-test ${c.warn ? "warning" : "FAILED"}: ${c.name} (${c.detail})`)
      }
      return res
    }
    if (config.selftest !== false) selfTest()
    const healthy = () => config.selftest === false || state.selftest?.ok !== false

    let reloading = null
    const fresh = () => {
      const now = Date.now()
      if (!(config.reloadMs > 0) || now - state.checkedAt < config.reloadMs) return reloading
      state.checkedAt = now
      reloading ??= (async () => {
        if ((await fingerprint(state.watch)) !== state.fp) await rebuild("reload")
      })()
        .catch((error) => console.error(`${TAG} reload failed: ${String(error?.message ?? error)}`))
        .finally(() => {
          reloading = null
        })
      return reloading
    }

    const store = createSessionStore({ maxSessions: config.maxSessions }, (id) => {
      return new PlaceholderSession({
        prefix: config.prefix,
        ttlMs: config.ttlMs,
        maxMappings: config.maxMappings,
        key: deriveKey(master, `session\0${id}`),
        known,
      })
    })
    const getSession = (id) => store.get(id)

    // ----------------------------------------------------------------- routing
    const routing = compileRouting(config, directory)
    const fingerprints = new FingerprintRegistry(deriveKey(master, "fingerprints"))
    if (routing.enabled && routing.fingerprints) {
      try {
        fingerprints.load(await ctx.storage?.get?.("fingerprints"))
      } catch {
        // start empty
      }
    }
    let fpTimer = null
    const saveFingerprints = (now = false) => {
      if (!fingerprints.dirty) return
      const write = async () => {
        fpTimer = null
        fingerprints.dirty = false
        try {
          await ctx.storage?.set?.("fingerprints", fingerprints.toJSON())
        } catch (error) {
          record("storage.error", { key: "fingerprints", message: String(error?.message ?? error) })
        }
      }
      if (now) return write()
      fpTimer ??= setTimeout(write, 1000)
      fpTimer.unref?.()
    }
    /** Last model per session (preflight in execute.before). */
    const lastModel = new Map()
    /** Persistent per-session taint: restricted sources a session has seen. */
    const taints = new Map()
    const getTaint = async (sid) => {
      if (!sid) return new Set()
      let t = taints.get(sid)
      if (t) return t
      t = new Set()
      try {
        const stored = await ctx.storage?.get?.(`taint:${sid}`)
        if (Array.isArray(stored)) stored.forEach((s) => t.add(String(s)))
      } catch {
        // none
      }
      taints.set(sid, t)
      return t
    }
    const addTaint = async (sid, names) => {
      const t = await getTaint(sid)
      const before = t.size
      names.forEach((n) => t.add(n))
      if (t.size === before) return
      try {
        await ctx.storage?.set?.(`taint:${sid}`, [...t])
      } catch (error) {
        record("storage.error", { key: "taint", message: String(error?.message ?? error) })
      }
    }
    const clearTaint = async (sid) => {
      taints.set(sid, new Set())
      try {
        await ctx.storage?.remove?.(`taint:${sid}`)
      } catch {
        // ignore
      }
    }
    const describeModel = (m) => (m ? `${m.providerID}/${m.id}` : "unknown")
    const allowList = (name) => {
      const s = routing.sources.find((x) => x.name === name)
      return s?.allow ? [...s.allow].join(", ") : "*"
    }

    /**
     * Which restricted sources does this request carry that its endpoint may not see?
     * Signals: tool calls of restricted sources in the history, the session taint,
     * and fingerprints of restricted content in any string.
     */
    const routingViolations = async (event, endpoint) => {
      const denied = deniedSources(routing, endpoint)
      if (denied.length === 0) return { violations: [], toolParts: [] }
      const deniedNames = new Set(denied.map((s) => s.name))
      const violations = new Map()
      const toolParts = []
      const calls = new Map()
      for (const message of Array.isArray(event.messages) ? event.messages : []) {
        for (const part of Array.isArray(message?.content) ? message.content : []) {
          if (part?.type !== "tool-call") continue
          const names = toolNames(part.name, part.namespace, part.input)
          const hit = sourcesForCall(routing, names, part.input).filter((n) => deniedNames.has(n))
          if (hit.length) calls.set(part.id, hit)
        }
      }
      // Only results carry data: a call that was denied (preflight) or failed has none.
      for (const message of Array.isArray(event.messages) ? event.messages : []) {
        for (const part of Array.isArray(message?.content) ? message.content : []) {
          if (part?.type !== "tool-result" || !calls.has(part.id) || part.result?.type === "error") continue
          toolParts.push({ part, sources: calls.get(part.id) })
          calls.get(part.id).forEach((n) => violations.set(n, "tool result in history"))
        }
      }
      for (const n of await getTaint(event.sessionID)) {
        if (deniedNames.has(n) && !violations.has(n)) violations.set(n, "session tainted")
      }
      const contentHits = new Map()
      if (routing.fingerprints && fingerprints.size > 0) {
        const withheld = new Set(toolParts.map((t) => t.part))
        const scan = (value, inWithheld) => {
          for (const s of allStrings(value)) {
            for (const [src, score] of fingerprints.check(s)) {
              if (!deniedNames.has(src)) continue
              const prev = contentHits.get(src) ?? { score: 0, outside: false }
              contentHits.set(src, { score: prev.score + score, outside: prev.outside || !inWithheld })
            }
          }
        }
        scan(event.system, false)
        for (const message of Array.isArray(event.messages) ? event.messages : []) {
          for (const part of Array.isArray(message?.content) ? message.content : []) scan(part, withheld.has(part))
        }
        for (const [src, hit] of contentHits) {
          if (hit.score >= 2 && !violations.has(src)) violations.set(src, "content fingerprint")
        }
      }
      return {
        violations: [...violations].map(([source, via]) => ({ source, via })),
        toolParts,
        derived: [...contentHits].some(([src, h]) => h.score >= 2 && h.outside && deniedNames.has(src)),
      }
    }

    const violationMessage = (violations, model, kind) =>
      `${TAG} blocked ${kind} request to ${describeModel(model)}: this session contains data from restricted source(s) ` +
      violations.map((v) => `"${v.source}" (allowed: ${allowList(v.source)}; ${v.via})`).join(", ") +
      `. Switch the session to an allowed model, or start a new session.`

    /** Trusted endpoint: no substitution at all; placeholders from earlier turns are turned back into real values. */
    const passthrough = (event) => {
      const session = getSession(event?.sessionID)
      if (!session) return 0
      let restored = 0
      const stats = createRestoreStats()
      for (const part of Array.isArray(event.system) ? event.system : []) {
        if (part?.type === "text" && typeof part.text === "string") part.text = restoreText(part.text, session, stats)
      }
      for (const message of Array.isArray(event.messages) ? event.messages : []) {
        if (typeof message?.content === "string") {
          message.content = restoreText(message.content, session, stats)
          continue
        }
        for (const part of Array.isArray(message?.content) ? message.content : []) {
          if (!part || typeof part !== "object") continue
          if (typeof part.text === "string") part.text = restoreText(part.text, session, stats)
          if (part.type === "tool-call" && part.input !== undefined) part.input = restoreValue(part.input, session, stats)
          if (part.type === "tool-result" && part.result !== undefined) part.result = restoreValue(part.result, session, stats)
        }
      }
      restored = stats.restored
      return restored
    }

    // ---------------------------------------------------------------- outbound
    const redactMedia = (part, red) => {
      const media = part.media
      const source = media?.source
      const type = source?.mediaType ?? ""
      if (!source || !TEXT_MEDIA.test(type)) return
      let text
      if (source.type === "base64" && typeof source.data === "string") text = Buffer.from(source.data, "base64").toString("utf8")
      else if (source.type === "bytes" && source.data instanceof Uint8Array) text = Buffer.from(source.data).toString("utf8")
      else return
      const after = red(text)
      if (after === text) return
      const data = source.type === "base64" ? Buffer.from(after, "utf8").toString("base64") : new Uint8Array(Buffer.from(after, "utf8"))
      part.media = Object.assign(Object.create(Object.getPrototypeOf(media)), media, { source: { ...source, data } })
    }

    const redactRequest = (event, kind) => {
      const session = getSession(event?.sessionID)
      if (!session) return { count: 0, categories: [] }
      session.cleanup()
      const patterns = state.patterns
      const counter = { count: 0, categories: new Set() }
      const red = (s) => {
        const r = redactText(s, patterns, session)
        counter.count += r.count
        for (const c of r.categories ?? []) counter.categories.add(c)
        return r.text
      }

      if (Array.isArray(event.system)) {
        for (const part of event.system) {
          if (part?.type !== "text" || typeof part.text !== "string") continue
          const t = red(part.text)
          if (t !== part.text) part.text = t
        }
      }

      for (const message of Array.isArray(event.messages) ? event.messages : []) {
        if (!message || typeof message !== "object") continue
        if (typeof message.content === "string") {
          const t = red(message.content)
          if (t !== message.content) message.content = t
          continue
        }
        if (!Array.isArray(message.content)) continue
        for (const part of message.content) {
          if (!part || typeof part !== "object") continue
          switch (part.type) {
            case "text":
            case "reasoning":
            case "compaction": {
              if (typeof part.text !== "string") break
              const t = red(part.text)
              if (t !== part.text) part.text = t
              break
            }
            case "tool-call": {
              // Replace with a redacted copy: the original args object is shared with session state.
              const next = redactValue(part.input, patterns, session, counter)
              if (next !== part.input) part.input = next
              break
            }
            case "tool-result": {
              const next = redactValue(part.result, patterns, session, counter)
              if (next !== part.result) part.result = next
              break
            }
            case "media":
              redactMedia(part, red)
              break
          }
        }
      }

      if (config.system_hint && kind !== "title" && Array.isArray(event.system)) {
        event.system.push({ type: "text", text: systemHint(config.prefix) })
      }
      return { count: counter.count, categories: [...counter.categories] }
    }

    for (const kind of REQUEST_KINDS) {
      await ctx.session.hook(kind, async (event) => {
        const endpoint = endpointFor(routing, event.model)
        if (event?.sessionID) lastModel.set(event.sessionID, { model: event.model, endpoint })

        if (routing.enabled) {
          let verdict
          try {
            verdict = await routingViolations(event, endpoint)
          } catch (error) {
            record("routing.error", { kind, message: String(error?.message ?? error) })
            if (config.fail_closed) throw new Error(`${TAG} routing check failed, request blocked (fail_closed): ${String(error?.message ?? error)}`)
            verdict = { violations: [], toolParts: [] }
          }
          if (verdict.violations.length) {
            const info = {
              session: event.sessionID,
              kind,
              model: describeModel(event.model),
              endpoint: endpoint?.name ?? null,
              sources: verdict.violations.map((v) => v.source),
              via: verdict.violations.map((v) => v.via),
            }
            if (kind === "title") {
              // Title requests may go to a small cloud model: name the session locally instead.
              event.result = "Session (restricted data)"
              record("routing.title", info)
              return
            }
            if (routing.onViolation === "withhold" && !verdict.derived && verdict.toolParts.length) {
              for (const { part, sources } of verdict.toolParts) {
                part.result = {
                  type: "text",
                  value: `[VibeGuard: content withheld. Data from source ${sources.map((s) => `"${s}"`).join(", ")} may only be processed by: ${sources.map(allowList).join(" / ")}]`,
                }
              }
              record("routing.withhold", { ...info, parts: verdict.toolParts.length })
            } else {
              record("routing.block", info)
              throw new Error(violationMessage(verdict.violations, event.model, kind))
            }
          }
        }

        if (endpoint?.trusted) {
          const restored = passthrough(event)
          record("passthrough", { session: event.sessionID, kind, endpoint: endpoint.name, restored })
          return
        }

        if (!healthy() && config.fail_closed) {
          record("request.blocked", { kind, reason: "selftest_failed" })
          throw new Error(`${TAG} self-test failed at startup; requests are blocked (fail_closed). Run /vibeguard test.`)
        }
        try {
          await fresh()
          const res = redactRequest(event, kind)
          if (res.count > 0) {
            log(`${kind}: redacted ${res.count} fragment(s)`)
            record("redact", { session: event.sessionID, kind, count: res.count, categories: res.categories })
          }
        } catch (error) {
          const message = String(error?.message ?? error)
          record("redact.error", { kind, message })
          if (config.fail_closed) throw new Error(`${TAG} redaction failed, request blocked (fail_closed): ${message}`)
          console.error(`${TAG} redaction failed (request sent unredacted!): ${message}`)
        }
      })
    }

    const guardMode = config.guard?.http ?? "redact"
    const guardOn = guardMode !== "off" && guardMode !== false
    const hostOf = (url) => {
      try {
        return new URL(url).host
      } catch {
        return ""
      }
    }
    await ctx.session.hook("http.request", async (event) => {
      const session = getSession(event?.sessionID)
      if (!session || !event.request) return
      const endpoint = endpointFor(routing, event.model)
      const urlOk = urlVerified(endpoint, event.request.url)
      const effective = endpoint && urlOk ? endpoint : null
      const host = hostOf(event.request.url)
      const egress = {
        session: event.sessionID,
        kind: event.kind,
        model: describeModel(event.model),
        host,
        endpoint: effective?.name ?? null,
        trusted: Boolean(effective?.trusted),
      }

      if (endpoint && !urlOk && (endpoint.trusted || routing.enabled)) {
        // The provider is configured as a local/allowed endpoint but the request goes elsewhere.
        record("routing.url_mismatch", { ...egress, expected: endpoint.name })
        if (endpoint.trusted) {
          throw new Error(`${TAG} blocked: provider "${event.model?.providerID}" is the trusted endpoint "${endpoint.name}", but the request goes to ${host}, which is not in its base_urls.`)
        }
      }

      if (routing.enabled) {
        const denied = deniedSources(routing, effective)
        if (denied.length) {
          const deniedNames = new Set(denied.map((s) => s.name))
          const reasons = []
          if (routing.onViolation === "block") {
            for (const n of await getTaint(event.sessionID)) if (deniedNames.has(n)) reasons.push({ source: n, via: "session tainted" })
          }
          if (routing.fingerprints && fingerprints.size > 0 && event.request.body) {
            let json = null
            try {
              json = JSON.parse(await event.request.clone().text())
            } catch {
              json = null
            }
            const score = new Map()
            for (const s of json ? allStrings(json) : []) for (const [src, n] of fingerprints.check(s)) if (deniedNames.has(src)) score.set(src, (score.get(src) ?? 0) + n)
            for (const [src, n] of score) if (n >= 2 && !reasons.some((r) => r.source === src)) reasons.push({ source: src, via: "content fingerprint" })
          }
          if (reasons.length) {
            record("routing.block", { ...egress, layer: "http", sources: reasons.map((r) => r.source), via: reasons.map((r) => r.via) })
            throw new Error(violationMessage(reasons, event.model, event.kind))
          }
        }
      }

      if (effective?.trusted || !guardOn) {
        record("egress", egress)
        return
      }
      {
        let res
        let body = null
        try {
          res = await guardRequest(event.request, state.raw, session, debug ? state.patterns : undefined)
          // Live pipeline check: the structural hooks must have run for agent-loop requests.
          if (config.system_hint && event.kind === "primary" && !state.pipelineChecked.has(event.sessionID)) {
            body = await event.request.clone().text()
            const ok = body.includes(HINT_MARKER)
            state.pipelineChecked.add(event.sessionID)
            state.pipeline = ok ? "✅ verified" : "❌ structural redaction did not run"
            record("pipeline", { session: event.sessionID, ok })
            if (!ok) console.error(`${TAG} live check: the structural redaction hooks did not run for this request.`)
          }
        } catch (error) {
          const message = String(error?.message ?? error)
          record("guard.error", { message })
          if (config.fail_closed) throw new Error(`${TAG} payload guard failed, request blocked (fail_closed): ${message}`)
          return
        }
        record("egress", { ...egress, guard: res.count })
        if (res.count === 0) return
        record("guard", { session: event.sessionID, kind: event.kind, count: res.count, mode: guardMode, paths: res.paths })
        if (guardMode === "block") {
          throw new Error(`${TAG} blocked ${event.kind} request: ${res.count} secret fragment(s) found in the raw payload`)
        }
        log(`http.request (${event.kind}): safety net replaced ${res.count} fragment(s)`)
        event.request = res.request
      }
    })

    if (config.guard?.websocket !== false) {
      await ctx.session.hook("experimental.ws.send", (event) => {
        const session = getSession(event?.sessionID)
        if (!session || typeof event.frame !== "string") return
        const endpoint = endpointFor(routing, event.model)
        if (endpoint?.trusted && urlVerified(endpoint, event.url ?? "")) return
        const res = guardRawText(event.frame, state.raw, session)
        if (!res.count) return
        record("guard.ws", { session: event.sessionID, count: res.count, mode: guardMode })
        if (guardMode === "block") throw new Error(`${TAG} blocked websocket frame: ${res.count} secret fragment(s)`)
        event.frame = res.text
      })
    }

    if (config.redact_prompt) {
      await ctx.session.hook("prompt", async (event) => {
        await fresh()
        const session = getSession(event?.sessionID)
        const text = event?.prompt?.text
        if (!session || typeof text !== "string") return
        const res = redactText(text, state.patterns, session)
        if (!res.count) return
        event.prompt.text = res.text
        // Attachment mention offsets refer to the old text.
        for (const file of Array.isArray(event.prompt.files) ? event.prompt.files : []) {
          if (file && typeof file === "object" && "mention" in file) delete file.mention
        }
        record("redact.prompt", { session: event.sessionID, count: res.count, categories: res.categories })
      })
    }

    // ----------------------------------------------------------------- inbound
    if (config.restore?.response !== false) {
      await ctx.session.hook("http.response", (event) => {
        const session = getSession(event?.sessionID)
        if (!session || !event.response?.ok) return
        try {
          const stats = createRestoreStats()
          const next = restoreResponse(event.response.clone(), session, stats)
          if (!next) return
          event.response = next
          trace("http.response", { kind: event.kind, type: next.headers.get("content-type") })
        } catch (error) {
          record("restore.error", { message: String(error?.message ?? error) })
        }
      })
      await ctx.session.hook("experimental.ws.receive", (event) => {
        const session = getSession(event?.sessionID)
        if (!session || typeof event.frame !== "string") return
        const next = restoreFrame(event.frame, session)
        if (next !== event.frame) event.frame = next
      })
    }

    const approved = new Set()
    await ctx.tool.hook("execute.before", async (event) => {
      const session = getSession(event?.sessionID)
      if (!session) return

      // Preflight: do not even fetch restricted data while the session runs on a model that may not see it.
      if (routing.enabled && routing.preflight) {
        const sources = sourcesForCall(routing, toolNames(event.tool, null, event.input), event.input)
        if (sources.length) {
          const current = lastModel.get(event.sessionID)
          const blocked = sources.filter((name) => !sourceAllowed(routing.sources.find((s) => s.name === name), current?.endpoint ?? null))
          if (blocked.length) {
            record("routing.preflight", { session: event.sessionID, tool: event.tool, sources: blocked, model: describeModel(current?.model) })
            throw new Error(
              `${TAG} tool "${event.tool}" reads data from source ${blocked.map((s) => `"${s}"`).join(", ")}, which may only be processed by ` +
                `${blocked.map(allowList).join(" / ")}. The current model ${describeModel(current?.model)} is not allowed. ` +
                `Ask the user to switch to an allowed (local) model for this task.`,
            )
          }
        }
      }

      const effect = toolEffect(event.tool, toolRules)
      if (effect === "keep") return
      const scan = scanPlaceholders(event.input, session)
      if (scan.restored === 0 && scan.unknown.size === 0) return

      if (scan.unknown.size > 0 && config.restore?.unknown !== "keep") {
        record("tool.unknown_placeholder", { session: event.sessionID, tool: event.tool, placeholders: [...scan.unknown].slice(0, 5) })
        throw new Error(
          `${TAG} the input of tool "${event.tool}" contains placeholder(s) that cannot be resolved in this session: ` +
            `${[...scan.unknown].slice(0, 5).join(", ")}. Never invent or modify placeholders; use them exactly as they ` +
            `appeared, or ask the user to provide the value again.`,
        )
      }
      if (scan.restored === 0) return

      const categories = [...scan.categories]
      if (effect === "deny") {
        record("tool.deny", { session: event.sessionID, tool: event.tool, categories })
        throw new Error(
          `${TAG} tool "${event.tool}" is not allowed to receive secret values (${categories.join(", ")}). ` +
            `Do not send secrets to this tool; use a local tool instead or ask the user.`,
        )
      }
      if (effect === "ask") {
        const key = `${event.sessionID}\0${event.tool}`
        if (!approved.has(key)) {
          if (typeof ctx.permission?.assert !== "function") {
            record("tool.deny", { session: event.sessionID, tool: event.tool, categories, reason: "no_permission_api" })
            throw new Error(`${TAG} tool "${event.tool}" needs approval to receive secrets, but permission prompts are unavailable.`)
          }
          try {
            await ctx.permission.assert({
              sessionID: event.sessionID,
              agent: event.agent,
              action: "vibeguard_secret",
              resources: categories.map((c) => `${event.tool}:${c}`),
              source: { type: "tool", messageID: event.messageID, id: event.id },
              metadata: { tool: event.tool, secrets: categories },
            })
          } catch (error) {
            record("tool.ask", { session: event.sessionID, tool: event.tool, categories, approved: false })
            throw error
          }
          approved.add(key)
          record("tool.ask", { session: event.sessionID, tool: event.tool, categories, approved: true })
        }
      }

      event.input = restoreValue(event.input, session)
      log(`execute.before ${event.tool}: restored ${scan.restored} placeholder(s)`)
      record("tool.restore", { session: event.sessionID, tool: event.tool, count: scan.restored, categories })
    })

    // Source tagging: every tool result from a configured source is audited, tagged in its
    // metadata, taints the session and (if restricted) is fingerprinted.
    if (routing.enabled && typeof ctx.tool?.hook === "function") {
      await ctx.tool.hook("execute.after", async (event) => {
        if (event?.status !== "completed") return
        const sources = sourcesForCall(routing, toolNames(event.tool, null, event.input), event.input)
        if (sources.length === 0) return
        const restricted = sources.filter((n) => routing.sources.find((s) => s.name === n)?.allow !== null)
        let fps = 0
        if (restricted.length && routing.fingerprints) {
          const strings = allStrings(event.result)
          for (const src of restricted) for (const s of strings) fps += fingerprints.add(src, s)
          saveFingerprints()
        }
        if (restricted.length) await addTaint(event.sessionID, restricted)
        record("source.access", { session: event.sessionID, tool: event.tool, sources, restricted, fingerprints: fps })
        try {
          const meta = event.result?.metadata && typeof event.result.metadata === "object" ? event.result.metadata : {}
          event.result = { ...event.result, metadata: { ...meta, vibeguard: { sources } } }
        } catch {
          // result shape not taggable
        }
      })
    }

    if (ctx.permission?.hook) {
      await ctx.permission.hook("evaluate", (event) => {
        if (event.action === "vibeguard_secret") {
          // The base policy allows `*`; secret hand-out must always be confirmed.
          if (event.effect === "allow") event.effect = "ask"
          event.message ??= `VibeGuard: allow the tool to receive the real value(s) of ${event.resources.join(", ")}?`
          return
        }
        if (event.effect === "deny") return
        const protect = config.protect ?? {}
        if (event.action === "read" && protect.reads !== false) {
          for (const resource of event.resources) {
            const hit = protectedPaths.matchPath(resource)
            if (!hit) continue
            event.effect = "deny"
            event.message = `VibeGuard: "${resource}" is a registered secret file; reading it into the conversation is blocked.`
            record("protect.read", { session: event.sessionID, path: resource })
            return
          }
        }
        if (event.action === "shell" && protect.shell && protect.shell !== "off") {
          for (const resource of event.resources) {
            const hit = protectedPaths.matchCommand(resource)
            if (!hit) continue
            event.effect = protect.shell === "deny" ? "deny" : "ask"
            event.message = `VibeGuard: this command references the registered secret file "${hit}".`
            record("protect.shell", { session: event.sessionID, effect: event.effect, path: hit })
            return
          }
        }
      })
    }

    // ------------------------------------------------------------- operations
    if (config.command?.enabled !== false && ctx.command?.transform) {
      const handler = createCommandHandler({
        config,
        directory,
        getState: () => state,
        rebuild,
        selfTest,
        audit,
        sessions: () => store.size(),
        routing: {
          info: routing,
          getTaint,
          clearTaint: async (sid) => {
            await clearTaint(sid)
            record("taint.clear", { session: sid })
          },
          lastModel: (sid) => lastModel.get(sid),
          fingerprints: () => fingerprints.size,
        },
      })
      await ctx.command.transform((editor) => {
        editor.add({
          name: handler.name,
          description: "VibeGuard: status, add/remove secrets (clipboard), reload, self-test, audit log",
          execute: async (input) => {
            const sub = String(input?.prompt?.text ?? "").trim().split(/\s+/)[0] || "status"
            let text
            try {
              text = await handler.run(input?.prompt?.text ?? "", { sessionID: input?.sessionID })
            } catch (error) {
              text = `VibeGuard command failed: ${String(error?.message ?? error)}`
            }
            try {
              await ctx.session.synthetic({ sessionID: input.sessionID, text, description: "VibeGuard", resume: false })
              record("command", { session: input.sessionID, sub })
            } catch (error) {
              const message = String(error?.message ?? error)
              record("command.error", { session: input.sessionID, sub, message })
              console.error(`${TAG} could not post command output: ${message}`)
            }
          },
        })
      })
    }

    record("active", {
      directory,
      config: config.loadedFrom,
      selftest: state.selftest?.ok ?? null,
      guard: guardMode,
      restore_response: config.restore?.response !== false,
      endpoints: routing.endpoints.map((e) => `${e.name}${e.trusted ? " (trusted)" : ""}`),
      sources: routing.sources.map((s) => `${s.name}${s.allow ? ` -> ${[...s.allow].join("|")}` : ""}`),
    })
    log(`active: prefix=${config.prefix} guard=${guardMode} restore.response=${config.restore?.response !== false}`)
    return async () => {
      if (fpTimer) clearTimeout(fpTimer)
      await saveFingerprints(true)
      store.clear()
    }
  },
}
