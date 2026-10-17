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
    if (guardMode !== "off" && guardMode !== false) {
      await ctx.session.hook("http.request", async (event) => {
        const session = getSession(event?.sessionID)
        if (!session || !event.request) return
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
        if (res.count === 0) return
        record("guard", { session: event.sessionID, kind: event.kind, count: res.count, mode: guardMode, paths: res.paths })
        if (guardMode === "block") {
          throw new Error(`${TAG} blocked ${event.kind} request: ${res.count} secret fragment(s) found in the raw payload`)
        }
        log(`http.request (${event.kind}): safety net replaced ${res.count} fragment(s)`)
        event.request = res.request
      })
    }

    if (config.guard?.websocket !== false) {
      await ctx.session.hook("experimental.ws.send", (event) => {
        const session = getSession(event?.sessionID)
        if (!session || typeof event.frame !== "string") return
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
      })
      await ctx.command.transform((editor) => {
        editor.add({
          name: handler.name,
          description: "VibeGuard: status, add/remove secrets (clipboard), reload, self-test, audit log",
          execute: async (input) => {
            const sub = String(input?.prompt?.text ?? "").trim().split(/\s+/)[0] || "status"
            let text
            try {
              text = await handler.run(input?.prompt?.text ?? "")
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
    })
    log(`active: prefix=${config.prefix} guard=${guardMode} restore.response=${config.restore?.response !== false}`)
    return () => store.clear()
  },
}
