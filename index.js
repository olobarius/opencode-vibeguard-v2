import { appendFileSync } from "node:fs"
import { randomBytes } from "node:crypto"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { loadConfig } from "./config.js"
import { buildPatternSet } from "./patterns.js"
import { KnownRegistry, PlaceholderSession, createSessionStore, deriveKey } from "./session.js"
import { collectKnownSecrets, fingerprint } from "./known.js"
import { redactText } from "./engine.js"
import { redactValue } from "./deep.js"
import { createRestoreStats, restoreValue, scanPlaceholders } from "./restore.js"
import { buildRawPatterns, guardRawText, guardRequest } from "./guard.js"
import { restoreFrame, restoreResponse } from "./stream.js"
import { ProtectedPaths, compileToolRules, toolEffect } from "./policy.js"
import { expandPath } from "./util.js"

const TAG = "[opencode-vibeguard]"
const REQUEST_KINDS = ["context", "compaction", "generate", "title"]
const TEXT_MEDIA = /^(?:text\/|application\/(?:json|xml|yaml|x-yaml|toml|x-sh|javascript|typescript|x-ndjson))/i

/**
 * Trace for hook wiring diagnostics (`debug: true` or OPENCODE_VIBEGUARD_DEBUG).
 * JSON lines in `<tmpdir>/opencode-vibeguard-trace.log`. Counts only, never values.
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
    `Privacy notice: secrets, passwords and other sensitive values in this conversation are replaced by placeholders ` +
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
    // ephemeral key: placeholders change after a restart
  }
  return key
}

/**
 * VibeGuard for OpenCode V2.
 *
 * Outbound (nothing sensitive reaches the provider):
 * - session hooks context/compaction/generate/title: structural redaction of system, messages, tool calls/results
 * - session hook http.request (+ experimental.ws.send): raw payload safety net for known values and strong rules
 * - session hook prompt (opt-in): redact the user prompt before it is persisted
 *
 * Inbound / local:
 * - session hook http.response (+ experimental.ws.receive): restore placeholders in model text
 * - tool hook execute.before: restore real values for local tools, with a per-tool allow/ask/deny/keep policy
 * - permission hook evaluate: block reading files whose contents are registered secrets
 */
export default {
  id: "opencode-vibeguard",
  async setup(ctx) {
    const directory = ctx.location?.directory ?? process.cwd()
    const config = await loadConfig(directory, ctx.options)
    const debug = Boolean(process.env.OPENCODE_VIBEGUARD_DEBUG) || config.debug
    const trace = createTrace(debug)
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
    const state = { patterns: null, raw: null, watch: [], fp: "", checkedAt: Date.now() }

    async function rebuild(reason) {
      const res = await collectKnownSecrets(config, directory)
      const patterns = buildPatternSet(config.patterns, res.entries)
      known.load(patterns.keywords)
      state.patterns = patterns
      state.raw = buildRawPatterns(patterns, config.guard?.regex ?? "strong")
      state.watch = res.watch
      state.fp = await fingerprint(res.watch)
      const extra = (Array.isArray(config.protect?.paths) ? config.protect.paths : []).map((p) => expandPath(p, directory))
      protectedPaths.set([...res.protectedPaths, ...extra])
      for (const e of patterns.errors) console.error(`${TAG} skipped invalid rule /${e.pattern}/${e.flags}: ${e.message}`)
      for (const f of res.failed) console.error(`${TAG} secret source unreadable: ${f.file}: ${f.message}`)
      log(`${reason}: ${known.size} known value(s) (${JSON.stringify(res.counts)}), ${patterns.regex.length} rule(s), ${protectedPaths.list.length} protected path(s)`)
      trace("load", { reason, counts: res.counts, rules: patterns.regex.length, protected: protectedPaths.list.length })
    }
    await rebuild("setup")

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
      const next = Object.assign(Object.create(Object.getPrototypeOf(media)), media, { source: { ...source, data } })
      part.media = next
    }

    const redactRequest = (event, kind) => {
      const session = getSession(event?.sessionID)
      if (!session) return 0
      session.cleanup()
      const patterns = state.patterns
      const counter = { count: 0 }
      const red = (s) => {
        const r = redactText(s, patterns, session)
        counter.count += r.count
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
      return counter.count
    }

    for (const kind of REQUEST_KINDS) {
      await ctx.session.hook(kind, async (event) => {
        try {
          await fresh()
          const count = redactRequest(event, kind)
          if (count > 0) {
            log(`${kind}: redacted ${count} fragment(s)`)
            trace("request", { kind, count })
          }
        } catch (error) {
          const message = String(error?.message ?? error)
          trace("request.error", { kind, message })
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
        try {
          res = await guardRequest(event.request, state.raw, session, debug ? state.patterns : undefined)
        } catch (error) {
          const message = String(error?.message ?? error)
          trace("http.request.error", { message })
          if (config.fail_closed) throw new Error(`${TAG} payload guard failed, request blocked (fail_closed): ${message}`)
          return
        }
        if (res.count === 0) return
        trace("http.request", { kind: event.kind, count: res.count, mode: guardMode, paths: res.paths })
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
        trace("ws.send", { count: res.count })
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
        trace("prompt", { count: res.count })
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
          trace("http.response.error", { message: String(error?.message ?? error) })
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
        trace("tool.unknown", { tool: event.tool, count: scan.unknown.size })
        throw new Error(
          `${TAG} the input of tool "${event.tool}" contains placeholder(s) that cannot be resolved in this session: ` +
            `${[...scan.unknown].slice(0, 5).join(", ")}. Never invent or modify placeholders; use them exactly as they ` +
            `appeared, or ask the user to provide the value again.`,
        )
      }
      if (scan.restored === 0) return

      const categories = [...scan.categories]
      if (effect === "deny") {
        trace("tool.deny", { tool: event.tool, categories })
        throw new Error(
          `${TAG} tool "${event.tool}" is not allowed to receive secret values (${categories.join(", ")}). ` +
            `Do not send secrets to this tool; use a local tool instead or ask the user.`,
        )
      }
      if (effect === "ask") {
        const key = `${event.sessionID}\0${event.tool}`
        if (!approved.has(key)) {
          if (typeof ctx.permission?.assert !== "function") {
            throw new Error(`${TAG} tool "${event.tool}" needs approval to receive secrets, but permission prompts are unavailable.`)
          }
          await ctx.permission.assert({
            sessionID: event.sessionID,
            agent: event.agent,
            action: "vibeguard_secret",
            resources: categories.map((c) => `${event.tool}:${c}`),
            source: { type: "tool", messageID: event.messageID, id: event.id },
            metadata: { tool: event.tool, secrets: categories },
          })
          approved.add(key)
        }
      }

      event.input = restoreValue(event.input, session)
      log(`execute.before ${event.tool}: restored ${scan.restored} placeholder(s)`)
      trace("tool.restore", { tool: event.tool, count: scan.restored })
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
            trace("protect.read", { action: event.action })
            return
          }
        }
        if (event.action === "shell" && protect.shell && protect.shell !== "off") {
          for (const resource of event.resources) {
            const hit = protectedPaths.matchCommand(resource)
            if (!hit) continue
            event.effect = protect.shell === "deny" ? "deny" : "ask"
            event.message = `VibeGuard: this command references the registered secret file "${hit}".`
            trace("protect.shell", { effect: event.effect })
            return
          }
        }
      })
    }

    log(`active: prefix=${config.prefix} guard=${guardMode} restore.response=${config.restore?.response !== false}`)
    return () => store.clear()
  },
}
