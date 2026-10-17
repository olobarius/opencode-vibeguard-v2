import { createHmac } from "node:crypto"
import { expandPath, globToRegex, isPlainObject, normalizePath } from "./util.js"

/**
 * Data-source tagging and endpoint routing.
 *
 * endpoints: named model endpoints (provider/model globs, optional base URL globs
 *            verified on the wire, `trusted` = no redaction at all).
 * sources:   named data sources (tool name globs, path globs, URL globs). A source
 *            with `allow` may only be processed by the listed endpoints.
 *
 * Enforcement (see index.js): preflight in execute.before, session taint after a
 * restricted tool ran, content fingerprints of restricted tool results checked in
 * every outgoing request, plus a final check in http.request.
 */

const list = (v) => (Array.isArray(v) ? v : v === undefined || v === null || v === "" ? [] : [v]).map(String)

const PATH_KEYS = /^(?:path|paths|filepath|file_path|filename|file|files|directory|dir|cwd|workdir|target|source|src|dest|destination|root|folder)$/i
const URL_KEYS = /^(?:url|uri|href|link|endpoint)$/i
const TEXT_KEYS = /^(?:command|cmd|script|code|query|args?|arguments|expression)$/i

function compilePathGlob(glob, directory) {
  const abs = normalizePath(expandPath(glob, directory))
  const star = abs.indexOf("*")
  const prefix = (star >= 0 ? abs.slice(0, star) : abs).replace(/\/+$/, "")
  return { re: globToRegex(abs), prefix: prefix.length >= 4 ? prefix : null, exact: star < 0 ? abs : null }
}

export function compileRouting(config, directory) {
  const endpoints = []
  for (const [name, e] of Object.entries(isPlainObject(config.endpoints) ? config.endpoints : {})) {
    if (!isPlainObject(e)) continue
    endpoints.push({
      name,
      providers: list(e.providers).map(globToRegex),
      models: list(e.models).map(globToRegex),
      baseUrls: list(e.base_urls).map(globToRegex),
      hasBaseUrls: list(e.base_urls).length > 0,
      trusted: e.trusted === true,
      description: typeof e.description === "string" ? e.description : "",
    })
  }
  const sources = []
  for (const [name, s] of Object.entries(isPlainObject(config.sources) ? config.sources : {})) {
    if (!isPlainObject(s)) continue
    sources.push({
      name,
      tools: list(s.tools).map(globToRegex),
      paths: list(s.paths).map((p) => compilePathGlob(p, directory)),
      urls: list(s.urls).map(globToRegex),
      allow: s.allow === undefined ? null : new Set(list(s.allow)),
      description: typeof s.description === "string" ? s.description : "",
    })
  }
  const routing = isPlainObject(config.routing) ? config.routing : {}
  return {
    directory,
    endpoints,
    sources,
    restricted: sources.filter((s) => s.allow !== null),
    onViolation: routing.on_violation === "withhold" ? "withhold" : "block",
    preflight: routing.preflight !== false,
    fingerprints: routing.fingerprints !== false,
    enabled: sources.length > 0,
  }
}

/** Endpoint for a model ref, or null (= unknown / cloud). */
export function endpointFor(routing, model) {
  if (!model) return null
  const provider = String(model.providerID ?? "")
  const id = String(model.id ?? "")
  for (const e of routing.endpoints) {
    if (e.providers.length && !e.providers.some((re) => re.test(provider))) continue
    if (!e.providers.length && !e.models.length) continue
    if (e.models.length && !e.models.some((re) => re.test(id))) continue
    return e
  }
  return null
}

export function urlVerified(endpoint, url) {
  if (!endpoint) return false
  if (!endpoint.hasBaseUrls) return true
  return endpoint.baseUrls.some((re) => re.test(String(url ?? "")))
}

export function sourceAllowed(source, endpoint) {
  if (!source || source.allow === null) return true
  if (source.allow.has("*")) return true
  return Boolean(endpoint) && source.allow.has(endpoint.name)
}

/** Restricted sources this endpoint may not see. */
export function deniedSources(routing, endpoint) {
  return routing.restricted.filter((s) => !sourceAllowed(s, endpoint))
}

/** `tools.exchange.get_message(...)` / `tools["excel-mcp"].file(...)` in Code Mode scripts. */
export function codeToolRefs(code) {
  const out = []
  const re = /tools(?:\.([A-Za-z_$][\w$]*)|\[\s*["']([^"']+)["']\s*\])(?:\.([A-Za-z_$][\w$]*)|\[\s*["']([^"']+)["']\s*\])?/g
  for (const m of String(code ?? "").matchAll(re)) {
    const ns = m[1] ?? m[2]
    const tool = m[3] ?? m[4]
    if (!ns) continue
    out.push(ns)
    if (tool) out.push(`${ns}_${tool}`, `${ns}.${tool}`)
  }
  return out
}

/** Candidate tool ids for a tool-call part or hook event. */
export function toolNames(name, namespace, input) {
  const out = new Set()
  if (name) out.add(String(name))
  if (namespace && name) {
    out.add(`${namespace}_${name}`)
    out.add(`${namespace}.${name}`)
  }
  if (input && typeof input === "object") {
    for (const key of ["code", "script"]) if (typeof input[key] === "string") codeToolRefs(input[key]).forEach((n) => out.add(n))
  }
  return [...out]
}

function collectInputs(input, directory) {
  const paths = []
  const urls = []
  const texts = []
  const walk = (node, key, depth) => {
    if (depth > 5 || node === null || node === undefined) return
    if (typeof node === "string") {
      if (key && PATH_KEYS.test(key)) paths.push(node)
      else if (key && URL_KEYS.test(key)) urls.push(node)
      else if (key && TEXT_KEYS.test(key)) texts.push(node)
      else if (/^(?:[A-Za-z]:[\\/]|\/|~[\\/])/.test(node)) paths.push(node)
      else if (/^https?:\/\//i.test(node)) urls.push(node)
      return
    }
    if (Array.isArray(node)) node.forEach((v) => walk(v, key, depth + 1))
    else if (typeof node === "object") for (const [k, v] of Object.entries(node)) walk(v, k, depth + 1)
  }
  walk(typeof input === "string" ? { command: input } : input, "", 0)
  for (const t of texts) for (const m of t.matchAll(/https?:\/\/[^\s"'<>]+/gi)) urls.push(m[0])
  return {
    paths: paths.map((p) => normalizePath(expandPath(p, directory))),
    urls,
    texts: texts.map((t) => normalizePath(t.replace(/\\\\/g, "\\"))),
  }
}

/**
 * Which sources does a tool call touch?
 * @returns {string[]} source names
 */
export function sourcesForCall(routing, names, input) {
  if (!routing.enabled) return []
  const { paths, urls, texts } = collectInputs(input, routing.directory)
  const hits = []
  for (const s of routing.sources) {
    const byTool = s.tools.length > 0 && names.some((n) => s.tools.some((re) => re.test(n)))
    const byPath =
      s.paths.length > 0 &&
      (paths.some((p) => s.paths.some((g) => g.re.test(p) || (g.prefix && (p === g.prefix || p.startsWith(`${g.prefix}/`))) || g.exact === p)) ||
        texts.some((t) => s.paths.some((g) => g.prefix && t.includes(g.prefix))))
    const byUrl = s.urls.length > 0 && urls.some((u) => s.urls.some((re) => re.test(u)))
    if (byTool || byPath || byUrl) hits.push(s.name)
  }
  return hits
}

// ---------------------------------------------------------------------------
// Content fingerprints of restricted data
// ---------------------------------------------------------------------------

const WINDOW = 8

/** Lines / JSON fields of at least 24 characters, whitespace-normalized. */
export function segments(text) {
  const out = []
  for (const raw of String(text ?? "").split(/\r?\n|\\n|\t|","/)) {
    const s = raw.replace(/\s+/g, " ").trim()
    if (s.length >= 24) out.push(s.length > 4000 ? s.slice(0, 4000) : s)
  }
  return out
}

/**
 * HMAC fingerprints of restricted tool results, so copies of that content are
 * recognized later: in subagent prompts, files written and read back, other sessions.
 * Paraphrases are not recognized.
 */
export class FingerprintRegistry {
  constructor(key, max = 200_000) {
    this.key = key
    this.max = max
    this.map = new Map()
    this.version = 0
    this.cache = new Map()
    this.dirty = false
  }

  hash(seg) {
    return createHmac("sha256", this.key).update(seg.toLowerCase()).digest("base64url").slice(0, 16)
  }

  /**
   * Word windows (8 words) so a copy is found regardless of what surrounds it.
   * Registration steps by 4 words; checking tests every offset, so any copied
   * run of >= 11 words hits at least one registered window.
   */
  windows(seg, step) {
    const words = seg.toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(Boolean)
    if (words.length < WINDOW) return seg.length >= 24 ? [`s:${words.join(" ")}`] : []
    const out = []
    for (let i = 0; i + WINDOW <= words.length; i += step) out.push(words.slice(i, i + WINDOW).join(" "))
    if (step > 1 && (words.length - WINDOW) % step) out.push(words.slice(-WINDOW).join(" "))
    return out
  }

  add(source, text) {
    let added = 0
    let n = 0
    for (const seg of segments(text)) {
      for (const w of this.windows(seg, 4)) {
        if (++n > 20_000) break
        const h = this.hash(w)
        if (this.map.get(h) === source) continue
        this.map.delete(h)
        this.map.set(h, source)
        added++
      }
    }
    while (this.map.size > this.max) this.map.delete(this.map.keys().next().value)
    if (added) {
      this.version++
      this.cache.clear()
      this.dirty = true
    }
    return added
  }

  /** @returns {Map<string, number>} source -> score (a segment counts 1, a long one 2) */
  check(text) {
    if (this.map.size === 0 || typeof text !== "string" || text.length < 24) return new Map()
    const cached = this.cache.get(text)
    if (cached) return cached
    const out = new Map()
    const seen = new Set()
    for (const seg of segments(text)) {
      for (const w of this.windows(seg, 1)) {
        const h = this.hash(w)
        if (seen.has(h)) continue
        seen.add(h)
        const src = this.map.get(h)
        if (src) out.set(src, (out.get(src) ?? 0) + (w.startsWith("s:") && w.length >= 60 ? 2 : 1))
      }
    }
    if (text.length < 200_000) {
      if (this.cache.size > 5000) this.cache.clear()
      this.cache.set(text, out)
    }
    return out
  }

  get size() {
    return this.map.size
  }

  toJSON() {
    return [...this.map.entries()]
  }

  load(entries) {
    if (!Array.isArray(entries)) return
    for (const e of entries) if (Array.isArray(e) && typeof e[0] === "string" && typeof e[1] === "string") this.map.set(e[0], e[1])
    this.version++
  }
}

/** Every string in a value (tool results, inputs). */
export function allStrings(value, out = [], depth = 0) {
  if (depth > 20 || value === null || value === undefined) return out
  if (typeof value === "string") out.push(value)
  else if (Array.isArray(value)) value.forEach((v) => allStrings(v, out, depth + 1))
  else if (typeof value === "object") Object.values(value).forEach((v) => allStrings(v, out, depth + 1))
  return out
}
