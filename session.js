import { createHmac, randomBytes } from "node:crypto"
import { sanitizeCategory } from "./patterns.js"
import { escapeRegex } from "./util.js"

/**
 * Placeholder grammar: `<prefix><CATEGORY>_<hash12>__` or `..._<hash12>_<n>__`.
 * CATEGORY is `[A-Z0-9]+(_[A-Z0-9]+)*`, so it never contains `__` and adjacent
 * placeholders cannot be merged into one bogus match.
 */
export function getPlaceholderRegex(prefix) {
  return new RegExp(`${escapeRegex(prefix)}[A-Z0-9]+(?:_[A-Z0-9]+)*_[a-f0-9]{12}(?:_\\d+)?__`, "g")
}

export function placeholderCategory(placeholder, prefix) {
  const body = placeholder.slice(prefix.length).replace(/__$/, "").replace(/_\d+$/, "")
  return body.replace(/_[a-f0-9]{12}$/, "")
}

function hash12(key, data) {
  return createHmac("sha256", key).update(data).digest("hex").slice(0, 12)
}

export function deriveKey(master, label) {
  return createHmac("sha256", master).update(String(label)).digest()
}

/**
 * Registry of known secrets (secrets files, env, config keywords, ...).
 * Placeholders are derived from a persistent master key, so they are stable
 * across sessions and restarts and can always be restored.
 */
export class KnownRegistry {
  constructor({ prefix, key }) {
    this.prefix = prefix
    this.key = key ?? randomBytes(32)
    this.byValue = new Map()
    this.byPlaceholder = new Map()
  }

  /** @param {Array<{value:string, category:string}>} entries */
  load(entries) {
    this.byValue = new Map()
    this.byPlaceholder = new Map()
    for (const e of entries) {
      if (!e?.value || this.byValue.has(e.value)) continue
      const cat = sanitizeCategory(e.category)
      const base = `${this.prefix}${cat}_${hash12(this.key, `known\0${cat}\0${e.value}`)}`
      let ph = `${base}__`
      for (let i = 2; this.byPlaceholder.has(ph); i++) ph = `${base}_${i}__`
      this.byValue.set(e.value, ph)
      this.byPlaceholder.set(ph, e.value)
    }
  }

  placeholderFor(value) {
    return this.byValue.get(value)
  }

  lookup(placeholder) {
    return this.byPlaceholder.get(placeholder)
  }

  get size() {
    return this.byValue.size
  }
}

const CACHE_MIN_CHARS = 64
const CACHE_MAX_CHARS = 8_000_000

/**
 * Per-session mapping for pattern-detected values.
 * - Deterministic per session (HMAC with a session key derived from the master key),
 *   so re-redacting history after a restart yields the same placeholders.
 * - Sliding TTL + LRU: every use refreshes an entry, so active mappings never expire mid-task.
 */
export class PlaceholderSession {
  /**
   * @param {{ prefix: string, ttlMs?: number, maxMappings?: number, secret?: Uint8Array, key?: Uint8Array, known?: KnownRegistry }} options
   */
  constructor(options) {
    this.prefix = String(options?.prefix ?? "__VG_")
    this.ttlMs = Number.isFinite(options?.ttlMs) ? Number(options.ttlMs) : 24 * 3_600_000
    this.maxMappings = Number.isFinite(options?.maxMappings) ? Number(options.maxMappings) : 100000
    this.key = options?.key ?? options?.secret ?? randomBytes(32)
    this.known = options?.known ?? null
    this.placeholderRe = getPlaceholderRegex(this.prefix)
    /** @type {Map<string, {original: string, at: number}>} insertion order == last use */
    this.forward = new Map()
    /** @type {Map<string, string>} */
    this.reverse = new Map()
    this.cache = new Map()
    this.cachePatterns = null
    this.cacheChars = 0
  }

  #touch(placeholder, entry, now = Date.now()) {
    entry.at = now
    this.forward.delete(placeholder)
    this.forward.set(placeholder, entry)
  }

  cleanup(now = Date.now()) {
    if (!(this.ttlMs > 0)) return
    for (const [placeholder, entry] of this.forward) {
      if (now - entry.at <= this.ttlMs) break
      this.forward.delete(placeholder)
      this.reverse.delete(entry.original)
    }
  }

  lookup(placeholder) {
    const known = this.known?.lookup(placeholder)
    if (known !== undefined) return known
    const entry = this.forward.get(placeholder)
    if (!entry) return undefined
    this.#touch(placeholder, entry)
    return entry.original
  }

  knownPlaceholder(value) {
    return this.known?.placeholderFor(value)
  }

  generatePlaceholder(original, category) {
    return `${this.prefix}${sanitizeCategory(category)}_${hash12(this.key, String(original))}__`
  }

  getOrCreatePlaceholder(original, category) {
    const known = this.known?.placeholderFor(original)
    if (known) return known

    const existing = this.reverse.get(original)
    if (existing) {
      const entry = this.forward.get(existing)
      if (entry) this.#touch(existing, entry)
      return existing
    }

    const now = Date.now()
    this.cleanup(now)
    while (this.maxMappings > 0 && this.forward.size >= this.maxMappings) {
      const oldest = this.forward.keys().next().value
      const entry = this.forward.get(oldest)
      this.forward.delete(oldest)
      if (entry) this.reverse.delete(entry.original)
    }

    const base = this.generatePlaceholder(original, category)
    let candidate = base
    for (let i = 2; ; i++) {
      const prev = this.forward.get(candidate)
      if (!prev || prev.original === original) break
      candidate = `${base.slice(0, -2)}_${i}__`
    }
    this.forward.set(candidate, { original, at: now })
    this.reverse.set(original, candidate)
    return candidate
  }

  /** Memoized redaction results: history is re-sent on every turn. */
  cacheGet(text, patterns) {
    if (text.length < CACHE_MIN_CHARS) return undefined
    if (this.cachePatterns !== patterns) return undefined
    const hit = this.cache.get(text)
    if (!hit) return undefined
    if (hit.count > 0) {
      this.placeholderRe.lastIndex = 0
      for (const m of hit.text.matchAll(this.placeholderRe)) {
        if (this.lookup(m[0]) === undefined) return undefined
      }
    }
    return hit
  }

  cacheSet(text, patterns, out, count) {
    if (text.length < CACHE_MIN_CHARS) return
    if (this.cachePatterns !== patterns) {
      this.cache.clear()
      this.cacheChars = 0
      this.cachePatterns = patterns
    }
    const size = text.length + (out === text ? 0 : out.length)
    if (size > CACHE_MAX_CHARS / 4) return
    while (this.cacheChars + size > CACHE_MAX_CHARS && this.cache.size > 0) {
      const [k, v] = this.cache.entries().next().value
      this.cache.delete(k)
      this.cacheChars -= k.length + (v.text === k ? 0 : v.text.length)
    }
    this.cache.set(text, { text: out, count })
    this.cacheChars += size
  }

  get size() {
    return this.forward.size
  }
}

/** Bounded per-session store with LRU eviction. */
export function createSessionStore(options, create) {
  const maxSessions = Number.isFinite(options?.maxSessions) && options.maxSessions > 0 ? Math.floor(options.maxSessions) : 100
  const sessions = new Map()
  return {
    get(key) {
      const id = String(key ?? "")
      if (!id) return null
      const existing = sessions.get(id)
      if (existing) {
        sessions.delete(id)
        sessions.set(id, existing)
        return existing
      }
      const created = create(id)
      sessions.set(id, created)
      while (sessions.size > maxSessions) sessions.delete(sessions.keys().next().value)
      return created
    },
    size() {
      return sessions.size
    },
    clear() {
      sessions.clear()
    },
  }
}
