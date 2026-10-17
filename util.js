import os from "node:os"
import path from "node:path"

export function escapeRegex(input) {
  return String(input).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}

export function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false
  const proto = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

/** Expand `~`, `$HOME`, `%USERPROFILE%` and `${VAR}` in a path; resolve relative to `base`. */
export function expandPath(input, base) {
  let p = String(input ?? "").trim()
  if (!p) return ""
  const home = os.homedir()
  if (p === "~" || p.startsWith("~/") || p.startsWith("~\\")) p = home + p.slice(1)
  p = p.replace(/^\$HOME(?=$|[\\/])/, home)
  p = p.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|%([A-Za-z_][A-Za-z0-9_]*)%/g, (m, a, b) => process.env[a ?? b] ?? m)
  return base ? path.resolve(base, p) : path.resolve(p)
}

/** Normalize a path for comparisons: forward slashes, no trailing slash, lowercase on Windows. */
export function normalizePath(input) {
  let p = String(input ?? "").replace(/\\/g, "/")
  if (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1)
  return process.platform === "win32" ? p.toLowerCase() : p
}

/** Whole-value wildcard (`*`, `?`) to RegExp, case-insensitive. */
export function globToRegex(glob) {
  const body = String(glob)
    .split("")
    .map((c) => (c === "*" ? ".*" : c === "?" ? "." : escapeRegex(c)))
    .join("")
  return new RegExp(`^${body}$`, "i")
}

export function stripBom(text) {
  const s = String(text ?? "")
  return s.charCodeAt(0) === 0xfeff ? s.slice(1) : s
}

/** Strip `//` and `/* *\/` comments plus trailing commas from JSONC. */
export function stripJsonc(text) {
  const s = stripBom(text)
  let out = ""
  let inString = false
  for (let i = 0; i < s.length; i++) {
    const c = s[i]
    if (inString) {
      out += c
      if (c === "\\") {
        out += s[++i] ?? ""
      } else if (c === '"') {
        inString = false
      }
      continue
    }
    if (c === '"') {
      inString = true
      out += c
      continue
    }
    if (c === "/" && s[i + 1] === "/") {
      while (i < s.length && s[i] !== "\n") i++
      out += "\n"
      continue
    }
    if (c === "/" && s[i + 1] === "*") {
      i += 2
      while (i < s.length && !(s[i] === "*" && s[i + 1] === "/")) i++
      i++
      continue
    }
    out += c
  }
  return out.replace(/,(\s*[}\]])/g, "$1")
}

/**
 * Copy-on-write deep map over every string leaf (object values, array items,
 * Map values, Set items). Returns the original reference when nothing changed,
 * so callers can cheaply detect "no-op" and never mutate shared state.
 */
export function mapStrings(value, fn, seen = new WeakMap()) {
  if (typeof value === "string") return fn(value)
  if (!value || typeof value !== "object") return value
  if (seen.has(value)) return seen.get(value)
  seen.set(value, value)

  if (Array.isArray(value)) {
    let out = value
    for (let i = 0; i < value.length; i++) {
      const v = value[i]
      const nv = mapStrings(v, fn, seen)
      if (nv === v) continue
      if (out === value) out = value.slice()
      out[i] = nv
    }
    seen.set(value, out)
    return out
  }

  if (value instanceof Map) {
    let changed = false
    const entries = []
    for (const [k, v] of value) {
      const nv = mapStrings(v, fn, seen)
      if (nv !== v) changed = true
      entries.push([k, nv])
    }
    const out = changed ? new Map(entries) : value
    seen.set(value, out)
    return out
  }

  if (value instanceof Set) {
    let changed = false
    const items = []
    for (const v of value) {
      const nv = mapStrings(v, fn, seen)
      if (nv !== v) changed = true
      items.push(nv)
    }
    const out = changed ? new Set(items) : value
    seen.set(value, out)
    return out
  }

  if (!isPlainObject(value)) return value

  let out = value
  for (const key of Object.keys(value)) {
    const v = value[key]
    const nv = mapStrings(v, fn, seen)
    if (nv === v) continue
    if (out === value) out = { ...value }
    out[key] = nv
  }
  seen.set(value, out)
  return out
}

export function parseDurationMs(input, fallback) {
  if (Number.isFinite(input) && input >= 0) return Number(input)
  const m = String(input ?? "").trim().match(/^(\d+(?:\.\d+)?)(ms|s|m|h|d)$/)
  if (!m) return fallback
  const n = Number(m[1])
  const unit = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2]]
  return n * unit
}
