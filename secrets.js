import { readFile } from "node:fs/promises"
import { sanitizeCategory } from "./patterns.js"
import { expandPath, stripBom } from "./util.js"

const PLACEHOLDER_WORDS = new Set([
  "changeme",
  "change-me",
  "change_me",
  "password",
  "secret",
  "example",
  "test",
  "xxx",
  "xxxx",
  "tbd",
  "todo",
  "none",
  "null",
  "undefined",
  "true",
  "false",
  "yes",
  "no",
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "development",
  "production",
  "staging",
  "utf-8",
  "utf8",
])

/** Parse the value part of a dotenv / yaml line: quotes, inline comments, trailing `;`/`,`. */
function parseValue(raw) {
  let v = String(raw ?? "").trim()
  const q = v[0]
  if (q === '"' || q === "'" || q === "`") {
    const end = v.indexOf(q, 1)
    if (end > 0) return v.slice(1, end)
    return v.slice(1)
  }
  const hash = v.search(/\s#/)
  if (hash >= 0) v = v.slice(0, hash)
  return v.replace(/[;,]+$/, "").trim()
}

/**
 * Extract `{ name, value }` pairs from a text file.
 * Handles `KEY=VALUE` (.env, shell `export`), `KEY: VALUE` (yaml), JSON-ish
 * `"key": "value"` lines and bare single-token lines (name = null).
 * @param {string} text
 * @param {{ minLen?: number, bare?: boolean }} [opts]
 */
export function extractNamedSecrets(text, opts) {
  const minLen = Number.isFinite(opts?.minLen) && opts.minLen > 0 ? Math.floor(opts.minLen) : 8
  const allowBare = opts?.bare !== false
  const out = []
  const seen = new Set()
  const push = (name, raw, quotedOk, mode) => {
    const value = quotedOk ? raw : parseValue(raw)
    if (value.length < minLen) return
    if (/[\r\n]/.test(value)) return
    if (!quotedOk && /\s/.test(value) && !opts?.spaces) return
    if (PLACEHOLDER_WORDS.has(value.toLowerCase())) return
    if (seen.has(value)) return
    seen.add(value)
    const entry = { name: name ? sanitizeCategory(name) : null, value }
    if (mode) entry.mode = mode
    out.push(entry)
  }

  for (const rawLine of stripBom(text).split(/\r?\n/)) {
    const line = rawLine.trim()
    if (!line || line.startsWith("#") || line.startsWith("//") || line.startsWith(";")) continue
    // NAME=value, NAME[exact|word|context|off]=value, export NAME=value, NAME: value
    const kv = line.match(/^(?:export\s+)?["']?([A-Za-z_][A-Za-z0-9_.\-]*)["']?(?:\[(exact|word|context|off)\])?\s*(=|:)\s*(.*)$/i)
    if (kv) {
      if (kv[4] === "" || kv[4] === "{" || kv[4] === "[") continue
      push(kv[1], kv[4], false, kv[2]?.toLowerCase())
      continue
    }
    if (line.startsWith("{") || line.startsWith("[") || line.startsWith("}") || line.startsWith("]")) continue
    if (allowBare) push(null, line, false)
  }
  return out
}

/** Back-compat: values only. */
export function extractSecretsFromText(text, opts) {
  return extractNamedSecrets(text, opts).map((x) => x.value)
}

const MAX_FILE_BYTES = 256 * 1024

/**
 * Read protected-file paths and return keyword entries.
 * Missing/unreadable files are reported in `failed`, never thrown. Values are never logged.
 * @param {string[]} files
 * @param {{ minLen?: number, category?: string, maxBytes?: number, base?: string, spaces?: boolean }} opts
 */
export async function loadProtectedKeywords(files, opts) {
  const list = Array.isArray(files) ? files : []
  const fallback = sanitizeCategory(opts?.category ?? "SECRET_FILE")
  const maxBytes = Number.isFinite(opts?.maxBytes) && opts.maxBytes > 0 ? opts.maxBytes : MAX_FILE_BYTES
  const keywords = []
  const failed = []
  const read = []
  const seen = new Set()
  for (const file of list) {
    const path = expandPath(file, opts?.base)
    if (!path) continue
    try {
      const text = await readFile(path, "utf8")
      read.push(path)
      const sliced = text.length > maxBytes ? text.slice(0, maxBytes) : text
      for (const { name, value, mode } of extractNamedSecrets(sliced, opts)) {
        if (seen.has(value)) continue
        seen.add(value)
        keywords.push(mode ? { value, category: name ?? fallback, mode } : { value, category: name ?? fallback })
      }
    } catch (error) {
      failed.push({ file: path, code: error?.code, message: String(error?.message ?? error) })
    }
  }
  return { keywords, failed, read }
}

/**
 * Read deny_paths from a cc-safety-net policy.json file.
 * Returns [] when missing/unparsable (never throws).
 */
export async function readDenyPaths(policyPath) {
  try {
    const json = JSON.parse(stripBom(await readFile(String(policyPath), "utf8")))
    const paths = json?.secret_protection?.deny_paths
    if (!Array.isArray(paths)) return []
    return paths.map((p) => String(p ?? "").trim()).filter(Boolean)
  } catch {
    return []
  }
}
