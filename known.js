import { execFile } from "node:child_process"
import { readFile, stat } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { sanitizeCategory } from "./patterns.js"
import { loadProtectedKeywords, readDenyPaths } from "./secrets.js"
import { expandPath, globToRegex, isPlainObject, stripBom } from "./util.js"

const SENSITIVE_ENV =
  /(?:^|_)(?:PASSWORD|PASSWD|PASSPHRASE|PWD|PASS|SECRET|SECRETS|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CLIENT_?SECRET|CREDENTIALS?|AUTH|AUTH_?TOKEN|SESSION_?KEY|SIGNING_?KEY|ENCRYPTION_?KEY|MASTER_?KEY|CONNECTION_?STRING|CONN_?STR|DSN|DATABASE_URL|WEBHOOK(?:_URL)?)(?:$|_)/i
const IGNORE_ENV = /^(?:PWD|OLDPWD|SSH_AUTH_SOCK|GIT_ASKPASS|SSH_ASKPASS|SUDO_ASKPASS|.*_(?:PATH|DIR|HOME|FILE|SOCK|URL_BASE))$/i
const BORING_VALUE = /^(?:true|false|yes|no|on|off|null|none|0|1|localhost|development|production|staging|test)$/i

export function defaultDataDir() {
  const xdg = process.env.XDG_DATA_HOME
  return xdg ? path.join(xdg, "opencode") : path.join(os.homedir(), ".local", "share", "opencode")
}

function looksLikePath(v) {
  return /^(?:[A-Za-z]:[\\/]|\/|~[\\/]|\.{1,2}[\\/])/.test(v) && !/[@:].*@/.test(v)
}

/** Scan process.env for values of sensitive-looking variables. */
export function envSecrets(option, env = process.env) {
  if (option === false) return []
  const include = Array.isArray(option?.include) ? option.include.map(globToRegex) : []
  const exclude = Array.isArray(option?.exclude) ? option.exclude.map(globToRegex) : []
  const minLen = Number.isFinite(option?.min_len) ? option.min_len : 8
  const out = []
  for (const [name, value] of Object.entries(env)) {
    if (typeof value !== "string") continue
    if (exclude.some((re) => re.test(name))) continue
    const forced = include.some((re) => re.test(name))
    if (!forced && (!SENSITIVE_ENV.test(name) || IGNORE_ENV.test(name))) continue
    const v = value.trim()
    if (v.length < minLen || BORING_VALUE.test(v)) continue
    if (!forced && (looksLikePath(v) || /^\d+$/.test(v))) continue
    out.push({ value: v, category: `ENV_${sanitizeCategory(name)}` })
  }
  return out
}

/** Credentials stored by OpenCode itself (provider API keys / OAuth tokens). */
export async function opencodeAuthSecrets(files) {
  const out = []
  const read = []
  for (const file of files) {
    let json
    try {
      json = JSON.parse(stripBom(await readFile(file, "utf8")))
      read.push(file)
    } catch {
      continue
    }
    const walk = (node, provider, depth) => {
      if (!node || typeof node !== "object" || depth > 6) return
      for (const [k, v] of Object.entries(node)) {
        if (typeof v === "string") {
          if (v.length >= 16 && /key|token|access|refresh|secret|password|credential/i.test(k)) {
            out.push({ value: v, category: `OPENCODE_AUTH_${sanitizeCategory(provider || k)}` })
          }
        } else walk(v, provider || k, depth + 1)
      }
    }
    walk(json, "", 0)
  }
  return { entries: out, read }
}

function runCommand(spec) {
  return new Promise((resolve) => {
    const cmd = Array.isArray(spec.command) ? spec.command : null
    const opts = { timeout: Number.isFinite(spec.timeout) ? spec.timeout : 10_000, windowsHide: true, maxBuffer: 1024 * 1024 }
    const done = (error, stdout) => resolve(error ? { error: String(error?.message ?? error) } : { stdout: String(stdout ?? "") })
    if (cmd && cmd.length > 0) execFile(String(cmd[0]), cmd.slice(1).map(String), opts, done)
    else if (typeof spec.command === "string") execFile(spec.command, { ...opts, shell: true }, done)
    else resolve({ error: "missing command" })
  })
}

/** Secrets from password managers: `{ name, command: ["pass","show","x"], all_lines? }`. */
export async function commandSecrets(specs) {
  const out = []
  const failed = []
  for (const spec of Array.isArray(specs) ? specs : []) {
    if (!isPlainObject(spec)) continue
    const name = sanitizeCategory(spec.name ?? "COMMAND_SECRET")
    const res = await runCommand(spec)
    if (res.error) {
      failed.push({ file: `command:${name}`, message: res.error })
      continue
    }
    const lines = res.stdout.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)
    for (const value of spec.all_lines ? lines : lines.slice(0, 1)) {
      if (value.length >= 4) out.push({ value, category: name })
    }
  }
  return { entries: out, failed }
}

/**
 * Encoded forms of a secret that commonly show up in tool output:
 * URL-encoding, standalone base64/base64url and the three alignment-independent
 * base64 "cores" (so a secret embedded in a larger base64 blob is still caught,
 * e.g. `kubectl get secret -o yaml` or Basic auth headers).
 */
export function secretVariants(value) {
  const out = new Map()
  if (value.length < 8) return out
  const url = encodeURIComponent(value)
  if (url !== value) out.set(url, "URL")
  const buf = Buffer.from(value, "utf8")
  const add = (s) => {
    if (s.length < 12 || s === value) return
    out.set(s, "B64")
    const urlsafe = s.replace(/\+/g, "-").replace(/\//g, "_")
    if (urlsafe !== s) out.set(urlsafe, "B64")
  }
  add(buf.toString("base64"))
  add(buf.toString("base64").replace(/=+$/, ""))
  for (const pad of [0, 1, 2]) {
    const enc = Buffer.concat([Buffer.alloc(pad), buf]).toString("base64")
    const start = pad === 0 ? 0 : 4
    const end = (pad + buf.length) % 3 === 0 ? enc.length : enc.length - 4
    add(enc.slice(start, end))
  }
  return out
}

/**
 * Resolve every known-secret source into keyword entries.
 * Order defines naming precedence when the same value appears in several sources.
 * @returns {Promise<{ entries: Array<{value:string,category:string}>, watch: string[], failed: Array<{file:string,message:string}>, protectedPaths: string[], counts: Record<string, number> }>}
 */
export async function collectKnownSecrets(config, directory) {
  const secrets = config.secrets ?? {}
  const patterns = config.patterns ?? {}
  const watch = []
  const failed = []
  const protectedPaths = []
  const counts = {}
  const all = []
  const push = (source, list) => {
    counts[source] = (counts[source] ?? 0) + list.length
    all.push(...list)
  }

  // 1. Dedicated secrets lists (named, explicit). Bare lines are passwords/terms.
  const secretFiles = (Array.isArray(secrets.files) ? secrets.files : []).map((f) => expandPath(f, directory)).filter(Boolean)
  watch.push(...secretFiles)
  protectedPaths.push(...secretFiles)
  const listed = await loadProtectedKeywords(secretFiles, {
    minLen: Number.isFinite(secrets.min_len) ? secrets.min_len : 4,
    category: "SECRET",
    spaces: true,
  })
  push("secrets_files", listed.keywords)
  failed.push(...listed.failed.filter((f) => f.code !== "ENOENT"))

  // 2. Protected files + cc-safety-net deny list (contents become keywords).
  const extra = (Array.isArray(patterns.protected_files) ? patterns.protected_files : []).map((f) => expandPath(f, directory))
  if (patterns.import_deny_paths) {
    const policy = expandPath(patterns.deny_policy || "~/.cc-safety-net/policy.json", directory)
    watch.push(policy)
    extra.push(...(await readDenyPaths(policy)).map((p) => expandPath(p, directory)))
  }
  watch.push(...extra)
  protectedPaths.push(...extra)
  const files = await loadProtectedKeywords(extra, { minLen: patterns.min_secret_len ?? 8, category: "SECRET_FILE" })
  push("protected_files", files.keywords)
  failed.push(...files.failed.filter((f) => f.code !== "EISDIR"))

  // 3. Environment of the OpenCode server process.
  if (secrets.env !== false) push("env", envSecrets(secrets.env === true ? {} : secrets.env))

  // 4. OpenCode's own credential stores.
  if (secrets.opencode_auth !== false) {
    const dataDir = defaultDataDir()
    const authFiles = [path.join(dataDir, "auth.json"), path.join(dataDir, "mcp-auth.json")]
    watch.push(...authFiles)
    protectedPaths.push(...authFiles, path.join(dataDir, "opencode.db"))
    push("opencode_auth", (await opencodeAuthSecrets(authFiles)).entries)
  }

  // 5. Password manager commands (run once per load).
  if (Array.isArray(secrets.commands) && secrets.commands.length > 0) {
    const res = await commandSecrets(secrets.commands)
    push("commands", res.entries)
    failed.push(...res.failed)
  }

  const exclude = new Set((Array.isArray(patterns.exclude) ? patterns.exclude : []).map(String))
  const seen = new Set()
  const entries = []
  for (const e of all) {
    if (!e?.value || seen.has(e.value) || exclude.has(e.value)) continue
    seen.add(e.value)
    entries.push({ value: e.value, category: sanitizeCategory(e.category) })
  }
  if (secrets.variants !== false) {
    for (const e of [...entries]) {
      for (const [variant, suffix] of secretVariants(e.value)) {
        if (seen.has(variant)) continue
        seen.add(variant)
        entries.push({ value: variant, category: `${e.category}_${suffix}` })
      }
    }
  }
  counts.total = entries.length
  return { entries, watch: [...new Set(watch)], failed, protectedPaths: [...new Set(protectedPaths)], counts }
}

/** Cheap change detection for hot reload. */
export async function fingerprint(files) {
  const parts = await Promise.all(
    files.map(async (f) => {
      try {
        const s = await stat(f)
        return `${f}:${s.mtimeMs}:${s.size}`
      } catch {
        return `${f}:-`
      }
    }),
  )
  return parts.join("|")
}
