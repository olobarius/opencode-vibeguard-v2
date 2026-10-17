import { execFile } from "node:child_process"
import { sanitizeCategory } from "./patterns.js"
import { extractNamedSecrets } from "./secrets.js"
import { listCredentials } from "./wincred.js"

/**
 * Bitwarden / Vaultwarden via the official `bw` CLI (Vaultwarden is
 * API-compatible: `bw config server https://vault.example`).
 *
 * The unlocked session key comes from the Windows Credential Manager
 * (written by `scripts/bw-unlock.mjs`) or an env var. It is passed only to
 * the `bw` child process via BW_SESSION, never via the command line and never
 * into OpenCode's own environment (the agent's shell would inherit it).
 */
export const DEFAULT_SESSION_TARGET = "vibeguard-bw-session"

export function runBw(cli, args, env, timeout = 30_000) {
  const [cmd, ...pre] = Array.isArray(cli) && cli.length ? cli.map(String) : [String(cli || "bw")]
  args = [...pre, ...args]
  const opts = { env, timeout, windowsHide: true, maxBuffer: 64 * 1024 * 1024 }
  return new Promise((resolve) => {
    const done = (error, stdout, stderr) =>
      resolve(error ? { error: String(stderr || error.message).trim().split("\n")[0], code: error.code } : { stdout: String(stdout ?? "") })
    execFile(cmd, args, opts, (error, stdout, stderr) => {
      // npm installs `bw.cmd`, which execFile cannot start without a shell on Windows.
      if (error?.code === "ENOENT" && process.platform === "win32" && !/\.(?:cmd|exe)$/i.test(cmd)) {
        execFile(`${cmd}.cmd`, args, { ...opts, shell: true }, done)
        return
      }
      done(error, stdout, stderr)
    })
  })
}

async function sessionKey(cfg) {
  if (cfg.session_env) {
    const v = process.env[cfg.session_env]
    if (v) return { session: v }
  }
  const target = cfg.session_wincred ?? DEFAULT_SESSION_TARGET
  if (process.platform === "win32" && target) {
    const res = await listCredentials([target])
    const hit = res.items.find((c) => c.target.toLowerCase() === String(target).toLowerCase())
    if (hit?.secret) return { session: hit.secret }
    if (res.error) return { error: res.error }
  }
  return { error: "vault locked or no session (run: node scripts/bw-unlock.mjs, then /vibeguard reload)" }
}

function parseJson(text) {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

const list = (v) => (Array.isArray(v) ? v : v ? [v] : []).map(String)

/**
 * Turn `bw list items` output into keyword entries. Defaults: passwords,
 * hidden custom fields, TOTP seeds and card number/code. Usernames, text
 * fields and notes only when enabled (they are often harmless or very common).
 */
export function extractBitwardenItems(items, cfg = {}) {
  const out = []
  const push = (value, category) => {
    const v = String(value ?? "").trim()
    if (v.length >= 4 && !/[\r\n]/.test(v)) out.push({ value: v, category: sanitizeCategory(category), source: "bitwarden" })
  }
  for (const item of Array.isArray(items) ? items : []) {
    if (!item || item.deletedDate) continue
    const name = sanitizeCategory(item.name || "BITWARDEN")
    if (item.login) {
      push(item.login.password, name)
      if (cfg.totp !== false) push(item.login.totp, `${name}_TOTP`)
      if (cfg.usernames) push(item.login.username, `${name}_USER`)
    }
    if (item.card) {
      push(item.card.number, `${name}_CARD_NUMBER`)
      push(item.card.code, `${name}_CARD_CODE`)
    }
    for (const field of Array.isArray(item.fields) ? item.fields : []) {
      const hidden = field?.type === 1
      if (hidden || (cfg.text_fields && field?.type === 0)) push(field.value, `${name}_${field.name || "FIELD"}`)
    }
    if (cfg.notes && typeof item.notes === "string") {
      for (const e of extractNamedSecrets(item.notes, { minLen: 6, bare: false })) push(e.value, `${name}_${e.name ?? "NOTE"}`)
    }
  }
  return out
}

/**
 * Config: `{ cli?, folders: ["VibeGuard"] | folder, collections?, session_wincred?, session_env?,
 *            sync?, usernames?, totp?, text_fields?, notes?, timeout? }`
 */
export async function bitwardenSecrets(cfg) {
  if (!cfg || typeof cfg !== "object") return { entries: [], failed: [] }
  const folders = [...list(cfg.folders), ...list(cfg.folder)]
  const collections = list(cfg.collections)
  if (folders.length === 0 && collections.length === 0) {
    return { entries: [], failed: [{ file: "bitwarden", message: "set secrets.bitwarden.folders (never the whole vault)" }] }
  }
  const key = await sessionKey(cfg)
  if (key.error) return { entries: [], failed: [{ file: "bitwarden", message: key.error }] }
  const env = { ...process.env, BW_SESSION: key.session, BW_NOINTERACTION: "true" }
  const timeout = Number.isFinite(cfg.timeout) ? cfg.timeout : 30_000
  const failed = []

  if (cfg.sync !== false) {
    const res = await runBw(cfg.cli, ["sync"], env, timeout)
    if (res.error) failed.push({ file: "bitwarden:sync", message: res.error })
  }

  const ids = []
  if (folders.length) {
    const res = await runBw(cfg.cli, ["list", "folders"], env, timeout)
    const all = res.error ? null : parseJson(res.stdout)
    if (!Array.isArray(all)) return { entries: [], failed: [...failed, { file: "bitwarden:folders", message: res.error ?? "unexpected output" }] }
    for (const wanted of folders) {
      const hit = all.find((f) => String(f?.name ?? "").toLowerCase() === wanted.toLowerCase())
      if (hit?.id) ids.push(["--folderid", hit.id])
      else failed.push({ file: `bitwarden:folder:${wanted}`, message: "folder not found" })
    }
  }
  if (collections.length) {
    const res = await runBw(cfg.cli, ["list", "collections"], env, timeout)
    const all = res.error ? [] : (parseJson(res.stdout) ?? [])
    for (const wanted of collections) {
      const hit = all.find((c) => String(c?.name ?? "").toLowerCase() === wanted.toLowerCase())
      if (hit?.id) ids.push(["--collectionid", hit.id])
      else failed.push({ file: `bitwarden:collection:${wanted}`, message: res.error ?? "collection not found" })
    }
  }

  const entries = []
  for (const [flag, id] of ids) {
    const res = await runBw(cfg.cli, ["list", "items", flag, id], env, timeout)
    const items = res.error ? null : parseJson(res.stdout)
    if (!Array.isArray(items)) {
      failed.push({ file: `bitwarden:${id}`, message: res.error ?? "unexpected output" })
      continue
    }
    entries.push(...extractBitwardenItems(items, cfg))
  }
  return { entries, failed }
}
