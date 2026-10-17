import { existsSync } from "node:fs"
import * as fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { isPlainObject, parseDurationMs, stripJsonc } from "./util.js"

export const DEFAULTS = Object.freeze({
  enabled: false,
  debug: false,
  placeholder_prefix: "__VG_",
  // Block the model request when redaction throws instead of sending plaintext.
  fail_closed: true,
  // Add a short system note telling the model how to treat placeholders.
  system_hint: true,
  // Also redact the user prompt at admission (persisted transcript keeps placeholders).
  redact_prompt: false,
  session: { ttl: "24h", max_mappings: 100000, max_sessions: 100 },
  patterns: {
    keywords: [],
    regex: [],
    exclude: [],
    min_secret_len: 8,
    // Thresholds for the `entropy_secret` rule (part of the default "secrets" group).
    entropy: { min_bits: 3.5, min_hex_bits: 3.0, min_len: 16 },
    protected_files: [],
    import_deny_paths: false,
    deny_policy: "",
  },
  // Known secrets: exact values that are always replaced with stable, named placeholders.
  secrets: {
    files: ["~/.config/opencode/vibeguard.secrets", ".opencode/vibeguard.secrets"],
    env: true,
    opencode_auth: true,
    commands: [],
    // Windows Credential Manager (Windows only): generic credentials `vibeguard:<NAME>`.
    windows_credentials: [{ filter: "vibeguard:*" }],
    // KeePass/KeePassXC via keepassxc-cli: { database, password_env | password_wincred | no_password, entries, group }
    keepass: null,
    // Where `/vibeguard add` stores new secrets: file | wincred
    store: "file",
    variants: true,
    min_len: 4,
    reload_interval: "5s",
  },
  // Security event log (JSONL, rotated). Never contains secret values.
  audit: { enabled: true, path: "", max_bytes: 5 * 1024 * 1024, max_files: 3 },
  // Pipeline self-test at startup; failure blocks requests when fail_closed is on.
  selftest: true,
  // `/vibeguard` slash command.
  command: { enabled: true, name: "vibeguard", mask_chars: 2 },
  // Last line of defence on the raw provider payload.
  guard: { http: "redact", websocket: true, regex: "strong" },
  restore: {
    // Restore placeholders in streamed model text (display / transcript).
    response: true,
    // Per-tool policy for receiving real secret values: allow | ask | deny. First match wins.
    tools: { execute: "keep", webfetch: "ask", websearch: "deny", "*": "allow" },
    // What to do when a tool input carries a placeholder that cannot be resolved: error | keep
    unknown: "error",
  },
  // Native permission guard for files whose contents are secret.
  protect: { reads: true, shell: "ask", paths: [] },
})

function deepMerge(base, over) {
  if (!isPlainObject(over)) return base
  const out = { ...base }
  for (const [k, v] of Object.entries(over)) {
    if (v === undefined) continue
    out[k] = isPlainObject(v) && isPlainObject(base?.[k]) ? deepMerge(base[k], v) : v
  }
  return out
}

function int(value, fallback) {
  return Number.isFinite(value) && Number(value) > 0 ? Math.floor(Number(value)) : fallback
}

export function normalizeConfig(raw) {
  const cfg = deepMerge(DEFAULTS, isPlainObject(raw) ? raw : {})
  // A `restore.tools` object given by the user replaces the defaults entirely.
  if (isPlainObject(raw?.restore?.tools)) cfg.restore = { ...cfg.restore, tools: raw.restore.tools }
  // Keep the V1-era `builtin` semantics: absent -> ["secrets"].
  if (!("builtin" in (raw?.patterns ?? {}))) cfg.patterns = { ...cfg.patterns, builtin: ["secrets"] }

  return {
    ...cfg,
    enabled: Boolean(cfg.enabled),
    debug: Boolean(cfg.debug),
    prefix: typeof cfg.placeholder_prefix === "string" && cfg.placeholder_prefix ? cfg.placeholder_prefix : "__VG_",
    ttlMs: parseDurationMs(cfg.session?.ttl, 24 * 3_600_000),
    maxMappings: int(cfg.session?.max_mappings, 100000),
    maxSessions: int(cfg.session?.max_sessions, 100),
    reloadMs: parseDurationMs(cfg.secrets?.reload_interval, 5000),
  }
}

async function readConfigFile(filepath) {
  try {
    const text = await fs.readFile(filepath, "utf8")
    return JSON.parse(stripJsonc(text))
  } catch (error) {
    return { __error: String(error?.message ?? error) }
  }
}

export function getConfigCandidates(directory) {
  const dir = String(directory ?? process.cwd())
  const xdg = process.env.XDG_CONFIG_HOME
  const globalDir = xdg ? path.join(xdg, "opencode") : path.join(os.homedir(), ".config", "opencode")
  const list = [
    path.join(dir, "vibeguard.config.json"),
    path.join(dir, "vibeguard.config.jsonc"),
    path.join(dir, ".opencode", "vibeguard.config.json"),
    path.join(dir, ".opencode", "vibeguard.config.jsonc"),
    path.join(globalDir, "vibeguard.config.json"),
    path.join(globalDir, "vibeguard.config.jsonc"),
  ]
  const env = process.env.OPENCODE_VIBEGUARD_CONFIG
  return env ? [path.resolve(dir, env), ...list] : list
}

/**
 * Load plugin config. First existing file wins; plugin `options` from
 * opencode.json(c) are merged on top. Missing config means disabled (no-op).
 */
export async function loadConfig(directory, options) {
  const opts = isPlainObject(options) ? options : {}
  const errors = []
  for (const file of getConfigCandidates(directory)) {
    if (!existsSync(file)) continue
    const raw = await readConfigFile(file)
    if (raw?.__error) {
      errors.push(`${file}: ${raw.__error}`)
      continue
    }
    return { ...normalizeConfig(deepMerge(raw, opts)), loadedFrom: file, errors }
  }
  if (Object.keys(opts).length > 0) {
    return { ...normalizeConfig(opts), loadedFrom: "plugin options", errors }
  }
  return { ...normalizeConfig({ enabled: false }), loadedFrom: "", errors }
}
