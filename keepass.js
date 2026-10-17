import { execFile } from "node:child_process"
import { sanitizeCategory } from "./patterns.js"
import { expandPath } from "./util.js"
import { listCredentials } from "./wincred.js"

/**
 * KeePass / KeePassXC databases via `keepassxc-cli`. The database password is
 * piped on stdin; it comes from an env var or the Windows Credential Manager,
 * never from the config file.
 */
function run(cli, args, stdin, timeout) {
  const [cmd, ...pre] = Array.isArray(cli) ? cli.map(String) : [String(cli || "keepassxc-cli")]
  return new Promise((resolve) => {
    const child = execFile(cmd, [...pre, ...args], { timeout, windowsHide: true, maxBuffer: 16 * 1024 * 1024 }, (error, stdout, stderr) =>
      resolve({ error: error ? String(stderr || error.message).trim().split("\n")[0] : null, stdout: String(stdout ?? "") }),
    )
    child.stdin?.end(stdin ?? "")
  })
}

/** Minimal RFC 4180 CSV parser. */
export function parseCsv(text) {
  const rows = []
  let row = []
  let field = ""
  let quoted = false
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') {
        field += '"'
        i++
      } else if (c === '"') quoted = false
      else field += c
    } else if (c === '"') quoted = true
    else if (c === ",") {
      row.push(field)
      field = ""
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++
      row.push(field)
      rows.push(row)
      row = []
      field = ""
    } else field += c
  }
  if (field || row.length) {
    row.push(field)
    rows.push(row)
  }
  return rows.filter((r) => r.length > 1 || r[0])
}

async function databasePassword(cfg) {
  if (cfg.no_password) return { password: "" }
  if (cfg.password_env) {
    const v = process.env[cfg.password_env]
    return v ? { password: v } : { error: `env var ${cfg.password_env} is not set` }
  }
  if (cfg.password_wincred) {
    const res = await listCredentials([cfg.password_wincred])
    const hit = res.items.find((c) => c.target.toLowerCase() === String(cfg.password_wincred).toLowerCase())
    return hit ? { password: hit.secret } : { error: res.error ?? `credential ${cfg.password_wincred} not found` }
  }
  return { error: "no password source (password_env, password_wincred or no_password)" }
}

/**
 * Config: `{ database, cli?, key_file?, password_env? | password_wincred? | no_password?,
 *            entries?: [{ name, entry, attribute? }], group?: "VibeGuard" }`
 */
export async function keepassSecrets(cfg, directory) {
  if (!cfg || !cfg.database) return { entries: [], failed: [] }
  const db = expandPath(cfg.database, directory)
  const timeout = Number.isFinite(cfg.timeout) ? cfg.timeout : 20_000
  const pw = await databasePassword(cfg)
  if (pw.error) return { entries: [], failed: [{ file: `keepass:${db}`, message: pw.error }] }
  const auth = [...(cfg.key_file ? ["-k", expandPath(cfg.key_file, directory)] : []), ...(cfg.no_password ? ["--no-password"] : [])]
  const stdin = cfg.no_password ? "" : `${pw.password}\n`
  const entries = []
  const failed = []

  for (const spec of Array.isArray(cfg.entries) ? cfg.entries : []) {
    if (!spec?.entry) continue
    const res = await run(cfg.cli, ["show", "-q", "-s", "-a", spec.attribute ?? "Password", ...auth, db, spec.entry], stdin, timeout)
    if (res.error) {
      failed.push({ file: `keepass:${spec.entry}`, message: res.error })
      continue
    }
    const value = res.stdout.replace(/\r?\n$/, "")
    if (value.length >= 4) entries.push({ value, category: sanitizeCategory(spec.name ?? spec.entry.split("/").pop()), source: "keepass" })
  }

  if (cfg.group) {
    const res = await run(cfg.cli, ["export", "-q", "-f", "csv", ...auth, db], stdin, timeout)
    if (res.error) failed.push({ file: `keepass:${db}`, message: res.error })
    else {
      const rows = parseCsv(res.stdout)
      const header = (rows.shift() ?? []).map((h) => h.toLowerCase())
      const gi = header.indexOf("group")
      const ti = header.indexOf("title")
      const pi = header.indexOf("password")
      const want = String(cfg.group).replace(/^\/+|\/+$/g, "").toLowerCase()
      for (const r of rows) {
        const group = String(r[gi] ?? "").replace(/^Root\/?/i, "").toLowerCase()
        if (!(group === want || group.startsWith(`${want}/`))) continue
        const value = r[pi] ?? ""
        if (value.length >= 4) entries.push({ value, category: sanitizeCategory(r[ti] ?? "KEEPASS"), source: "keepass" })
      }
    }
  }
  return { entries, failed }
}
