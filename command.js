import { execFile } from "node:child_process"
import { createHash } from "node:crypto"
import { mkdir, readdir, readFile, rename, stat, writeFile } from "node:fs/promises"
import path from "node:path"
import { sanitizeCategory } from "./patterns.js"
import { expandPath, stripBom } from "./util.js"
import { deleteCredential, writeCredential } from "./wincred.js"

/**
 * `gh▒▒▒▒▒`: first characters only, fixed-width mask. Values under 16 chars
 * (typical passwords) are fully masked. Command output becomes part of the
 * conversation on the next turn, so it must never carry more than this.
 */
export function mask(value, visible = 2) {
  const v = String(value ?? "")
  if (v.length < 16 || visible <= 0) return "▒▒▒▒▒"
  return `${v.slice(0, Math.min(visible, 4))}▒▒▒▒▒`
}

export function readClipboard() {
  const [cmd, args] =
    process.platform === "win32"
      ? ["powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-Clipboard -Raw"]]
      : process.platform === "darwin"
        ? ["pbpaste", []]
        : process.env.WAYLAND_DISPLAY
          ? ["wl-paste", ["--no-newline"]]
          : ["xclip", ["-o", "-selection", "clipboard"]]
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: 10_000, windowsHide: true }, (error, stdout) =>
      resolve(error ? { error: String(error.message).split("\n")[0] } : { value: String(stdout ?? "").replace(/\r?\n$/, "") }),
    )
  })
}

function quoteValue(v) {
  if (!/[\s#"'`]/.test(v)) return v
  if (!v.includes('"')) return `"${v}"`
  if (!v.includes("'")) return `'${v}'`
  return `\`${v}\``
}

async function atomicWrite(file, text) {
  await mkdir(path.dirname(file), { recursive: true })
  const tmp = `${file}.tmp-${process.pid}`
  await writeFile(tmp, text, "utf8")
  await rename(tmp, file)
}

async function readText(file) {
  try {
    return stripBom(await readFile(file, "utf8"))
  } catch (error) {
    if (error?.code === "ENOENT") return ""
    throw error
  }
}

const lineFor = (name) => new RegExp(`^\\s*(?:export\\s+)?${name}(?:\\[\\w+\\])?\\s*[=:]`, "i")

export async function addToSecretsFile(file, name, value) {
  const text = await readText(file)
  const lines = text.split(/\r?\n/).filter((l, i, a) => !(i === a.length - 1 && l === ""))
  const re = lineFor(name)
  const next = lines.filter((l) => !re.test(l))
  const replaced = next.length !== lines.length
  next.push(`${name}=${quoteValue(value)}`)
  await atomicWrite(file, `${next.join("\n")}\n`)
  return { replaced }
}

export async function removeFromSecretsFile(file, name) {
  const text = await readText(file)
  const lines = text.split(/\r?\n/)
  const re = lineFor(name)
  const next = lines.filter((l) => !re.test(l))
  if (next.length === lines.length) return { removed: false }
  await atomicWrite(file, next.join("\n"))
  return { removed: true }
}

const HELP = (n) => `**/${n}** – VibeGuard secret protection

| Command | Effect |
|---|---|
| \`/${n}\` or \`/${n} status\` | Status, sources, masked known secrets |
| \`/${n} add NAME\` | Add a secret **from the clipboard** (nothing typed into the chat) |
| \`/${n} add NAME=value\` | Add a secret typed inline (redacted before any request) |
| \`/${n} add NAME --wincred\` | Store in Windows Credential Manager (\`vibeguard:NAME\`) instead of the file |
| \`/${n} remove NAME\` | Remove from the secrets file / Credential Manager |
| \`/${n} reload\` | Re-read all sources (incl. password managers) |
| \`/${n} check [--hibp]\` | Strength of each secret, collisions with project files, optional breach check |
| \`/${n} taint [clear]\` | Restricted data sources this session has seen |
| \`/${n} test\` | Run the self-test |
| \`/${n} audit [n]\` | Last n audit events (default 20) |`

const STRENGTH = { strong: "strong", medium: "medium", weak: "⚠️ weak" }

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "out", ".next", ".venv", "venv", "__pycache__", "target", "bin", "obj"])

async function listProjectFiles(directory) {
  const viaGit = await new Promise((resolve) => {
    execFile("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], { cwd: directory, windowsHide: true, maxBuffer: 32 * 1024 * 1024, timeout: 15_000 }, (error, stdout) =>
      resolve(error ? null : String(stdout).split("\0").filter(Boolean).map((f) => path.join(directory, f))),
    )
  })
  if (viaGit) return viaGit.slice(0, 5000)
  const out = []
  const walk = async (dir, depth) => {
    if (depth > 6 || out.length >= 5000) return
    let items
    try {
      items = await readdir(dir, { withFileTypes: true })
    } catch {
      return
    }
    for (const it of items) {
      if (out.length >= 5000) return
      if (it.isDirectory()) {
        if (!SKIP_DIRS.has(it.name) && !it.name.startsWith(".")) await walk(path.join(dir, it.name), depth + 1)
      } else if (it.isFile()) out.push(path.join(dir, it.name))
    }
  }
  await walk(directory, 0)
  return out
}

/** Occurrences of values in project text files. Returns counts only. */
export async function scanProject(directory, values) {
  const result = new Map()
  const files = await listProjectFiles(directory)
  for (const file of files) {
    let text
    try {
      const s = await stat(file)
      if (s.size > 512 * 1024) continue
      const buf = await readFile(file)
      if (buf.includes(0)) continue
      text = buf.toString("utf8")
    } catch {
      continue
    }
    for (const v of values) {
      let n = 0
      for (let i = text.indexOf(v); i !== -1; i = text.indexOf(v, i + v.length)) n++
      if (!n) continue
      const r = result.get(v) ?? { files: 0, hits: 0 }
      r.files++
      r.hits += n
      result.set(v, r)
    }
  }
  return result
}

/** Have I Been Pwned "Pwned Passwords" range API (k-anonymity). */
export async function hibpCounts(values, fetchImpl = globalThis.fetch) {
  const out = new Map()
  const byPrefix = new Map()
  for (const v of new Set(values)) {
    const h = createHash("sha1").update(v, "utf8").digest("hex").toUpperCase()
    const p = h.slice(0, 5)
    if (!byPrefix.has(p)) byPrefix.set(p, [])
    byPrefix.get(p).push([v, h.slice(5)])
  }
  for (const [prefix, list] of [...byPrefix].slice(0, 200)) {
    try {
      const res = await fetchImpl(`https://api.pwnedpasswords.com/range/${prefix}`, {
        headers: { "Add-Padding": "true", "User-Agent": "opencode-vibeguard" },
        signal: AbortSignal.timeout(10_000),
      })
      if (!res.ok) continue
      const counts = new Map()
      for (const line of (await res.text()).split(/\r?\n/)) {
        const [suffix, count] = line.trim().split(":")
        if (suffix) counts.set(suffix.toUpperCase(), Number(count) || 0)
      }
      for (const [v, suffix] of list) out.set(v, counts.get(suffix) ?? 0)
    } catch {
      // offline: leave unknown
    }
  }
  return out
}

/**
 * Handler for the `/vibeguard` command. Returns markdown for a synthetic message.
 * Never echoes secret values.
 */
export function createCommandHandler(deps) {
  const { config, directory, getState, rebuild, selfTest, audit, sessions } = deps
  const name = config.command?.name ?? "vibeguard"
  const visible = Number.isFinite(config.command?.mask_chars) ? config.command.mask_chars : 2
  const secretsFile = () => expandPath((config.secrets?.files ?? [])[0] ?? "~/.config/opencode/vibeguard.secrets", directory)

  const status = async (sessionID) => {
    const st = getState()
    if (sessionID && deps.routing) taintCache.set(sessionID, await deps.routing.getTaint(sessionID))
    const lines = []
    const health = st.selftest?.ok
      ? st.selftest.warnings
        ? `✅ passed with ${st.selftest.warnings} warning(s) – run \`/${name} test\``
        : "✅ passed"
      : st.selftest
        ? `❌ FAILED – requests are blocked while fail_closed is on; run \`/${name} test\``
        : "not run"
    lines.push(`**VibeGuard status**`, "")
    lines.push(`- Config: \`${config.loadedFrom}\``)
    lines.push(`- Self-test: ${health}${st.pipeline ? ` · live pipeline: ${st.pipeline}` : ""}`)
    lines.push(`- Known values: ${st.known?.named ?? 0} named (+${(st.known?.entries.length ?? 0) - (st.known?.named ?? 0)} encoded variants)`)
    lines.push(`- Detection rules: ${st.patterns?.regex.length ?? 0} · protected paths: ${st.protectedCount ?? 0} · sessions: ${sessions()}`)
    lines.push(`- Payload guard: ${config.guard?.http ?? "redact"} · stream restore: ${config.restore?.response !== false ? "on" : "off"} · fail_closed: ${config.fail_closed}`)
    lines.push(`- Audit log: ${audit.enabled ? `\`${audit.path}\`` : "off"}`)
    const counts = st.known?.counts ?? {}
    lines.push(`- Sources: ${Object.entries(counts).filter(([k]) => k !== "total").map(([k, v]) => `${k}=${v}`).join(", ") || "none"}`)
    for (const f of st.known?.failed ?? []) lines.push(`- ⚠️ unreadable: \`${f.file}\` (${f.message})`)
    lines.push(...routingStatus(sessionID))
    const named = (st.known?.entries ?? []).slice(0, st.known?.named ?? 0)
    const weak = named.filter((e) => e.strength === "weak")
    if (weak.length) {
      lines.push("", `⚠️ **${weak.length} weak secret(s)** – only replaced in a credential context (\`${name} check\` for details). Change these passwords:`)
      lines.push(weak.slice(0, 20).map((e) => `\`${e.category}\``).join(", "))
    }
    if (named.length) {
      lines.push("", "| Name | Value | Length | Strength | Match | Source |", "|---|---|---|---|---|---|")
      for (const e of named.slice(0, 60)) {
        lines.push(`| ${e.category} | \`${mask(e.value, visible)}\` | ${e.value.length} | ${STRENGTH[e.strength] ?? "?"} | ${e.mode ?? "exact"} | ${e.source} |`)
      }
      if (named.length > 60) lines.push(`| … | | | | | ${named.length - 60} more |`)
    }
    return lines.join("\n")
  }

  const routingStatus = (sessionID) => {
    const r = deps.routing?.info
    if (!r || (!r.endpoints.length && !r.sources.length)) return []
    const out = ["", "**Routing**"]
    for (const e of r.endpoints) {
      out.push(`- Endpoint \`${e.name}\`${e.trusted ? " (trusted: no substitution)" : ""}${e.hasBaseUrls ? "" : " ⚠️ no base_urls – provider ID is trusted"}`)
    }
    for (const s of r.sources) out.push(`- Source \`${s.name}\` → ${s.allow ? [...s.allow].join(", ") : "any endpoint (tagging only)"}`)
    out.push(`- On violation: ${r.onViolation} · preflight: ${r.preflight} · content fingerprints: ${deps.routing.fingerprints()}`)
    if (sessionID) {
      const lm = deps.routing.lastModel(sessionID)
      const taint = taintCache.get(sessionID)
      out.push(`- This session: model ${lm?.model ? `${lm.model.providerID}/${lm.model.id}` : "unknown"} → endpoint ${lm?.endpoint?.name ?? "none (cloud/unknown)"}`)
      if (taint?.size) out.push(`- This session contains restricted data from: ${[...taint].map((t) => `\`${t}\``).join(", ")}`)
    }
    return out
  }
  const taintCache = new Map()

  const taint = async (args, sessionID) => {
    if (!deps.routing) return "Routing is not configured."
    if (!sessionID) return "No session."
    if (args[0] === "clear") {
      await deps.routing.clearTaint(sessionID)
      taintCache.delete(sessionID)
      return "Cleared the restricted-data marker of this session. History that still contains such data keeps being blocked for other endpoints."
    }
    const t = await deps.routing.getTaint(sessionID)
    return t.size
      ? `This session contains restricted data from: ${[...t].map((x) => `\`${x}\``).join(", ")}. Requests to other endpoints are blocked. \`/${name} taint clear\` removes the marker.`
      : "This session contains no restricted data."
  }

  const check = async (args) => {
    const st = getState()
    const named = (st.known?.entries ?? []).slice(0, st.known?.named ?? 0)
    if (!named.length) return "No known secrets registered."
    const lines = ["**VibeGuard secret check**", ""]
    const nonStrong = named.filter((e) => e.strength !== "strong")
    const collisions = nonStrong.length ? await scanProject(directory, nonStrong.map((e) => e.value)) : new Map()
    let pwned = null
    if (args.includes("--hibp")) pwned = await hibpCounts(named.map((e) => e.value))
    lines.push("| Name | Strength | Match | Why | In project files | Breaches (HIBP) |", "|---|---|---|---|---|---|")
    for (const e of named.slice(0, 100)) {
      const c = collisions.get(e.value)
      const hits = e.strength === "strong" ? "–" : c ? `${c.files} file(s), ${c.hits}×` : "0"
      const breach = pwned ? (pwned.get(e.value) === undefined ? "?" : pwned.get(e.value) ? `⚠️ ${pwned.get(e.value)}` : "0") : "–"
      lines.push(`| ${e.category} | ${STRENGTH[e.strength] ?? "?"} | ${e.mode} | ${(e.reasons ?? []).join(", ") || "–"} | ${hits} | ${breach} |`)
    }
    lines.push(
      "",
      "Weak secrets are only replaced right after a credential key (`Passwort: …`, `-p…`, `user:…@`). Elsewhere they are left as they are, because replacing a common word breaks normal text and code and the context gives it away anyway. **Change weak passwords.**",
      "Override per name with `NAME[exact|word|context|off]=…` in the secrets file or `secrets.match`.",
    )
    if (!pwned) lines.push("", `Breach check: \`/${name} check --hibp\` (k-anonymity: only the first 5 hex chars of each SHA-1 hash leave this machine).`)
    return lines.join("\n")
  }

  const add = async (restText) => {
    const flags = new Set([...restText.matchAll(/(?:^|\s)--(wincred|file)(?=\s|$)/g)].map((m) => m[1]))
    const wincred = flags.has("wincred") || (config.secrets?.store === "wincred" && !flags.has("file"))
    const rest = restText.replace(/(?:^|\s)--(?:wincred|file)(?=\s|$)/g, "").trim()
    const eq = rest.indexOf("=")
    const rawName = eq >= 0 ? rest.slice(0, eq) : rest
    const key = sanitizeCategory(rawName.trim())
    if (!rawName.trim()) return "Usage: `/vibeguard add NAME` (value from clipboard) or `/vibeguard add NAME=value`."
    let value = eq >= 0 ? rest.slice(eq + 1).trim().replace(/^(["'`])(.*)\1$/, "$2") : ""
    let from = "inline"
    if (!value) {
      const clip = await readClipboard()
      if (clip.error) return `Could not read the clipboard: ${clip.error}`
      value = clip.value.trim()
      from = "clipboard"
    }
    if (value.length < 4) return "The value is shorter than 4 characters – not added."
    if (/[\r\n]/.test(value)) return "Multi-line values are not supported – not added."
    let where
    if (wincred) {
      const res = await writeCredential(`vibeguard:${key}`, value)
      if (res.error) return `Credential Manager write failed: ${res.error}`
      where = `Windows Credential Manager (\`vibeguard:${key}\`)`
    } else {
      const file = secretsFile()
      const res = await addToSecretsFile(file, key, value)
      where = `\`${file}\`${res.replaced ? " (replaced)" : ""}`
    }
    await rebuild("command add", { refreshSlow: wincred })
    audit.write("command.add", { name: key, store: wincred ? "wincred" : "file", from })
    const note = from === "inline" ? "\n\nThe value was typed into the chat input; it is redacted before every provider request from now on." : ""
    return `Added **${key}** (\`${mask(value, visible)}\`, ${value.length} chars, from ${from}) to ${where}. It is replaced by a placeholder from now on.${note}`
  }

  const remove = async (args) => {
    const key = sanitizeCategory(args.join(" "))
    if (!args.length) return "Usage: `/vibeguard remove NAME`"
    const file = secretsFile()
    const res = await removeFromSecretsFile(file, key)
    let wc = { error: "skipped" }
    if (process.platform === "win32") wc = await deleteCredential(`vibeguard:${key}`)
    if (!res.removed && wc.error) return `**${key}** was not found in \`${file}\` or the Credential Manager.`
    await rebuild("command remove", { refreshSlow: !wc.error })
    audit.write("command.remove", { name: key })
    return `Removed **${key}**${res.removed ? ` from \`${file}\`` : ""}${wc.error ? "" : " from the Credential Manager"}.`
  }

  const test = () => {
    const res = selfTest()
    const head = res.ok ? (res.warnings ? `✅ passed with ${res.warnings} warning(s)` : "✅ passed") : "❌ FAILED"
    const icon = (c) => (c.ok ? "✅" : c.warn ? "⚠️" : "❌")
    return [`**VibeGuard self-test: ${head}**`, "", ...res.checks.map((c) => `- ${icon(c)} ${c.name}${c.detail ? ` – ${c.detail}` : ""}`)].join("\n")
  }

  const auditTail = (args) => {
    const n = Math.min(Math.max(Number(args[0]) || 20, 1), 200)
    if (!audit.enabled) return "The audit log is disabled (`audit.enabled: false`)."
    const rows = audit.tail(n)
    if (!rows.length) return `No audit events yet (\`${audit.path}\`).`
    const fmt = (r) => {
      const { schema_version, ts, type, ...rest } = r
      return `- \`${ts}\` **${type}** ${Object.entries(rest).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join("/") : typeof v === "object" ? JSON.stringify(v) : v}`).join(" ")}`
    }
    return [`**Last ${rows.length} audit events** (\`${audit.path}\`)`, "", ...rows.map(fmt)].join("\n")
  }

  return {
    name,
    async run(text, ctx = {}) {
      const body = String(text ?? "").trim().replace(new RegExp(`^/?${name}\\b`), "").trim()
      const m = body.match(/^(\S+)\s*([\s\S]*)$/)
      const sub = m?.[1] ?? "status"
      const restText = m?.[2] ?? ""
      const args = restText.split(/\s+/).filter(Boolean)
      switch (sub.toLowerCase()) {
        case "status":
          return status(ctx.sessionID)
        case "add":
          return add(restText)
        case "remove":
        case "rm":
          return remove(args)
        case "check":
          return check(args)
        case "taint":
          return taint(args, ctx.sessionID)
        case "reload":
          await rebuild("command reload", { refreshSlow: true })
          return `Reloaded.\n\n${await status(ctx.sessionID)}`
        case "test":
        case "selftest":
          return test()
        case "audit":
          return auditTail(args)
        default:
          return HELP(name)
      }
    },
  }
}
