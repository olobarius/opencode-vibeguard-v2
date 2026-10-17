import { execFile } from "node:child_process"
import { mkdir, readFile, rename, writeFile } from "node:fs/promises"
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

const lineFor = (name) => new RegExp(`^\\s*(?:export\\s+)?${name}\\s*[=:]`)

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
| \`/${n} test\` | Run the self-test |
| \`/${n} audit [n]\` | Last n audit events (default 20) |`

/**
 * Handler for the `/vibeguard` command. Returns markdown for a synthetic message.
 * Never echoes secret values.
 */
export function createCommandHandler(deps) {
  const { config, directory, getState, rebuild, selfTest, audit, sessions } = deps
  const name = config.command?.name ?? "vibeguard"
  const visible = Number.isFinite(config.command?.mask_chars) ? config.command.mask_chars : 2
  const secretsFile = () => expandPath((config.secrets?.files ?? [])[0] ?? "~/.config/opencode/vibeguard.secrets", directory)

  const status = () => {
    const st = getState()
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
    const named = (st.known?.entries ?? []).slice(0, st.known?.named ?? 0)
    if (named.length) {
      lines.push("", "| Name | Value | Length | Source |", "|---|---|---|---|")
      for (const e of named.slice(0, 60)) lines.push(`| ${e.category} | \`${mask(e.value, visible)}\` | ${e.value.length} | ${e.source} |`)
      if (named.length > 60) lines.push(`| … | | | ${named.length - 60} more |`)
    }
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
    async run(text) {
      const body = String(text ?? "").trim().replace(new RegExp(`^/?${name}\\b`), "").trim()
      const m = body.match(/^(\S+)\s*([\s\S]*)$/)
      const sub = m?.[1] ?? "status"
      const restText = m?.[2] ?? ""
      const args = restText.split(/\s+/).filter(Boolean)
      switch (sub.toLowerCase()) {
        case "status":
          return status()
        case "add":
          return add(restText)
        case "remove":
        case "rm":
          return remove(args)
        case "reload":
          await rebuild("command reload", { refreshSlow: true })
          return `Reloaded.\n\n${status()}`
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
