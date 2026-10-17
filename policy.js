import path from "node:path"
import { globToRegex, isPlainObject, normalizePath } from "./util.js"

// allow: restore real values | ask: restore after user approval (once per session+tool)
// deny: reject the call | keep: run with placeholders untouched (e.g. Code Mode: nested calls decide)
const EFFECTS = new Set(["allow", "ask", "deny", "keep"])

/** `{ "webfetch": "ask", "chrome-devtools_*": "ask", "*": "allow" }` -> ordered rules. */
export function compileToolRules(spec) {
  const rules = []
  if (isPlainObject(spec)) {
    for (const [pattern, effect] of Object.entries(spec)) {
      const e = String(effect).toLowerCase()
      if (EFFECTS.has(e)) rules.push({ pattern, re: globToRegex(pattern), effect: e })
    }
  }
  return rules
}

/** First matching rule wins; default allow. */
export function toolEffect(tool, rules) {
  const name = String(tool ?? "")
  for (const r of rules) if (r.re.test(name)) return r.effect
  return "allow"
}

/**
 * Paths whose contents are secret. Matches exact files and anything below a
 * protected directory. Comparison is case-insensitive on Windows.
 */
export class ProtectedPaths {
  constructor(paths = [], directory = process.cwd()) {
    this.directory = directory
    this.set(paths)
  }

  set(paths) {
    this.list = [...new Set(paths.filter(Boolean).map((p) => normalizePath(path.resolve(this.directory, p))))]
    this.names = [
      ...new Set(
        this.list
          .map((p) => p.split("/").pop())
          .filter((n) => n && n.length >= 6 && /[._-]/.test(n)),
      ),
    ]
  }

  matchPath(resource) {
    const raw = String(resource ?? "").trim()
    if (!raw || raw === "*") return null
    const r = normalizePath(path.resolve(this.directory, raw))
    for (const p of this.list) if (r === p || r.startsWith(`${p}/`)) return p
    return null
  }

  matchCommand(command) {
    const c = normalizePath(String(command ?? ""))
    if (!c) return null
    for (const p of this.list) if (c.includes(p)) return p
    const words = c.split(/[\s"'`=;|&<>()]+/)
    for (const n of this.names) if (words.some((w) => w === n || w.endsWith(`/${n}`))) return n
    return null
  }
}
