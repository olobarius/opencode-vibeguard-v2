import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, unlinkSync } from "node:fs"
import path from "node:path"

export const AUDIT_SCHEMA_VERSION = 1

/**
 * JSONL audit log with size-based rotation (`audit.jsonl`, `.1`, `.2`, ...).
 * Records event types, counts, categories, tool names and placeholder names,
 * never secret values. Write failures never block an operation.
 * @param {{ enabled?: boolean, path: string, maxBytes?: number, maxFiles?: number }} opts
 */
export function createAudit(opts) {
  const enabled = opts?.enabled !== false && Boolean(opts?.path)
  const file = opts?.path ?? ""
  const maxBytes = Number.isFinite(opts?.maxBytes) && opts.maxBytes > 0 ? opts.maxBytes : 5 * 1024 * 1024
  const maxFiles = Number.isFinite(opts?.maxFiles) && opts.maxFiles > 0 ? Math.floor(opts.maxFiles) : 3
  let size = -1
  let failures = 0

  const rotate = () => {
    for (let i = maxFiles - 1; i >= 1; i--) {
      const from = i === 1 ? file : `${file}.${i - 1}`
      const to = `${file}.${i}`
      if (!existsSync(from)) continue
      if (existsSync(to)) unlinkSync(to)
      renameSync(from, to)
    }
    if (maxFiles <= 1 && existsSync(file)) unlinkSync(file)
    size = 0
  }

  const write = (type, data = {}) => {
    if (!enabled) return
    try {
      const line = `${JSON.stringify({ schema_version: AUDIT_SCHEMA_VERSION, ts: new Date().toISOString(), type, ...data })}\n`
      if (size < 0) {
        mkdirSync(path.dirname(file), { recursive: true })
        size = existsSync(file) ? statSync(file).size : 0
      }
      if (size > 0 && size + line.length > maxBytes) rotate()
      appendFileSync(file, line)
      size += Buffer.byteLength(line)
    } catch {
      failures++
    }
  }

  /** Last `n` entries (current file, then rotated ones). */
  const tail = (n = 20) => {
    const out = []
    for (let i = 0; i < maxFiles && out.length < n; i++) {
      const f = i === 0 ? file : `${file}.${i}`
      if (!existsSync(f)) continue
      try {
        const lines = readFileSync(f, "utf8").trim().split("\n").filter(Boolean)
        for (let j = lines.length - 1; j >= 0 && out.length < n; j--) {
          try {
            out.push(JSON.parse(lines[j]))
          } catch {
            // skip partial line
          }
        }
      } catch {
        // unreadable rotation file
      }
    }
    return out.reverse()
  }

  return { enabled, path: file, write, tail, failures: () => failures }
}
