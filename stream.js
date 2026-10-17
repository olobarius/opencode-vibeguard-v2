import { restoreText } from "./restore.js"

/**
 * Keys whose subtree is left untouched: tool-call arguments must keep their
 * placeholders so the per-tool restore policy in `execute.before` applies,
 * and opaque provider blobs must never be rewritten.
 */
const SKIP_KEYS = new Set([
  "arguments",
  "partial_json",
  "input",
  "args",
  "function_call",
  "functionCall",
  "tool_calls",
  "tool_use",
  "toolUse",
  "toolCall",
  "parameters",
  "signature",
  "encrypted_content",
  "encrypted",
  "redacted_thinking",
  "data",
  // Reasoning stays verbatim: providers echo it back via provider metadata
  // (outside the structural redaction) and some sign it (Anthropic thinking).
  "thinking",
  "reasoning",
  "reasoning_content",
  "reasoning_details",
  "reasoning_text",
  "summary",
])
const TEXT_KEYS = new Set(["text", "content", "thinking", "reasoning", "reasoning_content", "delta", "refusal"])
const CHANNEL_FIELDS = ["index", "output_index", "content_index", "item_id", "summary_index"]
const TOOL_EVENT = /function_call|tool|arguments|input_json|mcp_call|custom_tool/i
const REASONING_EVENT = /reasoning|thinking/i

function skipEventType(type) {
  return (TOOL_EVENT.test(type) && !/output_text|text_delta/i.test(type)) || REASONING_EVENT.test(type)
}

function isDeltaPath(path, type) {
  const last = path.at(-1)
  if (!TEXT_KEYS.has(last)) return false
  if (path.includes("delta") || last === "delta") return true
  if (/delta/i.test(type)) return true
  // Gemini streams text parts as increments: candidates.N.content.parts.N.text
  return path[0] === "candidates" && path.includes("parts") && last === "text"
}

function channelKey(obj, path) {
  const ids = CHANNEL_FIELDS.map((f) => (obj && obj[f] !== undefined ? String(obj[f]) : "")).join(",")
  return `${path.join(".")}|${ids}`
}

function getAt(obj, path) {
  let cur = obj
  for (const k of path.slice(0, -1)) cur = cur?.[k]
  return cur
}

/** Earliest index from which `s` could still be the beginning of a placeholder. */
export function holdbackIndex(s, prefix) {
  const max = prefix.length + 96
  const from = Math.max(0, s.length - max)
  for (let i = s.indexOf(prefix[0], from); i !== -1; i = s.indexOf(prefix[0], i + 1)) {
    const tail = s.slice(i)
    if (tail.length < prefix.length) {
      if (prefix.startsWith(tail)) return i
    } else if (tail.startsWith(prefix) && /^[A-Za-z0-9_]*$/.test(tail.slice(prefix.length))) {
      return i
    }
  }
  return s.length
}

/** Blank every other delta payload in a synthetic copy so nothing is duplicated. */
function scrubTemplate(node, targetPath, path = [], inDelta = false) {
  if (!node || typeof node !== "object") return
  for (const key of Object.keys(node)) {
    const p = [...path, key]
    const deltaHere = inDelta || key === "delta"
    if (key === "usage" || key === "sequence_number") {
      delete node[key]
      continue
    }
    if (key === "finish_reason" || key === "stop_reason") {
      node[key] = null
      continue
    }
    if (deltaHere && SKIP_KEYS.has(key)) {
      delete node[key]
      continue
    }
    const v = node[key]
    if (typeof v === "string") {
      const isTarget = p.length === targetPath.length && p.every((x, i) => String(x) === String(targetPath[i]))
      if (!isTarget && TEXT_KEYS.has(key) && (deltaHere || isDeltaPath(p, ""))) node[key] = ""
    } else scrubTemplate(v, targetPath, p, deltaHere)
  }
}

/**
 * Stateful SSE rewriter. Feed decoded text with `push()`, finish with `end()`.
 * Any internal error switches it into pass-through mode.
 */
export function createSseRestorer(session, stats) {
  const prefix = session.prefix
  const pending = new Map()
  let buffer = ""
  let broken = false

  const flushAll = (except) => {
    let out = ""
    for (const [key, p] of pending) {
      if (except?.has(key)) continue
      pending.delete(key)
      if (!p.text) continue
      const clone = structuredClone(p.obj)
      scrubTemplate(clone, p.path)
      const holder = getAt(clone, p.path)
      if (holder) holder[p.path.at(-1)] = p.text
      out += [...p.other, `data: ${JSON.stringify(clone)}`].join("\n") + "\n\n"
    }
    return out
  }

  const processEvent = (raw) => {
    const lines = raw.split(/\r?\n/)
    const data = []
    const other = []
    for (const l of lines) {
      if (l.startsWith("data:")) data.push(l.slice(l[5] === " " ? 6 : 5))
      else other.push(l)
    }
    const eventName = (other.find((l) => l.startsWith("event:")) ?? "").slice(6).trim()
    if (data.length === 0) return /ping/i.test(eventName) || raw.trim() === "" || raw.startsWith(":") ? raw : flushAll() + raw
    const payload = data.join("\n")
    if (payload.trim() === "[DONE]") return flushAll() + raw
    let obj
    try {
      obj = JSON.parse(payload)
    } catch {
      return flushAll() + raw
    }
    if (!obj || typeof obj !== "object") return flushAll() + raw
    const type = typeof obj.type === "string" ? obj.type : eventName
    if (/^ping$/i.test(type)) return raw

    const toolEvent = skipEventType(type)
    const touched = new Set()
    let changed = false

    const walk = (node, path) => {
      if (!node || typeof node !== "object") return
      for (const key of Object.keys(node)) {
        if (SKIP_KEYS.has(key)) continue
        const v = node[key]
        const p = [...path, key]
        if (typeof v === "string") {
          if (toolEvent) continue
          if (isDeltaPath(p, type)) {
            const ch = channelKey(obj, p)
            const prev = pending.get(ch)
            const combined = (prev?.text ?? "") + v
            const restored = restoreText(combined, session, stats)
            const cut = holdbackIndex(restored, prefix)
            const emit = restored.slice(0, cut)
            if (emit !== v) {
              node[key] = emit
              changed = true
            }
            touched.add(ch)
            pending.set(ch, { text: restored.slice(cut), obj: null, path: p, other })
          } else if (v.includes(prefix)) {
            const restored = restoreText(v, session, stats)
            if (restored !== v) {
              node[key] = restored
              changed = true
            }
          }
        } else walk(v, p)
      }
    }
    walk(obj, [])

    const before = flushAll(touched)
    for (const ch of touched) {
      const p = pending.get(ch)
      if (p && p.text) p.obj = structuredClone(obj)
      else pending.delete(ch)
    }
    if (!changed) return before + raw
    return before + [...other, `data: ${JSON.stringify(obj)}`].join("\n")
  }

  return {
    push(text) {
      if (broken) return text
      buffer += text
      let out = ""
      const re = /\r\n\r\n|\n\n|\r\r/g
      let last = 0
      try {
        for (let m; (m = re.exec(buffer)); ) {
          out += processEvent(buffer.slice(last, m.index)) + m[0]
          last = m.index + m[0].length
        }
      } catch {
        broken = true
        const rest = buffer.slice(last)
        buffer = ""
        return out + rest
      }
      buffer = buffer.slice(last)
      return out
    },
    end() {
      if (broken) {
        const rest = buffer
        buffer = ""
        return rest
      }
      let out = ""
      try {
        if (buffer.trim()) out += processEvent(buffer)
        else out += buffer
        out += flushAll()
      } catch {
        out += buffer
      }
      buffer = ""
      return out
    },
  }
}

function restoreJsonTree(node, session, stats) {
  if (!node || typeof node !== "object") return
  for (const key of Object.keys(node)) {
    if (SKIP_KEYS.has(key)) continue
    const v = node[key]
    if (typeof v === "string") {
      if (v.includes(session.prefix)) node[key] = restoreText(v, session, stats)
    } else restoreJsonTree(v, session, stats)
  }
}

/** Restore placeholders inside a single JSON frame (WebSocket receive). */
export function restoreFrame(frame, session, stats) {
  if (typeof frame !== "string" || !frame.includes(session.prefix)) return frame
  try {
    const obj = JSON.parse(frame)
    if (skipEventType(String(obj?.type ?? ""))) return frame
    restoreJsonTree(obj, session, stats)
    return JSON.stringify(obj)
  } catch {
    return frame
  }
}

/**
 * Wrap a provider response so placeholders in model text are restored.
 * Returns null when the response type is not handled (caller keeps original).
 */
export function restoreResponse(response, session, stats) {
  if (!response?.body) return null
  const type = (response.headers.get("content-type") ?? "").toLowerCase()
  const sse = type.includes("text/event-stream")
  const json = !sse && type.includes("json")
  if (!sse && !json) return null

  const headers = new Headers(response.headers)
  headers.delete("content-length")
  headers.delete("content-encoding")
  const encoder = new TextEncoder()
  const decoder = new TextDecoder()

  let transform
  if (sse) {
    const restorer = createSseRestorer(session, stats)
    transform = new TransformStream({
      transform(chunk, controller) {
        const out = restorer.push(decoder.decode(chunk, { stream: true }))
        if (out) controller.enqueue(encoder.encode(out))
      },
      flush(controller) {
        const out = restorer.push(decoder.decode()) + restorer.end()
        if (out) controller.enqueue(encoder.encode(out))
      },
    })
  } else {
    let text = ""
    transform = new TransformStream({
      transform(chunk) {
        text += decoder.decode(chunk, { stream: true })
      },
      flush(controller) {
        text += decoder.decode()
        let out = text
        if (text.includes(session.prefix)) {
          try {
            const obj = JSON.parse(text)
            restoreJsonTree(obj, session, stats)
            out = JSON.stringify(obj)
          } catch {
            out = text
          }
        }
        controller.enqueue(encoder.encode(out))
      },
    })
  }

  return new Response(response.body.pipeThrough(transform), {
    status: response.status,
    statusText: response.statusText,
    headers,
  })
}
