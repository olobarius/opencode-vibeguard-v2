import { findMatches, redactText } from "./engine.js"
import { compileKeywords } from "./patterns.js"

function jsonForms(value) {
  const forms = new Set()
  const escaped = JSON.stringify(value).slice(1, -1)
  forms.add(escaped)
  if (escaped.includes("/")) forms.add(escaped.replace(/\//g, "\\/"))
  const ascii = escaped.replace(/[\u007f-\uffff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`)
  forms.add(ascii)
  forms.delete(value)
  return forms
}

/**
 * Pattern set for raw provider payloads (JSON text): every known value in its
 * literal and JSON-escaped forms (mapped back to the canonical value) plus the
 * high-confidence ("strong") regex rules, whose charsets need no JSON escaping.
 */
export function buildRawPatterns(patterns, mode) {
  const keywords = []
  for (const e of patterns.keywords) {
    keywords.push(e)
    if (e.ignoreCase || e.wholeWord) continue
    for (const form of jsonForms(e.value)) keywords.push({ ...e, value: form, canonical: e.canonical ?? e.value })
  }
  const regex = mode === "off" || mode === false ? [] : mode === "all" ? patterns.regex : patterns.regex.filter((r) => r.strong)
  return {
    keywords,
    keywordMatchers: compileKeywords(keywords),
    regex,
    exclude: patterns.exclude,
    errors: [],
  }
}

/**
 * Diagnostics: JSON paths (array indices collapsed) of string leaves that
 * still contain sensitive matches. Never returns values.
 */
export function locateHits(text, patterns, placeholderRe, limit = 10) {
  let obj
  try {
    obj = JSON.parse(text)
  } catch {
    return []
  }
  const out = new Set()
  const walk = (node, path) => {
    if (out.size >= limit) return
    if (typeof node === "string") {
      if (findMatches(node, patterns, placeholderRe).length > 0) out.add(path || "$")
      return
    }
    if (!node || typeof node !== "object") return
    if (Array.isArray(node)) node.forEach((v) => walk(v, `${path}[]`))
    else for (const [k, v] of Object.entries(node)) walk(v, path ? `${path}.${k}` : k)
  }
  walk(obj, "")
  return [...out]
}

const TEXTUAL = /json|text|xml|x-www-form-urlencoded|ndjson/i

/**
 * Redact a raw request body. Returns `{ text, count }`; `text` is null when the
 * body was not textual or not changed.
 */
export function guardRawText(raw, rawPatterns, session) {
  const res = redactText(raw, rawPatterns, session, { cache: false })
  return res.count > 0 ? res : { text: null, count: 0 }
}

export async function guardRequest(request, rawPatterns, session, diagnose) {
  if (!request || !request.body) return { request, count: 0 }
  const type = request.headers.get("content-type") ?? ""
  if (type && !TEXTUAL.test(type)) return { request, count: 0 }
  const body = await request.clone().text()
  const res = guardRawText(body, rawPatterns, session)
  if (!res.count) return { request, count: 0 }
  const paths = diagnose ? locateHits(body, diagnose, session.placeholderRe) : undefined
  const headers = new Headers(request.headers)
  headers.delete("content-length")
  const next = new Request(request.url, {
    method: request.method,
    headers,
    body: res.text,
    signal: request.signal,
    redirect: request.redirect,
  })
  return { request: next, count: res.count, paths }
}
