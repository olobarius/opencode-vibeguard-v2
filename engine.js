function subtractCovered(start, end, covered) {
  if (start >= end) return []
  const out = []
  let cur = start
  for (const c of covered) {
    if (c.end <= cur) continue
    if (c.start >= end) break
    if (c.start > cur) out.push({ start: cur, end: Math.min(c.start, end) })
    cur = Math.max(cur, c.end)
    if (cur >= end) break
  }
  if (cur < end) out.push({ start: cur, end })
  return out
}

function insertCovered(covered, span) {
  let i = 0
  while (i < covered.length && covered[i].start < span.start) i++
  covered.splice(i, 0, { start: span.start, end: span.end })
  const merged = []
  for (const c of covered) {
    const last = merged.at(-1)
    if (last && c.start <= last.end) {
      if (c.end > last.end) last.end = c.end
    } else merged.push(c)
  }
  return merged
}

/**
 * Spans to replace for one regex match: every matched `secret*` group and
 * `user*` group, or the whole match when the rule has no such groups.
 */
function ruleSpans(m) {
  const groups = m.indices?.groups
  if (!groups) return [{ start: m.index, end: m.index + m[0].length, user: false }]
  const out = []
  for (const [name, span] of Object.entries(groups)) {
    if (!span) continue
    if (/^secret\d*$/.test(name)) out.push({ start: span[0], end: span[1], user: false })
    else if (/^user\d*$/.test(name)) out.push({ start: span[0], end: span[1], user: true })
  }
  return out.length ? out : [{ start: m.index, end: m.index + m[0].length, user: false }]
}

/**
 * Find all sensitive spans in `text`.
 * Order of precedence: existing placeholders (never touched) > known values > regex rules.
 */
export function findMatches(text, patterns, placeholderRe) {
  let covered = []
  if (placeholderRe) {
    placeholderRe.lastIndex = 0
    for (const m of text.matchAll(placeholderRe)) covered.push({ start: m.index, end: m.index + m[0].length })
  }

  const planned = []
  const add = (start, end, category, canonical) => {
    for (const seg of subtractCovered(start, end, covered)) {
      const whole = seg.start === start && seg.end === end
      planned.push({ start: seg.start, end: seg.end, category, canonical: whole ? canonical : undefined })
      covered = insertCovered(covered, seg)
    }
  }

  for (const matcher of patterns.keywordMatchers ?? []) {
    matcher.regex.lastIndex = 0
    for (const m of text.matchAll(matcher.regex)) {
      const found = m[0]
      const entry = matcher.map.get(matcher.ignoreCase ? found.toLowerCase() : found)
      if (!entry || patterns.exclude.has(found)) continue
      // Case-insensitive hits restore to the casing actually seen, so they are not "known".
      const canonical = matcher.ignoreCase && found !== entry.value ? undefined : (entry.canonical ?? entry.value)
      add(m.index, m.index + found.length, entry.category, canonical)
    }
  }

  for (const rule of patterns.regex) {
    rule.regex.lastIndex = 0
    for (const m of text.matchAll(rule.regex)) {
      if (!m[0]) continue
      const spans = ruleSpans(m).filter((s) => s.start < s.end)
      if (spans.length === 0) continue
      const primary = spans.find((s) => !s.user) ?? spans[0]
      const original = text.slice(primary.start, primary.end)
      if (patterns.exclude.has(original) || patterns.exclude.has(m[0])) continue
      if (rule.validate && !rule.validate(original, m)) continue
      const keepUser = !rule.userFilter || rule.userFilter(m)
      for (const s of spans) {
        if (s.user && !keepUser) continue
        const value = text.slice(s.start, s.end)
        if (patterns.exclude.has(value)) continue
        if (rule.resolve) {
          const r = rule.resolve(value)
          if (!r) continue
          add(s.start, s.end, r.category, r.canonical)
        } else {
          add(s.start, s.end, s.user ? rule.userCategory : rule.category, undefined)
        }
      }
    }
  }

  planned.sort((a, b) => a.start - b.start)
  return planned
}

/**
 * Redact sensitive values in a string.
 * @returns {{ text: string, count: number }}
 */
export function redactText(input, patterns, session, opts) {
  const text = typeof input === "string" ? input : String(input ?? "")
  if (!text) return { text, count: 0 }
  const useCache = opts?.cache !== false

  const cached = useCache ? session.cacheGet?.(text, patterns) : undefined
  if (cached !== undefined) return { text: cached.text, count: cached.count, categories: cached.categories ?? [] }

  const planned = findMatches(text, patterns, session.placeholderRe)
  if (planned.length === 0) {
    if (useCache) session.cacheSet?.(text, patterns, text, 0, [])
    return { text, count: 0, categories: [] }
  }

  let out = ""
  let cur = 0
  for (const m of planned) {
    const original = text.slice(m.start, m.end)
    const placeholder =
      (m.canonical !== undefined ? session.knownPlaceholder?.(m.canonical) : undefined) ??
      session.getOrCreatePlaceholder(original, m.category)
    out += text.slice(cur, m.start) + placeholder
    cur = m.end
  }
  out += text.slice(cur)
  const categories = [...new Set(planned.map((m) => m.category))]
  if (useCache) session.cacheSet?.(text, patterns, out, planned.length, categories)
  return { text: out, count: planned.length, categories }
}
