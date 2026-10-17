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

function secretSpan(m) {
  if (m.indices?.groups) {
    for (const name of ["secret", "secret2", "secret3"]) {
      const span = m.indices.groups[name]
      if (span) return span
    }
  }
  return [m.index, m.index + m[0].length]
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
      const [start, end] = secretSpan(m)
      if (start >= end) continue
      const original = text.slice(start, end)
      if (patterns.exclude.has(original) || patterns.exclude.has(m[0])) continue
      if (rule.validate && !rule.validate(original, m)) continue
      add(start, end, rule.category, undefined)
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
