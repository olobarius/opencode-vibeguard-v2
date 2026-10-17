import { placeholderCategory } from "./session.js"
import { mapStrings } from "./util.js"

export function createRestoreStats() {
  return { restored: 0, categories: new Set(), unknown: new Set() }
}

/**
 * Restore placeholders in a string; unknown placeholders are left as-is and
 * reported in `stats.unknown`.
 * @param {string} input
 * @param {{ prefix: string, placeholderRe?: RegExp, lookup(ph: string): string | undefined }} session
 * @param {ReturnType<typeof createRestoreStats>} [stats]
 * @param {(original: string) => string} [encode] optional encoder for the inserted value
 */
export function restoreText(input, session, stats, encode) {
  const text = typeof input === "string" ? input : String(input ?? "")
  if (!text || !text.includes(session.prefix)) return text
  const re = session.placeholderRe
  re.lastIndex = 0
  return text.replace(re, (ph) => {
    const original = session.lookup(ph)
    if (original === undefined) {
      stats?.unknown.add(ph)
      return ph
    }
    if (stats) {
      stats.restored++
      stats.categories.add(placeholderCategory(ph, session.prefix))
    }
    return encode ? encode(original) : original
  })
}

/** Copy-on-write restore of every string inside `value`. */
export function restoreValue(value, session, stats) {
  return mapStrings(value, (s) => restoreText(s, session, stats))
}

/** Dry run: which placeholders does `value` contain? */
export function scanPlaceholders(value, session) {
  const stats = createRestoreStats()
  mapStrings(value, (s) => {
    restoreText(s, session, stats)
    return s
  })
  return stats
}
