import { restoreText } from "./restore.js"
import { redactText } from "./engine.js"
import { isPlainObject, mapStrings } from "./util.js"

/**
 * Copy-on-write redaction: returns a new structure when something was
 * redacted and the original reference otherwise. Prefer this over the
 * in-place variants for hook payloads that may share objects with state.
 */
export function redactValue(value, patterns, session, counter) {
  return mapStrings(value, (s) => {
    const res = redactText(s, patterns, session)
    if (counter && res.count) {
      counter.count += res.count
      for (const c of res.categories ?? []) counter.categories?.add(c)
    }
    return res.text
  })
}

/**
 * Deep-walk a tool argument object and restore every placeholder string in place.
 * - Walks Array / PlainObject / Map / Set
 * - Uses a WeakSet to avoid infinite recursion on cycles
 * @returns {number} number of restored strings
 * @param {unknown} value
 * @param {{ prefix: string, lookup(ph: string): string | undefined }} session
 */
export function restoreDeep(value, session) {
  const seen = new WeakSet()
  let changed = 0

  const restoreString = (v) => {
    const after = restoreText(v, session)
    if (after !== v) changed++
    return after
  }

  const walk = (node) => {
    if (!node || typeof node !== "object") return
    if (seen.has(node)) return
    seen.add(node)

    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) {
        const v = node[i]
        if (typeof v === "string") node[i] = restoreString(v)
        if (v && typeof v === "object") walk(v)
      }
      return
    }

    if (node instanceof Map) {
      for (const [k, v] of node.entries()) {
        const nk = typeof k === "string" ? restoreString(k) : k
        let nv = v
        if (typeof v === "string") nv = restoreString(v)
        else if (v && typeof v === "object") walk(v)
        if (nk !== k) node.delete(k)
        node.set(nk, nv)
      }
      return
    }

    if (node instanceof Set) {
      for (const v of node.values()) {
        if (typeof v === "string") {
          const after = restoreString(v)
          if (after !== v) {
            node.delete(v)
            node.add(after)
          }
        } else if (v && typeof v === "object") walk(v)
      }
      return
    }

    if (!isPlainObject(node)) return

    for (const key of Object.keys(node)) {
      const v = node[key]
      if (typeof v === "string") node[key] = restoreString(v)
      if (v && typeof v === "object") walk(v)
    }
  }

  walk(value)
  return changed
}

/**
 * Deep-walk an object and replace every sensitive string with a placeholder in place.
 * - Walks Array / PlainObject / Map / Set
 * - Uses a WeakSet to avoid infinite recursion on cycles
 * @returns {number} number of redacted strings
 * @param {unknown} value
 * @param {{ keywords: Array<{value:string,category:string}>, regex: Array<{pattern:string,flags:string,category:string}>, exclude: Set<string> }} patterns
 * @param {{ getOrCreatePlaceholder(original: string, category: string): string }} session
 */
export function redactDeep(value, patterns, session) {
  const seen = new WeakSet()
  let changed = 0

  const redactString = (v) => {
    const after = redactText(v, patterns, session).text
    if (after !== v) changed++
    return after
  }

  const walk = (node) => {
    if (!node || typeof node !== "object") return
    if (seen.has(node)) return
    seen.add(node)

    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) {
        const v = node[i]
        if (typeof v === "string") node[i] = redactString(v)
        if (v && typeof v === "object") walk(v)
      }
      return
    }

    if (node instanceof Map) {
      for (const [k, v] of node.entries()) {
        const nk = typeof k === "string" ? redactString(k) : k
        let nv = v
        if (typeof v === "string") nv = redactString(v)
        else if (v && typeof v === "object") walk(v)
        if (nk !== k) node.delete(k)
        node.set(nk, nv)
      }
      return
    }

    if (node instanceof Set) {
      for (const v of node.values()) {
        if (typeof v === "string") {
          const after = redactString(v)
          if (after !== v) {
            node.delete(v)
            node.add(after)
          }
        } else if (v && typeof v === "object") walk(v)
      }
      return
    }

    if (!isPlainObject(node)) return

    for (const key of Object.keys(node)) {
      const v = node[key]
      if (typeof v === "string") node[key] = redactString(v)
      if (v && typeof v === "object") walk(v)
    }
  }

  walk(value)
  return changed
}
