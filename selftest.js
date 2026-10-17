import { randomBytes } from "node:crypto"
import { redactText } from "./engine.js"
import { buildRawPatterns, guardRawText } from "./guard.js"
import { buildPatternSet } from "./patterns.js"
import { compileToolRules } from "./policy.js"
import { restoreText } from "./restore.js"
import { KnownRegistry, PlaceholderSession } from "./session.js"
import { createSseRestorer } from "./stream.js"

function alnum(n) {
  return randomBytes(n * 2)
    .toString("base64")
    .replace(/[^A-Za-z0-9]/g, "")
    .slice(0, n)
}

/**
 * End-to-end self-test of the redaction pipeline with random canaries
 * (never real secrets). Runs at setup and via `/vibeguard test`.
 * @returns {{ ok: boolean, checks: Array<{ name: string, ok: boolean, detail?: string }> }}
 */
export function runSelfTest(config) {
  const prefix = config.prefix ?? "__VG_"
  const checks = []
  // `warn` checks are reported but do not fail the test (protection still works).
  const check = (name, fn, warn = false) => {
    try {
      const r = fn()
      checks.push(r === true ? { name, ok: true, warn } : { name, ok: false, warn, detail: String(r) })
    } catch (error) {
      checks.push({ name, ok: false, warn, detail: String(error?.message ?? error) })
    }
  }

  const canary = `vg-canary-${alnum(16)}`
  const token = `ghp_${alnum(36)}`
  const patterns = buildPatternSet(config.patterns, [{ value: canary, category: "VG_SELFTEST" }])
  const known = new KnownRegistry({ prefix, key: randomBytes(32) })
  known.load(patterns.keywords)
  const session = new PlaceholderSession({ prefix, known })
  const builtin = config.patterns?.builtin
  const secretsOn = builtin === undefined || (Array.isArray(builtin) && (builtin.includes("secrets") || builtin.includes("all")))

  let redacted = ""
  check("rules compile", () => patterns.errors.length === 0 || `${patterns.errors.length} invalid rule(s) skipped: ${patterns.errors.map((e) => e.pattern).join(", ")}`, true)
  check("known value is redacted", () => {
    redacted = redactText(`user said ${canary} here`, patterns, session).text
    return (!redacted.includes(canary) && redacted.includes(`${prefix}VG_SELFTEST_`)) || "canary still visible"
  })
  check("placeholder restores to the real value", () => restoreText(redacted, session) === `user said ${canary} here` || "restore mismatch")
  check("redaction is idempotent", () => redactText(redacted, patterns, session).text === redacted || "placeholder was re-redacted")
  if (secretsOn) {
    check("token rule detects a GitHub token", () => !redactText(`t=${token}`, patterns, session).text.includes(token) || "token still visible")
  }
  check("raw payload guard catches JSON-escaped value", () => {
    const raw = buildRawPatterns(patterns, config.guard?.regex ?? "strong")
    const body = JSON.stringify({ messages: [{ content: `"${canary}"` }] })
    const res = guardRawText(body, raw, session)
    return (res.count > 0 && !res.text.includes(canary)) || "guard missed the canary"
  })
  check("stream restore joins split placeholders", () => {
    const ph = known.placeholderFor(canary)
    const r = createSseRestorer(session)
    const chunk = (t) => `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: t } }] })}\n\n`
    const out = r.push(chunk(`a ${ph.slice(0, 7)}`) + chunk(ph.slice(7)) + chunk(" b") + "data: [DONE]\n\n") + r.end()
    const text = out
      .split("\n\n")
      .filter((e) => e.startsWith("data: {"))
      .map((e) => JSON.parse(e.slice(6)).choices[0].delta.content)
      .join("")
    return text === `a ${canary} b` || "split placeholder not restored"
  })
  check(
    "tool policy compiles",
    () => {
      const rules = compileToolRules(config.restore?.tools)
      return rules.length > 0 || "no valid restore.tools rules (every tool gets real values)"
    },
    true,
  )
  return { ok: checks.every((c) => c.ok || c.warn), warnings: checks.filter((c) => !c.ok && c.warn).length, checks }
}
