import { escapeRegex } from "./util.js"

const R = String.raw

export function sanitizeCategory(input) {
  const safe = String(input ?? "")
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
  return safe || "TEXT"
}

/** Go-style leading `(?i)` / `(?m)` / `(?s)` flags. */
function peelInlineFlags(pattern, flags) {
  let p = String(pattern ?? "")
  let f = String(flags ?? "")
  for (let m; (m = p.match(/^\(\?([ims]+)\)/)); ) {
    p = p.slice(m[0].length)
    for (const c of m[1]) if (!f.includes(c)) f += c
  }
  return { pattern: p, flags: f }
}

// ---------------------------------------------------------------------------
// Validators (reduce false positives of the context-based rules)
// ---------------------------------------------------------------------------

const CODE_WORDS = new Set(
  (
    "string str number int integer float bool boolean any unknown null nil none undefined true false object " +
    "optional required text password passwd pass pwd secret secrets token tokens apikey api_key key credential " +
    "credentials changeme change_me example sample placeholder dummy redacted masked hidden empty default test " +
    "testing todo tbd value values input data config settings params props args kwargs req request res response " +
    "ctx context field fields type types function async await new return self this env environment yes no on off"
  ).split(" "),
)

function looksLikeReference(v) {
  return (
    /^(?:\$\{?|%\(|\{\{|<[^>]*>$|\[\[|process\.env|os\.environ|env\(|getenv|import\.meta|secrets\.|vars\.|ENV\[|System\.getenv)/i.test(v) ||
    /^(?:x{3,}|\*{3,}|\.{3,}|-{3,}|•{3,}|_{3,}|#{3,})$/i.test(v) ||
    /^(?:your|my|enter|insert|replace|put|add)[-_ ]?(?:own[-_ ]?)?(?:api|secret|token|key|password|pass|value)/i.test(v) ||
    /\b(?:changeme|replace[-_]?me|placeholder|redacted|example)\b/i.test(v)
  )
}

/** Value validator for `key = value` style rules. */
function validateAssignedValue(value, quoted) {
  const v = String(value ?? "").trim()
  if (v.length < 4) return false
  if (v.includes("__VG_")) return false
  if (CODE_WORDS.has(v.toLowerCase())) return false
  if (looksLikeReference(v)) return false
  if (/^\d{1,7}$/.test(v)) return false
  if (/^[A-Za-z_$][\w$]*\s*\(/.test(v)) return false
  if (!quoted) {
    if (/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(v)) return false // member expression
    if (/^[a-z]+(?:[A-Z][a-z0-9]*)+$/.test(v)) return false // camelCase identifier
    if (/^[A-Za-z_]+$/.test(v) && /pass|secret|token|key|cred/i.test(v)) return false // PASSWORD=PASSWORD
    if (/^(?:true|false|null|none|nil)[,;)]?$/i.test(v)) return false
  }
  return true
}

const NON_SECRET_KEY = /(?:_?(?:count|type|length|len|name|names|id|ids|file|path|dir|url|uri|field|label|hint|policy|prompt|required|expiry|expires|expires_at|ttl|min|max|limit|usage|header|param|env|var|prefix|format|version)|tokens|tokenizer)$/i

function validateGeneric(_original, match) {
  const key = match.groups?.key ?? ""
  if (NON_SECRET_KEY.test(key) && !/credentials?$/i.test(key)) return false
  const quoted = match.groups?.secret !== undefined || match.groups?.secret2 !== undefined
  const value = match.groups?.secret ?? match.groups?.secret2 ?? match.groups?.secret3
  return validateAssignedValue(value, quoted)
}

function validateUrlPassword(original) {
  if (/^\d{1,5}$/.test(original)) return false
  return validateAssignedValue(original, true)
}

function luhn(digits) {
  let sum = 0
  let alt = false
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48
    if (alt) {
      n *= 2
      if (n > 9) n -= 9
    }
    sum += n
    alt = !alt
  }
  return sum % 10 === 0
}

function validateCard(original) {
  const d = original.replace(/[ -]/g, "")
  return d.length >= 13 && d.length <= 19 && luhn(d)
}

function validateIban(original) {
  const s = original.replace(/ /g, "").toUpperCase()
  const r = s.slice(4) + s.slice(0, 4)
  let rem = 0
  for (const c of r) {
    const n = c >= "A" ? String(c.charCodeAt(0) - 55) : c
    for (const d of n) rem = (rem * 10 + Number(d)) % 97
  }
  return rem === 1
}

// ---------------------------------------------------------------------------
// Rules. `strong`: distinctive prefix, safe to apply on raw JSON payloads.
// A named group `secret` (or `secret2`/`secret3`) limits redaction to the value.
// ---------------------------------------------------------------------------

const KEY_NAMES = R`password|passwd|passphrase|passwort|kennwort|pwd|secret|api[_\-]?key|apikey|api[_\-]?secret|access[_\-]?key|access[_\-]?token|auth[_\-]?token|refresh[_\-]?token|id[_\-]?token|client[_\-]?secret|app[_\-]?secret|private[_\-]?key|secret[_\-]?key|encryption[_\-]?key|signing[_\-]?key|master[_\-]?key|connection[_\-]?string|credentials?|token`

/** @type {Array<[string, {pattern:string, flags?:string, category:string, strong?:boolean, validate?:Function}]>} */
const SECRET_LIST = [
  ["private_key", { category: "PRIVATE_KEY", strong: true, pattern: R`-----BEGIN[A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----(?:[\s\S]{0,16384}?-----END[A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----|[A-Za-z0-9+/=\s:,\\\-]*)` }],
  ["putty_key", { category: "PRIVATE_KEY", strong: true, pattern: R`PuTTY-User-Key-File-\d+:[\s\S]{0,8192}?Private-MAC: ?[0-9a-fA-F]+` }],
  ["age_key", { category: "PRIVATE_KEY", strong: true, pattern: R`AGE-SECRET-KEY-1[0-9A-Z]{58}` }],
  ["anthropic_key", { category: "ANTHROPIC_KEY", strong: true, pattern: R`sk-ant-[A-Za-z0-9_\-]{20,}` }],
  ["openrouter_key", { category: "OPENROUTER_KEY", strong: true, pattern: R`sk-or-v1-[A-Za-z0-9]{32,}` }],
  ["openai_key", { category: "OPENAI_KEY", strong: true, pattern: R`(?<![A-Za-z0-9_\-])sk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}|[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}|[A-Za-z0-9]{32,})` }],
  ["ai_keys", { category: "AI_API_KEY", strong: true, pattern: R`(?<![A-Za-z0-9])(?:gsk_[A-Za-z0-9]{40,}|xai-[A-Za-z0-9]{60,}|pplx-[A-Za-z0-9]{40,}|r8_[A-Za-z0-9]{30,}|lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}|tvly-(?:dev-)?[A-Za-z0-9]{20,}|hf_[A-Za-z]{30,})` }],
  ["google_api_key", { category: "GOOGLE_API_KEY", strong: true, pattern: R`AIza[0-9A-Za-z\-_]{35}` }],
  ["google_oauth", { category: "GOOGLE_OAUTH", strong: true, pattern: R`GOCSPX-[A-Za-z0-9_\-]{28}|ya29\.[0-9A-Za-z_\-]{20,}` }],
  ["github_token", { category: "GITHUB_TOKEN", strong: true, pattern: R`gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,}` }],
  ["gitlab_token", { category: "GITLAB_TOKEN", strong: true, pattern: R`gl(?:pat|dt|ptt|rt|cbt|oas|imt|ft|soat|agent)-[A-Za-z0-9_\-]{20,}` }],
  ["aws_access_key", { category: "AWS_ACCESS_KEY", strong: true, pattern: R`(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16}(?![A-Z0-9])` }],
  ["aws_secret", { category: "AWS_SECRET", flags: "i", pattern: R`aws.{0,20}?(?:secret|key).{0,20}?['"=:\s]\s*['"]?(?<secret>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])` }],
  ["azure_storage", { category: "AZURE_KEY", strong: true, pattern: R`AccountKey=(?<secret>[A-Za-z0-9+/]{86}==)` }],
  ["azure_sas", { category: "AZURE_SAS", pattern: R`[?&]sig=(?<secret>[A-Za-z0-9%+/=]{20,})` }],
  ["azure_ad_secret", { category: "AZURE_SECRET", strong: true, pattern: R`(?<![A-Za-z0-9_~.\-])[A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.\-]{31,34}(?![A-Za-z0-9_~.\-])` }],
  ["vault_token", { category: "VAULT_TOKEN", strong: true, pattern: R`hvs\.[A-Za-z0-9_\-]{24,}|[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-=]{60,}` }],
  ["slack_token", { category: "SLACK_TOKEN", strong: true, pattern: R`xox[abposr]-[A-Za-z0-9\-]{10,}|xapp-\d-[A-Za-z0-9\-]{10,}` }],
  ["slack_webhook", { category: "SLACK_WEBHOOK", strong: true, pattern: R`https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_\-]{20,}` }],
  ["discord_webhook", { category: "DISCORD_WEBHOOK", strong: true, pattern: R`https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{20,}` }],
  ["teams_webhook", { category: "TEAMS_WEBHOOK", strong: true, pattern: R`https://[a-z0-9\-]+\.webhook\.office\.com/webhookb2/[A-Za-z0-9@/_\-]{40,}` }],
  ["telegram_bot", { category: "TELEGRAM_TOKEN", strong: true, pattern: R`(?<!\d)\d{8,10}:AA[0-9A-Za-z_\-]{33}(?![0-9A-Za-z_\-])` }],
  ["stripe_key", { category: "STRIPE_KEY", strong: true, pattern: R`(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{20,}|whsec_[A-Za-z0-9]{24,}` }],
  ["sendgrid_key", { category: "SENDGRID_KEY", strong: true, pattern: R`SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}` }],
  ["mailgun_key", { category: "MAILGUN_KEY", strong: true, pattern: R`(?<![A-Za-z0-9])key-[0-9a-f]{32}(?![A-Za-z0-9])` }],
  ["twilio_key", { category: "TWILIO_KEY", strong: true, pattern: R`(?<![A-Za-z0-9])SK[0-9a-f]{32}(?![A-Za-z0-9])` }],
  ["npm_token", { category: "NPM_TOKEN", strong: true, pattern: R`npm_[A-Za-z0-9]{36}` }],
  ["pypi_token", { category: "PYPI_TOKEN", strong: true, pattern: R`pypi-[A-Za-z0-9_\-]{50,}` }],
  ["digitalocean_token", { category: "DIGITALOCEAN_TOKEN", strong: true, pattern: R`do[por]_v1_[a-f0-9]{64}` }],
  ["shopify_token", { category: "SHOPIFY_TOKEN", strong: true, pattern: R`shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}` }],
  ["databricks_token", { category: "DATABRICKS_TOKEN", strong: true, pattern: R`dapi[a-f0-9]{32}(?:-\d)?` }],
  ["atlassian_token", { category: "ATLASSIAN_TOKEN", strong: true, pattern: R`ATATT3[A-Za-z0-9_\-=]{150,}` }],
  ["linear_key", { category: "LINEAR_KEY", strong: true, pattern: R`lin_api_[A-Za-z0-9]{40}` }],
  ["notion_token", { category: "NOTION_TOKEN", strong: true, pattern: R`ntn_[A-Za-z0-9]{40,}|secret_[A-Za-z0-9]{43}` }],
  ["supabase_key", { category: "SUPABASE_KEY", strong: true, pattern: R`sbp_[a-f0-9]{40}|sb_secret_[A-Za-z0-9_\-]{20,}` }],
  ["docker_token", { category: "DOCKER_TOKEN", strong: true, pattern: R`dckr_pat_[A-Za-z0-9_\-]{20,}` }],
  ["sentry_dsn", { category: "SENTRY_DSN", pattern: R`https://(?<secret>[a-f0-9]{32})@[a-z0-9.\-]+\.ingest\.(?:[a-z]+\.)?sentry\.io/\d+` }],
  ["jwt", { category: "JWT", strong: true, pattern: R`eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}` }],
  ["url_credentials", { category: "URL_PASSWORD", validate: validateUrlPassword, pattern: R`(?<![A-Za-z0-9+.\-])[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://[^\s:/@'"<>]{1,128}:(?<secret>[^\s/@'"<>]{1,256})@[A-Za-z0-9.\-\[\]_]` }],
  ["auth_header", { category: "AUTH_HEADER", flags: "i", pattern: R`authorization["']?\s*[:=]\s*["']?(?:Basic|Bearer|Token|Digest)\s+(?<secret>[A-Za-z0-9._~+/\-]{8,}=*)` }],
  ["bearer_token", { category: "BEARER_TOKEN", pattern: R`(?<![A-Za-z0-9])Bearer\s+(?<secret>[A-Za-z0-9._~+/\-]{20,}=*)` }],
  [
    "generic_secret",
    {
      category: "SECRET",
      flags: "i",
      validate: validateGeneric,
      pattern: R`(?<![A-Za-z0-9])(?<key>[A-Za-z0-9_.\-]{0,40}?(?:${KEY_NAMES})[A-Za-z0-9_\-]{0,20})["']?\s*(?:=>|:=|=|:)\s*(?:"(?<secret>[^"\r\n]{4,256})"|'(?<secret2>[^'\r\n]{4,256})'|(?<secret3>[^\s"'${"`"},;{}()<>\[\]]{4,256}))`,
    },
  ],
]

const SECRET_RULES = new Map(SECRET_LIST)
// Back-compat aliases from earlier versions.
SECRET_RULES.set("github_pat", SECRET_RULES.get("github_token"))
SECRET_RULES.set("database_url", SECRET_RULES.get("url_credentials"))
const SECRET_GROUP = SECRET_LIST.map(([name]) => name)

const PII_RULES = new Map([
  ["email", { category: "EMAIL", flags: "i", pattern: R`[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}` }],
  ["china_phone", { category: "CHINA_PHONE", pattern: R`(?<!\d)1[3-9]\d{9}(?!\d)` }],
  ["china_id", { category: "CHINA_ID", pattern: R`(?<!\d)\d{17}[\dXx](?!\d)` }],
  ["uuid", { category: "UUID", pattern: R`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}` }],
  ["ipv4", { category: "IPV4", pattern: R`(?<![\w.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![\w.])` }],
  ["mac", { category: "MAC", flags: "i", pattern: R`(?<![0-9a-f:])(?:[0-9a-f]{2}[:\-]){5}[0-9a-f]{2}(?![0-9a-f:])` }],
  ["iban", { category: "IBAN", validate: validateIban, pattern: R`(?<![A-Z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?(?![A-Z0-9])` }],
  ["credit_card", { category: "CREDIT_CARD", validate: validateCard, pattern: R`(?<!\d)(?:\d[ \-]?){12,18}\d(?!\d)` }],
  ["stripe_publishable", { category: "STRIPE_KEY", pattern: R`pk_(?:live|test)_[0-9a-zA-Z]{24,}` }],
])

export const BUILTIN_NAMES = [...SECRET_GROUP, ...PII_RULES.keys()]

function compileRule(id, pattern, flags, category, extra, errors) {
  const peeled = peelInlineFlags(pattern, flags)
  let f = peeled.flags.replace(/[gdy]/g, "")
  f += "g"
  const hasGroup = /\(\?<secret\d?>/.test(peeled.pattern)
  if (hasGroup) f += "d"
  try {
    return {
      id,
      regex: new RegExp(peeled.pattern, f),
      category: sanitizeCategory(category),
      hasGroup,
      strong: Boolean(extra?.strong),
      validate: typeof extra?.validate === "function" ? extra.validate : null,
    }
  } catch (error) {
    errors.push({ pattern: peeled.pattern, flags: f, message: String(error?.message ?? error) })
    return null
  }
}

/**
 * Compile literal keywords into a few alternation regexes (longest first),
 * grouped by case-sensitivity and whole-word matching.
 * @param {Array<{value:string,category:string,ignoreCase?:boolean,wholeWord?:boolean,canonical?:string}>} entries
 */
export function compileKeywords(entries) {
  const groups = new Map()
  for (const e of entries) {
    if (!e?.value) continue
    const key = `${e.ignoreCase ? "i" : ""}${e.wholeWord ? "w" : ""}`
    if (!groups.has(key)) groups.set(key, { ignoreCase: Boolean(e.ignoreCase), wholeWord: Boolean(e.wholeWord), map: new Map() })
    const g = groups.get(key)
    const k = g.ignoreCase ? e.value.toLowerCase() : e.value
    if (!g.map.has(k)) g.map.set(k, e)
  }
  const out = []
  for (const g of groups.values()) {
    const values = [...g.map.keys()].sort((a, b) => b.length - a.length)
    if (values.length === 0) continue
    let body = values.map(escapeRegex).join("|")
    if (g.wholeWord) body = R`(?<![\p{L}\p{N}_])(?:${body})(?![\p{L}\p{N}_])`
    out.push({ regex: new RegExp(body, `gu${g.ignoreCase ? "i" : ""}`), map: g.map, ignoreCase: g.ignoreCase })
  }
  return out
}

/**
 * Build the pattern set used by the engine.
 * @param {object} raw `config.patterns`
 * @param {Array} knownEntries resolved known secrets (named, stable placeholders)
 * @param {{ strongOnly?: boolean }} [opts]
 */
export function buildPatternSet(raw, knownEntries = [], opts = {}) {
  const cfg = raw && typeof raw === "object" ? raw : {}
  const errors = []
  const regexRules = []

  for (const x of Array.isArray(cfg.regex) ? cfg.regex : []) {
    if (!x || typeof x !== "object") continue
    const pattern = String(x.pattern ?? "").trim()
    if (!pattern) continue
    const rule = compileRule(`custom:${pattern}`, pattern, typeof x.flags === "string" ? x.flags : "", x.category, { strong: x.strong }, errors)
    if (rule) regexRules.push(rule)
  }

  const builtin = cfg.builtin === undefined ? ["secrets"] : Array.isArray(cfg.builtin) ? cfg.builtin : []
  const names = new Set()
  for (const name of builtin) {
    const key = String(name ?? "").trim()
    if (key === "secrets") SECRET_GROUP.forEach((n) => names.add(n))
    else if (key === "all") BUILTIN_NAMES.forEach((n) => names.add(n))
    else if (key) names.add(key)
  }
  for (const name of names) {
    const rule = SECRET_RULES.get(name) ?? PII_RULES.get(name)
    if (!rule) {
      errors.push({ pattern: name, flags: "", message: "unknown builtin" })
      continue
    }
    const compiled = compileRule(name, rule.pattern, rule.flags, rule.category, rule, errors)
    if (compiled && !regexRules.some((r) => r.id === name)) regexRules.push(compiled)
  }

  const keywords = []
  for (const x of Array.isArray(cfg.keywords) ? cfg.keywords : []) {
    if (!x || typeof x !== "object") continue
    const value = String(x.value ?? "").trim()
    if (!value) continue
    keywords.push({
      value,
      category: sanitizeCategory(x.category ?? "KEYWORD"),
      ignoreCase: Boolean(x.ignore_case ?? x.ignoreCase),
      wholeWord: Boolean(x.whole_word ?? x.wholeWord),
    })
  }
  for (const e of knownEntries) keywords.push(e)

  return {
    keywords,
    keywordMatchers: compileKeywords(keywords),
    regex: opts.strongOnly ? regexRules.filter((r) => r.strong) : regexRules,
    exclude: new Set((Array.isArray(cfg.exclude) ? cfg.exclude : []).map((x) => String(x ?? ""))),
    errors,
    minSecretLen: Number.isFinite(cfg.min_secret_len) && cfg.min_secret_len > 0 ? Math.floor(cfg.min_secret_len) : 8,
  }
}
