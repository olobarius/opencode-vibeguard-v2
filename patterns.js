import { escapeRegex } from "./util.js"
import { CREDENTIAL_RULES, buildContextRule } from "./credentials.js"
import { DUMMY_FRAGMENT, looksLikeIdentifier, looksLikeMemberExpr, looksLikeReference, shannon, validateAssignedValue } from "./validators.js"

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

const NON_SECRET_KEY = /(?:_?(?:count|type|length|len|name|names|id|ids|file|path|dir|url|uri|field|label|hint|policy|prompt|required|expiry|expires|expires_at|ttl|min|max|limit|usage|header|param|env|var|prefix|format|version)|tokens|tokenizer)$/i

function validateGeneric(_original, match) {
  const key = match.groups?.key ?? ""
  if (NON_SECRET_KEY.test(key) && !/credentials?$/i.test(key)) return false
  const quoted = match.groups?.secret !== undefined || match.groups?.secret2 !== undefined
  const value = match.groups?.secret ?? match.groups?.secret2 ?? match.groups?.secret3
  // `apiKey = makeKey(...)`: an unquoted value directly followed by a call is code.
  if (!quoted && (match.input ?? "")[match.index + match[0].length] === "(") return false
  // Prose like "Secrets: Dateien": single words (and dummy passwords) are left alone.
  return validateAssignedValue(value, quoted)
}

function validateUrlPassword(original) {
  if (/^\d{1,5}$/.test(original)) return false
  return validateAssignedValue(original, true)
}

export { shannon }

/**
 * High-entropy value next to a secret-ish key name. Rejects identifiers,
 * paths, file names, UUIDs and word-like values; hex needs >= 32 chars.
 */
export function makeEntropyValidator(opts = {}) {
  const minBits = Number.isFinite(opts.min_bits) ? opts.min_bits : 3.5
  const minHexBits = Number.isFinite(opts.min_hex_bits) ? opts.min_hex_bits : 3.0
  const minLen = Number.isFinite(opts.min_len) ? opts.min_len : 16
  return (original, match) => {
    const v = String(original ?? "")
    if (v.length < minLen || v.includes("__VG_")) return false
    const key = match?.groups?.key ?? ""
    if (NON_SECRET_KEY.test(key) && !/credentials?$/i.test(key)) return false
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) return false
    if (/^[A-Za-z]+$/.test(v) || /^[\d.\-]+$/.test(v)) return false
    if (/\.(?:[cm]?[jt]sx?|json|md|py|go|rs|java|kt|cs|css|s?html?|ya?ml|toml|txt|lock|png|jpe?g|gif|svg|xml|sh|ps1)$/i.test(v)) return false
    if (/^\.{0,2}\//.test(v) || /^[A-Za-z]:[\\/]/.test(v)) return false
    if (v.split(/[-_./+~]/).filter((s) => /^[A-Za-z]{4,}$/.test(s)).length >= 2) return false
    if (looksLikeIdentifier(v) || looksLikeMemberExpr(v)) return false
    if ((match?.input ?? "")[match.index + match[0].length] === "(") return false
    if (DUMMY_FRAGMENT.test(v)) return false
    if (looksLikeReference(v)) return false
    const h = shannon(v)
    if (/^[0-9a-f]+$/i.test(v)) return v.length >= 32 && h >= minHexBits
    const classes = [/[a-z]/, /[A-Z]/, /[0-9]/].filter((re) => re.test(v)).length
    if (classes < 2 || !/[0-9]/.test(v)) return false
    return h >= minBits
  }
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

// Issuer prefix + allowed lengths (Visa, Mastercard, Amex, Discover, Diners, JCB, Maestro, UnionPay).
const CARD_IIN = [
  [/^4/, [13, 16, 19]],
  [/^(?:5[1-5]|2(?:2[2-9][1-9]|2[3-9]\d|[3-6]\d\d|7[01]\d|720))/, [16]],
  [/^3[47]/, [15]],
  [/^(?:6011|65|64[4-9])/, [16, 17, 18, 19]],
  [/^3(?:0[0-5]|[68])/, [14, 15, 16, 17, 18, 19]],
  [/^35(?:2[89]|[3-8]\d)/, [16, 17, 18, 19]],
  [/^(?:5[06-9]|6[37])/, [12, 13, 14, 15, 16, 17, 18, 19]],
  [/^62/, [16, 17, 18, 19]],
]

function validateCard(original) {
  const d = original.replace(/[ -]/g, "")
  if (d.length < 13 || d.length > 19) return false
  if (!CARD_IIN.some(([re, lens]) => re.test(d) && lens.includes(d.length))) return false
  return luhn(d)
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

const KEY_NAMES = R`password|passwd|passphrase|passwort|kennwort|pwd|secret|api[_\-]?key|apikey|api[_\-]?secret|access[_\-]?key|access[_\-]?token|auth[_\-]?token|refresh[_\-]?token|id[_\-]?token|client[_\-]?secret|app[_\-]?secret|private[_\-]?key|secret[_\-]?key|encryption[_\-]?key|signing[_\-]?key|master[_\-]?key|connection[_\-]?string|credentials?|token|psk|wpa[_\-]?(?:passphrase|psk)|pre[_\-]?shared[_\-]?key|wifi[_\-]?password|wlan[_\-]?(?:passwort|key)`

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
  ...CREDENTIAL_RULES,
  [
    "generic_secret",
    {
      category: "SECRET",
      flags: "i",
      validate: validateGeneric,
      pattern: R`(?<![A-Za-z0-9])(?<key>[A-Za-z0-9_.\-]{0,40}?(?:${KEY_NAMES})[A-Za-z0-9_\-]{0,20})["']?\s*(?:=>|:=|=|:)\s*(?:"(?<secret>[^"\r\n]{4,256})"|'(?<secret2>[^'\r\n]{4,256})'|(?<secret3>[^\s"'${"`"},;&{}()<>\[\]]{4,256}))`,
    },
  ],
  [
    // Broader key context (also `--token VALUE`, `x-auth: VALUE`, `stripeKey`), but only
    // for random-looking values: Shannon entropy + character-class checks.
    "entropy_secret",
    {
      category: "HIGH_ENTROPY_SECRET",
      flags: "i",
      entropy: true,
      pattern: R`(?<![A-Za-z0-9])(?<key>-{0,2}[A-Za-z0-9_.\-]{0,40}?(?:key|auth|sig|signature|pass|pwd|cred|secret|token|license|private|salt|cookie|bearer)[A-Za-z0-9_\-]{0,20})["']?(?:\s*(?:=>|:=|=|:)\s*|[ \t]+)["']?(?<secret>[A-Za-z0-9+/=_\-.~]{16,256})(?![A-Za-z0-9+/=_\-.~])`,
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
  const hasGroup = /\(\?<(?:secret|user)\d*>/.test(peeled.pattern)
  if (hasGroup) f += "d"
  try {
    return {
      id,
      regex: new RegExp(peeled.pattern, f),
      category: sanitizeCategory(category),
      userCategory: sanitizeCategory(extra?.userCategory ?? "LOGIN"),
      hasGroup,
      strong: Boolean(extra?.strong),
      validate: typeof extra?.validate === "function" ? extra.validate : null,
      userFilter: typeof extra?.userFilter === "function" ? extra.userFilter : null,
      resolve: typeof extra?.resolve === "function" ? extra.resolve : null,
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
    const extra = rule.entropy ? { ...rule, validate: makeEntropyValidator(cfg.entropy) } : rule
    const compiled = compileRule(name, rule.pattern, rule.flags, rule.category, extra, errors)
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
  // Known secrets by match mode: exact (substring), word (whole token), context
  // (only after a credential key), off (registered but never replaced).
  const contextEntries = []
  for (const e of knownEntries) {
    const mode = e.mode ?? "exact"
    if (mode === "off") continue
    if (mode === "context") contextEntries.push(e)
    else keywords.push(mode === "word" ? { ...e, wholeWord: true } : e)
  }
  const ctxSpec = buildContextRule(contextEntries)
  if (ctxSpec) {
    const ctxRule = compileRule("known_context", ctxSpec.pattern, ctxSpec.flags, ctxSpec.category, ctxSpec, errors)
    if (ctxRule) regexRules.unshift(ctxRule)
  }

  return {
    // `keywords`: everything the registry knows (named placeholders); `matchKeywords`: literal matching.
    keywords: [...keywords, ...contextEntries],
    matchKeywords: keywords,
    keywordMatchers: compileKeywords(keywords),
    regex: opts.strongOnly ? regexRules.filter((r) => r.strong) : regexRules,
    exclude: new Set((Array.isArray(cfg.exclude) ? cfg.exclude : []).map((x) => String(x ?? ""))),
    errors,
    minSecretLen: Number.isFinite(cfg.min_secret_len) && cfg.min_secret_len > 0 ? Math.floor(cfg.min_secret_len) : 8,
  }
}
