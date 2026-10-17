import { escapeRegex } from "./util.js"
import {
  COMMON_PASSWORDS,
  shannon,
  validateAssignedValue,
  validateStatedSecret,
  validateUsername,
} from "./validators.js"

const R = String.raw
const L = "A-Za-zÄÖÜäöüß"
const SP = R`[^\S\r\n]`

/** Case-insensitive literal for patterns that otherwise stay case-sensitive. */
function ci(s) {
  return s.replace(/[a-z]/gi, (c) => `[${c.toLowerCase()}${c.toUpperCase()}]`)
}

// ---------------------------------------------------------------------------
// Strength assessment of known secrets
// ---------------------------------------------------------------------------

/**
 * strong: random-looking, safe to replace everywhere (substring match).
 * medium: words / identifier-like, replace only as a whole token.
 * weak:   short, a single word, a word with a short suffix or a top-list password.
 *         Replacing it everywhere breaks normal text and code and still gives the
 *         word away through context; it is only replaced in a credential context.
 * @returns {{ strength: "strong" | "medium" | "weak", reasons: string[] }}
 */
export function assessSecret(value) {
  const v = String(value ?? "")
  const reasons = []
  const lower = v.toLowerCase()
  if (COMMON_PASSWORDS.has(lower) || COMMON_PASSWORDS.has(lower.replace(/[!?.]+$/, ""))) reasons.push("dummy or top-list password")
  if (v.length < 8) reasons.push("shorter than 8 characters")
  if (/^\d+$/.test(v)) reasons.push("digits only")
  else if (v.length < 16 && new RegExp(`^[${L}]+$`).test(v)) reasons.push("a single word")
  else if (v.length < 16 && new RegExp(`^[${L}]{2,}[0-9!?.#*+_\\-$%&@]{1,6}$`).test(v)) reasons.push("a word with a short suffix")
  else if (v.length < 16 && new RegExp(`^[0-9!?.#*+_\\-$%&@]{1,6}[${L}]{2,}$`).test(v)) reasons.push("a word with a short prefix")
  if (reasons.length) return { strength: "weak", reasons }

  const h = shannon(v)
  if (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(v) && (/[a-z][A-Z]/.test(v) || v.includes("_")) && h < 3.8 && v.length < 40) {
    return { strength: "medium", reasons: ["looks like a code identifier"] }
  }
  const letters = (v.match(new RegExp(`[${L}]{3,}`, "g")) ?? []).join("").length
  if (letters / v.length >= 0.7 && h < 3.7) return { strength: "medium", reasons: ["mostly words"] }
  return { strength: "strong", reasons: [] }
}

export const MATCH_MODES = new Set(["exact", "word", "context", "off"])

export function resolveMode(entry, overrides, weakMode) {
  const explicit = entry.mode ?? overrides?.[entry.category]
  if (MATCH_MODES.has(explicit)) return explicit
  if (entry.strength === "strong") return "exact"
  if (entry.strength === "medium") return "word"
  return MATCH_MODES.has(weakMode) ? weakMode : "context"
}

// ---------------------------------------------------------------------------
// Credential context (shared by the context rule and natural-language rules)
// ---------------------------------------------------------------------------

const PW_KEYS = R`passwor[dt]|passwd|pass-?phrase|kennwort|zugangscode|wlan-?(?:passwort|schl(?:ü|ue)ssel|key)|wifi[- ]?(?:password|key)|pwd|pw`
const KEY = R`(?<![${L}0-9_])(?<key>[${L}0-9]{0,20}-?(?:${PW_KEYS}))(?![${L}])`
const VERB = R`ist|lautet|lautete|war|is|was|heißt|heisst`
const FILLER = R`(?:${SP}+(?!(?:${VERB})(?![${L}]))[${L}0-9.\-/]{1,30}){0,5}?`
const SEP = R`(?:${SP}*(?:[:=]{1,2}|->|=>|→)${SP}*|${SP}+(?:${VERB})(?:${SP}+(?:jetzt|nun|now|neu|new|noch|still|weiterhin))?${SP}*:?${SP}+)`
const QUOTE = R`["'„“»‚‘\x60]?`
const VALUE_CHARS = R`[^\s"'„“”«»‚‘’\x60<>()\[\]{}|]`
const VALUE = R`(?<secret>${VALUE_CHARS}{3,63}[^\s"'„“”«»‚‘’\x60<>()\[\]{}|.,;:])`

/**
 * One rule for all known secrets in "context" mode: replaced only right after a
 * credential key ("Passwort: x", "pw = x", "Kennwort für Router ist x"), in URL
 * userinfo, after `-p` / `--password` / `pass:` / `%` (smbclient) and in netrc lines.
 * Values stay case-sensitive; the keys are case-insensitive.
 */
export function buildContextRule(entries) {
  const map = new Map()
  for (const e of entries) if (e?.value && !map.has(e.value)) map.set(e.value, e)
  if (map.size === 0) return null
  const values = [...map.keys()].sort((a, b) => b.length - a.length).map(escapeRegex).join("|")
  const keys = ci(R`passwort|password|passwd|passphrase|kennwort|zugangscode|pwd|pw|pin|secret|geheimnis|credentials|zugangsdaten|anmeldedaten|login`)
  const verbs = ci(VERB)
  const prefix = [
    R`(?<![${L}0-9_])[${L}0-9]{0,20}-?(?:${keys})(?![${L}])(?:${SP}+[${L}0-9.\-/]{1,30}){0,5}?${SP}*(?:[:=]{1,2}|->|=>|${SP}(?:${verbs}))?${SP}*["'„“»\x60]?`,
    R`://[^\s:/@]{1,128}:`,
    R`${SP}-p`,
    R`${SP}-P${SP}+`,
    R`${SP}--?(?:${ci("password|passwd|pass|pw|token|secret")})(?:=|${SP}+)["']?`,
    R`(?:${ci("pass")}):`,
    R`[^\s%]%`,
    R`/${ci("pass(?:word)?")}:`,
  ].join("|")
  return {
    category: "SECRET",
    pattern: R`(?:${prefix})(?<secret>${values})(?![${L}0-9_])`,
    flags: "",
    resolve: (original) => {
      const e = map.get(original)
      return e ? { category: e.category, canonical: e.value } : null
    },
  }
}

// ---------------------------------------------------------------------------
// Validators for credential rules
// ---------------------------------------------------------------------------

function nearPassword(match, span = 200) {
  const input = match.input ?? ""
  const start = Math.max(0, match.index - span)
  const end = Math.min(input.length, match.index + match[0].length + span)
  return /passwor[dt]|kennwort|passwd|pass-?phrase|\bpwd?\b|\bpin\b|\bpass\b|zugangscode/i.test(input.slice(start, end))
}

function groupValue(m, ...names) {
  for (const n of names) if (m.groups?.[n] !== undefined) return m.groups[n]
  return undefined
}

/** First matched `secret*` / `user*` group (rules with alternations number their groups). */
function firstOf(m, test) {
  for (const [name, value] of Object.entries(m.groups ?? {})) if (value !== undefined && test(name)) return value
  return undefined
}
const secretOf = (m) => firstOf(m, isSecretGroup)
const userOf = (m) => firstOf(m, isUserGroup)

const validateStated = (_o, m) => !continuesAsCode(m) && validateStatedSecret(groupValue(m, "secret"))

const validateBareStated = (_o, m) => {
  const v = groupValue(m, "secret") ?? ""
  // Without "ist" / ":" the value must not look like a word: needs a digit or an inner symbol.
  const core = v.replace(/[?!.]+$/, "")
  if (!/[0-9]/.test(core) && !/[^A-Za-zÄÖÜäöüß]/.test(core)) return false
  return validateStatedSecret(v)
}

const validateFlag = (_o, m) => {
  const quoted = m.groups?.secret !== undefined || m.groups?.secret2 !== undefined
  return validateAssignedValue(groupValue(m, "secret", "secret2", "secret3"), quoted)
}

const validateCliSecret = (_o, m) => validateAssignedValue(secretOf(m), true)

const validatePair = (_o, m) => {
  const secret = secretOf(m)
  if (secret === undefined) return false
  return validateAssignedValue(secret, true)
}

/** `username: parts[0]`, `user = getUser()`, `login: auth.user`: the value continues as code. */
function continuesAsCode(m) {
  const input = m.input ?? ""
  const i = m.index + m[0].length
  const next = input[i]
  const after = input[i + 1] ?? ""
  if (next === "(" || next === "[") return true
  // ".foo" / "?.foo" continue an expression; "." at the end of a sentence does not.
  if (next === "." && /[A-Za-z_$]/.test(after)) return true
  return next === "?" && after === "."
}

const validateLogin = (_o, m) => !continuesAsCode(m) && validateUsername(userOf(m)) && nearPassword(m)

/** Keep the username span only when it looks like a real login (not admin/root/test). */
function pairUserFilter(m) {
  const user = userOf(m)
  return user !== undefined && validateUsername(user)
}

// ---------------------------------------------------------------------------
// Credential rules (part of the default "secrets" group)
// ---------------------------------------------------------------------------

const USER_KEYS = R`benutzer(?:name|kennung)?|nutzer(?:name)?|anmelde(?:name|kennung)|kennung|username|user(?:[ _-]?(?:name|id))?|login(?:[ _-]?name)?|account(?:[ _-]?name)?|konto|e-?mail|uid`
const USER_VALUE = R`(?<user>[^\s"'„“”,;()<>\[\]{}|]{1,63}[^\s"'„“”,;()<>\[\]{}|.:])`
const FLAG_VALUE = R`(?:"(?<secret>[^"\r\n]{3,200})"|'(?<secret2>[^'\r\n]{3,200})'|(?<secret3>[^\s"'|;&<>(){}\[\]$%\x60][^\s"'|;&<>\x60]{2,199}))`
const BARE = R`[^\s"'|;&<>\x60]`

/** @type {Array<[string, object]>} */
export const CREDENTIAL_RULES = [
  [
    "password_hash",
    { category: "PASSWORD_HASH", strong: true, pattern: R`\$(?:apr1|2[abxy]|5|6|y|argon2(?:id|i|d))\$[A-Za-z0-9./$=,+\-]{20,}` },
  ],
  [
    "stated_password",
    {
      // "Mein Passwort ist X", "Kennwort für den Router: X", "the password is X", "PW: X"
      category: "PASSWORD",
      flags: "i",
      validate: validateStated,
      pattern: R`${KEY}${FILLER}${SEP}${QUOTE}${VALUE}`,
    },
  ],
  [
    "stated_password_bare",
    {
      // "pw Xy7!kL9", "password Xy7!kL9" (no separator: value needs a digit or symbol)
      category: "PASSWORD",
      flags: "i",
      validate: validateBareStated,
      pattern: R`${KEY}${SP}+${VALUE}`,
    },
  ],
  [
    "stated_pin",
    {
      category: "PIN",
      pattern: R`(?<![${L}])(?:PIN|Pin|PUK|SIM-PIN|PIN-Code|Pincode|PIN-Nummer|Geheimzahl)(?:${SP}+[${L}0-9.\-]{1,30}){0,4}?${SP}*(?:[:=]|${SP}(?:ist|lautet|is|was|war))${SP}*["']?(?<secret>\d{4,8})(?!\d)`,
    },
  ],
  [
    "credential_pair",
    {
      // "user/pass: max/Xy7!", "Zugangsdaten: max / Xy7!", "Login: max:Xy7!"
      category: "PASSWORD",
      userCategory: "LOGIN",
      flags: "i",
      validate: validatePair,
      userFilter: pairUserFilter,
      pattern: R`(?<![${L}0-9_])(?:(?:user(?:name)?|login|benutzer(?:name)?)${SP}*/${SP}*(?:pass(?:word|wort)?|pw|pwd|kennwort)|zugangsdaten|anmeldedaten|login-?daten|credentials|creds)${SP}*(?:[:=]|${SP}(?:sind|are|lauten))${SP}*["']?(?<user>[A-Za-z0-9ÄÖÜäöüß][A-Za-z0-9ÄÖÜäöüß._@+\\\-]{1,63})${SP}*(?:/|:|,|${SP})${SP}*["']?(?<secret>[^\s,;"'()\[\]{}<>]{3,128})`,
    },
  ],
  [
    "stated_login",
    {
      // "Benutzer: max.mustermann" / "Login ist m.mueller@firma.de" when a password is nearby
      category: "LOGIN",
      userCategory: "LOGIN",
      flags: "i",
      validate: validateLogin,
      pattern: R`(?<![${L}0-9_])(?:${USER_KEYS})(?![${L}])${SP}*(?:[:=]|${SP}(?:ist|lautet|is))${SP}*["'„“]?${USER_VALUE}`,
    },
  ],
  [
    "cli_password_flag",
    {
      // --password X, --token=X, -Password "X" (PowerShell), --client-secret X, -storepass X
      category: "PASSWORD",
      flags: "i",
      validate: validateFlag,
      pattern: R`(?<![\w-])(?:--(?:password|passwd|pass|pw|passphrase|db-password|http-password|ftp-password|proxy-password|client-secret|secret|api-key|apikey|token|auth-token|access-token|storepass|keypass|srcstorepass|deststorepass)|-(?:Password|ApiKey|Token|Secret|ClientSecret|AccessToken|Passphrase|storepass|keypass))(?:=|${SP}+)${FLAG_VALUE}`,
    },
  ],
  [
    "cli_password_tools",
    {
      // mysql -pX, sshpass -p X, 7z -pX, zip -P X, sqlcmd -P X, openssl -pass pass:X, ConvertTo-SecureString "X" -AsPlainText
      category: "PASSWORD",
      validate: validateCliSecret,
      pattern: [
        R`\b(?:mysql|mysqldump|mysqladmin|mysqlimport|mariadb|mariadb-dump)\b[^\r\n|;&]*?${SP}-p(?<secret>[^\s"'\-]${BARE}{2,127})`,
        R`\bsshpass\b[^\r\n|;&]*?${SP}-p${SP}*["']?(?<secret2>[^\s"']{3,128})`,
        R`\b7z[az]?\b[^\r\n|;&]*?${SP}-p(?<secret3>[^\s"'\-]${BARE}{2,127})`,
        R`\b(?:zip|unzip|sqlcmd|bcp|osql|isql)\b[^\r\n|;&]*?${SP}-P${SP}*["']?(?<secret4>[^\s"'\-]${BARE}{2,127})`,
        R`-pass(?:in|out)?${SP}+pass:(?<secret5>${BARE}{3,128})`,
        R`ConvertTo-SecureString${SP}+(?:-String${SP}+)?["'](?<secret6>[^"'\r\n]{3,200})["'][^\r\n]{0,40}?-AsPlainText`,
      ].join("|"),
    },
  ],
  [
    "cli_user_password",
    {
      // curl -u user:pass, smbclient -U user%pass, net use ... /user:x pass, sqlplus user/pass@db, NetworkCredential("u","p")
      category: "PASSWORD",
      userCategory: "LOGIN",
      validate: validatePair,
      userFilter: pairUserFilter,
      pattern: [
        R`(?:${SP}(?:-u|--user|--proxy-user)|--http-user=)${SP}*["']?(?<user>[^\s:"'@$]{1,64}):(?<secret>[^\s"'@]{3,128})`,
        R`${SP}-U${SP}+["']?(?<user2>[^\s%"']{1,64})%(?<secret2>[^\s"']{3,128})`,
        R`\bnet${SP}+use\b[^\r\n]*?/user:(?<user3>[^\s"']+)${SP}+(?<secret3>[^\s/"'*][^\s"']{2,127})`,
        R`\bsqlplus${SP}+(?<user4>[A-Za-z0-9_$#]{1,64})/(?<secret4>[^\s@"']{3,128})`,
        R`NetworkCredential\(${SP}*["'](?<user5>[^"']{1,64})["']${SP}*,${SP}*["'](?<secret5>[^"'\r\n]{3,200})["']`,
        R`\bmachine${SP}+\S+${SP}+login${SP}+(?<user6>\S+)${SP}+password${SP}+(?<secret6>\S{3,128})`,
      ].join("|"),
    },
  ],
  [
    "credential_files",
    {
      // .pgpass lines, netrc "password X" lines, <password>X</password>, docker config "auth"
      category: "PASSWORD",
      flags: "im",
      validate: validateCliSecret,
      pattern: [
        R`^(?:[A-Za-z0-9.\-*]+):(?:\d{1,5}|\*):(?:[^:\s]+):(?<user>[^:\s]+):(?<secret>[^\s:]{3,128})$`,
        R`^${SP}*password${SP}+(?<secret2>\S{3,128})${SP}*$`,
        R`<(?:password|passwd|pwd|passphrase|secret|apiKey|api_key|token|accessToken|clientSecret|connectionString)>(?<secret3>[^<\r\n]{3,256})</`,
        R`"auth"${SP}*:${SP}*"(?<secret4>[A-Za-z0-9+/]{12,}={0,2})"`,
      ].join("|"),
    },
  ],
]

/** Named groups that hold a secret value (`secret`, `secret2`, ...) or a username (`user`, `user2`, ...). */
export function isSecretGroup(name) {
  return /^secret\d*$/.test(name)
}
export function isUserGroup(name) {
  return /^user\d*$/.test(name)
}
