/**
 * Shared value checks for the detection rules.
 *
 * Philosophy: values that are public anyway (dummy passwords in examples,
 * top-list passwords, single dictionary words) are not worth a placeholder.
 * Replacing them only confuses the model and, through the surrounding text,
 * still gives the word away.
 */

export const CODE_WORDS = new Set(
  (
    "string str number int integer float bool boolean any unknown null nil none undefined true false object " +
    "optional required text password passwd pass pwd secret secrets token tokens apikey api_key key credential " +
    "credentials changeme change_me example sample placeholder dummy redacted masked hidden empty default test " +
    "testing todo tbd value values input data config settings params props args kwargs req request res response " +
    "ctx context field fields type types function async await new return self this env environment yes no on off " +
    "yield yield* typeof instanceof void delete class import require const let var static public private protected " +
    "readonly export default extends implements interface enum struct schema"
  ).split(" "),
)

/** `Schema.Uint8Array`, `kvs.getUint8Array`, `os.environ`: dotted code paths made of words. */
export function looksLikeMemberExpr(v) {
  const s = String(v ?? "")
  if (!/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(s)) return false
  return wordCoverage(s.replace(/\./g, "")) >= 0.6
}

/** Dummy values from docs/examples and the very top of public password lists. */
export const COMMON_PASSWORDS = new Set(
  (
    "password password1 password12 password123 password1234 password! passw0rd p@ssw0rd p@ssword pa55word pa$$word " +
    "pass pass1 pass12 pass123 pass1234 passwort passwort1 passwort123 kennwort kennwort1 geheim geheim1 geheim123 " +
    "secret secret1 secret12 secret123 s3cr3t s3cret mysecret topsecret supersecret verysecret notasecret secretpassword " +
    "admin admin1 admin12 admin123 admin1234 administrator root root123 toor qwerty qwertz qwerty123 qwertz123 " +
    "qwertyuiop asdf asdfgh asdfghjkl yxcvbnm 1234 12345 123456 1234567 12345678 123456789 1234567890 0000 1111 " +
    "111111 000000 654321 abc123 abcd1234 abcdef letmein letmein1 welcome welcome1 welcome123 willkommen " +
    "willkommen1 hallo hallo123 hello hello123 test test1 test12 test123 test1234 testtest tester testing " +
    "demo demo123 guest gast user user1 user123 benutzer default changeme changeme1 changeit change_me changethis " +
    "foobar foo bar baz qux example sample dummy placeholder hunter2 iloveyou monkey dragon master sunshine " +
    "princess football baseball shadow superman batman trustno1 starwars mypassword mypass mypwd yourpassword " +
    "your_password your-password yourpass pwd pwd123 postgres mysql oracle sa raspberry ubuntu vagrant docker " +
    "kubernetes minio minioadmin rabbitmq guest123 xxx xxxx xxxxx xxxxxx xxxxxxxx xxxxxxxxxx none null " +
    "letmeinplease opensesame sesam sesamoeffnedich correcthorsebatterystaple"
  ).split(" "),
)

export const COMMON_USERS = new Set(
  (
    "admin administrator root user user1 username test testuser tester guest gast sa postgres mysql oracle demo " +
    "example sample default anonymous nobody alice bob charlie dave eve mallory john jane johndoe janedoe jdoe " +
    "max mustermann maxmustermann foo bar foobar me myuser youruser your_username your-username dein_name"
  ).split(" "),
)

/** Words that commonly follow "Passwort ist ..." without being a password. */
export const STOPWORDS = new Set(
  (
    "falsch richtig korrekt zu sehr nicht kein keine leer ungültig ungueltig abgelaufen gesperrt geändert geaendert " +
    "neu sicher unsicher schwach stark lang kurz vergessen erforderlich notwendig nötig noetig optional gleich " +
    "identisch derselbe dasselbe dieselbe hier unten oben folgendes folgendermaßen gespeichert hinterlegt " +
    "verschlüsselt verschluesselt bekannt unbekannt siehe steht liegt findest bitte noch immer auch jetzt dann " +
    "wird wurde muss soll kann darf sind haben hat mein meins dein deins sein ihr unser euer das der die den dem " +
    "ein eine einen einem und oder aber für fuer mit ohne von vom im in am an auf aus bei per via über ueber unter " +
    "wrong incorrect invalid expired required missing empty correct changed reset set stored saved encrypted " +
    "hashed hidden too not the a an my your this that same below above here following provided needed weak " +
    "strong long short secure insecure ok okay fine valid unknown known see please still also now then will " +
    "must should can may are have has and or but for with without from into onto at by via over under " +
    "manager management policy policies hash hashes field feld eingabe input prompt dialog maske reset ändern aendern"
  ).split(" "),
)

export function looksLikeReference(v) {
  return (
    /^(?:\$\{?|%\(|%[A-Za-z_]+%|\{\{|<[^>]*>?$|\[\[|process\.env|os\.environ|env\(|getenv|import\.meta|secrets\.|vars\.|ENV\[|System\.getenv)/i.test(v) ||
    /^(?:x{3,}|\*{3,}|\.{3,}|-{3,}|•{3,}|_{3,}|#{3,}|▒+)$/i.test(v) ||
    /^(?:your|my|enter|insert|replace|put|add|dein|ihr|mein)[-_ ]?(?:own[-_ ]?)?(?:api|secret|token|key|password|passwort|pass|value)/i.test(v) ||
    /\b(?:changeme|replace[-_]?me|placeholder|redacted|example)\b/i.test(v)
  )
}

/** Shannon entropy in bits per character. */
export function shannon(s) {
  const freq = new Map()
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1)
  let h = 0
  for (const n of freq.values()) {
    const p = n / s.length
    h -= p * Math.log2(p)
  }
  return h
}

/** Share of characters that belong to word-like runs (`Credential`, `remove`). */
export function wordCoverage(v) {
  const s = String(v ?? "")
  if (!s) return 0
  return (s.match(/[A-ZÄÖÜ]?[a-zäöüß]{2,}/g) ?? []).join("").length / s.length
}

/** `V2CredentialRemoveErrors`, `userProfileSettings`: code identifiers, not secrets. */
export function looksLikeIdentifier(v) {
  const s = String(v ?? "")
  if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(s)) return false
  // Random lowercase/digit tokens have many short letter runs; require real word structure.
  const caps = s.match(/[A-Z][a-z]{2,}/g) ?? []
  if (caps.length >= 2 && wordCoverage(s) >= 0.7) return true
  if (/^[a-z]{2,}(?:[A-Z][a-z]{2,})+\d*$/.test(s)) return true
  const snake = s.split("_").filter((x) => /^[a-z]{3,}\d*$/.test(x))
  return s.includes("_") && snake.length >= 2 && wordCoverage(s) >= 0.7
}

/** Example values in docs and code: `sbp_abc123`, `your_api_key`, `test-token`. */
export const DUMMY_FRAGMENT =
  /abc123|123456|abcdef|qwerty|x{4,}|dummy|example|sample|foobar|changeme|placeholder|lorem|(?:^|[-_])test(?:ing)?(?:[-_]|$)|your[-_]?(?:api|token|key|secret|pass)|^(?:my|the)?[-_]?(?:secret|password|passwort|token|apikey|api[-_]key)[-_:.]/i

/** Dummy/top-list value or a single dictionary-looking word: not worth a placeholder. */
export function isTrivialValue(value) {
  const v = String(value ?? "").trim()
  const lower = v.toLowerCase()
  if (COMMON_PASSWORDS.has(lower) || COMMON_PASSWORDS.has(lower.replace(/[!?.]+$/, ""))) return true
  if (v.length < 16 && /^(?:[a-zäöüß]+|[A-ZÄÖÜ][a-zäöüß]+|[A-ZÄÖÜ]+)$/.test(v)) return true
  return false
}

/** Value validator for `key = value` style rules. */
export function validateAssignedValue(value, quoted) {
  const v = String(value ?? "").trim()
  if (v.length < 4) return false
  if (v.includes("__VG_")) return false
  if (CODE_WORDS.has(v.toLowerCase())) return false
  if (isTrivialValue(v)) return false
  if (looksLikeReference(v)) return false
  if (DUMMY_FRAGMENT.test(v)) return false
  if (/^\d{1,7}$/.test(v)) return false
  if (/^[A-Za-z_$][\w$]*\s*\(/.test(v)) return false
  if (!quoted) {
    if (/^\/[*/]/.test(v) || v.includes("?.") || v.includes("=>")) return false // comments, optional chaining, arrows
    if (looksLikeIdentifier(v) || looksLikeMemberExpr(v)) return false
    if (/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(v)) return false // member expression
    if (/^[a-z]+(?:[A-Z][a-z0-9]*)+$/.test(v)) return false // camelCase identifier
    if (/^[A-Za-z_]+$/.test(v) && /pass|secret|token|key|cred/i.test(v)) return false // PASSWORD=PASSWORD
    if (/^(?:true|false|null|none|nil)[,;)]?$/i.test(v)) return false
  }
  return true
}

/** Values found in natural-language credential statements ("Passwort ist ..."). */
export function validateStatedSecret(value) {
  const v = String(value ?? "").trim()
  if (v.length < 4 || v.startsWith("-")) return false
  // Judge the word core: "vergessen?" is a sentence, not a password with a symbol.
  const core = v.replace(/[?!.]+$/, "")
  if (STOPWORDS.has(v.toLowerCase()) || STOPWORDS.has(core.toLowerCase())) return false
  if (isTrivialValue(core)) return false
  if (/^\d{1,3}$/.test(v)) return false
  return validateAssignedValue(v, false)
}

/** Usernames next to a password. Common dummy users are left alone. */
export function validateUsername(value) {
  const v = String(value ?? "").trim()
  if (v.length < 2 || v.includes("__VG_") || !/^[\p{L}\p{N}]/u.test(v)) return false
  const lower = v.toLowerCase()
  if (COMMON_USERS.has(lower) || CODE_WORDS.has(lower) || STOPWORDS.has(lower)) return false
  if (/pass|kennwort|secret|token|geheim/i.test(v)) return false
  if (looksLikeReference(v)) return false
  if (/^\d+$/.test(v)) return false
  if (looksLikeIdentifier(v) && /[A-Z]/.test(v)) return false
  // `request.user` / `Prompt.text` are code, `max.mustermann` is a login.
  if (/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(v) && (CODE_SEGMENT.test(v) || /[A-Z]/.test(v))) return false
  if (/^[a-z]+(?:[A-Z][a-z0-9]*)+$/.test(v)) return false
  return true
}

const CODE_SEGMENT =
  /(?:^|\.)(?:user|users|username|name|login|id|value|body|params|query|env|config|cfg|this|self|request|req|res|props|state|data|form|input|account|credentials|auth|args|options|opts|ctx|context|session|process|os|settings|model|current|get|set)(?:\.|$)/i
