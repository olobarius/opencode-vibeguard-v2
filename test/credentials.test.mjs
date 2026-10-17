import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, writeFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { buildPatternSet } from "../patterns.js"
import { redactText } from "../engine.js"
import { KnownRegistry, PlaceholderSession } from "../session.js"
import { restoreText } from "../restore.js"
import { assessSecret } from "../credentials.js"
import { collectKnownSecrets } from "../known.js"
import { normalizeConfig } from "../config.js"

// Built at runtime so the test file itself holds no literal secrets.
const PW = ["Kq7", "!zR2", "-vM9"].join("")
const session = (known) => new PlaceholderSession({ prefix: "__VG_", known })
const P = buildPatternSet({})
const red = (t) => redactText(t, P, session()).text

const SHOULD_REDACT = [
  `Mein Passwort ist ${PW}`,
  `mein passwort lautet ${PW}.`,
  `Das Kennwort für den Router ist ${PW}`,
  `The password is ${PW}`,
  `PW: ${PW}`,
  `pwd=${PW}`,
  `WLAN-Passwort: ${PW}`,
  `Root-Passwort: "${PW}"`,
  `Login: max.mustermann Passwort: ${PW}`,
  `Benutzername: m.mueller@firma.de, Kennwort: ${PW}`,
  `user/pass: maxm/${PW}`,
  `Zugangsdaten: maxm / ${PW}`,
  `mysql -u app -p${PW} shop`,
  `sshpass -p '${PW}' ssh host`,
  `curl -u maxm:${PW} https://api.example.com`,
  `docker login -u maxm --password ${PW} registry.io`,
  `az login -u x --password=${PW}`,
  `$p = ConvertTo-SecureString "${PW}" -AsPlainText -Force`,
  `net use Z: \\\\srv\\share /user:corp\\maxm ${PW}`,
  `smbclient //srv/share -U maxm%${PW}`,
  `sqlcmd -S db -U sa -P ${PW}`,
  `openssl enc -aes-256-cbc -pass pass:${PW} -in a`,
  `7z a -p${PW} out.7z dir`,
  `machine github.com login maxm password ${PW}`,
  `db.internal:5432:shop:app:${PW}`,
  `<password>${PW}</password>`,
  `Server=db;User ID=app;Password=${PW};`,
  `https://example.com/login?user=maxm&password=${PW}&x=1`,
  `psk=${PW}`,
  `New-Object System.Net.NetworkCredential("maxm", "${PW}")`,
]

const SHOULD_NOT_REDACT = [
  "Das Passwort ist falsch",
  "Passwort vergessen? Dann klicke auf zurücksetzen.",
  "Das Passwort ist zu kurz",
  "The password is incorrect",
  "password is required",
  "Passwort: siehe KeePass",
  "Bitte gib dein Passwort ein",
  "password: string;",
  "const password = req.body.password",
  "password = os.environ['DB_PASSWORD']",
  'password: "changeme"',
  "DB_PASSWORD=" + "postgres",
  "Passwort: " + "Sommer",
  "mkdir -p src/components",
  "ssh -p 22 host",
  "docker run -p 8080:80 nginx",
  "git add -p",
  "git push -u origin main",
  "docker run -u 1000:1000 img",
  "Password Manager nutzen",
  "password VARCHAR(255) NOT NULL",
  "user = request.user",
  "--password-stdin",
  "--token $GITHUB_TOKEN",
  "-Password (Read-Host -AsSecureString)",
  "Login: max",
  "Passwort-Hashing mit bcrypt",
  "set the password field to required",
  "user: ${USER}, password: ${PASS}",
  "Passwort: ********",
  "Passwort: <dein Passwort>",
  "password=<password>",
  "machine github.com login maxm password changeme",
  '{ command: "myapp login --token sbp_abc123" }',
  "export type V2CredentialRemoveError = V2CredentialRemoveErrors[keyof V2CredentialRemoveErrors]",
  "setting: keyof LanguageModelV3CallOptions; details?: string",
  "const username = Prompt.text({ message: 'Enter' })",
  "return { username: parts[0], password: parts[1] }",
  "export const setPassword = /*#__PURE__*/dual(2, (url, password) => url)",
  "const apiKey = yield* Config.redacted('API_KEY')",
  "publicKey: Schema.String, privateKey: Schema.Uint8Array })",
  'windows_credentials: [{ filter: "vibeguard:*" }],',
]

test("credentials: real-world login and password statements are redacted", () => {
  for (const t of SHOULD_REDACT) {
    const out = red(t)
    assert.ok(!out.includes(PW), `leaked: ${t.replaceAll(PW, "<PW>")} -> ${out.replaceAll(PW, "<PW>")}`)
  }
})

test("credentials: prose, code and dummy values are left alone", () => {
  for (const t of SHOULD_NOT_REDACT) assert.equal(red(t), t, t)
})

test("credentials: usernames next to a password become LOGIN placeholders", () => {
  assert.match(red(`Login: max.mustermann Passwort: ${PW}`), /^Login: __VG_LOGIN_[a-f0-9]{12}__ Passwort: __VG_PASSWORD_[a-f0-9]{12}__$/)
  assert.match(red(`curl -u maxm:${PW} x`), /-u __VG_LOGIN_[a-f0-9]{12}__:__VG_PASSWORD_[a-f0-9]{12}__ x/)
  // common dummy users stay readable
  assert.match(red(`Benutzer: admin, Passwort: ${PW}`), /^Benutzer: admin, Passwort: __VG_PASSWORD_/)
})

test("credentials: PINs need a PIN keyword", () => {
  assert.ok(!red("PIN: 4711").includes("4711"))
  assert.ok(!red("Meine PIN lautet 8264").includes("8264"))
  assert.equal(red("pin 12"), "pin 12")
  assert.equal(red("Version 4711"), "Version 4711")
})

test("credentials: login + password typed in chat restore exactly for tools", () => {
  const s = session()
  const text = `Mein Login ist m.mueller@firma.de und mein Passwort lautet ${PW}`
  const out = redactText(text, P, s).text
  assert.ok(!out.includes(PW) && !out.includes("m.mueller"))
  assert.equal(restoreText(out, s), text)
})

// ------------------------------------------------------------- weak secrets

test("assess: strength classes", () => {
  assert.equal(assessSecret("sonne").strength, "weak")
  assert.equal(assessSecret("Sommer2024!").strength, "weak")
  assert.equal(assessSecret("password123").strength, "weak")
  assert.equal(assessSecret("123456").strength, "weak")
  assert.equal(assessSecret("getUserName").strength, "weak")
  assert.equal(assessSecret("my_db_password").strength, "medium")
  assert.equal(assessSecret("Acme Rocket Corp").strength, "medium")
  assert.equal(assessSecret(PW + "xY").strength, "strong")
  assert.equal(assessSecret("ghp_" + "aB3dE5gH7jK9mN1pQ2rS4tU6vW8xY0zA1bC3").strength, "strong")
})

function knownSet(entries, config = {}) {
  return (async () => {
    const dir = mkdtempSync(join(tmpdir(), "vg-cred-"))
    const file = join(dir, "s.secrets")
    writeFileSync(file, entries.join("\n") + "\n")
    const cfg = normalizeConfig({ ...config, secrets: { files: [file], env: false, opencode_auth: false, windows_credentials: [], ...config.secrets } })
    const res = await collectKnownSecrets(cfg, dir)
    rmSync(dir, { recursive: true, force: true })
    const patterns = buildPatternSet(cfg.patterns, res.entries)
    const known = new KnownRegistry({ prefix: "__VG_", key: Buffer.alloc(32, 3) })
    known.load(patterns.keywords)
    return { res, patterns, known }
  })()
}

test("known weak secret: replaced only in a credential context", async () => {
  const { res, patterns, known } = await knownSet(["WLAN_PW=" + "sonne"])
  const e = res.entries.find((x) => x.category === "WLAN_PW")
  assert.equal(e.strength, "weak")
  assert.equal(e.mode, "context")
  assert.ok(!res.entries.some((x) => x.variant && x.category.startsWith("WLAN_PW")), "no encoded variants for weak values")
  const s = session(known)
  assert.equal(redactText("Die sonne scheint, function sonne() {}", patterns, s).text, "Die sonne scheint, function sonne() {}")
  for (const t of ["WLAN-Passwort: sonne", "das passwort ist sonne", "pw=sonne", "https://u:sonne@host"]) {
    const out = redactText(t, patterns, s).text
    assert.match(out, /__VG_WLAN_PW_[a-f0-9]{12}__/, t)
    assert.equal(restoreText(out, s), t)
  }
})

test("known medium secret: replaced only as a whole token", async () => {
  const { patterns, known } = await knownSet(['CUSTOMER="Acme Rocket"'])
  const s = session(known)
  assert.match(redactText("Kunde: Acme Rocket.", patterns, s).text, /Kunde: __VG_CUSTOMER_[a-f0-9]{12}__\./)
  assert.equal(redactText("Acme RocketScience", patterns, s).text, "Acme RocketScience")
})

test("known secrets: per-entry and config overrides of the match mode", async () => {
  const { res, patterns, known } = await knownSet(["PIN_A[exact]=4711", "OLD=" + "sonne"], { secrets: { match: { OLD: "off" } } })
  assert.equal(res.entries.find((x) => x.category === "PIN_A").mode, "exact")
  assert.equal(res.entries.find((x) => x.category === "OLD").mode, "off")
  const s = session(known)
  assert.match(redactText("code 4711 here", patterns, s).text, /__VG_PIN_A_/)
  assert.equal(redactText("Passwort: sonne", patterns, s).text, "Passwort: sonne")
})

test("known secrets: secrets.weak = exact restores the old behaviour", async () => {
  const { patterns, known } = await knownSet(["WLAN_PW=" + "sonne"], { secrets: { weak: "exact" } })
  assert.match(redactText("Die sonne scheint", patterns, session(known)).text, /__VG_WLAN_PW_/)
})
