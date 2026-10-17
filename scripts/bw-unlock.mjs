#!/usr/bin/env node
/**
 * bw-unlock: unlock Bitwarden/Vaultwarden locally and hand the session key to
 * VibeGuard via the Windows Credential Manager. The master password is read
 * hidden from this terminal and passed to `bw` through an environment variable
 * of the child process only. It never goes through the AI chat.
 *
 * Usage:
 *   node scripts/bw-unlock.mjs            unlock, store session (default target vibeguard-bw-session)
 *   node scripts/bw-unlock.mjs --lock     `bw lock` and delete the stored session
 *   node scripts/bw-unlock.mjs --status   show `bw status` (server, user, state)
 * Options: --target NAME  --cli PATH_TO_BW
 *
 * One-time setup for Vaultwarden:
 *   bw config server https://vault.example.com
 *   bw login
 */
import { DEFAULT_SESSION_TARGET, runBw } from "../bitwarden.js"
import { deleteCredential, writeCredential } from "../wincred.js"

function parseArgs(argv) {
  const out = { target: DEFAULT_SESSION_TARGET, cli: "bw", lock: false, status: false }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === "--target") out.target = argv[++i] ?? out.target
    else if (a === "--cli") out.cli = argv[++i] ?? out.cli
    else if (a === "--lock") out.lock = true
    else if (a === "--status") out.status = true
    else if (a === "--help" || a === "-h") out.help = true
  }
  return out
}

function readHidden(prompt) {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin
    process.stderr.write(prompt)
    if (!stdin.isTTY) {
      let data = ""
      stdin.setEncoding("utf8")
      stdin.on("data", (d) => (data += d))
      stdin.on("end", () => resolve(data.replace(/\r?\n$/, "")))
      return
    }
    let value = ""
    stdin.setRawMode(true)
    stdin.resume()
    stdin.setEncoding("utf8")
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") {
          stdin.setRawMode(false)
          stdin.pause()
          stdin.off("data", onData)
          process.stderr.write("\n")
          resolve(value)
          return
        }
        if (ch === "\u0003") {
          stdin.setRawMode(false)
          process.stderr.write("\n")
          reject(new Error("aborted"))
          return
        }
        if (ch === "\u007f" || ch === "\b") value = value.slice(0, -1)
        else value += ch
      }
    }
    stdin.on("data", onData)
  })
}

const args = parseArgs(process.argv.slice(2))
if (args.help) {
  console.log("usage: bw-unlock.mjs [--lock | --status] [--target NAME] [--cli PATH]")
  process.exit(0)
}

if (args.status) {
  const res = await runBw(args.cli, ["status"], process.env)
  if (res.error) {
    console.error(`bw status failed: ${res.error}`)
    process.exit(1)
  }
  console.log(res.stdout.trim())
  process.exit(0)
}

if (args.lock) {
  await runBw(args.cli, ["lock"], process.env)
  const res = await deleteCredential(args.target)
  console.log(res.error ? `no stored session (${res.error})` : `locked; removed ${args.target}`)
  process.exit(0)
}

let master
try {
  master = await readHidden("Bitwarden/Vaultwarden master password: ")
} catch {
  process.exit(130)
}
const env = { ...process.env, VG_BW_MASTER: master, BW_NOINTERACTION: "true" }
const res = await runBw(args.cli, ["unlock", "--passwordenv", "VG_BW_MASTER", "--raw"], env, 60_000)
master = ""
if (res.error || !res.stdout.trim()) {
  console.error(`unlock failed: ${res.error ?? "empty session"}. Did you run 'bw config server ...' and 'bw login'?`)
  process.exit(1)
}
const stored = await writeCredential(args.target, res.stdout.trim(), "bitwarden")
if (stored.error) {
  console.error(`could not store the session: ${stored.error}`)
  process.exit(1)
}
console.log(`unlocked; session stored in Windows Credential Manager as "${args.target}". Run /vibeguard reload in OpenCode.`)
console.log("Lock again with: node scripts/bw-unlock.mjs --lock")
