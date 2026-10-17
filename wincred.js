import { execFile } from "node:child_process"

/**
 * Windows Credential Manager access via advapi32 (CredEnumerate / CredWrite /
 * CredDelete) from a PowerShell child process. No dependencies. Secrets travel
 * base64-encoded over stdout/stdin only, never on a command line.
 */
const CSHARP = String.raw`
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class VgCred {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct CREDENTIAL {
    public UInt32 Flags; public UInt32 Type; public string TargetName; public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public UInt32 CredentialBlobSize; public IntPtr CredentialBlob; public UInt32 Persist;
    public UInt32 AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName;
  }
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredEnumerate(string filter, UInt32 flags, out UInt32 count, out IntPtr creds);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredWrite(ref CREDENTIAL cred, UInt32 flags);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredDelete(string target, UInt32 type, UInt32 flags);
  [DllImport("advapi32.dll")] static extern void CredFree(IntPtr p);
  static string B64(string s) { return Convert.ToBase64String(Encoding.UTF8.GetBytes(s ?? "")); }
  public static List<string> List(string filter) {
    var r = new List<string>(); UInt32 n; IntPtr p;
    if (!CredEnumerate(filter, 0, out n, out p)) return r;
    try {
      for (int i = 0; i < n; i++) {
        var c = (CREDENTIAL)Marshal.PtrToStructure(Marshal.ReadIntPtr(p, i * IntPtr.Size), typeof(CREDENTIAL));
        string s = "";
        if (c.CredentialBlobSize > 0) {
          var b = new byte[c.CredentialBlobSize]; Marshal.Copy(c.CredentialBlob, b, 0, b.Length);
          s = (b.Length % 2 == 0 && b.Length > 1 && b[1] == 0) ? Encoding.Unicode.GetString(b) : Encoding.UTF8.GetString(b);
        }
        r.Add(B64(c.TargetName) + "\t" + B64(c.UserName) + "\t" + B64(s));
      }
    } finally { CredFree(p); }
    return r;
  }
  public static bool Write(string target, string user, string secret) {
    var bytes = Encoding.Unicode.GetBytes(secret);
    var c = new CREDENTIAL(); c.Type = 1; c.TargetName = target; c.UserName = user; c.Persist = 2;
    c.CredentialBlobSize = (UInt32)bytes.Length; c.CredentialBlob = Marshal.AllocHGlobal(bytes.Length);
    try { Marshal.Copy(bytes, 0, c.CredentialBlob, bytes.Length); return CredWrite(ref c, 0); }
    finally { Marshal.FreeHGlobal(c.CredentialBlob); }
  }
  public static bool Delete(string target) { return CredDelete(target, 1, 0); }
}`

const psQuote = (s) => `'${String(s).replace(/'/g, "''")}'`

function runPowerShell(script, stdin, timeout = 20_000) {
  return new Promise((resolve) => {
    const full = `$ErrorActionPreference='Stop'\nAdd-Type -TypeDefinition @'\n${CSHARP}\n'@\n${script}`
    const encoded = Buffer.from(full, "utf16le").toString("base64")
    const child = execFile(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
      { timeout, windowsHide: true, maxBuffer: 4 * 1024 * 1024 },
      (error, stdout, stderr) => resolve({ error: error ? String(stderr || error.message).trim().split("\n")[0] : null, stdout: String(stdout ?? "") }),
    )
    if (stdin !== undefined) child.stdin?.end(stdin)
    else child.stdin?.end()
  })
}

const fromB64 = (s) => Buffer.from(s, "base64").toString("utf8")

/** @returns {Promise<{ items: Array<{target:string,user:string,secret:string}>, error?: string }>} */
export async function listCredentials(filters) {
  if (process.platform !== "win32") return { items: [], error: "Windows Credential Manager is only available on Windows" }
  const list = filters.map(psQuote).join(",")
  const res = await runPowerShell(`foreach ($f in @(${list})) { [VgCred]::List($f) | ForEach-Object { $_ } }`)
  if (res.error) return { items: [], error: res.error }
  const items = []
  for (const line of res.stdout.split(/\r?\n/)) {
    const parts = line.trim().split("\t")
    if (parts.length !== 3) continue
    items.push({ target: fromB64(parts[0]), user: fromB64(parts[1]), secret: fromB64(parts[2]) })
  }
  return { items }
}

export async function writeCredential(target, secret, user = "vibeguard") {
  if (process.platform !== "win32") return { error: "Windows only" }
  const script =
    `$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()))\n` +
    `if (-not [VgCred]::Write(${psQuote(target)}, ${psQuote(user)}, $s)) { throw 'CredWrite failed' }`
  const res = await runPowerShell(script, Buffer.from(secret, "utf8").toString("base64"))
  return res.error ? { error: res.error } : { ok: true }
}

export async function deleteCredential(target) {
  if (process.platform !== "win32") return { error: "Windows only" }
  const res = await runPowerShell(`if (-not [VgCred]::Delete(${psQuote(target)})) { throw 'not found' }`)
  return res.error ? { error: res.error } : { ok: true }
}

/**
 * Resolve `secrets.windows_credentials` specs into keyword entries.
 * Spec: `{ filter: "vibeguard:*" }` (name = target without the filter prefix)
 *    or `{ target: "git:https://github.com", name: "GITHUB_GCM" }`.
 */
export async function windowsCredentialSecrets(specs) {
  const list = (Array.isArray(specs) ? specs : []).filter((s) => s && (s.filter || s.target))
  if (list.length === 0) return { entries: [], failed: [] }
  const res = await listCredentials(list.map((s) => s.filter ?? s.target))
  if (res.error) return { entries: [], failed: [{ file: "windows_credentials", message: res.error }] }
  const entries = []
  for (const spec of list) {
    const pattern = String(spec.filter ?? spec.target)
    const prefix = pattern.endsWith("*") ? pattern.slice(0, -1) : null
    const matches = res.items.filter((c) => (prefix !== null ? c.target.toLowerCase().startsWith(prefix.toLowerCase()) : c.target.toLowerCase() === pattern.toLowerCase()))
    for (const c of matches) {
      if (!c.secret || c.secret.length < 4) continue
      const name = spec.name ?? (prefix !== null ? c.target.slice(prefix.length) : c.target)
      entries.push({ value: c.secret, category: name || "WINCRED", source: "windows_credentials" })
      if (spec.include_user && c.user && c.user.length >= 4) entries.push({ value: c.user, category: `${name}_USER`, source: "windows_credentials" })
    }
  }
  return { entries, failed: [] }
}
