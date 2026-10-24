import type { ArtifactType, SandboxCheck, SandboxResult } from "./types.ts";

// Static sandbox: content is parsed and inspected as text only. Nothing is executed and no network is used.

const DESTRUCTIVE: { re: RegExp; label: string }[] = [
  { re: /\brm\s+-[a-z]*r[a-z]*f?\s+(\/|~|\$HOME|\*)(\s|$)/i, label: "Recursive delete of a root, home or wildcard path" },
  { re: /\bmkfs(\.\w+)?\b/i, label: "Filesystem format command" },
  { re: /\bdd\s+[^\n]*of=\/dev\//i, label: "Raw disk write" },
  { re: /:\(\)\s*\{\s*:\|:&\s*\};:/, label: "Fork bomb" },
  { re: /\bchmod\s+(-R\s+)?777\s+\//i, label: "World-writable permissions on system paths" },
  { re: /\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b/i, label: "Downloads and executes a remote script" },
  { re: /\b(iex|Invoke-Expression)\b[^\n]*(DownloadString|Invoke-WebRequest|iwr|Net\.WebClient)/i, label: "Downloads and executes remote PowerShell" },
  { re: /\bufw\s+disable\b/i, label: "Turns the firewall off" },
  { re: /netsh\s+advfirewall\s+set\s+\w+\s+state\s+off/i, label: "Turns Windows Firewall off" },
  { re: /Set-MpPreference[^\n]*-Disable\w*\s+\$?true/i, label: "Disables Microsoft Defender protection" },
  { re: /\bsetenforce\s+0\b/i, label: "Disables SELinux" },
  { re: /\biptables\s+-F\b/i, label: "Flushes all firewall rules" },
  { re: /\bshutdown\b|\breboot\b|Restart-Computer|Stop-Computer/i, label: "Shuts down or restarts the machine" },
  { re: /\buserdel\b|Remove-LocalUser/i, label: "Deletes user accounts" },
  { re: /Format-Volume|Clear-Disk|diskpart/i, label: "Formats or wipes a disk" },
];

const SECRET_PATTERNS: { re: RegExp; label: string }[] = [
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/, label: "Embedded private key" },
  { re: /\bAKIA[0-9A-Z]{16}\b/, label: "Embedded AWS access key" },
  { re: /\b(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*["']?(?!<|\$|\{|your|change|example|REPLACE)[^\s"'<>]{6,}/i, label: "Hard-coded credential" },
];

function check(id: string, label: string, level: SandboxCheck["level"], detail: string): SandboxCheck {
  return { id, label, level, detail };
}

function meaningfulLines(content: string, comment = /^\s*#/): string[] {
  return content.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !comment.test(l));
}

function commonChecks(content: string, artifact: ArtifactType): SandboxCheck[] {
  const out: SandboxCheck[] = [];
  out.push(content.trim().length > 0
    ? check("not_empty", "Content present", "pass", `${content.length} characters`)
    : check("not_empty", "Content present", "error", "The file is empty."));
  out.push(content.length <= 20000
    ? check("size", "Size within limits", "pass", "Under 20,000 characters")
    : check("size", "Size within limits", "error", "File is too large to review safely."));

  if (artifact !== "checklist") {
    const code = content.split(/\r?\n/).filter((l) => !/^\s*#/.test(l)).join("\n");
    const hits = DESTRUCTIVE.filter((d) => d.re.test(code)).map((d) => d.label);
    out.push(hits.length
      ? check("destructive", "No destructive commands", "error", hits.join("; "))
      : check("destructive", "No destructive commands", "pass", "No destructive or remote-execution patterns found"));
  }
  const secrets = SECRET_PATTERNS.filter((s) => s.re.test(content)).map((s) => s.label);
  out.push(secrets.length
    ? check("secrets", "No embedded secrets", "error", secrets.join("; "))
    : check("secrets", "No embedded secrets", "pass", "No keys or passwords found in the file"));
  return out;
}

function nginxChecks(content: string): SandboxCheck[] {
  const out: SandboxCheck[] = [];
  const stripped = content.replace(/#[^\n]*/g, "");
  let depth = 0;
  let underflow = false;
  for (const ch of stripped) {
    if (ch === "{") depth++;
    if (ch === "}") { depth--; if (depth < 0) underflow = true; }
  }
  out.push(depth === 0 && !underflow
    ? check("braces", "Blocks are balanced", "pass", "Every { has a matching }")
    : check("braces", "Blocks are balanced", "error", "Unbalanced { } blocks would stop the web server from loading this file."));
  const bad = meaningfulLines(content).filter((l) => !/[;{}]$/.test(l));
  out.push(bad.length === 0
    ? check("terminators", "Directives terminated", "pass", "Every directive ends with ; or a block")
    : check("terminators", "Directives terminated", "error", `Missing semicolon: ${bad.slice(0, 3).join(" | ")}`));
  if (/\bautoindex\s+on\b/i.test(content)) out.push(check("autoindex", "Directory listing", "error", "autoindex on exposes file listings."));
  if (/\bssl_protocols\b[^;]*(SSLv3|TLSv1(\.0)?\s|TLSv1;|TLSv1\.1)/i.test(content)) {
    out.push(check("tls", "Modern TLS only", "error", "Outdated TLS/SSL protocol versions enabled."));
  }
  if (/\bserver_tokens\s+on\b/i.test(content)) out.push(check("tokens", "Version hidden", "warning", "server_tokens on reveals the server version."));
  return out;
}

function apacheChecks(content: string): SandboxCheck[] {
  const stack: string[] = [];
  let ok = true;
  for (const m of content.replace(/#[^\n]*/g, "").matchAll(/<(\/?)([A-Za-z]+)[^>]*>/g)) {
    if (m[1]) { if (stack.pop() !== m[2].toLowerCase()) ok = false; }
    else stack.push(m[2].toLowerCase());
  }
  const out = [ok && stack.length === 0
    ? check("sections", "Sections balanced", "pass", "Every <Section> is closed")
    : check("sections", "Sections balanced", "error", "Unclosed or mismatched <Section> tags.")];
  if (/Options\s+[^\n]*\+?Indexes/i.test(content) && !/-Indexes/i.test(content)) {
    out.push(check("indexes", "Directory listing", "error", "Options Indexes exposes file listings."));
  }
  return out;
}

const HEADER_NAME = /^[A-Za-z0-9-]+$/;

function headerChecks(content: string): SandboxCheck[] {
  const out: SandboxCheck[] = [];
  const lines = meaningfulLines(content);
  const malformed = lines.filter((l) => { const i = l.indexOf(":"); return i < 1 || !HEADER_NAME.test(l.slice(0, i).trim()) || !l.slice(i + 1).trim(); });
  out.push(malformed.length === 0 && lines.length > 0
    ? check("format", "Header syntax", "pass", `${lines.length} well-formed headers`)
    : check("format", "Header syntax", "error", malformed.length ? `Malformed: ${malformed.slice(0, 3).join(" | ")}` : "No headers found."));
  const map = new Map(lines.map((l) => [l.slice(0, l.indexOf(":")).trim().toLowerCase(), l.slice(l.indexOf(":") + 1).trim()]));
  const hsts = map.get("strict-transport-security");
  if (hsts !== undefined) {
    const age = Number(hsts.match(/max-age=(\d+)/i)?.[1]);
    out.push(age >= 86400
      ? check("hsts", "HSTS max-age", "pass", `max-age=${age}`)
      : check("hsts", "HSTS max-age", "error", "Strict-Transport-Security needs a numeric max-age of at least one day."));
  }
  const xfo = map.get("x-frame-options");
  if (xfo !== undefined && !/^(DENY|SAMEORIGIN)$/i.test(xfo)) out.push(check("xfo", "X-Frame-Options value", "error", "Must be DENY or SAMEORIGIN."));
  const csp = map.get("content-security-policy");
  if (csp !== undefined && /'unsafe-inline'|'unsafe-eval'/.test(csp)) {
    out.push(check("csp", "Content-Security-Policy strength", "warning", "Uses unsafe-inline or unsafe-eval, which weakens protection against injected scripts."));
  }
  if (csp !== undefined) out.push(check("csp_break", "Site compatibility", "warning", "A new Content-Security-Policy can block legitimate scripts. Roll out in report-only mode first."));
  return out;
}

function ufwChecks(content: string): SandboxCheck[] {
  const out: SandboxCheck[] = [];
  const lines = meaningfulLines(content);
  const bad = lines.filter((l) => !/^(sudo\s+)?ufw\s+/.test(l));
  out.push(bad.length === 0
    ? check("syntax", "Only firewall commands", "pass", `${lines.length} ufw commands`)
    : check("syntax", "Only firewall commands", "error", `Non-ufw lines are not allowed here: ${bad.slice(0, 3).join(" | ")}`));
  const deniesIncoming = lines.some((l) => /ufw\s+default\s+deny\s+incoming/.test(l));
  const enables = lines.some((l) => /ufw\s+(--force\s+)?enable/.test(l));
  const allowsSsh = lines.some((l) => /ufw\s+(allow|limit)\s+.*\b(22|ssh|OpenSSH)\b/i.test(l));
  if (deniesIncoming && enables && !allowsSsh) {
    out.push(check("lockout", "Remote access preserved", "error", "Denies all incoming traffic without allowing SSH. You could lock yourself out of a remote server."));
  } else {
    out.push(check("lockout", "Remote access preserved", "pass", allowsSsh ? "SSH remains allowed" : "No default-deny that removes remote access"));
  }
  if (lines.some((l) => /ufw\s+allow\s+from\s+any\s+to\s+any\s*$/i.test(l) || /ufw\s+default\s+allow\s+incoming/.test(l))) {
    out.push(check("open", "No allow-all rule", "error", "Allows all incoming traffic, defeating the firewall."));
  }
  return out;
}

const SSHD_KEYS = new Set([
  "port", "addressfamily", "listenaddress", "protocol", "hostkey", "permitrootlogin", "passwordauthentication",
  "pubkeyauthentication", "permitemptypasswords", "challengeresponseauthentication", "kbdinteractiveauthentication",
  "usepam", "x11forwarding", "maxauthtries", "maxsessions", "logingracetime", "clientaliveinterval",
  "clientalivecountmax", "allowusers", "allowgroups", "denyusers", "denygroups", "authenticationmethods",
  "allowtcpforwarding", "allowagentforwarding", "permittunnel", "ciphers", "macs", "kexalgorithms", "loglevel",
  "banner", "printmotd", "subsystem", "authorizedkeysfile", "ignorerhosts", "hostbasedauthentication",
  "strictmodes", "usedns", "match", "acceptenv", "gssapiauthentication", "include",
]);

function sshdChecks(content: string): SandboxCheck[] {
  const out: SandboxCheck[] = [];
  const lines = meaningfulLines(content);
  const entries = lines.map((l) => { const [k, ...rest] = l.split(/\s+/); return { k: k.toLowerCase(), v: rest.join(" ").toLowerCase() }; });
  const malformed = entries.filter((e) => !e.v && e.k !== "match");
  const unknown = entries.filter((e) => !SSHD_KEYS.has(e.k)).map((e) => e.k);
  out.push(malformed.length === 0
    ? check("syntax", "Keyword syntax", "pass", `${entries.length} settings`)
    : check("syntax", "Keyword syntax", "error", "Some settings have no value."));
  if (unknown.length) out.push(check("unknown", "Recognized keywords", "warning", `Unrecognized: ${unknown.slice(0, 5).join(", ")}`));
  const get = (k: string) => entries.find((e) => e.k === k)?.v;
  if (get("permitrootlogin") === "yes") out.push(check("root", "Root login", "error", "PermitRootLogin yes allows direct root login."));
  if (get("permitemptypasswords") === "yes") out.push(check("empty", "Empty passwords", "error", "PermitEmptyPasswords yes is unsafe."));
  if (get("passwordauthentication") === "no") {
    out.push(check("keys", "Key access confirmed", "warning", "Disables password login. Confirm your SSH key works in a second session before reloading, or you may be locked out."));
  }
  return out;
}

function iniChecks(content: string): SandboxCheck[] {
  const lines = meaningfulLines(content, /^\s*[#;]/);
  const hasSection = lines.some((l) => /^\[[^\]]+\]$/.test(l));
  const bad = lines.filter((l) => !/^\[[^\]]+\]$/.test(l) && !/^[A-Za-z0-9_.-]+\s*=/.test(l) && !/^\s/.test(l));
  return [
    hasSection ? check("sections", "Has [jail] sections", "pass", "Section headers found") : check("sections", "Has [jail] sections", "error", "No [section] headers found."),
    bad.length === 0 ? check("syntax", "key = value syntax", "pass", "All lines parse") : check("syntax", "key = value syntax", "error", `Unparseable: ${bad.slice(0, 3).join(" | ")}`),
  ];
}

function jsonChecks(content: string): SandboxCheck[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch (e) {
    return [check("parse", "Valid JSON", "error", (e as Error).message.slice(0, 160))];
  }
  const out = [check("parse", "Valid JSON", "pass", "Parsed successfully")];
  const statements = (parsed as { Statement?: unknown })?.Statement;
  const list = Array.isArray(statements) ? statements : statements ? [statements] : [];
  const wildcard = list.some((s) => {
    const st = s as Record<string, unknown>;
    const has = (v: unknown) => v === "*" || (Array.isArray(v) && v.includes("*"));
    return st?.Effect === "Allow" && has(st.Action) && has(st.Resource);
  });
  if (wildcard) out.push(check("least_privilege", "Least privilege", "error", "Allows every action on every resource."));
  else if (list.length) out.push(check("least_privilege", "Least privilege", "pass", "No allow-everything statements"));
  return out;
}

function scriptChecks(content: string, artifact: "bash_script" | "powershell_script"): SandboxCheck[] {
  const out: SandboxCheck[] = [];
  if (artifact === "bash_script") {
    const opens = (content.match(/\b(if|case)\b/g) ?? []).length;
    const closes = (content.match(/\b(fi|esac)\b/g) ?? []).length;
    out.push(opens === closes
      ? check("structure", "Control blocks closed", "pass", "if/fi and case/esac balanced")
      : check("structure", "Control blocks closed", "error", "Unbalanced if/fi or case/esac."));
  } else {
    let depth = 0;
    for (const ch of content.replace(/#[^\n]*/g, "")) { if (ch === "{") depth++; if (ch === "}") depth--; }
    out.push(depth === 0
      ? check("structure", "Script blocks closed", "pass", "Braces balanced")
      : check("structure", "Script blocks closed", "error", "Unbalanced { } in script."));
  }
  out.push(check("review", "Manual review required", "warning", "Scripts change your system when run. Read every line before running it yourself."));
  return out;
}

function checklistChecks(content: string): SandboxCheck[] {
  const steps = content.split(/\r?\n/).filter((l) => /^\s*([-*]|\d+\.)\s+/.test(l)).length;
  return [steps > 0
    ? check("steps", "Actionable steps", "pass", `${steps} steps`)
    : check("steps", "Actionable steps", "error", "No list items found.")];
}

export function runSandbox(artifact: ArtifactType, content: string, rollbackSupported: boolean): SandboxResult {
  const checks = commonChecks(content, artifact);
  switch (artifact) {
    case "nginx_conf": checks.push(...nginxChecks(content)); break;
    case "apache_conf": checks.push(...apacheChecks(content)); break;
    case "http_headers": checks.push(...headerChecks(content)); break;
    case "ufw_rules": checks.push(...ufwChecks(content)); break;
    case "sshd_config": checks.push(...sshdChecks(content)); break;
    case "fail2ban_jail": checks.push(...iniChecks(content)); break;
    case "json_policy": checks.push(...jsonChecks(content)); break;
    case "bash_script":
    case "powershell_script": checks.push(...scriptChecks(content, artifact)); break;
    case "checklist": checks.push(...checklistChecks(content)); break;
  }
  if (artifact !== "checklist") {
    checks.push(rollbackSupported
      ? check("rollback", "Rollback available", "pass", "Rollback instructions provided")
      : check("rollback", "Rollback available", "warning", "No rollback is available for this change."));
  }
  const errors = checks.filter((c) => c.level === "error").length;
  const warnings = checks.filter((c) => c.level === "warning").length;
  return {
    passed: errors === 0,
    checks,
    summary: errors
      ? `Failed: ${errors} blocking issue${errors === 1 ? "" : "s"}${warnings ? `, ${warnings} warning${warnings === 1 ? "" : "s"}` : ""}.`
      : `Passed static analysis${warnings ? ` with ${warnings} warning${warnings === 1 ? "" : "s"}` : ""}. Not executed on any real system.`,
  };
}

export async function sha256(text: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
