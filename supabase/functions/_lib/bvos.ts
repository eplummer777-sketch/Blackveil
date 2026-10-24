export const ALLOWED_COMMANDS = new Set([
  "echo", "pwd", "ls", "uname", "hostname", "whoami", "id", "date", "uptime",
  "free", "df", "ps", "top", "env", "sleep", "true", "false", "head", "tail",
  "wc", "grep", "egrep", "sort", "uniq", "find", "du", "stat", "file", "cat",
  "less", "more", "printf", "seq", "python3", "python", "node", "sh", "bash",
  "nproc", "lscpu", "arch",
]);

export const MAX_COMMAND_LEN = 400;
export const MAX_OUTPUT = 60000;
export const ONLINE_MS = 90_000;
export const TOKEN_RE = /^bvos_[A-Za-z0-9_-]{40,60}$/;
export const tokenPrefix = (token: string) => token.slice(0, 12);

export function sanitizeCommand(raw: unknown): { ok: true; command: string } | { ok: false; error: string } {
  const s = String(raw ?? "").trim();
  if (!s) return { ok: false, error: "Enter a command." };
  if (s.length > MAX_COMMAND_LEN) return { ok: false, error: "Command is too long." };
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(s)) return { ok: false, error: "Command contains invalid characters." };
  if (/[;&|<>\n\r]/.test(s)) return { ok: false, error: "Shell operators (chaining, pipes, redirection) are disabled in the restricted shell." };
  if (s.includes("`") || s.includes("$(")) return { ok: false, error: "Command substitution is disabled." };
  const first = s.split(/\s+/)[0].split("/").pop() ?? "";
  if (!ALLOWED_COMMANDS.has(first)) {
    return { ok: false, error: `"${first}" is not available in the restricted Blackveil OS shell.` };
  }
  return { ok: true, command: s };
}

// Keeps newlines and tabs, drops ANSI escapes and other control characters.
export function cleanOutput(v: unknown, n = MAX_OUTPUT): string {
  return String(v ?? "")
    // eslint-disable-next-line no-control-regex
    .replace(/\u001b\[[0-9;?]*[A-Za-z]/g, "")
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "")
    .slice(0, n);
}

export type WorkerState = "online" | "unhealthy" | "unauthorized" | "offline";

export interface WorkerRow {
  revoked: boolean;
  last_seen_at: string | null;
  last_auth_fail_at?: string | null;
  last_auth_fail_reason?: string | null;
  caps: unknown;
}

export function workerHealth(w: WorkerRow, now = Date.now()): { state: WorkerState; reason: string } {
  if (w.revoked) return { state: "unauthorized", reason: "This worker was revoked. Register a new one to reconnect." };
  const seen = w.last_seen_at ? new Date(w.last_seen_at).getTime() : 0;
  const failed = w.last_auth_fail_at ? new Date(w.last_auth_fail_at).getTime() : 0;
  if (failed && failed > seen) {
    return { state: "unauthorized", reason: w.last_auth_fail_reason || "The worker's token was rejected." };
  }
  if (!seen) return { state: "offline", reason: "Never connected. Start the worker on your Linux host." };
  if (now - seen > ONLINE_MS) return { state: "offline", reason: "No heartbeat in the last 90 seconds." };
  const caps = (w.caps && typeof w.caps === "object" ? w.caps : {}) as Record<string, unknown>;
  if (caps.docker !== true) return { state: "unhealthy", reason: "Connected, but Docker is not reachable on the host." };
  if (caps.sandbox_ok !== true) {
    return { state: "unhealthy", reason: String(caps.sandbox_error || "Connected, but the sandbox self-test failed.") };
  }
  return { state: "online", reason: "Heartbeat received and sandbox self-test passed." };
}
