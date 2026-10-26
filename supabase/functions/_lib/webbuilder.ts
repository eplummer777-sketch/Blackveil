export const LIMITS = {
  maxFileChars: 200_000,
  maxFiles: 200,
  maxProjectChars: 2_000_000,
  maxSnapshots: 30,
  contextChars: 60_000,
  // One request must fit the on-device model's 8k-token window together with the project context.
  // A message over this length is refused with an explanation, never shortened silently.
  maxPromptChars: 12_000,
};

export interface OwnerConfig {
  owner_email: string;
  owner_user_id: string;
}

export interface AuthUser {
  id: string;
  email?: string | null;
  email_confirmed_at?: string | null;
}

export function isOwner(user: AuthUser | null | undefined, cfg: OwnerConfig | null | undefined): boolean {
  if (!user || !cfg || !cfg.owner_user_id || !cfg.owner_email) return false;
  if (!user.email || !user.email_confirmed_at) return false;
  return user.id === cfg.owner_user_id && user.email.trim().toLowerCase() === cfg.owner_email.trim().toLowerCase();
}

export function validatePath(input: unknown): { ok: true; path: string } | { ok: false; error: string } {
  if (typeof input !== "string") return { ok: false, error: "Path must be text." };
  const path = input.trim();
  if (!path || path.length > 200) return { ok: false, error: "Path must be 1-200 characters." };
  if (!/^[A-Za-z0-9._\-/]+$/.test(path)) return { ok: false, error: "Path may only use letters, numbers, . _ - and /." };
  if (path.startsWith("/")) return { ok: false, error: "Path must be relative to the project." };
  const parts = path.split("/");
  if (parts.some((p) => p === "" || p === "." || p === "..")) return { ok: false, error: "Path contains an invalid segment." };
  if (parts.length > 8) return { ok: false, error: "Path is nested too deeply." };
  return { ok: true, path };
}

export type FileMap = Record<string, string>;

export function checkProjectSize(files: FileMap): string | null {
  const paths = Object.keys(files);
  if (paths.length > LIMITS.maxFiles) return `A project can have at most ${LIMITS.maxFiles} files.`;
  let total = 0;
  for (const p of paths) {
    const len = files[p].length;
    if (len > LIMITS.maxFileChars) return `${p} is larger than ${LIMITS.maxFileChars} characters.`;
    total += len;
  }
  if (total > LIMITS.maxProjectChars) return `Project is larger than ${LIMITS.maxProjectChars} characters.`;
  return null;
}

export function buildContext(files: FileMap, ordered: string[], budget = LIMITS.contextChars): { included: string[]; omitted: string[]; text: string } {
  const included: string[] = [];
  const omitted: string[] = [];
  let used = 0;
  let text = "";
  for (const p of [...new Set(ordered)]) {
    if (!(p in files)) continue;
    const chunk = `--- FILE: ${p}\n${files[p]}\n--- END FILE: ${p}\n`;
    if (used + chunk.length > budget) { omitted.push(p); continue; }
    used += chunk.length;
    included.push(p);
    text += chunk;
  }
  return { included, omitted, text };
}

export interface PatchEdit { find: string; replace: string }

export type ProposedFile =
  | { path: string; action: "create" | "update"; content: string }
  | { path: string; action: "delete" }
  | { path: string; action: "rename"; from: string; content?: string }
  | { path: string; action: "patch"; edits: PatchEdit[] };

export const MAX_CHANGES_PER_REPLY = 60;
// A full-file rewrite larger than this is more likely to be a cut-off reply than a real file.
// Larger files must be changed with targeted "patch" edits instead.
export const FULL_FILE_MAX_CHARS = 8_000;

export interface ParsedChangeSet {
  reply: string;
  notes: string;
  changes: ProposedFile[];
  /** Entries that were refused, and why. Shown to the owner instead of disappearing. */
  dropped: string[];
  error?: string;
}

export function parseAiReply(raw: string): ParsedChangeSet {
  const o = extractJson(raw);
  if (!o) return { reply: raw.trim(), notes: "", changes: [], dropped: [], error: "AI reply was not a valid change set." };
  const reply = typeof o.reply === "string" ? o.reply : "";
  const notes = typeof o.notes === "string" ? o.notes.slice(0, 2000) : "";
  const list = Array.isArray(o.changes) ? o.changes : [];
  const dropped: string[] = [];
  if (list.length > MAX_CHANGES_PER_REPLY) {
    dropped.push(`${list.length - MAX_CHANGES_PER_REPLY} more change(s) than one reply may contain were left out`);
  }
  const changes: ProposedFile[] = [];
  const seen = new Set<string>();
  for (const item of list.slice(0, MAX_CHANGES_PER_REPLY)) {
    const c = (item ?? {}) as Record<string, unknown>;
    const v = validatePath(c.path);
    if (!v.ok) { dropped.push(`An entry with an unusable path was ignored (${v.error}).`); continue; }
    if (seen.has(v.path)) { dropped.push(`A second change for ${v.path} in the same reply was ignored.`); continue; }
    const content = typeof c.content === "string" && c.content.length <= LIMITS.maxFileChars ? c.content : undefined;
    if (c.action === "delete") changes.push({ path: v.path, action: "delete" });
    else if (c.action === "create" || c.action === "update") {
      if (content === undefined) {
        dropped.push(`${v.path} was skipped: the reply had no file content for it.`);
        continue;
      }
      if (content.length > FULL_FILE_MAX_CHARS) {
        dropped.push(`${v.path} was skipped: a ${content.length}-character full-file rewrite is over the ${FULL_FILE_MAX_CHARS}-character limit for one reply. Ask for smaller, targeted edits to this file instead.`);
        continue;
      }
      changes.push({ path: v.path, action: c.action, content });
    } else if (c.action === "rename") {
      const from = validatePath(c.from);
      if (!from.ok || from.path === v.path) { dropped.push(`A rename with an unusable source path was ignored.`); continue; }
      changes.push(content === undefined ? { path: v.path, action: "rename", from: from.path } : { path: v.path, action: "rename", from: from.path, content });
    } else if (c.action === "patch" && Array.isArray(c.edits)) {
      const edits = (c.edits as unknown[]).slice(0, 80)
        .map((e) => (e ?? {}) as Record<string, unknown>)
        .filter((e) => typeof e.find === "string" && e.find !== "" && typeof e.replace === "string")
        .map((e) => ({ find: e.find as string, replace: e.replace as string }));
      if (!edits.length) { dropped.push(`${v.path} was skipped: its patch had no usable find/replace pair.`); continue; }
      changes.push({ path: v.path, action: "patch", edits });
    } else {
      dropped.push(`${v.path} was skipped: "${String(c.action)}" is not a change this builder can make.`);
      continue;
    }
    seen.add(v.path);
  }
  return { reply: reply || (changes.length ? "Proposed changes are ready for review." : raw.trim()), notes, changes, dropped };
}

export function extractJson(raw: string): Record<string, unknown> | null {
  const stripped = raw.trim().replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/, "");
  const start = stripped.indexOf("{");
  const end = stripped.lastIndexOf("}");
  if (start < 0 || end <= start) return null;
  try {
    const v = JSON.parse(stripped.slice(start, end + 1));
    return v && typeof v === "object" && !Array.isArray(v) ? v as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

export interface InspectPlan {
  reply: string;
  goal: string;
  understanding: string;
  files: string[];
  targets: string[];
  creates: string[];
  plan: string[];
  /** One row per requirement the planner claims to cover, matched by the R-number ids it was given. */
  coverage: { requirement: string; covered_by: string }[];
  /** Anything the parser had to shorten, so the app can say so instead of cutting quietly. */
  trimmed: string[];
}

const inspectCoverage = (v: unknown): { requirement: string; covered_by: string }[] => {
  if (!Array.isArray(v)) return [];
  return v
    .map((r) => (r ?? {}) as Record<string, unknown>)
    .filter((r) => typeof r.requirement === "string")
    .map((r) => ({
      requirement: String(r.requirement).trim(),
      covered_by: typeof r.covered_by === "string" ? r.covered_by.trim() : "",
    }))
    .filter((r) => r.requirement !== "");
};

export function parseInspectReply(raw: string, existing: FileMap, maxFiles = 100): InspectPlan {
  const o = extractJson(raw) ?? {};
  const trimmed: string[] = [];
  const cut = (label: string, value: string, max: number) => {
    if (value.length > max) trimmed.push(`${label} shortened from ${value.length} to ${max} characters`);
    return value.slice(0, max);
  };
  const understanding = cut("understanding", typeof o.understanding === "string" ? o.understanding : "", 2_000);
  const goal = cut("goal", typeof o.goal === "string" ? o.goal : "", 600);
  const pick = (v: unknown) => [...new Set((Array.isArray(v) ? v : []).filter((p): p is string => typeof p === "string" && p in existing))];
  const files = pick(o.files_to_inspect).slice(0, maxFiles);
  const targets = pick(o.files_to_change).slice(0, maxFiles);
  const creates = [...new Set((Array.isArray(o.files_to_create) ? o.files_to_create : [])
    .map((p) => validatePath(p)).filter((r): r is { ok: true; path: string } => r.ok && !(r.path in existing)).map((r) => r.path))].slice(0, 60);
  const rawPlan = (Array.isArray(o.plan) ? o.plan : []).filter((s): s is string => typeof s === "string" && s.trim() !== "");
  if (rawPlan.length > 40) trimmed.push(`plan shortened from ${rawPlan.length} to 40 steps`);
  const plan = rawPlan.slice(0, 40).map((s) => cut("a plan step", s, 600));
  const reply = cut("answer", typeof o.reply === "string" ? o.reply.trim() : "", 8_000);
  return { reply, goal, understanding, files, targets, creates, plan, coverage: inspectCoverage(o.requirement_coverage), trimmed };
}

export interface VerifyCheck { name: string; ok: boolean; detail: string; warn?: boolean }

export function verifyAppliedFiles(stored: FileMap, expected: { path: string; after: string | null }[]): VerifyCheck[] {
  const mismatched = expected.filter((f) => (f.after === null ? f.path in stored : stored[f.path] !== f.after)).map((f) => f.path);
  return [{ name: "Saved files match the approved proposal", ok: mismatched.length === 0, detail: mismatched.length ? `Mismatch: ${mismatched.join(", ")}` : `${expected.length} file(s) re-read and confirmed` }];
}

export const STATIC_STARTER: FileMap = {
  "index.html": `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>New site</title>
  <link rel="stylesheet" href="styles.css" />
</head>
<body>
  <main class="hero">
    <h1>Hello from Blackveil Web Builder</h1>
    <p>Describe what you want in the chat, or edit these files directly.</p>
    <button id="cta">Click me</button>
  </main>
  <script src="script.js"></script>
</body>
</html>
`,
  "styles.css": `* { box-sizing: border-box; }
body { margin: 0; font-family: system-ui, sans-serif; background: #0b1220; color: #e2e8f0; }
.hero { min-height: 100vh; display: grid; place-content: center; text-align: center; gap: 16px; padding: 24px; }
h1 { margin: 0; font-size: 2.5rem; line-height: 1.2; }
button { padding: 12px 20px; border: 0; border-radius: 8px; background: #22d3ee; color: #0b1220; font-weight: 600; cursor: pointer; }
`,
  "script.js": `document.getElementById('cta')?.addEventListener('click', () => {
  document.querySelector('p').textContent = 'JavaScript is running in the preview.';
});
`,
};
